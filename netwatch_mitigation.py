"""Active mitigation engine: turn an alert into a (reversible, audited) block.

This is the "and mitigation" half of the product. It is built defensively:

- **Policy is pure and testable.** Allowlist checks, dedup, TTL expiry, the
  capacity cap, and the auto-vs-approve gate are decided without any side effects
  (``Mitigator.evaluate``). The effector is only touched when a decision is
  actually applied.
- **The effector is injectable.** ``WindowsFirewall`` wraps ``netsh advfirewall``;
  tests pass a recording fake so they never shell out. A ``dry_run`` effector
  logs the exact commands without executing them.
- **Safe by default.** Local/multicast/broadcast ranges are never blockable, an
  explicit allowlist is honored, every block carries an auto-expiry, and manual
  mode requires an explicit ``approve`` before anything happens.
- **Durable.** The active-block ledger is persisted to JSON so blocks survive a
  restart and their expiries are still honored (and cleaned up) on the next boot.

Windows-only at the effector layer; the policy layer is platform-agnostic and is
what the test suite exercises.
"""

import ipaddress
import json
import logging
import os
import subprocess
import time
from collections import deque

from netwatch_core import compile_networks, write_json_atomic

# Ranges that must never be blocked: RFC1918 private, loopback, link-local,
# multicast, broadcast, "this network". Blocking these would cut off the LAN.
# These dotted prefixes are the explicit IPv4 list; ``is_allowlisted`` also
# applies a structural check (``ipaddress`` private/loopback/link-local/multicast/
# reserved) which covers both IPv4 and IPv6 — e.g. ``fe80::``, ``fc00::``,
# ``ff02::`` — without enumerating v6 prefixes here.
#
# The structural check is NOT sufficient for IPv6 on its own: a home ISP delegates
# a globally-routable prefix to the LAN, so your own devices carry addresses that
# ``is_private`` reports as False. Those prefixes must be passed in as
# ``allowlist_networks`` (the monitor feeds it the same LOCAL_PREFIXES6 the
# detectors use) or NetWatch will happily firewall its own network.
DEFAULT_ALLOWLIST_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "127.", "169.254.",
    "224.", "239.", "255.", "0.",
)

# Decision outcomes from Mitigator.evaluate (no side effects).
BLOCK = "BLOCK"                      # eligible; apply will create a firewall rule
PENDING_APPROVAL = "PENDING_APPROVAL"  # eligible but manual mode requires approval
ALREADY_BLOCKED = "ALREADY_BLOCKED"  # an active rule already covers this IP
ALREADY_PENDING = "ALREADY_PENDING"  # an approval request already covers this IP
ALLOWLISTED = "ALLOWLISTED"          # protected range or explicit allowlist
AT_CAPACITY = "AT_CAPACITY"          # active-block cap reached; refuse new blocks
INVALID = "INVALID"                  # not a usable IPv4 or IPv6 address string


def _is_valid_ip(ip):
    """True for a parseable IPv4 or IPv6 address literal."""
    try:
        ipaddress.ip_address(str(ip))
        return True
    except ValueError:
        return False


def ip_key(ip):
    """Canonical address text without a zone id, so "2001:DB8::1%1" or a non-canonical
    allowlist entry cannot dodge an explicit match; unparseable text is returned as is."""
    try:
        return str(ipaddress.ip_address(str(ip).split("%", 1)[0].strip()))
    except ValueError:
        return str(ip)


def is_allowlisted(ip, allowlist_prefixes, allowlist_ips, allowlist_networks=()):
    """Pure: True if ``ip`` must never be blocked — it's in the explicit allowlist,
    matches a protected dotted prefix, falls inside an allowlisted network, or is
    structurally non-routable (private, loopback, link-local, multicast,
    unspecified, or reserved). The structural check covers both IPv4 and IPv6;
    ``allowlist_networks`` is what protects globally-routable LAN IPv6."""
    if ip_key(ip) in {ip_key(entry) for entry in allowlist_ips}:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # ip_network.__contains__ returns False across address families, so a mixed
    # v4/v6 allowlist needs no version bookkeeping here.
    if any(addr in net for net in (*compile_networks(allowlist_prefixes), *allowlist_networks)):
        return True
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_unspecified or addr.is_reserved)


def rule_name_for(ip):
    """Stable firewall rule name for an IP. Used for both create and delete."""
    return f"NetWatch Block {ip}"


class FirewallError(RuntimeError):
    pass


class WindowsFirewall:
    """Effector that creates/deletes ``netsh advfirewall`` block rules.

    Creates a paired inbound + outbound block for the remote IP under one rule
    name; deleting by name removes both. With ``dry_run=True`` it records the
    commands it *would* run instead of executing them (the default, on purpose).
    """

    def __init__(self, dry_run=True):
        self.dry_run = dry_run
        self.commands = deque(maxlen=256)  # recent issued (or simulated) commands; in memory only, the ledger is the record

    def _run(self, args):
        self.commands.append(args)
        if self.dry_run:
            return
        try:
            subprocess.run(args, check=True, capture_output=True, text=True, timeout=15)
        except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired) as e:
            raise FirewallError(f"{' '.join(args)} -> {e} {getattr(e, 'stdout', '') or ''}".rstrip()) from e

    def block(self, ip, rule_name):
        self._run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}",
        ])
        try:
            self._run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=out", "action=block", f"remoteip={ip}",
            ])
        except FirewallError:
            try:
                self.unblock(rule_name)
            except FirewallError as rollback_error:
                logging.getLogger("netwatch.ui").warning(
                    "rollback of half-installed rule %r failed: %s", rule_name, rollback_error)
            raise

    def unblock(self, rule_name):
        try:
            self._run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}",
            ])
        except FirewallError as e:
            # An absent rule is already unblocked; otherwise reconcile retries the entry forever.
            # shortcut: matches English netsh output only; key on `show rule` if a localized host appears.
            if "No rules match" not in str(e):
                raise


class Mitigator:
    """Policy + ledger + effector. Decides, applies, expires, and persists blocks.

    The decision path (``evaluate``) is pure; ``request``/``approve``/``reconcile``
    are the only methods that touch the effector or disk.
    """

    def __init__(
        self,
        effector=None,
        *,
        auto=False,
        block_ttl_sec=3600,
        max_active=256,
        allowlist_prefixes=DEFAULT_ALLOWLIST_PREFIXES,
        allowlist_ips=None,
        allowlist_networks=None,
        ledger_path=None,
    ):
        self.effector = effector if effector is not None else WindowsFirewall(dry_run=True)
        self.auto = auto
        self.block_ttl_sec = block_ttl_sec
        self.max_active = max_active
        self.allowlist_prefixes = tuple(allowlist_prefixes)
        self.allowlist_ips = set(allowlist_ips or ())
        self.allowlist_networks = compile_networks(allowlist_networks)
        self.ledger_path = ledger_path
        self._ledger_stamp = None
        self._unblock_failed = set()  # IPs already warned about; cleared on success
        self.active = {}   # ip -> {rule_name, reason, created_ts, expires_ts}
        self.pending = {}  # ip -> {reason, requested_ts}
        if ledger_path:
            self._load()

    # --- pure decision ---------------------------------------------------
    def evaluate(self, ip, now):
        """Classify what *would* happen for ``ip`` right now. No side effects."""
        if not _is_valid_ip(ip):
            return INVALID
        if is_allowlisted(ip, self.allowlist_prefixes, self.allowlist_ips, self.allowlist_networks):
            return ALLOWLISTED
        if ip in self.active:
            return ALREADY_BLOCKED
        if ip in self.pending:
            return ALREADY_PENDING
        if len(self.active) >= self.max_active:
            return AT_CAPACITY
        return BLOCK if self.auto else PENDING_APPROVAL

    # --- side-effecting paths -------------------------------------------
    def request(self, ip, reason, now=None, *, auto=None):
        """Entry point for an alert. In auto mode an eligible IP is blocked
        immediately; otherwise it is queued for approval. Returns the decision."""
        self._reload_if_changed()
        now = time.time() if now is None else now
        decision = self.evaluate(ip, now)
        effective_auto = self.auto if auto is None else bool(auto)
        if decision == ALREADY_PENDING:
            if not effective_auto:
                return ALREADY_PENDING
            if len(self.active) >= self.max_active:
                return AT_CAPACITY
            decision = BLOCK
        if decision in {BLOCK, PENDING_APPROVAL}:
            decision = BLOCK if effective_auto else PENDING_APPROVAL
        if decision == BLOCK:
            if not self._apply_block(ip, reason, now):
                return "MITIGATION_FAILED"
        elif decision == PENDING_APPROVAL:
            if ip not in self.pending and len(self.pending) >= self.max_active:  # more could never be applied
                logging.getLogger("netwatch.ui").warning("approval queue full (%d); %s not queued", len(self.pending), ip)
                return AT_CAPACITY
            self.pending[ip] = {"reason": reason, "requested_ts": now}
        return decision

    def approve(self, ip, now=None):
        """Approve a pending block (manual mode). Returns True if applied."""
        now = time.time() if now is None else now
        item = self.pending.get(ip)
        if item is None:
            return False
        # Re-check policy at approval time (e.g. it may now be allowlisted or
        # the cap may have filled since the request was queued).
        decision = self.evaluate(ip, now)
        if decision != ALREADY_PENDING:
            self.pending.pop(ip, None)
            return False
        if len(self.active) >= self.max_active:
            return False
        return self._apply_block(ip, item["reason"], now)

    def enforce(self, ip, reason, now=None):
        """Apply an explicit policy-engine block regardless of the interactive
        ``auto`` preference while preserving every allowlist, capacity, TTL, and
        rollback invariant."""
        now = time.time() if now is None else now
        decision = self.evaluate(ip, now)
        if decision == ALREADY_BLOCKED:
            return True
        if decision == ALREADY_PENDING and len(self.active) >= self.max_active:
            return False
        if decision not in (BLOCK, PENDING_APPROVAL, ALREADY_PENDING):
            return False
        return self._apply_block(ip, reason, now)

    def deny(self, ip):
        """Drop a pending request without blocking. Returns True if one existed."""
        return self.pending.pop(ip, None) is not None

    def unblock(self, ip):
        """Manually lift an active block. Returns True if one existed."""
        self._reload_if_changed()
        entry = self.active.get(ip)
        if entry is None:
            return False
        self.effector.unblock(entry["rule_name"])
        self.active.pop(ip)
        self._save()
        return True

    def reconcile(self, now=None):
        """Lift every block whose TTL has expired. Returns the list of unblocked
        IPs. Call periodically and on startup."""
        self._reload_if_changed()
        now = time.time() if now is None else now
        expired = [ip for ip, e in self.active.items() if e["expires_ts"] <= now]
        unblocked = []
        for ip in expired:
            entry = self.active[ip]
            try:
                self.effector.unblock(entry["rule_name"])
            except FirewallError as e:
                if ip not in self._unblock_failed:
                    self._unblock_failed.add(ip)
                    logging.getLogger("netwatch.ui").warning("unblock of %s failed, will retry: %s", ip, e)
                continue
            self._unblock_failed.discard(ip)
            self.active.pop(ip)
            unblocked.append(ip)
        if unblocked:
            self._save()
        return unblocked

    def _apply_block(self, ip, reason, now):
        rule = rule_name_for(ip)
        try:
            self.effector.block(ip, rule)
        except FirewallError:
            return False
        self.active[ip] = {
            "rule_name": rule,
            "reason": reason,
            "created_ts": now,
            "expires_ts": now + self.block_ttl_sec,
            "dry_run": bool(getattr(self.effector, "dry_run", False)),
        }
        self.pending.pop(ip, None)
        self._save()
        return True

    # --- persistence -----------------------------------------------------
    def _save(self):
        if not self.ledger_path:
            return
        if not write_json_atomic(self.ledger_path, {"active": self.active}):
            # An unsaved block is not expired after a restart; the next save rewrites the whole set.
            logging.getLogger(__name__).error("firewall block ledger not saved: %s", self.ledger_path)
        self._ledger_stamp = self._stamp()

    def _load(self):
        try:
            with open(self.ledger_path) as f:
                data = json.load(f)
            # A dry-run block placed no rule: a live engine must not treat it as active.
            live = not getattr(self.effector, "dry_run", False)
            self.active = {ip: e for ip, e in dict(data.get("active", {})).items()
                           if not (live and isinstance(e, dict) and e.get("dry_run"))}
        except (OSError, ValueError):
            self.active = {}
        self._ledger_stamp = self._stamp()

    def _stamp(self):
        try:
            info = os.stat(self.ledger_path)
        except OSError:
            return None
        return info.st_ino, info.st_mtime_ns, info.st_size  # each atomic write is a new inode

    def _reload_if_changed(self):
        """Adopt another writer's ledger (the CLI's block or unblock), as the quarantine engine
        does, so a block lifted elsewhere is not written back on this engine's next save."""
        if self.ledger_path and self._stamp() != self._ledger_stamp:
            self._load()
