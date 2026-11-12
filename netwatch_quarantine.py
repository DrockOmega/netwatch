"""Active LAN quarantine: put a boot on a misbehaving device's wheel.

Where ``netwatch_mitigation`` blocks a bad *external* IP at this host's firewall,
this severs a *local* device from the network without any cooperation from the
gateway — which matters when the gateway is a locked-down ISP box (Xfinity xFi)
that exposes no firewall/VLAN/ACL surface.

Mechanism: ARP cache poisoning from this host. On a switched LAN, sending the
victim a forged ARP reply — "the gateway is at <sink MAC>" — makes the victim's
egress frames go to a MAC that isn't the gateway, so its internet path dies.
Optionally the gateway's cache is poisoned the same way for the return path, for
full bidirectional isolation. The poison is re-asserted on a short cadence because
the victim re-ARPs and the real gateway broadcasts gratuitous ARP; releasing a
quarantine sends *corrective* ARP so the victim recovers immediately instead of
waiting for its cache to time out.

This is the project's first active-emission capability — a deliberate lift of the
old passive-only convention. Like mitigation it ships live (``QUARANTINE_ENABLED`` on,
``QUARANTINE_DRY_RUN`` off); what may go on the wire is gated by ``RESPONSE_MODE``,
whose fresh-install default ``ids_only`` starts no new containment, and ``ready``
queues each one for approval.

Design mirrors ``netwatch_mitigation``:
- **Policy is pure and testable** (``Quarantine.evaluate``): the protected set,
  dedup, capacity cap, TTL, and the auto-vs-approve gate decide with no side
  effects. Tests drive it with a recording fake effector and never emit a frame.
- **The effector is injectable.** ``ArpQuarantineEffector`` owns all scapy + MAC
  resolution; ``RecordingQuarantineEffector`` records intents for tests. A
  ``dry_run`` effector logs the exact frames it *would* send.
- **Safe by default.** The gateway, this host, and broadcast/multicast/loopback
  are never quarantinable; every quarantine carries an auto-expiry; manual mode
  requires an explicit ``approve``.
- **Durable.** The active set is persisted so a quarantine survives a restart and
  is re-asserted (and still expires) on the next boot.
"""

import ipaddress
import json
import logging
import os
import re
import subprocess
import threading
import time

from netwatch_core import write_json_atomic
from netwatch_inventory import normalize_mac
from netwatch_mitigation import ip_key

# A locally-administered, almost-certainly-unused MAC used as the black hole. The
# U/L bit (0x02) is set and it belongs to no real vendor, so poisoning the victim
# with "gateway -> this MAC" sends its traffic to a port that does not exist
# rather than to us — no accidental man-in-the-middle if IP forwarding is on.
DEFAULT_SINK_MAC = "02:00:00:00:de:ad"

# Decision outcomes from Quarantine.evaluate (no side effects).
QUARANTINE = "QUARANTINE"                 # eligible; apply will poison the victim
PENDING_APPROVAL = "PENDING_APPROVAL"     # eligible but manual mode needs approval
ALREADY_QUARANTINED = "ALREADY_QUARANTINED"
PROTECTED = "PROTECTED"                   # gateway / self / structural / allowlisted
AT_CAPACITY = "AT_CAPACITY"               # active cap reached; refuse new quarantines
INVALID = "INVALID"                       # not a usable IPv4 address


def _valid_ipv4(ip):
    try:
        return isinstance(ipaddress.ip_address(str(ip)), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_protected(ip, *, gateway_ip, own_ip, allowlist_ips):
    """Pure: True if ``ip`` must never be quarantined — it is the gateway, this
    host, an explicitly allowlisted address, or structurally non-routable
    (loopback / link-local / multicast / unspecified / reserved / broadcast).

    Note this is the INVERSE of the mitigation allowlist: an ordinary private LAN
    address is a valid quarantine *target* here, so ``is_private`` is deliberately
    NOT protected."""
    if ip_key(ip) in {ip_key(gateway_ip), ip_key(own_ip), *(ip_key(entry) for entry in allowlist_ips)}:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable => refuse, fail safe
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return True
    return str(addr) == "255.255.255.255"


def _parse_arp_cache():
    """Parse the OS ARP cache into ``{ip: normalized_mac}``. Best-effort; an empty
    dict on any failure. Windows ``arp -a`` uses ``aa-bb-cc-dd-ee-ff`` form."""
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    table = {}
    row = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\b")
    for line in out.splitlines():
        m = row.match(line)
        if not m:
            continue
        mac = normalize_mac(m.group(2))
        if mac:
            table[m.group(1)] = mac
    return table


class RecordingQuarantineEffector:
    """Test/dry-planning effector: records intents instead of touching the wire.

    Resolves MACs from a caller-supplied table so policy tests are deterministic
    and never shell out or send a frame."""

    def __init__(self, mac_table=None, own_mac="02:00:00:00:00:01"):
        self.mac_table = dict(mac_table or {})
        self.own_mac = own_mac
        self.dry_run = True
        self.gateway_poisoned = False
        self.poisoned = []   # (victim_ip, gateway_ip, bidirectional)
        self.healed = []     # (victim_ip, gateway_ip)

    def resolve_mac(self, ip):
        return self.mac_table.get(ip)

    def quarantine(self, victim_ip, gateway_ip, *, bidirectional=True):
        self.poisoned.append((victim_ip, gateway_ip, bidirectional))
        return True

    def heal(self, victim_ip, gateway_ip):
        self.healed.append((victim_ip, gateway_ip))
        return True

    def is_gateway_poisoned(self, gateway_ip):
        del gateway_ip
        return self.gateway_poisoned


class ArpQuarantineEffector:
    """Real effector: forged/corrective ARP via scapy on a chosen interface.

    Owns all scapy imports and MAC resolution so the policy engine stays pure.
    Scapy is imported lazily inside the methods — the same localized-import
    discipline the sniffer uses — because quarantine emits at a few frames per
    second, never on the capture hot path. With ``dry_run=True`` it resolves and
    logs the exact frames it *would* send without transmitting."""

    def __init__(self, interface, *, sink_mac=DEFAULT_SINK_MAC, dry_run=True, logger=None):
        self.interface = interface
        self.sink_mac = normalize_mac(sink_mac) or DEFAULT_SINK_MAC
        self.dry_run = dry_run
        self.log = logger
        self._own_mac = None
        self._arp_cache_ts = 0.0
        self._arp_cache = {}
        self._known_macs = {}

    # --- resolution ------------------------------------------------------
    def own_mac(self):
        if self._own_mac is None:
            try:
                from scapy.arch import get_if_hwaddr
                self._own_mac = normalize_mac(get_if_hwaddr(self.interface))
            except Exception:
                self._own_mac = None
        return self._own_mac

    def resolve_mac(self, ip):
        """ARP cache first (cheap, reflects the OS's own learned bindings); fall
        back to one active ARP request if absent. Returns a normalized MAC or
        None."""
        now = time.time()
        if now - self._arp_cache_ts > 2.0:
            self._arp_cache = _parse_arp_cache()
            self._arp_cache_ts = now
        mac = self._arp_cache.get(ip)
        if mac and mac != self.sink_mac:
            self._known_macs[ip] = mac
            return mac
        known = self._known_macs.get(ip)
        if known:
            return known
        try:
            from scapy.layers.l2 import ARP, Ether
            from scapy.sendrecv import srp
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                         iface=self.interface, timeout=1, retry=1, verbose=0)
            for _, rcv in ans:
                resolved = normalize_mac(rcv.hwsrc)
                if resolved and resolved != self.sink_mac:
                    self._known_macs[ip] = resolved
                    return resolved
        except Exception:
            return None
        return None

    def is_gateway_poisoned(self, gateway_ip):
        """Return whether this host currently resolves its gateway to the sink."""
        return _parse_arp_cache().get(gateway_ip) == self.sink_mac

    def _send(self, frames, label):
        if self.log:
            for f in frames:
                self.log.info("quarantine %s%s: %s", "(dry-run) " if self.dry_run else "", label, f)
        if self.dry_run:
            return True
        try:
            from scapy.sendrecv import sendp
            sendp(frames, iface=self.interface, verbose=0)
            return True
        except Exception as exc:
            if self.log:
                self.log.error("quarantine send failed: %s: %s", type(exc).__name__, exc)
            return False

    # --- effector interface ---------------------------------------------
    def quarantine(self, victim_ip, gateway_ip, *, bidirectional=True):
        """Poison the victim's cache so ``gateway_ip`` resolves to the sink MAC;
        optionally poison the gateway so ``victim_ip`` resolves to the sink MAC.
        A missing victim/gateway MAC aborts (nothing half-poisoned)."""
        from scapy.layers.l2 import ARP, Ether
        victim_mac = self.resolve_mac(victim_ip)
        if victim_mac is None:
            if self.log:
                self.log.warning("quarantine: could not resolve victim MAC for %s", victim_ip)
            return False
        frames = [Ether(dst=victim_mac) / ARP(op=2, psrc=gateway_ip, hwsrc=self.sink_mac,
                                              pdst=victim_ip, hwdst=victim_mac)]
        if bidirectional:
            gw_mac = self.resolve_mac(gateway_ip)
            if gw_mac is not None:
                frames.append(Ether(dst=gw_mac) / ARP(op=2, psrc=victim_ip, hwsrc=self.sink_mac,
                                                       pdst=gateway_ip, hwdst=gw_mac))
        return self._send(frames, f"poison {victim_ip}")

    def heal(self, victim_ip, gateway_ip):
        """Send corrective ARP so the victim (and gateway) relearn the true MACs
        immediately instead of waiting for cache expiry."""
        from scapy.layers.l2 import ARP, Ether
        victim_mac = self.resolve_mac(victim_ip)
        gw_mac = self.resolve_mac(gateway_ip)
        frames = []
        if victim_mac and gw_mac:
            frames.append(Ether(dst=victim_mac) / ARP(op=2, psrc=gateway_ip, hwsrc=gw_mac,
                                                       pdst=victim_ip, hwdst=victim_mac))
            frames.append(Ether(dst=gw_mac) / ARP(op=2, psrc=victim_ip, hwsrc=victim_mac,
                                                   pdst=gateway_ip, hwdst=gw_mac))
        if not frames:
            return False
        return self._send(frames, f"heal {victim_ip}")


class Quarantine:
    """Policy + ledger + effector + re-assert loop for LAN quarantine.

    ``evaluate`` is pure; ``request``/``approve``/``release``/``reconcile`` are the
    side-effecting paths. ``start()`` spawns the daemon that re-asserts the poison
    for every active entry on ``reassert_sec`` cadence."""

    def __init__(
        self,
        effector,
        *,
        gateway_ip,
        own_ip="",
        auto=False,
        ttl_sec=1800,
        max_active=64,
        bidirectional=True,
        reassert_sec=2.0,
        allowlist_ips=None,
        ledger_path=None,
        logger=None,
        shutdown_event=None,
    ):
        self.effector = effector
        self.gateway_ip = gateway_ip or ""
        self.own_ip = own_ip or ""
        self.auto = auto
        self.ttl_sec = ttl_sec
        self.max_active = max_active
        self.bidirectional = bidirectional
        self.reassert_sec = max(0.5, float(reassert_sec))
        self.allowlist_ips = set(allowlist_ips or ())
        self.ledger_path = ledger_path
        self.log = logger
        self.shutdown_event = shutdown_event
        self.active = {}   # ip -> {mac, reason, created_ts, expires_ts}
        self.pending = {}  # ip -> {mac, reason, requested_ts}
        self._lock = threading.Lock()
        self._unhealed = set()
        self._thread = None
        self._stop_event = threading.Event()
        self._ledger_stamp = None
        if ledger_path:
            self._load()

    # --- pure decision ---------------------------------------------------
    def evaluate(self, ip, now):
        """Classify what *would* happen for ``ip`` right now. No side effects."""
        if not _valid_ipv4(ip):
            return INVALID
        if not self.gateway_ip:
            return INVALID  # cannot poison a gateway we do not know
        if is_protected(ip, gateway_ip=self.gateway_ip, own_ip=self.own_ip, allowlist_ips=self.allowlist_ips):
            return PROTECTED
        if ip in self.active:
            return ALREADY_QUARANTINED
        if len(self.active) >= self.max_active:
            return AT_CAPACITY
        return QUARANTINE if self.auto else PENDING_APPROVAL

    # --- side-effecting paths -------------------------------------------
    def request(self, ip, reason, mac=None, now=None, *, auto=None):
        """Entry point for an alert/operator. Auto mode quarantines an eligible
        target immediately; otherwise it is queued for approval. Returns the
        decision."""
        now = time.time() if now is None else now
        decision = self.evaluate(ip, now)
        if decision in {QUARANTINE, PENDING_APPROVAL}:
            decision = QUARANTINE if (self.auto if auto is None else bool(auto)) else PENDING_APPROVAL
        if decision == QUARANTINE:
            if not self._apply(ip, reason, mac, now):
                return "QUARANTINE_FAILED"
        elif decision == PENDING_APPROVAL:
            if ip not in self.pending and len(self.pending) >= self.max_active:  # more could never be applied
                logging.getLogger("netwatch.ui").warning("approval queue full (%d); %s not queued", len(self.pending), ip)
                return AT_CAPACITY
            self.pending[ip] = {"mac": mac, "reason": reason, "requested_ts": now}
        return decision

    def enforce(self, ip, reason, mac=None, now=None):
        """Apply an explicit policy quarantine while preserving protected-target,
        capacity, TTL, and rollback invariants."""
        now = time.time() if now is None else now
        decision = self.evaluate(ip, now)
        if decision == ALREADY_QUARANTINED:
            return True
        if decision not in (QUARANTINE, PENDING_APPROVAL):
            return False
        return self._apply(ip, reason, mac, now)

    def approve(self, ip, now=None):
        now = time.time() if now is None else now
        item = self.pending.get(ip)
        if item is None:
            return False
        if self.evaluate(ip, now) not in (QUARANTINE, PENDING_APPROVAL):
            self.pending.pop(ip, None)
            return False
        return self._apply(ip, item["reason"], item.get("mac"), now)

    def deny(self, ip):
        return self.pending.pop(ip, None) is not None

    def release(self, ip):
        """Lift a quarantine and heal the victim's cache. Returns True if one
        existed."""
        self._reload_if_changed()
        with self._lock:
            entry = self.active.pop(ip, None)
        if entry is None:
            return False
        try:
            healed = self.effector.heal(ip, self.gateway_ip)
        except Exception as exc:
            healed = False
            if self.log:
                self.log.error("quarantine heal failed for %s: %s: %s", ip, type(exc).__name__, exc)
        if healed is False:
            self._unhealed.add(ip)  # memory only; reconcile retries
            if self.log:
                self.log.critical("quarantine heal failed for %s; will retry", ip)
        self._save()
        return True

    def reconcile(self, now=None):
        """Lift every quarantine whose TTL expired (healing each). Returns the list
        of released IPs. Call periodically and on startup."""
        now = time.time() if now is None else now
        with self._lock:
            expired = [ip for ip, e in self.active.items() if e["expires_ts"] <= now]
        with self._lock:
            retry = [ip for ip in self._unhealed if ip not in self.active]
        for ip in retry:
            try:
                healed = self.effector.heal(ip, self.gateway_ip)
            except Exception:
                healed = False
            if healed is not False:
                self._unhealed.discard(ip)
        released = []
        for ip in expired:
            if self.release(ip):
                released.append(ip)
        return released

    def reassert(self, now=None):
        """Re-send the poison for every active, non-expired quarantine. This is
        what keeps a quarantine enforced against cache expiry and gratuitous ARP;
        the loop in ``start`` calls it, but it is exposed for tests."""
        now = time.time() if now is None else now
        self._reload_if_changed()
        self.reconcile(now)
        if self._gateway_poisoned():
            self._failsafe_release("gateway resolved to quarantine sink before reassert")
            return
        with self._lock:
            targets = list(self.active.keys())
        for ip in targets:
            with self._lock:  # a release since the snapshot must not be re-poisoned
                if ip not in self.active:
                    continue
            try:
                self.effector.quarantine(ip, self.gateway_ip, bidirectional=self.bidirectional)
                with self._lock:
                    released = ip not in self.active
                if released:  # a release landed mid-send: its heal went out before this poison
                    self.effector.heal(ip, self.gateway_ip)
                if self._gateway_poisoned():
                    self._failsafe_release("gateway resolved to quarantine sink after reassert")
                    return
            except Exception as exc:
                if self.log:
                    self.log.error("quarantine reassert failed for %s: %s: %s", ip, type(exc).__name__, exc)

    def start(self):
        """Spawn the re-assert daemon (idempotent). Also re-asserts anything the
        ledger restored on boot."""
        if self._thread is not None:
            return
        self.reconcile()
        self._stop_event.clear()

        def _loop():
            while not self._stop_event.is_set():
                if self.shutdown_event is not None and self.shutdown_event.is_set():
                    break
                if self._stop_event.wait(self.reassert_sec):
                    break
                if self.shutdown_event is not None and self.shutdown_event.is_set():
                    break
                try:
                    self.reassert()
                except Exception as exc:
                    if self.log:
                        self.log.error("quarantine loop fault: %s: %s", type(exc).__name__, exc)

        self._thread = threading.Thread(target=_loop, name="quarantine", daemon=True)
        self._thread.start()

    def stop(self, timeout=3.0):
        """Stop the re-assert loop without emitting another poison frame."""
        self._stop_event.set()
        thread = self._thread
        if thread is None or thread is threading.current_thread():
            return True
        thread.join(timeout=max(0.0, float(timeout)))
        return not thread.is_alive()

    def snapshot(self, now=None):
        now = time.time() if now is None else now
        with self._lock:
            return sorted(
                ({"ip": ip, "mac": e.get("mac") or "?", "reason": e.get("reason", ""),
                  "created_ts": e["created_ts"], "expires_ts": e["expires_ts"],
                  "remaining": max(0, e["expires_ts"] - now)}
                 for ip, e in self.active.items()),
                key=lambda r: r["ip"],
            )

    # --- internals -------------------------------------------------------
    def _apply(self, ip, reason, mac, now):
        self._reload_if_changed()
        if mac is None:
            try:
                mac = self.effector.resolve_mac(ip)
            except Exception:
                mac = None
        if self._gateway_poisoned():
            try:
                self.effector.heal(ip, self.gateway_ip)
            except Exception as exc:
                if self.log:
                    self.log.error("quarantine failsafe heal failed for %s: %s: %s", ip, type(exc).__name__, exc)
            if self.log:
                self.log.critical("quarantine aborted: local gateway resolved to sink before applying %s", ip)
            return False
        try:
            ok = self.effector.quarantine(ip, self.gateway_ip, bidirectional=self.bidirectional)
        except Exception as exc:
            if self.log:
                self.log.error("quarantine apply failed for %s: %s: %s", ip, type(exc).__name__, exc)
            return False
        if not ok:
            return False
        if self._gateway_poisoned():
            try:
                self.effector.heal(ip, self.gateway_ip)
            except Exception as exc:
                if self.log:
                    self.log.error("quarantine failsafe heal failed for %s: %s: %s", ip, type(exc).__name__, exc)
            if self.log:
                self.log.critical("quarantine aborted: local gateway resolved to sink after applying %s", ip)
            return False
        with self._lock:
            self.active[ip] = {"mac": mac, "reason": reason, "created_ts": now,
                               "expires_ts": now + self.ttl_sec,
                               "dry_run": bool(getattr(self.effector, "dry_run", False))}
        self.pending.pop(ip, None)
        self._save()
        return True

    def _gateway_poisoned(self):
        check = getattr(self.effector, "is_gateway_poisoned", None)
        if check is None:
            return False
        try:
            return bool(check(self.gateway_ip))
        except Exception as exc:
            if self.log:
                self.log.error("quarantine gateway failsafe check failed: %s: %s", type(exc).__name__, exc)
            return False

    def _failsafe_release(self, reason):
        with self._lock:
            targets = list(self.active.keys())
        if self.log:
            self.log.critical("quarantine failsafe release: %s", reason)
        for ip in targets:
            self.release(ip)

    def _save(self):
        if not self.ledger_path:
            return
        with self._lock:
            data = {"active": dict(self.active)}
        if not write_json_atomic(self.ledger_path, data):
            (self.log or logging.getLogger(__name__)).error("quarantine ledger not saved: %s", self.ledger_path)
        self._ledger_stamp = self._stamp()

    def _stamp(self):
        try:
            info = os.stat(self.ledger_path)
        except OSError:
            return None
        return info.st_ino, info.st_mtime_ns, info.st_size  # each atomic write is a new inode

    def _reload_if_changed(self):
        """Adopt another writer's ledger (the CLI's hold or release) so this engine neither
        re-poisons a device released elsewhere nor writes it back on its next save."""
        if self.ledger_path and self._stamp() != self._ledger_stamp:
            with self._lock:
                self._load()

    def _load(self):
        try:
            with open(self.ledger_path, encoding="utf-8") as f:
                raw = json.load(f).get("active", {})
            required = {"reason", "created_ts", "expires_ts"}
            # A dry-run hold sent no frame: a live engine must not re-assert it.
            live = not getattr(self.effector, "dry_run", False)
            self.active = {ip: e for ip, e in raw.items()
                           if isinstance(e, dict) and required <= e.keys() and not (live and e.get("dry_run"))}
        except (OSError, ValueError):
            self.active = {}
        self._ledger_stamp = self._stamp()
