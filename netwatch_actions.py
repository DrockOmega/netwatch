"""Durable response-action lifecycle owned by the headless service.

Records move requested -> approved|denied -> applied|failed -> released|expired.
The only effector wired by the service records an intent. It does not call the
firewall, ARP, or any other control. Readback stays unverified: a receipt is
not proof the network changed. Policy previews stay on their existing path.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import time
import uuid
from dataclasses import dataclass, field

from netwatch_config import detect_own_ipv4
from netwatch_core import compile_networks
from netwatch_inventory import is_usable_mac, normalize_mac
from netwatch_mitigation import DEFAULT_ALLOWLIST_PREFIXES, is_allowlisted
from netwatch_quarantine import is_protected
from netwatch_security_store import _encode

CONSOLE_ACTOR = "authenticated-console"
SERVICE_ACTOR = "netwatch-service"
KINDS = frozenset({"block_ip", "quarantine_mac"})
STATES = frozenset({"requested", "approved", "denied", "applied", "failed", "released", "expired"})
LEGAL = {
    "requested": frozenset({"approved", "denied"}),
    "approved": frozenset({"applied", "failed"}),
    "applied": frozenset({"released", "expired"}),
}
_TERMINAL = frozenset({"denied", "failed", "released", "expired"})


def legal_transition(old, new):
    """True only for the one-step moves the lifecycle allows."""
    return new in LEGAL.get(old, ())


@dataclass(frozen=True)
class Protection:
    """Inputs for the existing mitigation and quarantine predicates.

    This object does not reimplement those checks. Gateway, this host, local
    prefixes, explicit allowlist entries and structural addresses are refused
    by calling ``is_allowlisted`` and ``is_protected``.
    """

    allowlist_prefixes: tuple = DEFAULT_ALLOWLIST_PREFIXES
    allowlist_ips: frozenset = field(default_factory=frozenset)
    allowlist_networks: tuple = ()
    gateway_ip: str = ""
    own_ip: str = ""
    gateway_mac: str = ""
    own_mac: str = ""

    def __post_init__(self):
        object.__setattr__(self, "allowlist_prefixes", tuple(self.allowlist_prefixes))
        object.__setattr__(self, "allowlist_ips", frozenset(str(ip) for ip in self.allowlist_ips))
        object.__setattr__(self, "allowlist_networks", compile_networks(self.allowlist_networks))
        object.__setattr__(self, "gateway_ip", _canonical_ip(self.gateway_ip) or "")
        object.__setattr__(self, "own_ip", _canonical_ip(self.own_ip) or "")
        object.__setattr__(self, "gateway_mac", normalize_mac(self.gateway_mac) or "")
        object.__setattr__(self, "own_mac", normalize_mac(self.own_mac) or "")


def protection_from_config(config):
    """Build protection inputs from the service config without new policy."""
    config = config or {}
    prefixes = tuple(dict.fromkeys((
        *DEFAULT_ALLOWLIST_PREFIXES, *(config.get("LOCAL_PREFIXES") or ()))))
    own = config.get("OWN_IP") or detect_own_ipv4()
    return Protection(
        allowlist_prefixes=prefixes,
        allowlist_ips=config.get("ALLOWLIST_IPS") or (),
        allowlist_networks=tuple(config.get("LOCAL_PREFIXES6") or ()),
        gateway_ip=str(config.get("GATEWAY_IP") or ""),
        own_ip=str(own or ""),
        gateway_mac=str(config.get("GATEWAY_MAC") or ""),
        own_mac=str(config.get("OWN_MAC") or ""),
    )


def _ttl(config):
    try:
        ttl = float((config or {}).get("MITIGATION_TTL_SEC", 3600))
    except (TypeError, ValueError):
        return 3600.0
    if isinstance((config or {}).get("MITIGATION_TTL_SEC", 3600), bool) or not math.isfinite(ttl):
        return 3600.0
    if not 0 < ttl <= 86400 * 365:
        return 3600.0
    return ttl


class RecordingResponseEffector:
    """Remember apply and release intents. Never an enforcement adapter."""

    def __init__(self):
        self.operations = []

    def apply(self, action):
        return self._record("apply", action)

    def release(self, action):
        return self._record("release", action)

    def _record(self, operation, action):
        receipt = {
            "ok": True,
            "receipt_id": uuid.uuid4().hex,
            "effector": "recording",
            "operation": operation,
            "enforced": False,
            "kind": action["kind"],
            "target": action["target"],
        }
        self.operations.append(dict(receipt))
        del self.operations[:-256]  # in-memory echo only; the store's action audit rows are the record
        return receipt


def service_actions(store, config):
    """The only action owner the service constructs: recording, never enforcing."""
    return ActionService(
        store, RecordingResponseEffector(), protection_from_config(config), default_ttl=_ttl(config))


def _accepted_receipt(receipt, operation):
    """An apply/release counts only when it is an explicit non-enforcing recording."""
    if not isinstance(receipt, dict):
        return False
    receipt_id = receipt.get("receipt_id")
    return (receipt.get("ok") is True and receipt.get("enforced") is False
            and receipt.get("effector") == "recording" and receipt.get("operation") == operation
            and isinstance(receipt_id, str) and 1 <= len(receipt_id) <= 128)


def _text(value, label, limit, *, allow_empty=False):
    if not isinstance(value, str) or len(value) > limit or (not allow_empty and not value.strip()):
        raise ValueError(f"invalid {label}")
    return value.strip()


def _finite_time(value, label):
    if isinstance(value, bool):
        raise ValueError(f"invalid {label}")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"invalid {label}") from None
    if not math.isfinite(number):
        raise ValueError(f"invalid {label}")
    return number


def _canonical_ip(value):
    if not isinstance(value, str) or not value.strip() or "%" in value:  # a zone id is no response target
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


class ActionService:
    """Request, decide, record and expire actions in the security-store transaction."""

    def __init__(self, store, effector, protection, *, default_ttl=3600, clock=None):
        if not hasattr(effector, "apply") or not hasattr(effector, "release"):
            raise ValueError("response effector must record apply and release")
        self.store = store
        self.effector = effector
        self.protection = protection
        self.default_ttl = _finite_time(default_ttl, "ttl")
        if self.default_ttl <= 0:
            raise ValueError("invalid ttl")
        self.clock = time_clock if clock is None else clock

    def protected(self, kind, target, scope):
        """Refuse gateway, this host, local/allowlisted and structural targets."""
        if kind not in KINDS:
            raise ValueError("invalid kind")
        addresses = []
        if kind == "block_ip":
            ip = _canonical_ip(target)
            if ip is None:
                raise ValueError("invalid target")
            addresses.append(ip)
            scoped = _canonical_ip(scope) if scope else None
            if scoped is not None:
                addresses.append(scoped)
        else:
            mac = normalize_mac(target)
            if mac is None:
                raise ValueError("invalid target")
            protected_macs = {self.protection.gateway_mac, self.protection.own_mac} - {""}
            if not is_usable_mac(mac) or mac in protected_macs:
                raise ValueError("protected target")
            scoped = _canonical_ip(scope)
            if scoped is None:
                raise ValueError("quarantine scope must be the victim IP")
            self._local_unprotected(scoped)
            return
        if any(self._address_protected(ip) for ip in addresses):
            raise ValueError("protected target")

    def _local_unprotected(self, ip):
        # Quarantine is the inverse of blocking: the victim must be a
        # local device, and only the gateway, this host, explicit allowlist entries
        # and structural addresses are protected (see netwatch_quarantine).
        guard = self.protection
        if not is_allowlisted(ip, guard.allowlist_prefixes, set(), guard.allowlist_networks) or \
                is_protected(ip, gateway_ip=guard.gateway_ip, own_ip=guard.own_ip,
                             allowlist_ips=set(guard.allowlist_ips)):
            raise ValueError("protected target")

    def _address_protected(self, ip):
        guard = self.protection
        return (is_allowlisted(ip, guard.allowlist_prefixes, set(guard.allowlist_ips), guard.allowlist_networks)
                or is_protected(ip, gateway_ip=guard.gateway_ip, own_ip=guard.own_ip,
                               allowlist_ips=set(guard.allowlist_ips)))

    def request(self, *, kind, target, reason, requested_by, scope="", case_id=None,
                expires_at=None, now=None):
        now = self._now(now)
        if kind not in KINDS:
            raise ValueError("invalid kind")
        reason = _text(reason, "reason", 4096)
        requested_by = _text(requested_by, "requested_by", 256)
        scope = _text(scope, "scope", 256, allow_empty=True) if scope else ""
        self.protected(kind, target, scope)
        if kind == "block_ip":
            target = _canonical_ip(target)
            if scope and _canonical_ip(scope):
                scope = _canonical_ip(scope)
        else:
            target = normalize_mac(target)
            scope = _canonical_ip(scope)
        if expires_at is None:
            expires_at = now + self.default_ttl
        expires_at = _finite_time(expires_at, "expiry")
        if expires_at <= now:
            raise ValueError("expiry must be after the request")
        if expires_at - now > self.default_ttl:
            raise ValueError("expiry exceeds MITIGATION_TTL_SEC")
        if case_id is not None:
            case_id = _text(case_id, "case", 128)
        record = {
            "id": uuid.uuid4().hex,
            "case_id": case_id,
            "kind": kind,
            "target": target,
            "scope": scope,
            "requested_by": requested_by,
            "reason": reason,
            "state": "requested",
            "requested_at": now,
            "decided_at": None,
            "applied_at": None,
            "closed_at": None,
            "expires_at": expires_at,
            "readback": "unverified",
            "receipt": None,
        }
        with self.store._transaction():
            if case_id and not self.store.conn.execute(
                    "SELECT 1 FROM security_incidents WHERE incident_id=?", (case_id,)).fetchone():
                raise ValueError("unknown case")
            # A retry after an unknown outcome must not open a second action on the same target.
            existing = self.store.conn.execute(
                """SELECT action_id FROM security_response_actions WHERE kind=? AND target=?
                   AND state IN ('requested', 'approved', 'applied') AND expires_at>?
                   ORDER BY requested_at LIMIT 1""", (kind, target, now)).fetchone()
            if existing is None:
                self._insert(record)
                self._audit(record, "request", requested_by, now, {"from": None, "to": "requested"})
                if case_id:
                    self.store.conn.execute(
                        "INSERT OR IGNORE INTO security_case_links VALUES (?, 'response', ?)",
                        (case_id, record["id"]))
                    self.store._audit(case_id, "link",
                                      {"kind": "response", "reference": record["id"]}, requested_by, now)
        return self.store.get_action(existing["action_id"] if existing else record["id"])

    def approve(self, action_id, *, actor, now=None):
        """Approve, then record an effector receipt. Applied requires that receipt.

        The effector runs between two transactions so its calls never hold the
        store's write lock. A crash between
        them leaves the action approved; ``expire_due`` releases and closes it at expiry.
        """
        now = self._now(now)
        actor = _text(actor, "actor", 256)
        with self.store._transaction():
            current = self._locked(action_id)
            self._require(current, "approved")
            approved = self._move(current, "approved", actor=actor, now=now, operation="approve")
            if now >= approved["expires_at"] or approved["expires_at"] - now > self.default_ttl:
                self._move(approved, "failed", actor=actor, now=now, operation="fail",
                           detail={"reason": "expired before apply" if now >= approved["expires_at"]
                                   else "expiry exceeds cap", "receipt": None})
                return self.store.get_action(action_id)
        state, operation, detail = self._apply_outcome(approved)
        with self.store._transaction():
            current = self._locked(action_id)
            if current["state"] == "approved":  # expiry recovery may have closed it meanwhile
                self._move(current, state, actor=actor, now=now, operation=operation, detail=detail)
        return self.store.get_action(action_id)

    def deny(self, action_id, *, actor, now=None):
        now = self._now(now)
        actor = _text(actor, "actor", 256)
        with self.store._transaction():
            current = self._locked(action_id)
            self._require(current, "denied")
            self._move(current, "denied", actor=actor, now=now, operation="deny")
        return self.store.get_action(action_id)

    def release(self, action_id, *, actor, now=None):
        now = self._now(now)
        actor = _text(actor, "actor", 256)
        current = self.store.get_action(action_id)
        self._require(current, "released")
        receipt = self._release_receipt(current)  # outside the write lock, like apply
        with self.store._transaction():
            current = self._locked(action_id)
            self._require(current, "released")
            self._move(current, "released", actor=actor, now=now, operation="release",
                       detail={"receipt": receipt})
        return self.store.get_action(action_id)

    def expire_due(self, now=None):
        """Expire actions whose deadline has passed. Repeat calls are no-ops."""
        now = self._now(now)
        due = [row["action_id"] for row in self.store._read(
            """SELECT action_id FROM security_response_actions
               WHERE state IN ('applied', 'approved', 'requested') AND expires_at<=?
               ORDER BY expires_at, action_id""", (now,))]
        expired = 0
        for action_id in due:
            try:
                if self._expire_one(action_id, now):
                    expired += 1
            except Exception as exc:
                logging.getLogger(__name__).warning(
                    "response action expiry deferred: %s", type(exc).__name__)
        return expired

    def _expire_one(self, action_id, now):
        current = self.store.get_action(action_id)
        if current is None or current["state"] not in {"applied", "approved", "requested"} or current["expires_at"] > now:
            return False
        if current["state"] == "requested":
            # Nobody decided: nothing was applied, and an open request would keep the
            # supervisor from ever asking about this target again. Denied, not expired:
            # the store's transition trigger allows requested -> approved/denied only.
            with self.store._transaction():
                again = self._locked(action_id, missing_ok=True)
                if again is None or again["state"] != "requested":
                    return False
                self._move(again, "denied", actor=SERVICE_ACTOR, now=now, operation="expire",
                           detail={"reason": "expired undecided", "receipt": None})
            return True
        receipt = self._release_receipt(current)  # outside the write lock, like apply
        with self.store._transaction():
            again = self._locked(action_id, missing_ok=True)
            if again is None or again["state"] != current["state"]:
                return False
            if again["state"] == "approved":
                # An apply whose outcome was never recorded (crash between transactions):
                # the release just sent undoes whatever may have landed.
                self._move(again, "failed", actor=SERVICE_ACTOR, now=now, operation="fail",
                           detail={"reason": "apply outcome unknown; released at expiry", "receipt": receipt})
            else:
                self._move(again, "expired", actor=SERVICE_ACTOR, now=now, operation="expire",
                           detail={"receipt": receipt})
            return True

    def _apply_outcome(self, approved):
        try:
            receipt = self.effector.apply(dict(approved))
        except Exception as exc:
            return "failed", "fail", {"reason": f"{type(exc).__name__}", "receipt": None}
        if not _accepted_receipt(receipt, "apply"):
            return "failed", "fail", {"reason": "effector receipt rejected", "receipt": _public_receipt(receipt)}
        return "applied", "apply", {"receipt": dict(receipt)}

    def _release_receipt(self, current):
        try:
            receipt = self.effector.release(dict(current))
        except Exception as exc:
            raise ValueError("release receipt required") from exc
        if not _accepted_receipt(receipt, "release"):
            raise ValueError("release receipt required")
        return dict(receipt)

    def _require(self, current, new_state):
        if current is None:
            raise ValueError("unknown action")
        if not legal_transition(current["state"], new_state):
            raise ValueError("illegal transition")

    def _locked(self, action_id, missing_ok=False):
        if not isinstance(action_id, str) or not action_id:
            raise ValueError("unknown action")
        row = self.store.conn.execute(
            "SELECT body FROM security_response_actions WHERE action_id=?", (action_id,)).fetchone()
        if row is None:
            if missing_ok:
                return None
            raise ValueError("unknown action")
        return json.loads(row["body"])

    def _move(self, current, new_state, *, actor, now, operation, detail=None):
        if not legal_transition(current["state"], new_state):
            raise ValueError("illegal transition")
        updated = dict(current)
        updated["state"] = new_state
        if new_state in {"approved", "denied"}:
            updated["decided_at"] = now
        if new_state == "applied":
            updated["applied_at"] = now
        if new_state in _TERMINAL:
            updated["closed_at"] = now
        body_detail = {"from": current["state"], "to": new_state}
        if detail:
            if "receipt" in detail and detail["receipt"] is not None:
                updated["receipt"] = detail["receipt"]
            body_detail.update(detail)
        updated["readback"] = "unverified"
        self._update(updated)
        self._audit(updated, operation, actor, now, body_detail)
        return updated

    def _insert(self, record):
        record["readback"] = "unverified"
        self.store.conn.execute(
            """INSERT INTO security_response_actions (
                   action_id, case_id, kind, target, scope, requested_by, reason, state,
                   requested_at, decided_at, applied_at, closed_at, expires_at, readback, body
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unverified', ?)""",
            (record["id"], record["case_id"], record["kind"], record["target"], record["scope"],
             record["requested_by"], record["reason"], record["state"], record["requested_at"],
             record["decided_at"], record["applied_at"], record["closed_at"], record["expires_at"],
             _encode(record)))

    def _update(self, record):
        self.store.conn.execute(
            """UPDATE security_response_actions SET state=?, decided_at=?, applied_at=?, closed_at=?,
                      readback='unverified', body=? WHERE action_id=?""",
            (record["state"], record["decided_at"], record["applied_at"], record["closed_at"],
             _encode(record), record["id"]))

    def _audit(self, record, operation, actor, now, detail):
        self.store.conn.execute(
            """INSERT INTO security_action_audit
               (action_id, timestamp, actor, operation, state, body) VALUES (?, ?, ?, ?, ?, ?)""",
            (record["id"], now, actor, operation, record["state"], _encode(detail)))

    def _now(self, now):
        if now is None:
            now = self.clock()
        return _finite_time(now, "time")


def time_clock():
    return time.time()


def _public_receipt(receipt):
    if not isinstance(receipt, dict):
        return None
    kept = {key: receipt.get(key) for key in ("ok", "receipt_id", "effector", "operation", "enforced")}
    return kept
