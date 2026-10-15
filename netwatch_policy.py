"""Ordered, versioned network policy evaluation and durable decision auditing."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import time

from netwatch_inventory import normalize_mac

VALID_ACTIONS = frozenset({"allow", "alert", "block"})
VALID_MODES = frozenset({"monitor", "manual", "enforce"})


class PolicyConfigError(ValueError):
    pass


def _networks(values):
    compiled = []
    for value in values or ():
        try:
            compiled.append(ipaddress.ip_network(str(value), strict=False))
        except ValueError as exc:
            raise PolicyConfigError(f"invalid CIDR {value!r}") from exc
    return tuple(compiled)


def _ports(values):
    ports = set()
    for value in values or ():
        try:
            port = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise PolicyConfigError(f"invalid port {value!r}") from exc
        if not 0 <= port <= 65535:
            raise PolicyConfigError(f"invalid port {value!r}")
        ports.add(port)
    return frozenset(ports)


def _ip_in(value, networks):
    if not networks:
        return True
    try:
        address = ipaddress.ip_address(bytes(value) if isinstance(value, bytes | bytearray) else str(value))
    except ValueError:
        return False
    return any(address in network for network in networks)


def _domain_matches(domain, suffixes):
    if not suffixes:
        return True
    domain = str(domain or "").lower().rstrip(".")
    return any(domain == suffix or domain.endswith(f".{suffix}") for suffix in suffixes)


class PolicyRule:
    def __init__(self, raw, order):
        if not isinstance(raw, dict):
            raise PolicyConfigError(f"rule {order} must be an object")
        self.rule_id = str(raw.get("id") or f"rule-{order}")
        self.enabled = bool(raw.get("enabled", True))
        self.action = str(raw.get("action") or "alert").lower()
        if self.action not in VALID_ACTIONS:
            raise PolicyConfigError(f"{self.rule_id}: invalid action {self.action!r}")
        self.direction = str(raw.get("direction") or "any").lower()
        if self.direction not in {"any", "egress", "ingress", "lateral"}:
            raise PolicyConfigError(f"{self.rule_id}: invalid direction {self.direction!r}")
        self.protocol = str(raw.get("protocol") or "ANY").upper()
        self.src_networks = _networks(raw.get("source_cidrs"))
        self.dst_networks = _networks(raw.get("destination_cidrs"))
        self.dst_ports = _ports(raw.get("destination_ports"))
        # Capture reports colon form; a dash or bare rule entry would otherwise never match.
        self.source_macs = frozenset(normalize_mac(str(value)) for value in (raw.get("source_macs") or ()) if value)
        if None in self.source_macs:
            raise PolicyConfigError(f"{self.rule_id}: invalid source_macs entry")
        if self.action == "allow" and self.source_macs:
            raise PolicyConfigError(
                f"{self.rule_id}: source_macs cannot authorize allow; packet MACs are untrusted"
            )
        self.domain_suffixes = tuple(
            str(value).lower().strip().rstrip(".")
            for value in (raw.get("domain_suffixes") or ()) if value
        )
        try:
            self.expires_at = float(raw["expires_at"]) if raw.get("expires_at") is not None else None
        except (TypeError, ValueError, OverflowError) as exc:
            raise PolicyConfigError(f"{self.rule_id}: invalid expires_at") from exc
        self.description = str(raw.get("description") or self.rule_id)

    def matches(self, context, now):
        if not self.enabled or (self.expires_at is not None and now >= self.expires_at):
            return False
        if self.direction != "any" and context.get("direction") != self.direction:
            return False
        if self.protocol != "ANY" and context.get("protocol") != self.protocol:
            return False
        if self.dst_ports and int(context.get("destination_port") or 0) not in self.dst_ports:
            return False
        if self.source_macs and str(context.get("source_mac") or "").lower() not in self.source_macs:
            return False
        return (
            _ip_in(context.get("src_ip"), self.src_networks)
            and _ip_in(context.get("dst_ip"), self.dst_networks)
            and _domain_matches(context.get("domain"), self.domain_suffixes)
        )


class PolicyEngine:
    """First-match ordered policy with explicit monitor/manual/enforce staging."""

    def __init__(self, document, *, mode="monitor"):
        if not isinstance(document, dict):
            raise PolicyConfigError("policy top level must be an object")
        self.mode = str(mode).lower()
        if self.mode not in VALID_MODES:
            raise PolicyConfigError(f"invalid policy mode {mode!r}")
        try:
            self.version = int(document.get("version", 1))
        except (TypeError, ValueError, OverflowError) as exc:
            raise PolicyConfigError("policy version must be an integer") from exc
        self.default_action = str(document.get("default_action") or "allow").lower()
        if self.default_action not in VALID_ACTIONS:
            raise PolicyConfigError(f"invalid default action {self.default_action!r}")
        rules = document.get("rules", ())
        if not isinstance(rules, list):
            raise PolicyConfigError("policy rules must be a list")
        self.rules = tuple(PolicyRule(raw, order) for order, raw in enumerate(rules, 1))
        rule_ids = [rule.rule_id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise PolicyConfigError("policy rule IDs must be unique")
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        self.digest = hashlib.sha256(canonical).hexdigest()

    @classmethod
    def load(cls, path, *, mode="monitor"):
        try:
            with open(path, encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, ValueError) as exc:
            raise PolicyConfigError(f"cannot load policy {path}: {exc}") from exc
        return cls(document, mode=mode)

    def evaluate(self, context, now=None):
        now = time.time() if now is None else float(now)
        matched = next((rule for rule in self.rules if rule.matches(context, now)), None)
        action = matched.action if matched else self.default_action
        effective = action
        if action == "block" and self.mode == "monitor":
            effective = "alert"
        return {
            "timestamp": now,
            "policy_version": self.version,
            "policy_digest": self.digest,
            "mode": self.mode,
            "rule_id": matched.rule_id if matched else "default",
            "description": matched.description if matched else "Default policy",
            "configured_action": action,
            "effective_action": effective,
            "flow_id": str(context.get("flow_id") or ""),
            "direction": str(context.get("direction") or "any"),
            "protocol": str(context.get("protocol") or ""),
            "src_ip": context.get("src_ip"),
            "dst_ip": context.get("dst_ip"),
            "destination_port": int(context.get("destination_port") or 0),
            "source_mac": str(context.get("source_mac") or ""),
            "domain": str(context.get("domain") or ""),
        }


class DecisionLedger:
    """Append-only JSONL audit of non-default policy decisions."""

    def __init__(self, path, *, max_bytes=20_000_000, backups=3, max_buffer=10_000):
        self.path = path
        self.max_bytes = max(1024, int(max_bytes))
        self.backups = max(0, int(backups))
        self.max_buffer = max(1, int(max_buffer))
        self.buffer = []

    def append(self, decision):
        if not self.path:
            return False
        if len(self.buffer) >= self.max_buffer:
            return False
        row = dict(decision)
        for key in ("src_ip", "dst_ip"):
            value = row.get(key)
            if isinstance(value, bytes | bytearray):
                row[key] = str(ipaddress.ip_address(bytes(value)))
        self.buffer.append(json.dumps(row, separators=(",", ":")) + "\n")
        return True

    def flush(self):
        if not self.path or not self.buffer:
            return True
        lines = list(self.buffer)
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            self._rotate_if_needed()
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.writelines(lines)
        except OSError:
            return False
        del self.buffer[:len(lines)]
        return True

    def _rotate_if_needed(self):
        try:
            if os.path.getsize(self.path) < self.max_bytes:
                return
        except OSError:
            return
        if self.backups <= 0:
            try:
                os.remove(self.path)
            except OSError:
                pass
            return
        for index in range(self.backups, 0, -1):
            source = self.path if index == 1 else f"{self.path}.{index - 1}"
            destination = f"{self.path}.{index}"
            try:
                os.replace(source, destination)
            except OSError:
                continue
