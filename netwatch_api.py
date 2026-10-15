"""Authenticated version-one JSON API; no response effector is reachable here."""

import hmac
import io
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import socket
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from netwatch_actions import CONSOLE_ACTOR, STATES, service_actions
from netwatch_assets import AssetResolver, asset_detail, exposure, list_assets
from netwatch_evidence_catalog import EvidenceCatalog
from netwatch_history import HistoryStore
from netwatch_security_store import _encode, security_db_path
from netwatch_ui_state import RESPONSE_MODES, load_response_mode, save_response_mode

COMMUNITY_ID = re.compile(r"1:[A-Za-z0-9+/]{27}=")
FLOW_LIMIT = 500
MAX_CONNECTIONS = 32
REQUEST_DEADLINE_SEC = 5.0  # whole request line, headers and body; recv timeout alone lets a trickler hold a slot


def secret_path(config):
    return Path(security_db_path(config)).parent / "service-api.secret"


WINDOWS_ALLOWED = {"S-1-5-18", "SY", "S-1-5-32-544", "BA"}  # SYSTEM, BUILTIN\\Administrators (SDDL alias or SID)


def windows_acl_principals(path):
    """(ACE type, principal) pairs from the file's DACL, read as SDDL so names are never localized."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "acl.txt"
        subprocess.run(["icacls", str(path), "/save", str(out)], check=True, capture_output=True)
        sddl = out.read_bytes().decode("utf-16-le").lstrip("\ufeff")  # icacls /save writes UTF-16LE, no BOM
    dacl = sddl[sddl.index("D:"):]
    return [(f[0], f[5]) for f in (ace.split(";") for ace in re.findall(r"\(([^()]*)\)", dacl)) if len(f) > 5]


def check_windows_acl(path):
    """Refuse a token file any principal other than SYSTEM and Administrators can touch (inherited ACEs are fine)."""
    aces = windows_acl_principals(path)
    stray = [f"{kind}:{who}" for kind, who in aces if kind != "A" or who not in WINDOWS_ALLOWED]
    if not aces or stray:
        # Names the offending ACEs (SIDs, never the secret) so an operator can see what to remove.
        raise ValueError("API secret ACL must grant only SYSTEM and Administrators; run the console elevated"
                         f" (found {', '.join(stray) or 'no ACEs'})")


def hello_proof(secret, nonce):
    """Domain-separated so the unauthenticated hello is no oracle for the bearer token."""
    return hmac.new(secret, b"netwatch-server:" + nonce.encode(), "sha256").hexdigest()


def load_secret(path, *, create=False):
    """Never replace an existing credential; refuse links and unsafe POSIX modes or Windows ACLs."""
    path = Path(path)
    if create:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as handle:
                if os.name == "nt":
                    # The mode above sets no DACL, so the empty file inherits its folder's (often
                    # Users-readable) ACL; restrict it before the secret exists.
                    try:
                        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                                        "*S-1-5-18:F", "*S-1-5-32-544:F"], check=True, capture_output=True)
                        # An explicit OWNER RIGHTS ACE (GitHub's Windows runner adds one) survives
                        # the grant and would make check_windows_acl refuse the new secret.
                        subprocess.run(["icacls", str(path), "/remove:g", "*S-1-3-4"],
                                       check=True, capture_output=True)
                    except (OSError, subprocess.CalledProcessError):
                        handle.close()
                        path.unlink()  # an empty secret would refuse every later start
                        raise
                handle.write(secrets.token_bytes(32))
                handle.flush()
                os.fsync(handle.fileno())
    if path.is_symlink():
        raise ValueError("API secret cannot be a symbolic link")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or (os.name == "posix" and
                (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600)):
            raise ValueError("API secret must be an owner-only regular file")
        secret = handle.read(33)
    if os.name == "nt":
        check_windows_acl(path)
    if len(secret) != 32:
        raise ValueError("API secret must contain 32 bytes")
    return secret


class _DeadlineReader(io.RawIOBase):
    """Socket reads that share one deadline, so a client trickling bytes under the
    per-recv timeout still loses its handler slot once the whole request is late."""

    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("request deadline passed")
        self.sock.settimeout(min(3, left))
        return self.sock.recv_into(buffer)


class ServiceAPI:
    def __init__(self, supervisor, secret, *, host="127.0.0.1", port=8765, config=None):
        config = config or supervisor.runtime.config
        if not ipaddress.ip_address(host).is_loopback:
            if config.get("SERVICE_API_ALLOW_NON_LOOPBACK") is not True:
                raise ValueError("service API requires a loopback bind")
            logging.getLogger(__name__).warning("Non-loopback API enabled: bearer authentication has no transport encryption")
        self.config = config
        self.supervisor = supervisor
        self.store = supervisor.store
        root = config.get("EVIDENCE_DIR") or str(Path(config["DB_NAME"]).parent / "evidence")
        self.catalog = EvidenceCatalog(root, store=self.store)
        self.ledger_path = str(config["DB_NAME"])
        self.assets = AssetResolver(self.store, config)
        self.actions = getattr(supervisor, "actions", None)
        if self.actions is None:
            self.actions = service_actions(self.store, config)
            supervisor.actions = self.actions
        self.instance = uuid.uuid4().hex
        api = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(3)
                self.rfile.close()  # replaced: reads share one whole-request deadline
                self.rfile = io.BufferedReader(_DeadlineReader(self.connection, time.monotonic() + REQUEST_DEADLINE_SEC))

            def log_message(self, *_):
                pass  # Never log authorization headers or request bodies.

            def reply(self, status, data):
                body = json.dumps({"version": 1, "instance": api.instance, "data": data}, allow_nan=False).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def parse_request(self):
                if not super().parse_request():
                    return False
                hello = re.fullmatch(r"/v1/hello\?nonce=([0-9a-f]{32})", self.path)
                if self.command == "GET" and hello:  # Proof of the secret, so a client can check the server before sending the token.
                    body = json.dumps({"proof": hello_proof(secret, hello[1])}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(body)
                    return False
                expected = "Bearer " + secret.hex()
                supplied = self.headers.get("Authorization", "")
                if not hmac.compare_digest(supplied.encode(), expected.encode()):
                    # No instance identifier or ledger state on rejection, for any method.
                    # Drain a small unread body first: closing on unread data makes Windows reset the
                    # connection, and the client loses the 401 to an abort.
                    length = self.headers.get("Content-Length", "0")
                    if length.isdigit() and int(length) <= 65536:
                        self.rfile.read(int(length))
                    self.send_error(401, "Authentication required")
                    return False
                return True

            def dispatch(self, write=False):
                try:
                    parsed = urlsplit(self.path)
                    query = parse_qs(parsed.query)
                    path = parsed.path
                    body = {}
                    if write:
                        length = int(self.headers.get("Content-Length", "0"))
                        if not 0 < length <= 65536 or self.headers.get("Transfer-Encoding"):
                            raise ValueError("invalid request size")
                        body = json.loads(self.rfile.read(length))
                        if not isinstance(body, dict):
                            raise ValueError("object required")
                    self.connection.settimeout(3)  # the request is in; restore the full timeout for the reply
                    result = api.request(path, query, body, write=write)
                    self.reply(200, result)
                except (ValueError, TypeError, KeyError, OverflowError, RecursionError, TimeoutError):  # bad client input
                    self.reply(400, {"error": "Invalid request"})
                except Exception:
                    logging.getLogger(__name__).exception("Service API request failed")
                    self.reply(500, {"error": "Request failed"})

            def do_GET(self):
                self.dispatch()

            def do_POST(self):
                self.dispatch(write=True)

        class Server(ThreadingHTTPServer):
            address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
            daemon_threads = False

            def __init__(self, *args, **kwargs):
                self.active = set()
                self.active_lock = threading.Lock()
                super().__init__(*args, **kwargs)

            def process_request(self, request, client_address):
                with self.active_lock:
                    full = len(self.active) >= MAX_CONNECTIONS
                    if not full:
                        self.active.add(request)
                if full:
                    self.shutdown_request(request)  # Cap threads: drop without spawning a handler.
                    return
                super().process_request(request, client_address)

            def shutdown_request(self, request):
                with self.active_lock:
                    self.active.discard(request)
                super().shutdown_request(request)

        self.server = Server((host, port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, name="service-api")

    def request(self, path, query, body, *, write):
        case = query.get("case", [""])[0]
        if write:
            if path == "/v1/cases":
                allowed = {"case", "status", "assignment", "acknowledge", "note", "closure_reason"}
                if set(body) - allowed or not isinstance(body.get("case"), str):
                    raise ValueError("invalid case change")
                if "acknowledge" in body and not isinstance(body["acknowledge"], bool):
                    raise ValueError("invalid acknowledgement")
                return self.store.update_case(body["case"], actor="authenticated-console",
                                              **{key: value for key, value in body.items() if key != "case"})
            if path == "/v1/response-mode":
                if set(body) != {"mode"} or body["mode"] not in RESPONSE_MODES:
                    raise ValueError("invalid response mode")
                ledger = self.config.get("RESPONSE_MODE_LEDGER")
                old = load_response_mode(ledger, default=self.config.get("RESPONSE_MODE", "ids_only"))
                with self.store._transaction():  # durable audit; rolled back if the mode is not saved
                    self.store.conn.execute(
                        "INSERT INTO security_native_audit(timestamp,actor,operation,body) VALUES (?,?,?,?)",
                        (time.time(), CONSOLE_ACTOR, "response_mode", _encode({"from": old, "to": body["mode"]})))
                    save_response_mode(ledger, body["mode"])
                logging.getLogger(__name__).warning("response mode set to %s by %s", body["mode"], CONSOLE_ACTOR)
                return {"response_mode": body["mode"]}
            if path == "/v1/actions":
                return self._action_command(body)
            if path == "/v1/hunts":
                return self._hunt_command(body)
            raise ValueError("unsupported write")
        if path == "/v1/actions":
            return self._action_list(query)
        if path == "/v1/health":
            return {"service": self.store.source_health("RUNTIME:SERVICE"),
                    "actions": "recording-only",
                    "sensor_id": str(self.config.get("SENSOR_ID") or "unknown"),
                    "response_mode": load_response_mode(self.config.get("RESPONSE_MODE_LEDGER"),
                                                        default=self.config.get("RESPONSE_MODE", "ids_only"))}

        if path == "/v1/cases":
            return self.store.snapshot()
        if path == "/v1/traffic":
            return self._traffic(query)
        if path == "/v1/feed":
            after = query.get("after", ["0:0"])[0]
            if not re.fullmatch(r"\d{1,18}:\d{1,18}", after):
                raise ValueError("invalid cursor")
            case_after, action_after = map(int, after.split(":"))
            return self.store.feed(case_after, action_after, int(query.get("limit", ["200"])[0]))
        if path == "/v1/detections":
            return self.assets.annotate_detections(self.store.detections(case) if case else [
                item for row in self.store.snapshot() for item in self.store.detections(row["incident_id"], limit=10)])
        if path == "/v1/workflow":
            return self.store.audit(case)
        if path == "/v1/sources":
            return self.assets.annotate(self.store.source_events(limit=500))
        if path == "/v1/collection-health":
            # Store owns locking and decoding; reuse its read surface.
            return {row[0]: self.store.source_health(row[0]) for row in
                    self.store._read("SELECT source_key FROM security_source_health LIMIT 1000")}
        if path == "/v1/gaps":
            return self.store.spool_gaps() + [row for row in self.store.snapshot()
                                              if row["action"] != "SPOOL_COLLECTION_GAP"
                                              and ("GAP" in row["action"] or "FAILED" in row["action"])]
        if path == "/v1/evidence":
            return self.catalog.list()
        limit = query.get("limit", [None])[0]
        if path == "/v1/assets":
            return list_assets(self.store, limit, self.config.get("SECURE_NODES"))
        if path.startswith("/v1/assets/"):
            rest = path[len("/v1/assets/"):]
            if rest.endswith("/records"):
                rest = rest[:-len("/records")]
                return self.assets.asset_records(rest) if asset_detail(self.store, rest) else None
            return asset_detail(self.store, rest, self.config.get("SECURE_NODES"))
        if path == "/v1/exposure":
            return exposure(self.store, limit)
        if path == "/v1/rules":
            return self.store.rule_stats()
        if path == "/v1/hunts":
            return self.store.list_hunts()
        if path.startswith("/v1/flows/"):
            return self._flows(unquote(path[len("/v1/flows/"):]))
        raise ValueError("unsupported endpoint")

    def _traffic(self, query):
        """Ledger summary, top talkers and timeline over the last ``window`` seconds."""
        window = int(query.get("window", ["3600"])[0])
        bucket = int(query.get("bucket", ["60"])[0])
        end = float(query.get("end", [time.time()])[0])
        if not (60 <= window <= 7 * 86400 and 10 <= bucket <= 86400 and window // bucket <= 1000
                and math.isfinite(end)):
            raise ValueError("invalid traffic window")
        filters = {"since": end - window, "until": end}
        history = HistoryStore(self.ledger_path)  # Read-only; one connection per request thread.
        try:
            return {"window": window, "bucket": bucket, "since": filters["since"], "end": end,
                    "summary": history.summary(filters),
                    "sources": history.top_talkers(filters, direction="src"),
                    "destinations": history.top_talkers(filters, direction="dst"),
                    "domains": history.top_domains(filters), "countries": history.top_countries(filters),
                    "timeline": history.timeline(filters, bucket_sec=bucket)}
        finally:
            history.close()

    def _flows(self, community_id):
        """NetWatch ledger rows plus Suricata native records sharing one Community ID, bounded per source."""
        if not COMMUNITY_ID.fullmatch(community_id):
            raise ValueError("invalid community id")
        history = HistoryStore(self.ledger_path)  # Read-only; one connection per request thread.
        try:
            netwatch = history.query({"community_id": community_id}, limit=FLOW_LIMIT)
        finally:
            history.close()
        return {"community_id": community_id, "limit": FLOW_LIMIT, "netwatch": netwatch,
                "suricata": self.assets.annotate(
                    self.store.source_events("SURICATA", community_id=community_id, limit=FLOW_LIMIT))}

    def _action_command(self, body):
        """Console verbs. The actor is server-assigned and cannot be supplied."""
        op = body.get("op")
        if op == "request":
            allowed = {"op", "kind", "target", "reason", "scope", "case", "expires_at"}
            if set(body) - allowed or {"op", "kind", "target", "reason"} - set(body):
                raise ValueError("invalid action request")
            case = body.get("case")
            if case == "":
                case = None
            return self.actions.request(
                kind=body["kind"], target=body["target"], reason=body["reason"],
                requested_by=CONSOLE_ACTOR, scope=body.get("scope") or "",
                case_id=case, expires_at=body.get("expires_at"))
        if op in {"approve", "deny", "release"}:
            if set(body) != {"op", "id"} or not isinstance(body.get("id"), str):
                raise ValueError("invalid action")
            if op == "approve":
                return self.actions.approve(body["id"], actor=CONSOLE_ACTOR)
            if op == "deny":
                return self.actions.deny(body["id"], actor=CONSOLE_ACTOR)
            return self.actions.release(body["id"], actor=CONSOLE_ACTOR)
        raise ValueError("invalid action")

    def _hunt_command(self, body):
        """Create or run a saved hunt; the store validates names, filters and bounds."""
        op = body.get("op")
        if op == "create" and {"op", "name", "target", "filters"} <= set(body) <= \
                {"op", "name", "target", "filters", "limit", "description"}:
            return self.store.create_hunt(body["name"], body["target"], body["filters"], actor=CONSOLE_ACTOR,
                                          limit=body.get("limit", 100), description=body.get("description", ""))
        if op == "run" and {"op", "name"} <= set(body) <= {"op", "name", "params"}:
            return self.store.run_hunt(body["name"], body.get("params"), actor=CONSOLE_ACTOR,
                                       ledger_path=self.ledger_path)
        raise ValueError("invalid hunt command")

    def _action_list(self, query):
        state = query.get("state", [None])[0] or None
        case = query.get("case", [None])[0] or None
        if state is not None and state not in STATES:
            raise ValueError("invalid state")
        if case is not None and (not isinstance(case, str) or len(case) > 128):
            raise ValueError("invalid case")
        return self.store.list_actions(case_id=case, state=state)

    def start(self):
        self.thread.start()
        return self

    def close(self):
        if self.thread.is_alive():
            self.server.shutdown()
            self.thread.join()
        with self.server.active_lock:
            active = list(self.server.active)
        for sock in active:  # Unblock handlers stuck reading from a trickling client.
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.server.server_close()  # Wait for handlers before closing the store.
        self.catalog.close()
