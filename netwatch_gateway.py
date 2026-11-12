"""Console-host gateway: polls each NetWatch sensor through its SSH tunnel and serves the console.

Nodes are discovered from ``<config>/<node>.tunnel`` (``LOCAL_PORT=<port>``) beside ``<node>.secret``.
The console authenticates with the bearer token in ``<config>/ui.token``; it never sees a sensor secret.
"""

import argparse
import hmac
import json
import logging
import os
import secrets
import sqlite3
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

from netwatch_api import load_secret
from netwatch_client import ServiceClient

CONFIG_DIR = Path(os.environ.get("NETWATCH_GATEWAY_DIR", Path.home() / ".config" / "netwatch-gateway"))
ONLINE_SECONDS = 10
STALE_SECONDS = 60
DATA_DIR = Path(os.environ.get("NETWATCH_GATEWAY_DATA", Path.home() / ".local" / "share" / "netwatch-gateway"))
FEED_PAGES_PER_CYCLE = 20
CLOSED_STATUSES = ("Resolved", "Recovered", "Dismissed")
CLOSED_ACTION_STATES = ("denied", "failed", "released", "expired")
CASES_LIMIT = 2000  # closed rows beyond this drop out of the listing only; the cache keeps them
ACTIONS_LIMIT = 1000
CASE_COLUMNS = ("incident_id", "title", "target", "severity", "status", "confidence", "count",
                "first_seen", "last_seen", "action", "assignment", "acknowledged_by")
WRITE_ENDPOINTS = {"/api/case": "cases", "/api/action": "actions", "/api/response-mode": "response-mode"}
CONSOLE_ORIGINS = {"tauri://localhost", "http://tauri.localhost", "http://localhost:1420"}


def node_state(last_ok, now, since=None):
    """``since`` is when the gateway began watching; a node silent that long is offline, not 'never'."""
    if last_ok is None:
        return "never" if since is None or now - since <= STALE_SECONDS else "offline"
    age = now - last_ok
    return "online" if age <= ONLINE_SECONDS else "stale" if age <= STALE_SECONDS else "offline"


class Node:
    def __init__(self, name, url, secret):
        self.name = name
        self.url, self.secret = url, secret
        self.client = ServiceClient(url, secret, timeout=3)
        self.last_ok = None
        self.since = time.monotonic()
        self.feed_error = None
        self.poll_failing = False
        self.health = {}
        self.instance = None
        self.state = "never"
        self.was_offline = False
        self.gaps = []
        self.lock = threading.Lock()
        self.sync_lock = threading.Lock()
        self.restart_command = None  # remote shell command run over ssh to the node's alias  # the poll loop and a write's follow-up sync never interleave

    def poll(self):
        self.client.verified = False  # Re-prove every cycle so a port squatter never receives the token.
        try:
            result = self.client.request("health")
        except Exception as exc:  # noqa: BLE001 - any failure just ages the node toward offline
            if self.poll_failing is False:  # first failure only; offline transitions are logged separately
                logging.getLogger(__name__).warning("%s poll failed: %s", self.name, exc)
            self.poll_failing = True
            return False
        if self.poll_failing:
            logging.getLogger(__name__).warning("%s poll recovered", self.name)
        self.poll_failing = False
        with self.lock:
            if self.instance is not None and result["instance"] != self.instance:
                self.gaps = [*self.gaps, {"at": time.time(), "reason": "sensor service restarted"}][-100:]
            self.health, self.instance, self.last_ok = result["data"], result["instance"], time.monotonic()
        return True

    def transition(self, now=None):
        """Advance the remembered state; return the new state when it changed, else None."""
        with self.lock:
            state = node_state(self.last_ok, time.monotonic() if now is None else now, self.since)
            previous, self.state = self.state, state
        return state if state != previous else None

    def view(self, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            return {"node": self.name, "state": node_state(self.last_ok, now, self.since),
                    "seen_seconds_ago": None if self.last_ok is None else round(now - self.last_ok, 1),
                    "sensor_id": self.health.get("sensor_id"), "response_mode": self.health.get("response_mode"),
                    "actions_mode": self.health.get("actions"), "can_restart": bool(self.restart_command),
                    "instance": self.instance, "gaps": self.gaps, "feed_error": self.feed_error}


class Cache:
    """The gateway's copy of every sensor's cases and actions, advanced only by the sensor's feed.

    shortcut: rows a sensor prunes stay here until that sensor's feed reports a reset;
    add a retention pass if the cache outgrows the sensors.
    """

    SCHEMA = """
        CREATE TABLE IF NOT EXISTS cursors (node TEXT PRIMARY KEY, cursor TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS cases (node TEXT, incident_id TEXT, status TEXT, last_seen REAL, body TEXT,
            PRIMARY KEY (node, incident_id));
        CREATE TABLE IF NOT EXISTS detections (node TEXT, event_id TEXT, incident_id TEXT, received_at REAL,
            row TEXT, PRIMARY KEY (node, event_id));
        CREATE INDEX IF NOT EXISTS detections_case ON detections(node, incident_id, received_at);
        CREATE TABLE IF NOT EXISTS actions (node TEXT, id TEXT, state TEXT, body TEXT, PRIMARY KEY (node, id));
        CREATE TABLE IF NOT EXISTS case_audit (node TEXT, sequence INTEGER, incident_id TEXT, row TEXT,
            PRIMARY KEY (node, sequence));
        CREATE INDEX IF NOT EXISTS case_audit_case ON case_audit(node, incident_id, sequence);
        CREATE TABLE IF NOT EXISTS action_audit (node TEXT, sequence INTEGER, action_id TEXT, row TEXT,
            PRIMARY KEY (node, sequence));
        CREATE TABLE IF NOT EXISTS writes (id INTEGER PRIMARY KEY, at REAL NOT NULL, origin TEXT NOT NULL,
            node TEXT NOT NULL, endpoint TEXT NOT NULL, request TEXT NOT NULL, outcome TEXT NOT NULL, reply TEXT);
    """
    TABLES = ("cases", "detections", "actions", "case_audit", "action_audit")

    def __init__(self, path):
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=DELETE")  # rollback journal: no WAL-reset exposure
        self.conn.executescript(self.SCHEMA)
        self.lock = threading.Lock()
        self.version = 0
        self.initial = set()  # nodes mid first sync or reset resync: their backlog never alerts

    def cursor(self, node):
        with self.lock:
            row = self.conn.execute("SELECT cursor FROM cursors WHERE node=?", (node,)).fetchone()
        return row[0] if row else "0:0"

    def apply(self, node, page):
        """Store one feed page; return cases that just became critical (never during a first sync or reset resync)."""
        with self.lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                escalated = []
                synced_before = self.conn.execute("SELECT 1 FROM cursors WHERE node=?", (node,)).fetchone()
                if not synced_before or page["reset"]:
                    self.initial.add(node)
                if node not in self.initial:
                    for case in page["cases"]:
                        if case.get("severity") != "critical":
                            continue
                        prior = self.conn.execute(
                            "SELECT json_extract(body, '$.severity') FROM cases WHERE node=? AND incident_id=?",
                            (node, case["incident_id"])).fetchone()
                        if prior is None or prior[0] != "critical":
                            escalated.append(case)
                if page["reset"]:
                    for table in self.TABLES:
                        self.conn.execute(f"DELETE FROM {table} WHERE node=?", (node,))
                self.conn.executemany("INSERT OR REPLACE INTO cases VALUES (?, ?, ?, ?, ?)", [
                    (node, case["incident_id"], case.get("status"), case.get("last_seen"), json.dumps(case))
                    for case in page["cases"]])
                self.conn.executemany("INSERT OR REPLACE INTO detections VALUES (?, ?, ?, ?, ?)", [
                    (node, row["event_id"], row["incident_id"], row["received_at"], json.dumps(row))
                    for row in page["detections"]])
                self.conn.executemany("INSERT OR REPLACE INTO actions VALUES (?, ?, ?, ?)", [
                    (node, action["id"], action.get("state"), json.dumps(action)) for action in page["actions"]])
                self.conn.executemany("INSERT OR REPLACE INTO case_audit VALUES (?, ?, ?, ?)", [
                    (node, row["sequence"], row["incident_id"], json.dumps(row)) for row in page["case_audit"]])
                self.conn.executemany("INSERT OR REPLACE INTO action_audit VALUES (?, ?, ?, ?)", [
                    (node, row["sequence"], row["action_id"], json.dumps(row)) for row in page["action_audit"]])
                self.conn.execute("INSERT OR REPLACE INTO cursors VALUES (?, ?)", (node, page["cursor"]))
                self.conn.execute("COMMIT")
                if not page["more"]:
                    self.initial.discard(node)
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            if page["reset"] or any(page[table] for table in self.TABLES):
                self.version += 1
            return escalated

    def cases(self):
        with self.lock:
            rows = self.conn.execute(
                f"SELECT node, body FROM cases ORDER BY status IN {CLOSED_STATUSES}, last_seen DESC LIMIT ?",
                (CASES_LIMIT,)).fetchall()
        return [{"node": node} | {key: case.get(key) for key in CASE_COLUMNS}
                for node, case in ((node, json.loads(body)) for node, body in rows)]

    def case_detail(self, node, incident_id, limit=1000):
        """The case body, its newest detections (oldest first) and its non-detection history."""
        with self.lock:
            body = self.conn.execute("SELECT body FROM cases WHERE node=? AND incident_id=?",
                                     (node, incident_id)).fetchone()
            detections = self.conn.execute("""SELECT row FROM detections WHERE node=? AND incident_id=?
                ORDER BY received_at DESC LIMIT ?""", (node, incident_id, limit)).fetchall()
            history = self.conn.execute("""SELECT row FROM case_audit WHERE node=? AND incident_id=?
                AND json_extract(row, '$.operation')!='detection' ORDER BY sequence""", (node, incident_id)).fetchall()
        if body is None:
            return None
        return {"node": node, "case": json.loads(body[0]),
                "detections": [json.loads(row[0]) for row in reversed(detections)],
                "history": [json.loads(row[0]) for row in history]}

    def actions(self):
        with self.lock:
            rows = self.conn.execute(
                f"SELECT node, body FROM actions ORDER BY state IN {CLOSED_ACTION_STATES}, "
                "json_extract(body, '$.requested_at') DESC LIMIT ?", (ACTIONS_LIMIT,))
            return [{"node": node} | json.loads(body) for node, body in rows.fetchall()]

    def record_write(self, origin, node, endpoint, request):
        with self.lock:
            return self.conn.execute("INSERT INTO writes (at, origin, node, endpoint, request, outcome) "
                                     "VALUES (?, ?, ?, ?, ?, 'sending')",
                                     (time.time(), origin, node, endpoint, json.dumps(request))).lastrowid

    def finish_write(self, write_id, outcome, reply):
        with self.lock:
            self.conn.execute("UPDATE writes SET outcome=?, reply=? WHERE id=?", (outcome, json.dumps(reply), write_id))

    def writes(self, limit=200):
        with self.lock:
            rows = self.conn.execute("SELECT * FROM writes ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        names = ("id", "at", "origin", "node", "endpoint", "request", "outcome", "reply")
        return [dict(zip(names, row, strict=True)) for row in rows]

    def open_count(self, node):
        with self.lock:
            return self.conn.execute(
                f"SELECT COUNT(*) FROM cases WHERE node=? AND status NOT IN {CLOSED_STATUSES}", (node,)).fetchone()[0]


def sync(node, cache, pages=FEED_PAGES_PER_CYCLE, alert=None):
    """Pull feed pages until caught up; the cursor advances only with the rows it covers."""
    alert = alert or alert_critical
    with node.sync_lock:
        return _sync(node, cache, pages, alert)


def _sync(node, cache, pages, alert):
    for _ in range(pages):
        try:
            page = node.client.request("feed", after=cache.cursor(node.name), limit=500)["data"]
        except Exception as exc:  # noqa: BLE001 - next cycle resumes from the saved cursor
            if node.feed_error is None:  # first failure only, not every cycle
                logging.getLogger(__name__).warning("%s feed failed: %s", node.name, exc)
            node.feed_error = str(exc)[:200]
            return False
        if node.feed_error is not None:
            logging.getLogger(__name__).warning("%s feed recovered", node.name)
            node.feed_error = None
        try:
            escalated = cache.apply(node.name, page)
        except (KeyError, TypeError, ValueError) as exc:  # malformed page; apply rolled back, sqlite errors keep the retry path
            if node.feed_error is None:
                logging.getLogger(__name__).warning("%s feed page malformed: %r", node.name, exc)
            node.feed_error = f"malformed feed page: {exc!r}"[:200]
            return False
        if escalated:
            alert(node, escalated)
        if page["reset"]:
            logging.getLogger(__name__).warning("%s feed reset: cache resynced from zero", node.name)
        if not page["more"]:
            return True
    return False


def read_live(node, endpoints, timeout=10, **query):
    """Read-only pass-through for state too small, too fresh or too windowed to be worth caching."""
    client = ServiceClient(node.url, node.secret, timeout=timeout)
    return {endpoint: client.request(endpoint, **query)["data"] for endpoint in endpoints}


def send_write(node, cache, endpoint, body, origin):
    """Send one console write exactly once and record it; the feed, not a retry, settles an unknown outcome."""
    write_id = cache.record_write(origin, node.name, endpoint, body)
    try:
        reply = ServiceClient(node.url, node.secret, timeout=10).request(endpoint, body)["data"]
        outcome = "accepted" if reply not in (False, None) else "refused"
    except HTTPError as exc:
        reply, outcome = {"status": exc.code}, "refused"
    except Exception as exc:  # noqa: BLE001 - timeout or reset after sending: the sensor may have applied it
        reply, outcome = {"error": type(exc).__name__}, "unknown"
    cache.finish_write(write_id, outcome, reply)
    logging.getLogger(__name__).info("write %s to %s %s: %s", write_id, node.name, endpoint, outcome)
    node.poll()
    sync(node, cache)
    return {"write": write_id, "outcome": outcome, "reply": reply}


def restart_sensor(node, cache):
    """Run the node's restart command once over ssh; the poll loop shows the new instance."""
    write_id = cache.record_write("gateway-console", node.name, "restart", {"command": node.restart_command})
    try:
        done = subprocess.run(["ssh", "-o", "BatchMode=yes", node.name, node.restart_command],
                              capture_output=True, text=True, timeout=90)
        outcome = "accepted" if done.returncode == 0 else "refused"
        reply = {"returncode": done.returncode, "output": (done.stdout + done.stderr)[-2000:]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        outcome, reply = "unknown", {"error": type(exc).__name__}
    cache.finish_write(write_id, outcome, reply)
    logging.getLogger(__name__).info("restart of %s: %s", node.name, outcome)
    return {"write": write_id, "outcome": outcome, "reply": reply}


def notify(summary, body, urgency="normal"):
    if os.environ.get("NETWATCH_GATEWAY_NOTIFY", "1") == "0":  # muted: log only
        logging.getLogger(__name__).info("muted notification: %s", summary)
        return
    try:
        subprocess.run(["notify-send", "--app-name=NetWatch", f"--urgency={urgency}", summary, body],
                       check=True, timeout=10, capture_output=True)
        logging.getLogger(__name__).info("notified: %s", summary)
    except (OSError, subprocess.SubprocessError) as exc:
        logging.getLogger(__name__).warning("notification failed: %s: %s", summary, exc)


def announce(node, state):
    """Only offline and recovery from offline are worth interrupting the operator for."""
    name = node.health.get("sensor_id") or node.name
    if state == "offline":
        node.was_offline = True
        notify(f"{name} offline", f"No contact with {name} for over {STALE_SECONDS} seconds.", "critical")
    elif state == "online" and node.was_offline:
        node.was_offline = False
        notify(f"{name} back online", f"{name} is reachable again.")


def alert_critical(node, cases):
    name = node.health.get("sensor_id") or node.name
    if len(cases) == 1:
        notify(f"Critical on {name}: {cases[0].get('title')}", f"Target {cases[0].get('target')}", "critical")
    else:
        titles = sorted({str(case.get("title")) for case in cases})
        notify(f"{len(cases)} new critical cases on {name}", ", ".join(titles[:5]), "critical")


def discover_nodes(config_dir):
    nodes = []
    for tunnel in sorted(Path(config_dir).glob("*.tunnel")):
        values = {key.strip(): value.strip().strip('"') for key, _, value in
                  (line.partition("=") for line in tunnel.read_text().splitlines()) if value}
        try:
            secret = load_secret(tunnel.with_suffix(".secret"))
            node = Node(tunnel.stem, f"http://127.0.0.1:{int(values['LOCAL_PORT'])}", secret)
        except (OSError, ValueError, KeyError) as exc:  # one bad node file must not stop the others
            logging.getLogger(__name__).error("skipping node %s: %s: %s", tunnel.stem, type(exc).__name__, exc)
            continue
        node.restart_command = values.get("RESTART")
        nodes.append(node)
    return nodes


def load_token(path):
    path = Path(path)
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(secrets.token_hex(32))
    if path.stat().st_mode & 0o077:
        raise ValueError(f"{path} must be readable only by its owner")
    token = path.read_text().strip()
    if len(token) < 32:  # an empty token would let "Bearer " authenticate
        raise ValueError(f"{path} holds no usable token; delete it to regenerate")
    return token


class Gateway:
    def __init__(self, nodes, token, cache, *, host="127.0.0.1", port=8766, poll_interval=2):
        self.nodes = nodes
        self.cache = cache
        self.token = token
        self.poll_interval = poll_interval
        self.announce = announce
        self._stop = threading.Event()
        gateway = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, payload=None):
                body = b"" if payload is None else json.dumps(payload).encode()
                self.send_response(status)
                origin = self.headers.get("Origin")
                if origin in CONSOLE_ORIGINS:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
                    self.send_header("Access-Control-Allow-Methods", "GET, POST")
                    self.send_header("Vary", "Origin")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_OPTIONS(self):  # noqa: N802 - CORS preflight carries no token
                self._send(204)

            def _authorized(self):
                supplied = self.headers.get("Authorization", "")
                return hmac.compare_digest(supplied.encode(), ("Bearer " + gateway.token).encode())

            def do_POST(self):  # noqa: N802
                if not self._authorized():
                    return self._send(401, {"error": "unauthorized"})
                if self.path == "/api/restart":
                    return self._restart()
                endpoint = WRITE_ENDPOINTS.get(self.path)
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = -1
                if endpoint is None or not 0 < length <= 65536:
                    return self._send(400, {"error": "unsupported write"})
                try:
                    request = json.loads(self.rfile.read(length))
                    node = next(node for node in gateway.nodes if node.name == request["node"])
                    body = request["body"]
                    if not isinstance(body, dict):
                        raise ValueError("body must be an object")
                except (ValueError, KeyError, TypeError, StopIteration):
                    return self._send(400, {"error": "invalid write"})
                # shortcut: one console exists; record the phone as its own origin when it arrives
                result = send_write(node, gateway.cache, endpoint, body, "gateway-console")
                return self._send(200 if result["outcome"] == "accepted" else 502, result)

            def _restart(self):
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    if not 0 < length <= 4096:
                        raise ValueError("bad length")
                    request = json.loads(self.rfile.read(length))
                    node = next(node for node in gateway.nodes if node.name == request["node"])
                except (ValueError, KeyError, TypeError, StopIteration):
                    return self._send(400, {"error": "invalid restart"})
                name = node.health.get("sensor_id") or node.name
                if not node.restart_command or request.get("confirm") != name:
                    return self._send(400, {"error": f"type {name} to confirm"})
                result = restart_sensor(node, gateway.cache)
                return self._send(200 if result["outcome"] == "accepted" else 502, result)

            def do_GET(self):  # noqa: N802
                if not self._authorized():
                    return self._send(401, {"error": "unauthorized"})
                url = urlsplit(self.path)
                query = {key: values[0] for key, values in parse_qs(url.query).items()}
                if url.path == "/api/case":
                    detail = gateway.cache.case_detail(query.get("node", ""), query.get("id", ""))
                    return self._send(200, detail) if detail else self._send(404, {"error": "no such case"})
                if url.path == "/api/sensor":
                    node = next((node for node in gateway.nodes if node.name == query.get("node")), None)
                    if node is None:
                        return self._send(404, {"error": "no such sensor"})
                    try:
                        live = read_live(node, ("health", "collection-health", "gaps"))
                    except Exception:  # noqa: BLE001 - the console shows the sensor as unreachable
                        return self._send(502, {"error": "sensor unreachable"})
                    return self._send(200, live | {"node": node.view(), "connection_gaps": node.gaps})
                if url.path == "/api/traffic":
                    node = next((node for node in gateway.nodes if node.name == query.get("node")), None)
                    if node is None:
                        return self._send(404, {"error": "no such sensor"})
                    try:
                        window = {key: query[key] for key in ("window", "bucket", "end") if key in query}
                        traffic = read_live(node, ("traffic",), timeout=60, **window)["traffic"]
                    except ValueError:
                        return self._send(400, {"error": "invalid window"})
                    except Exception:  # noqa: BLE001 - HTTP 400 from the sensor or unreachable
                        return self._send(502, {"error": "sensor could not answer"})
                    return self._send(200, traffic)
                if self.path == "/api/actions":
                    return self._send(200, {"version": gateway.cache.version, "actions": gateway.cache.actions()})
                if self.path == "/api/writes":
                    return self._send(200, {"writes": gateway.cache.writes()})
                if self.path == "/api/nodes":
                    return self._send(200, {"version": gateway.cache.version, "nodes": [
                        node.view() | {"open_cases": gateway.cache.open_count(node.name)} for node in gateway.nodes]})
                if self.path == "/api/cases":
                    return self._send(200, {"version": gateway.cache.version, "cases": gateway.cache.cases()})
                return self._send(404, {"error": "not found"})

        self.server = ThreadingHTTPServer((host, port), Handler)
        self.server.daemon_threads = True

    def _poll_loop(self):
        while not self._stop.is_set():
            for node in self.nodes:
                try:
                    if node.poll():
                        sync(node, self.cache)
                    state = node.transition()
                    if state:
                        logging.getLogger(__name__).info("%s is %s", node.name, state)
                        self.announce(node, state)
                except Exception:  # noqa: BLE001 - one bad page or locked cache must not end polling for good
                    logging.getLogger(__name__).exception("%s poll failed; retrying next cycle", node.name)
            self._stop.wait(self.poll_interval)

    def start(self):
        threading.Thread(target=self._poll_loop, name="gateway-poll", daemon=True).start()
        threading.Thread(target=self.server.serve_forever, name="gateway-http", daemon=True).start()
        return self

    def close(self):
        self._stop.set()
        self.server.shutdown()
        self.server.server_close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="NetWatch console gateway")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    gateway = Gateway(discover_nodes(CONFIG_DIR), load_token(CONFIG_DIR / "ui.token"),
                      Cache(DATA_DIR / "cache.db"), port=args.port)
    logging.info("gateway serving %d node(s) on 127.0.0.1:%d", len(gateway.nodes), args.port)
    gateway.start()
    try:
        gateway._stop.wait()
    except KeyboardInterrupt:
        gateway.close()


if __name__ == "__main__":
    main()
