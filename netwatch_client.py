"""GUI-free authenticated polling client and console attach launcher."""

import argparse
import copy
import hmac
import json
import queue
import secrets
import threading
import time
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from netwatch_api import hello_proof, load_secret, secret_path


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Service API redirects are refused")


class ServiceClient:
    def __init__(self, url, secret, *, timeout=2, poll_interval=1, max_backoff=8):
        parsed = urlsplit(url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"} or parsed.username:
            raise ValueError("console attaches only to a loopback HTTP API")
        self.url = url.rstrip("/")
        self.secret = secret
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.max_backoff = max_backoff
        self.state = "Disconnected / stale"
        self.gaps = []
        self.instance = None
        self.data = {}
        self.failures = 0
        self.next_poll = 0
        self.last_success = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self.thread = None
        self.verified = False
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def verify_server(self):
        """Send the token only to a server that proves it knows the secret."""
        nonce = secrets.token_hex(16)
        with self.opener.open(self.url + "/v1/hello?" + urlencode({"nonce": nonce}), timeout=self.timeout) as response:
            proof = json.loads(response.read(1024)).get("proof")
        if not isinstance(proof, str) or not hmac.compare_digest(proof, hello_proof(self.secret, nonce)):
            raise ValueError("server failed to prove the API secret")
        self.verified = True

    def request(self, endpoint, body=None, **query):
        try:
            if not self.verified:
                self.verify_server()
            return self._request(endpoint, body, **query)
        except Exception:
            self.verified = False  # Any failure re-proves the server before the token is sent again.
            raise

    def _request(self, endpoint, body=None, **query):
        url = self.url + "/v1/" + endpoint
        if query:
            url += "?" + urlencode(query)
        request = Request(url, data=None if body is None else json.dumps(body).encode(),
                          headers={"Authorization": "Bearer " + self.secret.hex(), "Content-Type": "application/json"})
        with self.opener.open(request, timeout=self.timeout) as response:
            raw = response.read(16_777_217)
        if len(raw) > 16_777_216:
            raise ValueError("oversized API response")
        result = json.loads(raw)
        if result.get("version") != 1 or not isinstance(result.get("instance"), str):
            raise ValueError("unsupported service contract")
        return result

    def poll(self, now=None):
        now = time.monotonic() if now is None else now
        if now < self.next_poll:
            return False
        self.verified = False
        try:
            snapshot = {}
            instance = None
            for endpoint in ("health", "cases", "detections", "sources", "collection-health", "gaps", "evidence"):
                if self._stop.is_set():
                    return False
                result = self.request(endpoint)
                if instance is not None and result["instance"] != instance:
                    raise ValueError("service restarted during snapshot")
                instance = result["instance"]
                snapshot[endpoint] = result["data"]
            with self._lock:
                if self.instance is not None and (self.failures or instance != self.instance):
                    self.gaps.append({"message": "Console connection interrupted; collection continuity unverified",
                                      "reconnected_at": time.time(), "service_restarted": instance != self.instance})
                    self.gaps = self.gaps[-100:]
                self.data = snapshot
                self.instance = instance
                self.state = "Connected"
                self.last_success = time.monotonic()
                self.failures = 0
                self.next_poll = now + self.poll_interval
            return True
        except (OSError, URLError, ValueError, TypeError, KeyError):
            with self._lock:
                self.state = "Disconnected / stale"
                self.failures += 1
                self.next_poll = now + min(self.max_backoff, 2 ** min(self.failures - 1, 10))
            return False

    def start(self):
        def run():
            while not self._stop.is_set():
                self.poll()
                self._stop.wait(0.1)
        self.thread = threading.Thread(target=run, name="console-service-client")
        self.thread.start()
        return self

    def snapshot(self):
        with self._lock:
            return copy.deepcopy(self.data.get("cases", []))

    def detections(self, incident_id, limit=1000):
        with self._lock:
            return copy.deepcopy([row for row in self.data.get("detections", [])
                                  if row["incident_id"] == incident_id][-limit:])

    def source_events(self, source=None, **filters):
        with self._lock:
            rows = self.data.get("sources", [])
            return copy.deepcopy([row for row in rows if (source is None or row["source"] == source)
                                  and all(filters.get(key) is None or row.get(key) == filters[key]
                                          for key in ("event_type", "event_id", "sensor_id"))][:filters.get("limit", 500)])

    def source_health(self, key):
        with self._lock:
            return copy.deepcopy(self.data.get("collection-health", {}).get(key))

    def open_count(self):
        return sum(row["status"] not in {"Resolved", "Recovered", "Dismissed"} for row in self.snapshot())

    def critical_count(self):
        return sum(row["severity"] == "critical" and row["status"] not in
                   {"Resolved", "Recovered", "Dismissed"} for row in self.snapshot())

    def audit(self, incident_id):
        try:
            return self.request("workflow", case=incident_id)["data"]
        except (OSError, URLError, ValueError):
            self.state = "Disconnected / stale"
            return []

    def update_case(self, incident_id, *, actor, **changes):
        try:
            result = self.request("cases", {"case": incident_id, **changes})["data"]
        except (OSError, URLError, ValueError) as exc:
            self.state = "Disconnected / stale"
            raise ValueError("Service case change failed; reconnect before retrying") from exc
        self.next_poll = 0
        return result

    def set_incident_status(self, incident_id, status, response=None):
        return self.update_case(incident_id, actor="authenticated-console", status=status,
                                closure_reason=response or "Changed by authenticated console")

    def native_retention_status(self, event_id):
        return {"status": "Remote native retention controls unavailable"}

    def close(self):
        self._stop.set()
        if self.thread is not None:
            self.thread.join()


class RemoteEvidenceCatalog:
    def __init__(self, client):
        self.client = client

    def list(self):
        with self.client._lock:
            return copy.deepcopy(self.client.data.get("evidence", []))

    def get(self, evidence_id):
        return next((row for row in self.list() if row["evidence_id"] == evidence_id), None)

    def audit(self, evidence_id):
        return []  # Remote catalog is listing-only in this slice.

    def close(self):
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(description="Attach the console without owning monitoring workers")
    parser.add_argument("--base-dir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--url", default="http://127.0.0.1:8765")
    args = parser.parse_args(argv)
    from netwatch_config import build_config

    config, _ = build_config(str(args.base_dir.resolve()), resource_dir=str(Path(__file__).resolve().parent))
    client = ServiceClient(args.url, load_secret(secret_path(config)))
    from PyQt6.QtWidgets import QApplication

    from netwatch_ui import OperationsDashboard

    app = QApplication([])
    client.start()
    try:
        window = OperationsDashboard(queue.Queue(), queue.Queue(), queue.Queue(), queue.Queue(),
                                     config=config, service_client=client)
        window.show()
        return app.exec()
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
