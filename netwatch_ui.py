"""Modern, incident-first NetWatch operator console.

The worker topology remains unchanged.  This module owns only presentation,
bounded view models, and reversible response controls.
"""

from __future__ import annotations

import json
import queue
import socket
import sqlite3
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QAbstractTableModel, QPointF, Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStackedWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from netwatch_config import detect_own_ipv4
from netwatch_core import is_message_payload, make_message, newest_render_data
from netwatch_evidence_catalog import EvidenceCatalog
from netwatch_history import HistoryStore, timeline_series
from netwatch_log import setup_logging
from netwatch_mitigation import FirewallError
from netwatch_security_store import security_store_from_config
from netwatch_suricata import eve_freshness_status
from netwatch_ui_state import (
    INCIDENT_SCOPES,
    RESPONSE_MODE_LABELS,
    RESPONSE_MODES,
    filter_incident_rows,
    filter_traffic_events,
    heartbeat_label,
    load_inventory_snapshot,
    load_recent_traffic_events,
    load_response_mode,
    load_web_observation_events,
    normalize_response_mode,
    response_dispatch,
    save_response_mode,
    severity_for,
)


def _human_bytes(value):
    value = float(value or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if abs(value) < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _relative_time(timestamp, now=None):
    now = time.time() if now is None else now
    seconds = max(0, int(now - float(timestamp or 0)))
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


class DictTableModel(QAbstractTableModel):
    """Small immutable snapshots exposed through Qt's virtualized table API."""

    def __init__(self, columns, *, max_rows=1000, parent=None):
        super().__init__(parent)
        self.columns = tuple(columns)
        self.max_rows = max(1, int(max_rows))
        self.rows = []

    def rowCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(self.rows)

    def columnCount(self, parent=None):
        return 0 if parent is not None and parent.isValid() else len(self.columns)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.columns[section][1]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self.rows):
            return None
        row = self.rows[index.row()]
        key = self.columns[index.column()][0]
        if role == Qt.ItemDataRole.UserRole:
            return row
        if role == Qt.ItemDataRole.DisplayRole:
            value = row.get(key, "")
            formatter = self.columns[index.column()][2] if len(self.columns[index.column()]) > 2 else None
            return formatter(value, row) if formatter else str(value)
        if role == Qt.ItemDataRole.ForegroundRole:
            severity = row.get("severity")
            if key == "severity":
                return QBrush({
                    "critical": QColor("#ff7185"),
                    "alert": QColor("#f4ad57"),
                    "anomaly": QColor("#78aef8"),
                    "notice": QColor("#b49cf2"),
                }.get(severity, QColor("#9bacbf")))
            if row.get("alert"):
                return QBrush(QColor("#f4c06a"))
            if key in {"title", "source", "vendor", "target"}:
                return QBrush(QColor("#e6edf6"))
        if role == Qt.ItemDataRole.FontRole and key in {"title", "target", "vendor"}:
            font = QFont()
            font.setWeight(QFont.Weight.Medium)
            return font
        if role == Qt.ItemDataRole.TextAlignmentRole and key in {"count", "size", "port", "events", "bytes"}:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return None

    def replace(self, rows):
        snapshot = [dict(row) for row in rows[: self.max_rows]]
        self.beginResetModel()
        self.rows = snapshot
        self.endResetModel()

    def prepend(self, rows):
        incoming = [dict(row) for row in rows]
        if not incoming:
            return
        self.beginResetModel()
        self.rows = (incoming + self.rows)[: self.max_rows]
        self.endResetModel()


class SparklineWidget(QWidget):
    """Event-driven chart: it repaints only when a new snapshot arrives."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.values = [0.0] * 60
        self.setMinimumHeight(145)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setAccessibleName("Detection activity over the selected time window")

    def set_values(self, values):
        if not values:
            values = [0.0] * 60
        self.values = [max(0.0, float(value)) for value in values]
        self.update()

    def paintEvent(self, event):
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(14, 10, -14, -20)
        painter.fillRect(self.rect(), QColor("#101925"))
        painter.setPen(QPen(QColor("#243247"), 1))
        for fraction in (0.0, 0.5, 1.0):
            y = rect.top() + rect.height() * fraction
            painter.drawLine(rect.left(), int(y), rect.right(), int(y))
        if len(self.values) > 1:
            peak = max(1.0, max(self.values))
            points = []
            for index, value in enumerate(self.values):
                x = rect.left() + index * rect.width() / (len(self.values) - 1)
                y = rect.bottom() - (value / peak) * rect.height()
                points.append(QPointF(x, y))
            line = QPainterPath(points[0])
            for point in points[1:]:
                line.lineTo(point)
            area = QPainterPath(line)
            area.lineTo(points[-1].x(), rect.bottom())
            area.lineTo(points[0].x(), rect.bottom())
            area.closeSubpath()
            painter.fillPath(area, QColor(55, 125, 220, 38))
            painter.setPen(QPen(QColor("#65a4fa"), 2))
            painter.drawPath(line)
        painter.setPen(QColor("#71849b"))
        painter.drawText(rect.left(), self.height() - 5, "60m ago")
        painter.drawText(rect.right() - 24, self.height() - 5, "now")


class RenderDrainThread(QThread):
    batch_ready = pyqtSignal(list, float, bool)
    DRAIN_PER_TICK = 1000  # >= render queue maxsize; leftovers wait for next pass

    def __init__(self, render_queue, filter_state, filter_lock, max_events=10_000,
                 max_observations=10_000, db_path=None, observation_reload_sec=5,
                 activity_reload_sec=5, local_prefixes=(), local_prefixes6=(),
                 os_threshold_nix=64, os_threshold_win=128,
                 traffic_lookback_sec=86_400, parent=None):
        super().__init__(parent)
        self.render_queue = render_queue
        self.filter_state = filter_state
        self.filter_lock = filter_lock
        self._stop_event = threading.Event()
        self._refilter_event = threading.Event()
        self.raw_events = deque(maxlen=max(1, int(max_events)))
        self.raw_event_ids = set()
        self.observation_events = deque(maxlen=max(1, int(max_observations)))
        self.observation_flow_ids = set()
        self.db_path = db_path
        self.observation_reload_sec = max(1.0, float(observation_reload_sec))
        self.activity_reload_sec = max(1.0, float(activity_reload_sec))
        self.local_prefixes = tuple(local_prefixes or ())
        self.local_prefixes6 = tuple(local_prefixes6 or ())
        self.os_threshold_nix = int(os_threshold_nix)
        self.os_threshold_win = int(os_threshold_win)
        self.traffic_lookback_sec = max(1.0, float(traffic_lookback_sec))
        self.last_activity_reload = 0.0
        self.activity_out_of_order = False
        self.last_observation_reload = 0.0

    def _remember_raw(self, event):
        if not isinstance(event, dict):
            return
        event_id = str(event.get("event_id") or "")
        if event_id and event_id in self.raw_event_ids:
            return
        if len(self.raw_events) == self.raw_events.maxlen:
            expired = self.raw_events[-1]
            self.raw_event_ids.discard(str(expired.get("event_id") or ""))
        self.raw_events.appendleft(event)
        if event_id:
            self.raw_event_ids.add(event_id)

    def _reload_persisted_activity(self):
        loaded = load_recent_traffic_events(
            self.db_path, limit=self.raw_events.maxlen,
            local_prefixes=self.local_prefixes,
            local_prefixes6=self.local_prefixes6,
            os_threshold_nix=self.os_threshold_nix,
            os_threshold_win=self.os_threshold_win,
        )
        new_events = [
            event for event in loaded
            if str(event.get("event_id") or "")
            and str(event.get("event_id")) not in self.raw_event_ids
        ]
        # A full deque has evicted its oldest rows; durable rows at or below that floor
        # would come back as "new", so only rows newer than the retained tail are merged.
        if new_events and len(self.raw_events) == self.raw_events.maxlen:
            floor = min(self._event_timestamp(event) for event in self.raw_events)
            new_events = [event for event in new_events if self._event_timestamp(event) > floor]
        head = max((self._event_timestamp(event) for event in self.raw_events), default=0.0)
        merged = sorted((*self.raw_events, *new_events), key=self._event_timestamp, reverse=True)
        merged = merged[:self.raw_events.maxlen]
        kept = {id(event) for event in merged}
        new_events = [event for event in new_events if id(event) in kept]
        self.raw_events = deque(merged, maxlen=self.raw_events.maxlen)
        self.raw_event_ids = {str(event.get("event_id") or "") for event in merged} - {""}
        # rows older than what is already shown cannot be prepended without misordering
        self.activity_out_of_order = any(self._event_timestamp(event) < head for event in new_events)
        self.last_activity_reload = time.monotonic()
        return new_events

    def _remember_observation(self, event):
        if not isinstance(event, dict):
            return
        flow_id = str(event.get("flow_id") or "")
        if flow_id and flow_id in self.observation_flow_ids:
            return
        if len(self.observation_events) == self.observation_events.maxlen:
            expired = self.observation_events[-1]
            self.observation_flow_ids.discard(str(expired.get("flow_id") or ""))
        self.observation_events.appendleft(event)
        if flow_id:
            self.observation_flow_ids.add(flow_id)

    def _reload_persisted(self):
        loaded = load_web_observation_events(
            self.db_path, limit=self.observation_events.maxlen,
        )
        new_events = [
            event for event in loaded
            if str(event.get("flow_id") or "") not in self.observation_flow_ids
        ]
        for event in reversed(new_events):
            self._remember_observation(event)
        self.last_observation_reload = time.monotonic()
        return new_events

    @staticmethod
    def _observation_mode(filters):
        return filters.get("observation") in {
            "OUTBOUND WEB", "HUMAN SIGNAL", "LIKELY HUMAN",
            "POSSIBLE HUMAN", "WEB NOISE",
        }

    @staticmethod
    def _event_timestamp(event):
        observation = event.get("web_observation")
        observation = observation if isinstance(observation, dict) else {}
        try:
            return float(event.get("timestamp") or observation.get("started_at") or 0)
        except (TypeError, ValueError, OverflowError):
            return 0.0

    def _filtered_snapshot(self, filters):
        observation_mode = self._observation_mode(filters)
        if observation_mode:
            persisted = load_web_observation_events(
                self.db_path,
                limit=self.observation_events.maxlen,
                filters=filters,
                lookback_sec=self.traffic_lookback_sec,
                local_prefixes=self.local_prefixes,
                local_prefixes6=self.local_prefixes6,
            )
            cached = list(self.observation_events)
            key_name = "flow_id"
            limit = self.observation_events.maxlen
        else:
            persisted = load_recent_traffic_events(
                self.db_path,
                limit=self.raw_events.maxlen,
                local_prefixes=self.local_prefixes,
                local_prefixes6=self.local_prefixes6,
                os_threshold_nix=self.os_threshold_nix,
                os_threshold_win=self.os_threshold_win,
                filters=filters,
                lookback_sec=self.traffic_lookback_sec,
            )
            cached = list(self.raw_events)
            key_name = "event_id"
            limit = self.raw_events.maxlen
        merged = {}
        anonymous = []
        for event in (*cached, *persisted):
            key = str(event.get(key_name) or "")
            if key:
                merged.setdefault(key, event)
            else:
                anonymous.append(event)
        events = [*merged.values(), *anonymous]
        events.sort(key=self._event_timestamp, reverse=True)
        return filter_traffic_events(events, filters)[:limit]

    def run(self):
        self._reload_persisted_activity()
        self._reload_persisted()
        self._refilter_event.set()
        while not self._stop_event.is_set():
            payloads = []
            for _ in range(self.DRAIN_PER_TICK):
                try:
                    payloads.append(self.render_queue.get_nowait())
                except queue.Empty:
                    break
            if payloads:
                events, observations, total_ingested = newest_render_data(
                    payloads, event_limit=self.raw_events.maxlen,
                    observation_limit=self.observation_events.maxlen,
                )
                for event in events:
                    self._remember_raw(event)
                for observation in observations:
                    self._remember_observation(observation)
                with self.filter_lock:
                    filters = dict(self.filter_state)
                if self._refilter_event.is_set():
                    self._refilter_event.clear()
                    rows = self._filtered_snapshot(filters)
                    self.batch_ready.emit(rows, float(total_ingested), True)
                else:
                    source = observations if self._observation_mode(filters) else events
                    rows = filter_traffic_events(source, filters)
                    self.batch_ready.emit(rows, float(total_ingested), False)
            elif self._refilter_event.is_set():
                self._refilter_event.clear()
                with self.filter_lock:
                    filters = dict(self.filter_state)
                rows = self._filtered_snapshot(filters)
                self.batch_ready.emit(rows, 0.0, True)
            if time.monotonic() - self.last_observation_reload >= self.observation_reload_sec:
                new_events = self._reload_persisted()
                with self.filter_lock:
                    filters = dict(self.filter_state)
                if new_events and self._observation_mode(filters):
                    rows = filter_traffic_events(new_events, filters)
                    self.batch_ready.emit(rows, 0.0, False)
            if time.monotonic() - self.last_activity_reload >= self.activity_reload_sec:
                new_events = self._reload_persisted_activity()
                with self.filter_lock:
                    filters = dict(self.filter_state)
                if new_events and not self._observation_mode(filters):
                    if self.activity_out_of_order:
                        self._refilter_event.set()
                    else:
                        rows = filter_traffic_events(new_events, filters)
                        self.batch_ready.emit(rows, 0.0, False)
            self._stop_event.wait(0.1)

    def refilter(self):
        self._refilter_event.set()

    def stop(self):
        self._stop_event.set()


class EvidenceTaskThread(QThread):
    result_ready = pyqtSignal(dict)

    def __init__(self, catalog, operation, evidence_id, arguments, parent=None):
        super().__init__(parent)
        self.catalog = catalog
        self.operation = operation
        self.evidence_id = evidence_id
        self.arguments = arguments
        self.db_path = catalog.store.conn.execute("PRAGMA database_list").fetchone()[2]

    def run(self):
        # A separate connection keeps WAL metadata reads responsive during hashing.
        catalog = None
        try:
            catalog = EvidenceCatalog(self.catalog.directory, db_path=self.db_path) if self.db_path else self.catalog
            if self.operation == "verify":
                result = catalog.verify(self.evidence_id, **self.arguments)
            elif self.operation == "hold":
                result = catalog.hold(self.evidence_id, **self.arguments)
            elif self.operation == "export":
                result = catalog.export(self.evidence_id, **self.arguments)
            else:
                raise ValueError(f"unknown evidence operation {self.operation!r}")
            self.result_ready.emit({"ok": True, "operation": self.operation, "result": result})
        except Exception as exc:
            self.result_ready.emit({"ok": False, "operation": self.operation, "error": str(exc)})
        finally:
            if catalog is not None and catalog is not self.catalog:
                catalog.close()


class HistoryReadThread(QThread):
    snapshot_ready = pyqtSignal(dict)

    def __init__(self, db_path, overview_refresh_sec=60.0, detail_refresh_sec=30.0, parent=None):
        super().__init__(parent)
        self.db_path = db_path
        self.overview_refresh_sec = max(5.0, float(overview_refresh_sec))
        self.detail_refresh_sec = max(5.0, float(detail_refresh_sec))
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._family = None
        self._mode = "overview"
        self._filter_lock = threading.Lock()

    def set_family(self, text):
        family = 4 if text == "IPv4" else 6 if text == "IPv6" else None
        with self._filter_lock:
            self._family = family
        self._wake_event.set()

    def set_mode(self, mode):
        mode = mode if mode in {"overview", "detail", "off"} else "off"
        with self._filter_lock:
            self._mode = mode
        self._wake_event.set()

    def run(self):
        while not self._stop_event.is_set():
            self._wake_event.clear()
            with self._filter_lock:
                family = self._family
                mode = self._mode
            if mode == "off":
                self._wake_event.wait(60.0)
                continue
            now = time.time()
            bucket_sec = 60
            bucket_count = 60
            start = (int(now // bucket_sec) - (bucket_count - 1)) * bucket_sec
            filters = {"since": start, "until": now, "family": family}
            store = None
            try:
                store = HistoryStore(self.db_path)
                series = timeline_series(
                    store.timeline(filters, bucket_sec=bucket_sec),
                    end_ts=now,
                    bucket_sec=bucket_sec,
                    bucket_count=bucket_count,
                )
                summary = {
                    "events": sum(row["events"] for row in series),
                    "bytes": sum(row["bytes"] for row in series),
                }
                snapshot = {
                    "series": series,
                    "summary": summary,
                    "family": family,
                    "error": None,
                }
                if mode == "detail":
                    snapshot["summary"] = store.summary(filters)
                    snapshot["talkers"] = store.top_talkers(filters, limit=8)
                self.snapshot_ready.emit(snapshot)
            except (OSError, sqlite3.Error) as exc:
                self.snapshot_ready.emit({"error": f"{type(exc).__name__}: {exc}"})
            finally:
                if store is not None:
                    store.close()
            interval = self.detail_refresh_sec if mode == "detail" else self.overview_refresh_sec
            self._wake_event.wait(interval)

    def stop(self):
        self._stop_event.set()
        self._wake_event.set()


class StatCard(QFrame):
    activated = pyqtSignal()

    def __init__(self, label, accent="#e6edf6", *, action_text="", on_activate=None, parent=None):
        super().__init__(parent)
        self.setObjectName("statCard")
        interactive = on_activate is not None
        self.setProperty("interactive", interactive)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus if interactive else Qt.FocusPolicy.NoFocus)
        if interactive:
            self.setCursor(Qt.CursorShape.PointingHandCursor)
            self.setAccessibleName(f"{label}: open details")
            self.setToolTip(f"Open {label.lower()} details")
            self.activated.connect(on_activate)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(13, 11, 13, 11)
        layout.setSpacing(3)
        name = QLabel(label.upper())
        name.setObjectName("statLabel")
        self.action = QLabel(action_text.upper())
        self.action.setObjectName("statAction")
        self.action.setVisible(bool(action_text))
        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.addWidget(name)
        header.addStretch(1)
        header.addWidget(self.action)
        self.value = QLabel("0")
        self.value.setObjectName("statValue")
        self.value.setStyleSheet(f"color: {accent};")
        self.note = QLabel("")
        self.note.setObjectName("statNote")
        for label_widget in (name, self.action, self.value, self.note):
            label_widget.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        layout.addLayout(header)
        layout.addWidget(self.value)
        layout.addWidget(self.note)

    def set_value(self, value, note=""):
        self.value.setText(str(value))
        self.note.setText(str(note))

    def mouseReleaseEvent(self, event):
        if (self.property("interactive") and event.button() == Qt.MouseButton.LeftButton
                and self.rect().contains(event.position().toPoint())):
            self.activated.emit()
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def keyPressEvent(self, event):
        if self.property("interactive") and event.key() in {
            Qt.Key.Key_Enter,
            Qt.Key.Key_Return,
            Qt.Key.Key_Space,
        }:
            self.activated.emit()
            event.accept()
            return
        super().keyPressEvent(event)


class OperationsDashboard(QMainWindow):
    """Incident-first IDS/IPS console backed by the existing worker processes."""

    effect_done = pyqtSignal(object, object, object)
    ALERTS_PER_TICK = 50
    DRAIN_PER_TICK = 1000  # >= largest status/policy queue maxsize; leftovers wait for next tick
    EFFECT_BACKLOG_MAX = 256

    INCIDENT_COLUMNS = (
        ("severity", "Severity", lambda value, row: str(value).title()),
        ("title", "Incident"),
        ("target", "Asset / target"),
        ("count", "Evidence"),
        ("confidence", "Confidence"),
        ("last_seen", "Last seen", lambda value, row: _relative_time(value)),
        ("status", "Status"),
    )
    TRAFFIC_COLUMNS = (
        ("time", "Time"),
        ("source", "Source"),
        ("target", "Target"),
        ("protocol", "Proto"),
        ("port", "Port"),
        ("size", "Bytes"),
        ("country", "Geo"),
        ("os", "TTL profile"),
        ("scope", "Scope"),
        ("signal", "Human / noise evidence"),
    )
    ASSET_COLUMNS = (
        ("vendor", "Device / vendor"),
        ("ips", "IP addresses", lambda value, row: ", ".join(value) or "—"),
        ("mac", "MAC"),
        ("count", "Packets"),
        ("first_seen", "First seen", lambda value, row: _relative_time(value)),
        ("last_seen", "Last seen", lambda value, row: _relative_time(value)),
    )
    TALKER_COLUMNS = (
        ("host", "Source"),
        ("events", "Events"),
        ("bytes", "Volume", lambda value, row: _human_bytes(value)),
    )
    SOURCE_COLUMNS = (
        ("source", "Source"), ("event_type", "Record"), ("sensor_id", "Sensor"),
        ("event_time", "Event time", lambda value, row: datetime.fromtimestamp(value).isoformat(timespec="seconds")),
        ("src_ip", "Source address"), ("source_port", "Port"),
        ("dst_ip", "Destination address"), ("destination_port", "Port"),
        ("direction", "Direction"),
    )

    def __init__(self, render_queue, alert_queue, db_status_queue, worker_status_queue,
                 config=None, shutdown_event=None, workers=(), policy_queue=None, shutdown_callback=None, service_client=None):
        super().__init__()
        self.render_queue = render_queue
        self._closing = False
        self._effects = queue.Queue()
        self._effects_pending = 0
        self._effects_shed = 0
        self._effect_thread = None
        self._in_poll = False
        self._views_dirty = False
        self._reconcile_inflight = False
        self._case_inflight = 0
        self.case_buttons = []
        self.effect_done.connect(self._effect_finished)
        self.alert_queue = alert_queue
        self.db_status_queue = db_status_queue
        self.worker_status_queue = worker_status_queue
        self.policy_queue = policy_queue
        self.config = config or {}
        self.shutdown_event = shutdown_event
        self.shutdown_callback = shutdown_callback
        self.workers = tuple(workers)
        self.log = setup_logging("ui", self.config)
        self.alert_archive = setup_logging("alerts", self.config)
        self.service_client = service_client
        self.incidents = service_client or security_store_from_config(self.config)
        evidence_root = self.config.get("EVIDENCE_DIR") or str(Path(self.config.get("DB_NAME", "telemetry.db")).parent / "evidence")
        if service_client is not None:
            from netwatch_client import RemoteEvidenceCatalog

            self.evidence_catalog = RemoteEvidenceCatalog(service_client)
        else:
            self.evidence_catalog = EvidenceCatalog(evidence_root, store=self.incidents)
        self.evidence_task = None
        self.selected_evidence = None
        self.last_evidence_reload = 0.0
        self.selected_incident = None
        self.total_observed = 0
        self.policy_decisions = deque(maxlen=100)
        self.volume_history = deque([0.0] * 60, maxlen=60)
        self.filter_lock = threading.Lock()
        self.filter_state = {
            "scope": "ALL TRAFFIC",
            "node_scope": "ALL SOURCES",
            "os": "ALL TTL",
            "alerts": "ALL EVENTS",
            "family": "ALL IP",
            "observation": "ALL CAPTURED",
            "secure_nodes": self.config.get("SECURE_NODES", {}),
        }
        self.started_at = time.time()
        self.last_db_heartbeat = None
        self.db_heartbeat_timeout = float(self.config.get("DB_HEARTBEAT_TIMEOUT_SEC", 10))
        self.last_sniffer_heartbeat = self.last_core_heartbeat = None
        self.sniffer_status = self.core_status = "STARTING"
        self.capture_stats = {}
        self.db_fatal_triggered = False
        self.sniffer_fatal_triggered = False
        self.core_fatal_triggered = False
        shards = int(self.config.get("CORE_SHARDS", 1))
        # Every analytics worker's last live heartbeat (None until its first): the core, or the merge and its shards.
        self.core_heartbeats = dict.fromkeys(["DOD_CORE", *(f"DOD_CORE_{i}" for i in range(shards if shards > 1 else 0))])
        self.capture_degraded = False
        self.last_suricata_heartbeat = 0.0
        self.suricata_health = {}
        self.last_source_reload = 0.0
        self.sensor_name = socket.gethostname()
        self.last_reconcile = time.time()
        self._mit_dirty = False
        self.response_mode = load_response_mode(
            self.config.get("RESPONSE_MODE_LEDGER"),
            default=self.config.get("RESPONSE_MODE", "ids_only"),
        )
        self.mitigator = None if service_client is not None else self._build_mitigator()
        self.quarantine = None if service_client is not None else self._build_quarantine()
        self._q_seen = {row["ip"] for row in self.quarantine.snapshot()} if self.quarantine else set()

        self.incident_model = DictTableModel(self.INCIDENT_COLUMNS, max_rows=500, parent=self)
        self.incident_detail_model = DictTableModel(self.INCIDENT_COLUMNS, max_rows=500, parent=self)
        self.traffic_model = DictTableModel(
            self.TRAFFIC_COLUMNS,
            max_rows=int(self.config.get("UI_LOG_BLOCKS", 1000)),
            parent=self,
        )
        self.asset_model = DictTableModel(self.ASSET_COLUMNS, max_rows=2000, parent=self)
        self.talker_model = DictTableModel(self.TALKER_COLUMNS, max_rows=8, parent=self)
        self.evidence_model = DictTableModel((
            ("filename", "Capture"), ("status", "Integrity / retention"),
            ("held", "Investigation hold"), ("size_bytes", "Size", lambda value, row: _human_bytes(value)),
            ("created_at", "Created", lambda value, row: _relative_time(value)),
        ), max_rows=500, parent=self)
        self.source_model = DictTableModel(self.SOURCE_COLUMNS, max_rows=500, parent=self)

        self.setWindowTitle("NetWatch — Detection & Response")
        self.resize(1440, 900)
        self.setMinimumSize(1050, 680)
        self._build_shell()
        if service_client is not None:
            self.mode_selector.setEnabled(False)
            self.mode_selector.setToolTip("Service responses are recorded previews only")
        self._apply_theme()
        self._set_response_mode(self.response_mode, persist=False)
        self._refresh_assets()
        self._refresh_enforcement()
        self._refresh_incident_views()

        self.drain_thread = RenderDrainThread(
            render_queue, self.filter_state, self.filter_lock,
            max_events=int(self.config.get("UI_LOG_BLOCKS", 1000)),
            max_observations=int(self.config.get("UI_OBSERVATION_LOG_BLOCKS", 10_000)),
            db_path=self.config.get("DB_NAME"),
            observation_reload_sec=self.config.get("UI_OBSERVATION_RELOAD_SEC", 5),
            activity_reload_sec=self.config.get("UI_ACTIVITY_RELOAD_SEC", 5),
            local_prefixes=self.config.get("LOCAL_PREFIXES", ()),
            local_prefixes6=self.config.get("LOCAL_PREFIXES6", ()),
            os_threshold_nix=self.config.get("OS_THRESHOLD_NIX", 64),
            os_threshold_win=self.config.get("OS_THRESHOLD_WIN", 128),
            traffic_lookback_sec=self.config.get("UI_TRAFFIC_LOOKBACK_SEC", 86_400),
            parent=self,
        )
        self.drain_thread.batch_ready.connect(self.apply_render_batch)
        self.drain_thread.start()
        self.history_thread = HistoryReadThread(
            self.config.get("DB_NAME", "telemetry_ledger.db"),
            overview_refresh_sec=self.config.get("HISTORY_OVERVIEW_REFRESH_SEC", 60),
            detail_refresh_sec=self.config.get("HISTORY_DETAIL_REFRESH_SEC", 30),
            parent=self,
        )
        self.history_thread.snapshot_ready.connect(self.apply_history_snapshot)
        self.history_thread.start()
        self._history_page_changed(self.page_stack.currentIndex())

        self.poll_timer = QTimer(self)
        self.poll_timer.timeout.connect(self.poll_queues)
        self.poll_timer.start(100)
        self.ui_timer = QTimer(self)
        self.ui_timer.timeout.connect(self._refresh_periodic_ui)
        self.ui_timer.start(1000)
        self.asset_timer = QTimer(self)
        self.asset_timer.timeout.connect(self._refresh_assets)
        self.asset_timer.start(5000)

    def _apply_theme(self):
        self.setStyleSheet("""
            QMainWindow, QWidget#appRoot { background: #0b1018; color: #e6edf6; }
            QWidget { font-family: 'Segoe UI'; font-size: 12px; }
            QWidget#caseBody { background: #0d1520; }
            QScrollArea { border: 0; background: #0d1520; }
            QLineEdit { background: #101a27; color: #e6edf6; border: 1px solid #30455f;
                        padding: 6px; border-radius: 4px; }
            QFrame#topBar { background: #0e1520; border-bottom: 1px solid #243041; }
            QLabel#brand { color: #f2f6fb; font-size: 15px; font-weight: 600; letter-spacing: 1px; }
            QLabel#brandSub, QLabel#muted, QLabel#statLabel, QLabel#statNote { color: #71849b; }
            QLabel#brandSub, QLabel#statLabel, QLabel#statNote, QLabel#statAction { font-size: 10px; }
            QLabel#statAction { color: #76adff; font-weight: 600; }
            QLabel#healthGood { color: #58d6a4; }
            QLabel#healthBad { color: #ff7185; }
            QComboBox#modeSelector { background: #18263a; border: 1px solid #344a66; border-radius: 6px; color: #c5dbf5; font-weight: 600; padding: 6px 10px; }
            QFrame#sideBar { background: #0d141e; border-right: 1px solid #243041; }
            QPushButton#navButton { background: transparent; border: 0; border-radius: 6px; color: #8799af; padding: 9px 12px; text-align: left; }
            QPushButton#navButton:hover { background: #152131; color: #e6edf6; }
            QPushButton#navButton:checked { background: #17315a; color: #dcecff; }
            QLabel#pageTitle { color: #eef4fb; font-size: 21px; font-weight: 500; }
            QLabel#sectionTitle { color: #dfe7f1; font-size: 12px; font-weight: 500; }
            QFrame#panel, QFrame#statCard { background: #101925; border: 1px solid #263449; border-radius: 7px; }
            QFrame#statCard[interactive="true"]:hover { background: #142133; border-color: #45658b; }
            QFrame#statCard[interactive="true"]:focus { border: 2px solid #65a4fa; }
            QLabel#statValue { font-size: 23px; font-weight: 500; }
            QTableView { background: #101925; alternate-background-color: #111d2b; border: 0; color: #9bacbf; gridline-color: #202d3e; selection-background-color: #173a64; selection-color: #ffffff; }
            QTableView::item { border-bottom: 1px solid #202d3e; padding: 7px; }
            QHeaderView::section { background: #0f1824; border: 0; border-bottom: 1px solid #263449; color: #6f829a; font-size: 10px; padding: 7px; text-transform: uppercase; }
            QComboBox { background: #101925; border: 1px solid #304158; border-radius: 5px; color: #c3d0df; padding: 6px 8px; }
            QComboBox QAbstractItemView { background: #101925; color: #dce5f0; selection-background-color: #1d4777; }
            QPushButton#actionButton { background: #19283a; border: 1px solid #344b67; border-radius: 5px; color: #c5d3e5; padding: 7px 10px; }
            QPushButton#actionButton:hover { background: #21354d; }
            QPushButton#primaryAction { background: #245ca8; border: 1px solid #3474ca; border-radius: 5px; color: #f2f7ff; padding: 7px 10px; }
            QPushButton#dangerAction { background: #6f2938; border: 1px solid #a54153; border-radius: 5px; color: #ffdce2; padding: 7px 10px; }
            QPushButton:disabled { color: #536276; background: #131c28; border-color: #253246; }
            QListWidget, QPlainTextEdit { background: #0d1621; border: 1px solid #263449; border-radius: 5px; color: #aebdd0; selection-background-color: #1d4777; }
            QListWidget::item { padding: 6px; }
            QSplitter::handle { background: #1a2636; width: 2px; height: 2px; }
        """)

    def _build_shell(self):
        root = QWidget()
        root.setObjectName("appRoot")
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._build_top_bar())

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        side = QFrame()
        side.setObjectName("sideBar")
        side.setFixedWidth(190)
        nav_layout = QVBoxLayout(side)
        nav_layout.setContentsMargins(10, 16, 10, 12)
        nav_layout.setSpacing(4)
        nav_layout.addWidget(self._muted_label("OPERATIONS"))
        self.page_stack = QStackedWidget()
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        page_specs = (
            ("Overview", self._build_overview_page()),
            ("Incidents", self._build_incidents_page()),
            ("Investigate", self._build_investigate_page()),
            ("Traffic", self._build_traffic_page()),
            ("Assets", self._build_assets_page()),
            ("Enforcement", self._build_enforcement_page()),
            ("System", self._build_system_page()),
            ("Sources", self._build_sources_page()),
            ("Evidence", self._build_evidence_page()),
        )
        self.nav_buttons = {}
        self.page_indices = {}
        for index, (label, page) in enumerate(page_specs):
            button = QPushButton(label)
            button.setObjectName("navButton")
            button.setCheckable(True)
            button.clicked.connect(lambda checked=False, i=index: self.page_stack.setCurrentIndex(i))
            self.nav_group.addButton(button, index)
            self.nav_buttons[label] = button
            self.page_indices[label] = index
            nav_layout.addWidget(button)
            self.page_stack.addWidget(page)
        self.nav_buttons["Overview"].setChecked(True)
        self.page_stack.currentChanged.connect(self._history_page_changed)
        nav_layout.addStretch(1)
        self.intel_status = self._muted_label("Threat intelligence: local cache")
        self.ledger_status = self._muted_label("Ledger: bounded SQLite WAL")
        nav_layout.addWidget(self.intel_status)
        nav_layout.addWidget(self.ledger_status)
        body.addWidget(side)
        body.addWidget(self.page_stack, stretch=1)
        outer.addLayout(body, stretch=1)
        self.setCentralWidget(root)

    def _build_top_bar(self):
        bar = QFrame()
        bar.setObjectName("topBar")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 9, 16, 9)
        brand_box = QVBoxLayout()
        brand_box.setSpacing(0)
        brand = QLabel("NETWATCH")
        brand.setObjectName("brand")
        sub = QLabel("DETECTION & RESPONSE")
        sub.setObjectName("brandSub")
        brand_box.addWidget(brand)
        brand_box.addWidget(sub)
        layout.addLayout(brand_box)
        layout.addSpacing(30)
        self.sensor_health = QLabel(f"● SENSOR  {self.sensor_name}")
        self.capture_health = QLabel("● CAPTURE  Healthy")
        self.pipeline_health = QLabel("● PIPELINE  Nominal")
        for label in (self.sensor_health, self.capture_health, self.pipeline_health):
            label.setObjectName("healthGood")
            layout.addWidget(label)
        layout.addStretch(1)
        self.mode_selector = QComboBox()
        self.mode_selector.setObjectName("modeSelector")
        self.mode_selector.setAccessibleName("Detection and response operating mode")
        self.mode_selector.setToolTip("IDS only, approval-gated IPS readiness, or autonomous prevention")
        for mode in RESPONSE_MODES:
            self.mode_selector.addItem(RESPONSE_MODE_LABELS[mode], mode)
        selected = self.mode_selector.findData(self.response_mode)
        self.mode_selector.setCurrentIndex(max(0, selected))
        self.mode_selector.currentIndexChanged.connect(self._response_mode_changed)
        layout.addWidget(self.mode_selector)
        return bar

    def _page(self, title, subtitle):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)
        heading = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        label = QLabel(title)
        label.setObjectName("pageTitle")
        title_box.addWidget(label)
        title_box.addWidget(self._muted_label(subtitle))
        heading.addLayout(title_box)
        heading.addStretch(1)
        layout.addLayout(heading)
        return page, layout, heading

    @staticmethod
    def _muted_label(text):
        label = QLabel(text)
        label.setObjectName("muted")
        return label

    @staticmethod
    def _panel(title=None):
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        if title:
            heading = QLabel(title)
            heading.setObjectName("sectionTitle")
            heading.setContentsMargins(12, 10, 12, 8)
            layout.addWidget(heading)
        return panel, layout

    @staticmethod
    def _table(model, *, compact=False):
        table = QTableView()
        table.setModel(model)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setShowGrid(False)
        table.setWordWrap(False)
        table.verticalHeader().hide()
        table.verticalHeader().setDefaultSectionSize(34 if compact else 38)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        return table

    def _build_overview_page(self):
        page, layout, heading = self._page(
            "Security posture",
            "Current risk, capture integrity, and response state.",
        )
        window = QLabel("LAST 60 MINUTES")
        window.setObjectName("modePill")
        heading.addWidget(window)
        cards = QHBoxLayout()
        self.card_open = StatCard(
            "Open incidents", "#ff7185", action_text="Triage  ›", on_activate=self._open_incident_drilldown,
        )
        self.card_critical = StatCard(
            "Critical", "#f4ad57", action_text="Prioritize  ›",
            on_activate=lambda: self._open_incident_drilldown("CRITICAL ONLY"),
        )
        self.card_pending = StatCard(
            "Pending action", "#f4c45e", action_text="Review  ›", on_activate=self._open_pending_drilldown,
        )
        self.card_observed = StatCard(
            "Observed events", "#76adff", action_text="Explore  ›", on_activate=self._open_observed_drilldown,
        )
        for card in (self.card_open, self.card_critical, self.card_pending, self.card_observed):
            cards.addWidget(card)
        layout.addLayout(cards)

        split = QSplitter(Qt.Orientation.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)
        incident_panel, incident_layout = self._panel("INCIDENT QUEUE")
        self.overview_incident_table = self._table(self.incident_model, compact=True)
        self.overview_incident_table.hideColumn(3)
        self.overview_incident_table.hideColumn(4)
        self.overview_incident_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.overview_incident_table.setMaximumHeight(270)
        self.overview_incident_table.clicked.connect(self._incident_selected)
        incident_layout.addWidget(self.overview_incident_table)
        left_layout.addWidget(incident_panel)
        chart_panel, chart_layout = self._panel("DETECTION ACTIVITY")
        self.overview_chart = SparklineWidget()
        chart_layout.addWidget(self.overview_chart)
        left_layout.addWidget(chart_panel, stretch=1)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)
        detail_panel, detail_layout = self._panel("SELECTED INCIDENT")
        detail_body = QWidget()
        detail_body_layout = QVBoxLayout(detail_body)
        detail_body_layout.setContentsMargins(12, 10, 12, 12)
        self.overview_detail_title = QLabel("No active incident selected")
        self.overview_detail_title.setObjectName("sectionTitle")
        self.overview_detail = self._muted_label("Select an incident to inspect its evidence and response options.")
        self.overview_detail.setWordWrap(True)
        self.overview_detail_meta = self._muted_label("")
        detail_body_layout.addWidget(self.overview_detail_title)
        detail_body_layout.addWidget(self.overview_detail)
        detail_body_layout.addWidget(self.overview_detail_meta)
        detail_body_layout.addStretch(1)
        detail_body_layout.addLayout(self._incident_action_row())
        detail_layout.addWidget(detail_body)
        right_layout.addWidget(detail_panel, stretch=2)
        integrity_panel, integrity_layout = self._panel("SENSOR INTEGRITY")
        integrity_body = QWidget()
        integrity_grid = QGridLayout(integrity_body)
        integrity_grid.setContentsMargins(12, 10, 12, 12)
        self.integrity_capture = QLabel("Capture    Healthy")
        self.integrity_core = QLabel("Analytics  Healthy")
        self.integrity_db = QLabel("Ledger     Healthy")
        self.integrity_loss = QLabel("Packet loss  No active loss interval")
        for index, label in enumerate((self.integrity_capture, self.integrity_core, self.integrity_db, self.integrity_loss)):
            integrity_grid.addWidget(label, index, 0)
        integrity_layout.addWidget(integrity_body)
        right_layout.addWidget(integrity_panel, stretch=1)
        split.addWidget(left)
        split.addWidget(right)
        split.setSizes([760, 420])
        layout.addWidget(split, stretch=1)
        return page

    def _build_incidents_page(self):
        page, layout, heading = self._page(
            "Incidents",
            "Correlated findings grouped by detector, target, and time.",
        )
        self.incident_scope = QComboBox()
        self.incident_scope.setAccessibleName("Incident scope")
        self.incident_scope.setToolTip("Filter the active queue by operational priority")
        self.incident_scope.addItems(INCIDENT_SCOPES)
        self.incident_scope.currentTextChanged.connect(self._incident_scope_changed)
        heading.addWidget(self.incident_scope)
        panel, panel_layout = self._panel("ACTIVE QUEUE")
        self.incident_table = self._table(self.incident_detail_model)
        self.incident_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.incident_table.clicked.connect(self._incident_selected)
        panel_layout.addWidget(self.incident_table)
        layout.addWidget(panel, stretch=1)
        detail_panel, detail_layout = self._panel("EVIDENCE & RESPONSE")
        detail_body = QWidget()
        detail_body.setObjectName("caseBody")
        detail_body_layout = QVBoxLayout(detail_body)
        detail_body_layout.setContentsMargins(12, 10, 12, 12)
        self.incident_detail_title = QLabel("No incident selected")
        self.incident_detail_title.setObjectName("sectionTitle")
        self.incident_detail = self._muted_label("Select a row to inspect supporting evidence.")
        self.incident_detail.setWordWrap(True)
        self.incident_detail_meta = self._muted_label("")
        detail_body_layout.addWidget(self.incident_detail_title)
        detail_body_layout.addWidget(self.incident_detail)
        detail_body_layout.addWidget(self.incident_detail_meta)
        detail_body_layout.addLayout(self._incident_action_row())
        self.case_assignment = QLineEdit()
        self.case_assignment.setAccessibleName("Case assignment")
        self.case_assignment.setPlaceholderText("Assigned to")
        self.case_note = QLineEdit()
        self.case_note.setAccessibleName("Case note")
        self.case_note.setPlaceholderText("Add an investigation note")
        self.case_closure_reason = QLineEdit()
        self.case_closure_reason.setAccessibleName("Case closure reason")
        self.case_closure_reason.setPlaceholderText("Reason required to resolve the case")
        for field in (self.case_assignment, self.case_note, self.case_closure_reason):
            field.setMaxLength(16_384)
            detail_body_layout.addWidget(field)
        case_actions = QHBoxLayout()
        for label, callback in (("Acknowledge", self._acknowledge_case),
                                ("Save case", self._save_case),
                                ("Resolve case", self._resolve_case)):
            button = QPushButton(label)
            button.setObjectName("actionButton")
            button.clicked.connect(callback)
            self.case_buttons.append(button)
            case_actions.addWidget(button)
        detail_body_layout.addLayout(case_actions)
        self.case_audit = QPlainTextEdit()
        self.case_audit.setAccessibleName("Case audit history")
        self.case_audit.setReadOnly(True)
        self.case_audit.setMaximumBlockCount(300)
        detail_body_layout.addWidget(self.case_audit)
        self.case_evidence = QPlainTextEdit()
        self.case_evidence.setAccessibleName("Supporting detection records")
        self.case_evidence.setReadOnly(True)
        self.case_evidence.setMaximumBlockCount(1000)
        detail_body_layout.addWidget(self.case_evidence)
        detail_scroll = QScrollArea()
        detail_scroll.setWidgetResizable(True)
        detail_scroll.setWidget(detail_body)
        detail_layout.addWidget(detail_scroll)
        layout.addWidget(detail_panel, stretch=1)
        return page

    def _build_investigate_page(self):
        page, layout, heading = self._page(
            "Investigate",
            "Historical context and recent flow evidence for the selected incident.",
        )
        self.history_family = QComboBox()
        self.history_family.addItems(["ALL IP", "IPv4", "IPv6"])
        self.history_family.currentTextChanged.connect(self._history_family_changed)
        heading.addWidget(self.history_family)
        self.investigation_focus = QLabel("No incident selected")
        self.investigation_focus.setObjectName("sectionTitle")
        layout.addWidget(self.investigation_focus)
        split = QSplitter(Qt.Orientation.Horizontal)
        chart_panel, chart_layout = self._panel("ACTIVITY TIMELINE")
        self.investigation_chart = SparklineWidget()
        chart_layout.addWidget(self.investigation_chart)
        split.addWidget(chart_panel)
        talker_panel, talker_layout = self._panel("TOP SOURCES")
        self.talker_table = self._table(self.talker_model, compact=True)
        self.talker_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        talker_layout.addWidget(self.talker_table)
        split.addWidget(talker_panel)
        split.setSizes([760, 360])
        layout.addWidget(split, stretch=1)
        evidence_panel, evidence_layout = self._panel("RECENT FLOW EVIDENCE")
        self.evidence_table = self._table(self.traffic_model, compact=True)
        self.evidence_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        evidence_layout.addWidget(self.evidence_table)
        layout.addWidget(evidence_panel, stretch=2)
        self.history_status = self._muted_label("Waiting for ledger snapshot")
        layout.addWidget(self.history_status)
        return page

    def _build_traffic_page(self):
        page, layout, heading = self._page(
            "Traffic",
            "Exposure-first live and durable activity; classification narrows this evidence, never creates it.",
        )
        filters = QHBoxLayout()
        self.combo_scope = QComboBox()
        self.combo_scope.addItems(["ALL TRAFFIC", "EXTERNAL (HIDE LOCAL)", "INTERNAL ONLY"])
        self.combo_nodes = QComboBox()
        self.combo_nodes.addItems([
            "ALL SOURCES", "HIDE SECURE SOURCES", "HIDE SECURE ENDPOINTS",
        ])
        self.combo_nodes.setAccessibleName("Secure node visibility filter")
        self.combo_os = QComboBox()
        self.combo_os.addItems([
            "ALL TTL", "LOW TTL", "MID TTL", "HIGH TTL", "UNKNOWN TTL",
        ])
        self.combo_alerts = QComboBox()
        self.combo_alerts.addItems(["ALL EVENTS", "ALERTS ONLY"])
        self.combo_family = QComboBox()
        self.combo_family.addItems(["ALL IP", "IPv4", "IPv6"])
        self.combo_observation = QComboBox()
        self.combo_observation.addItems([
            "ALL CAPTURED", "ANY OUTBOUND", "UNCLASSIFIED OUTBOUND",
            "OUTBOUND WEB", "HUMAN SIGNAL", "LIKELY HUMAN",
            "POSSIBLE HUMAN", "WEB NOISE",
        ])
        self.combo_observation.setAccessibleName("Traffic observation filter")
        for combo, key in (
            (self.combo_scope, "scope"),
            (self.combo_nodes, "node_scope"),
            (self.combo_os, "os"),
            (self.combo_alerts, "alerts"),
            (self.combo_family, "family"),
            (self.combo_observation, "observation"),
        ):
            combo.currentTextChanged.connect(lambda text, field=key: self._set_filter(field, text))
            filters.addWidget(combo)
        heading.addLayout(filters)
        self.coverage_status = self._muted_label(
            "COVERAGE UNVERIFIED · awaiting observed-source evidence from the sensor"
        )
        self.coverage_status.setAccessibleName("Sensor capture coverage")
        layout.addWidget(self.coverage_status)
        panel, panel_layout = self._panel("LIVE FLOW TAIL")
        self.traffic_table = self._table(self.traffic_model)
        self.traffic_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.traffic_table.horizontalHeader().setSectionResizeMode(
            len(self.TRAFFIC_COLUMNS) - 1, QHeaderView.ResizeMode.Stretch,
        )
        panel_layout.addWidget(self.traffic_table)
        layout.addWidget(panel, stretch=1)
        return page

    def _build_assets_page(self):
        page, layout, _ = self._page(
            "Assets",
            "Passive MAC-keyed inventory with vendor, address, and recency context.",
        )
        panel, panel_layout = self._panel("DISCOVERED DEVICES")
        self.asset_table = self._table(self.asset_model)
        self.asset_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        panel_layout.addWidget(self.asset_table)
        layout.addWidget(panel, stretch=1)
        return page

    def _build_enforcement_page(self):
        page, layout, _ = self._page(
            "Enforcement",
            "Pending decisions, active controls, expiry, and rollback.",
        )
        cards = QHBoxLayout()
        self.card_blocks = StatCard("External blocks", "#58d6a4")
        self.card_quarantines = StatCard("LAN quarantine", "#ff7185")
        self.card_enforcement_pending = StatCard("Pending decisions", "#f4c45e")
        for card in (self.card_blocks, self.card_quarantines, self.card_enforcement_pending):
            cards.addWidget(card)
        layout.addLayout(cards)
        policy_panel, policy_layout = self._panel("ORDERED NETWORK POLICY")
        policy_body = QWidget()
        policy_body_layout = QVBoxLayout(policy_body)
        policy_body_layout.setContentsMargins(12, 10, 12, 12)
        self.policy_status = self._muted_label("Policy engine awaiting state")
        self.policy_list = QListWidget()
        self.policy_list.setMaximumHeight(150)
        policy_body_layout.addWidget(self.policy_status)
        policy_body_layout.addWidget(self.policy_list)
        policy_layout.addWidget(policy_body)
        layout.addWidget(policy_panel)
        split = QSplitter(Qt.Orientation.Horizontal)
        mit_panel, mit_layout = self._panel("FIREWALL RESPONSE")
        mit_body = QWidget()
        mit_body_layout = QVBoxLayout(mit_body)
        mit_body_layout.setContentsMargins(12, 10, 12, 12)
        self.mit_status = self._muted_label("Mitigation disabled")
        self.pending_list = QListWidget()
        self.active_list = QListWidget()
        mit_body_layout.addWidget(self.mit_status)
        mit_body_layout.addWidget(QLabel("PENDING APPROVAL"))
        mit_body_layout.addWidget(self.pending_list)
        mit_actions = QHBoxLayout()
        self.btn_approve = self._action_button("Approve", self._approve_selected, primary=True)
        self.btn_deny = self._action_button("Deny", self._deny_selected)
        self.btn_approve_all = self._action_button("Approve all", self._approve_all)
        for button in (self.btn_approve, self.btn_deny, self.btn_approve_all):
            mit_actions.addWidget(button)
        mit_body_layout.addLayout(mit_actions)
        mit_body_layout.addWidget(QLabel("ACTIVE BLOCKS"))
        mit_body_layout.addWidget(self.active_list)
        self.btn_unblock = self._action_button("Unblock selected", self._unblock_selected)
        mit_body_layout.addWidget(self.btn_unblock)
        mit_layout.addWidget(mit_body)
        split.addWidget(mit_panel)

        q_panel, q_layout = self._panel("LAN QUARANTINE")
        q_body = QWidget()
        q_body_layout = QVBoxLayout(q_body)
        q_body_layout.setContentsMargins(12, 10, 12, 12)
        self.q_status = self._muted_label("Quarantine disabled")
        self.q_pending_list = QListWidget()
        self.q_active_list = QListWidget()
        q_body_layout.addWidget(self.q_status)
        q_body_layout.addWidget(QLabel("PENDING APPROVAL"))
        q_body_layout.addWidget(self.q_pending_list)
        q_actions = QHBoxLayout()
        self.btn_q_approve = self._action_button("Quarantine", self._q_approve_selected, danger=True)
        self.btn_q_deny = self._action_button("Dismiss", self._q_deny_selected)
        q_actions.addWidget(self.btn_q_approve)
        q_actions.addWidget(self.btn_q_deny)
        q_body_layout.addLayout(q_actions)
        q_body_layout.addWidget(QLabel("QUARANTINED DEVICES"))
        q_body_layout.addWidget(self.q_active_list)
        self.btn_q_release = self._action_button("Release selected", self._q_release_selected)
        q_body_layout.addWidget(self.btn_q_release)
        q_layout.addWidget(q_body)
        split.addWidget(q_panel)
        layout.addWidget(split, stretch=1)
        return page

    def _build_system_page(self):
        page, layout, _ = self._page(
            "System",
            "Sensor health, persistence state, and durable operator audit events.",
        )
        health_panel, health_layout = self._panel("PIPELINE HEALTH")
        health_body = QWidget()
        grid = QGridLayout(health_body)
        grid.setContentsMargins(12, 10, 12, 12)
        self.system_sniffer = QLabel("Sniffer: awaiting heartbeat")
        self.system_core = QLabel("Analytics core: awaiting heartbeat")
        self.system_db = QLabel("Database: awaiting heartbeat")
        self.system_suricata = QLabel("Suricata: awaiting source evidence" if self.config.get("SURICATA_EVE_ENABLED") else "Suricata: disabled")
        self.system_capture = QLabel("Capture integrity: healthy")
        self.system_db_path = self._muted_label(f"Ledger: {self.config.get('DB_NAME', 'telemetry_ledger.db')}")
        self.system_log_path = self._muted_label(f"Logs: {self.config.get('LOG_DIR', 'logs')}")
        for row, widget in enumerate((self.system_sniffer, self.system_core, self.system_db,
                                      self.system_suricata,
                                      self.system_capture, self.system_db_path, self.system_log_path)):
            grid.addWidget(widget, row, 0)
        health_layout.addWidget(health_body)
        layout.addWidget(health_panel)
        audit_panel, audit_layout = self._panel("OPERATOR AUDIT")
        self.audit_log = QPlainTextEdit()
        self.audit_log.setReadOnly(True)
        self.audit_log.setMaximumBlockCount(500)
        audit_layout.addWidget(self.audit_log)
        layout.addWidget(audit_panel, stretch=1)
        return page

    def _build_evidence_page(self):
        page, layout, heading = self._page("Evidence", "Retained captures, integrity checks and investigation holds.")
        self.evidence_status = self._muted_label("Hashes detect changes against this local ledger; they do not attest against its administrator.")
        layout.addWidget(self.evidence_status)
        self.evidence_table = self._table(self.evidence_model)
        self.evidence_table.clicked.connect(self._evidence_selected)
        layout.addWidget(self.evidence_table, stretch=2)
        self.evidence_reason = QLineEdit()
        self.evidence_reason.setAccessibleName("Evidence hold or release reason")
        self.evidence_reason.setPlaceholderText("Required reason for a hold or release")
        layout.addWidget(self.evidence_reason)
        actions = QHBoxLayout()
        self.evidence_buttons = []
        for label, operation in (("Verify", "verify"), ("Hold", "hold"), ("Release hold", "release"), ("Export", "export")):
            button = self._action_button(label, lambda checked=False, op=operation: self._evidence_action(op))
            button.setEnabled(False)
            self.evidence_buttons.append(button)
            actions.addWidget(button)
        layout.addLayout(actions)
        self.evidence_detail = QPlainTextEdit()
        self.evidence_detail.setReadOnly(True)
        self.evidence_detail.setAccessibleName("Evidence provenance, triggers and audit")
        self.evidence_detail.setMaximumBlockCount(1000)
        layout.addWidget(self.evidence_detail, stretch=1)
        return page

    def _refresh_evidence(self, force=False):
        if not force and (time.time() - self.last_evidence_reload < 5 or
                          self.page_stack.currentIndex() != self.page_indices["Evidence"]):
            return
        self.evidence_model.replace(self.evidence_catalog.list())
        self.last_evidence_reload = time.time()

    def _evidence_selected(self, index):
        self.selected_evidence = index.data(Qt.ItemDataRole.UserRole)
        if not isinstance(self.selected_evidence, dict):
            return
        item = self.evidence_catalog.get(self.selected_evidence["evidence_id"])
        preview = json.dumps({"capture": item, "audit": self.evidence_catalog.audit(item["evidence_id"])}, indent=2)
        self.evidence_detail.setPlainText(preview[:100_000])
        for button in self.evidence_buttons:
            button.setEnabled(self.service_client is None and (not self.evidence_task or not self.evidence_task.isRunning()))

    def _evidence_action(self, operation):
        if self.service_client is not None:
            self.evidence_status.setText("Service evidence is listing-only")
            return
        if not self.selected_evidence or (self.evidence_task and self.evidence_task.isRunning()):
            return
        arguments = {"actor": "local-console"}
        if operation in {"hold", "release"}:
            reason = self.evidence_reason.text().strip()
            if not reason:
                self.evidence_status.setText("Enter a reason before changing an investigation hold.")
                return
            arguments.update(reason=reason, enabled=operation == "hold")
            operation = "hold"
        elif operation == "export":
            destination, _ = QFileDialog.getSaveFileName(self, "Export evidence", "capture.zip", "Evidence archive (*.zip)")
            if not destination:
                return
            arguments["destination"] = destination
        self.evidence_task = EvidenceTaskThread(self.evidence_catalog, operation,
                                               self.selected_evidence["evidence_id"], arguments, self)
        self.evidence_task.result_ready.connect(self._evidence_finished)
        self.evidence_task.finished.connect(self._evidence_thread_stopped)
        for button in self.evidence_buttons:
            button.setEnabled(False)
        self.evidence_status.setText("Evidence operation in progress")
        self.evidence_task.start()

    def _evidence_finished(self, result):
        if self._closing:
            return
        value = result.get("result", {})
        successful = result["ok"] and value.get("ok", True)
        self.evidence_status.setText("Evidence operation completed" if successful else
                                     "Evidence operation failed: " + str(result.get("error") or value.get("status", "integrity check failed")))
        self._refresh_evidence(force=True)
        if self.selected_evidence:
            item = self.evidence_catalog.get(self.selected_evidence["evidence_id"])
            self.selected_evidence = item
            self.evidence_detail.setPlainText(json.dumps({"capture": item, "audit": self.evidence_catalog.audit(item["evidence_id"])}, indent=2)[:100_000])

    def _evidence_thread_stopped(self):
        task = self.sender()
        if self.evidence_task is task:
            self.evidence_task = None
        task.deleteLater()
        if not self._closing:
            for button in self.evidence_buttons:
                button.setEnabled(bool(self.selected_evidence))

    def _build_sources_page(self):
        page, layout, heading = self._page("Sources", "Persisted protocol records and native collection evidence.")
        self.source_type = QLineEdit()
        self.source_type.setAccessibleName("Source event type filter")
        self.source_type.setPlaceholderText("Event type, e.g. dns, tls, flow, stats")
        self.source_type.returnPressed.connect(lambda: self._refresh_sources(force=True))
        heading.addWidget(self.source_type)
        self.source_health_label = self._muted_label("No live source health report yet")
        layout.addWidget(self.source_health_label)
        self.source_table = self._table(self.source_model)
        self.source_table.clicked.connect(self._source_selected)
        layout.addWidget(self.source_table, stretch=2)
        self.selected_source = None
        self.source_hold_reason = QLineEdit()
        self.source_hold_reason.setAccessibleName("Native record investigation hold reason")
        self.source_hold_reason.setPlaceholderText("Required reason for a native record hold or release")
        layout.addWidget(self.source_hold_reason)
        row = QHBoxLayout()
        self.source_hold_buttons = []
        for label, enabled in (("Hold native record", True), ("Release native hold", False)):
            button = self._action_button(label, lambda checked=False, value=enabled: self._source_hold(value))
            button.setEnabled(False)
            self.source_hold_buttons.append(button)
            row.addWidget(button)
        layout.addLayout(row)
        self.source_action_status = self._muted_label("")
        layout.addWidget(self.source_action_status)
        self.source_detail = QPlainTextEdit()
        self.source_detail.setAccessibleName("Native source record and normalized fields")
        self.source_detail.setReadOnly(True)
        self.source_detail.setMaximumBlockCount(1000)
        layout.addWidget(self.source_detail, stretch=1)
        return page

    def _refresh_sources(self, force=False):
        now = time.time()
        if not force and now - self.last_source_reload < 5:
            return
        if not force and self.page_stack.currentIndex() != self.page_indices["Sources"]:
            return
        records = self.incidents.source_events(event_type=self.source_type.text().strip().lower() or None,
                                               limit=500, include_native=False)
        self.source_model.replace([row["normalized"] for row in records])
        self.last_source_reload = now

    def _source_selected(self, index):
        row = index.data(Qt.ItemDataRole.UserRole)
        if not isinstance(row, dict):
            return
        self.selected_source = row["event_id"]
        for button in self.source_hold_buttons:
            button.setEnabled(self.service_client is None)
        records = self.incidents.source_events(event_id=row["event_id"], limit=1)
        preview = json.dumps({"records": records, "retention": self.incidents.native_retention_status(row["event_id"])},
                             indent=2, sort_keys=True)
        self.source_detail.setPlainText(preview[:100_000] + (
            "\nPreview truncated; complete native record remains in the security ledger."
            if len(preview) > 100_000 else ""
        ))

    def _source_hold(self, enabled):
        if self.service_client is not None:
            self.source_action_status.setText("Service native holds unavailable in this slice")
            return
        if not self.selected_source:
            return
        try:
            self.incidents.native_hold(self.selected_source, actor="local-console",
                                       reason=self.source_hold_reason.text().strip(), enabled=enabled)
            self.source_action_status.setText("Native record held" if enabled else "Native hold released")
            records = self.incidents.source_events(event_id=self.selected_source, limit=1)
            self.source_detail.setPlainText(json.dumps(
                {"records": records, "retention": self.incidents.native_retention_status(self.selected_source)},
                indent=2, sort_keys=True)[:100_000])
        except (ValueError, sqlite3.Error) as exc:
            self.source_action_status.setText("Native hold change failed: " + str(exc))

    def _incident_action_row(self):
        row = QHBoxLayout()
        investigate = self._action_button("Investigate", self._investigate_selected, primary=True)
        block = self._action_button("Queue block", self._block_selected_incident)
        quarantine = self._action_button("Queue quarantine", self._quarantine_selected_incident, danger=True)
        dismiss = self._action_button("Dismiss", self._dismiss_selected_incident)
        self.incident_action_buttons = getattr(self, "incident_action_buttons", [])
        self.incident_action_buttons.extend((
            ("investigate", investigate),
            ("block", block),
            ("quarantine", quarantine),
            ("dismiss", dismiss),
        ))
        for button in (investigate, block, quarantine, dismiss):
            button.setEnabled(False)
            row.addWidget(button)
        row.addStretch(1)
        return row

    @staticmethod
    def _action_button(text, callback, *, primary=False, danger=False):
        button = QPushButton(text)
        button.setObjectName("primaryAction" if primary else "dangerAction" if danger else "actionButton")
        button.clicked.connect(callback)
        return button

    def _response_mode_changed(self, index):
        mode = self.mode_selector.itemData(index)
        if mode:
            self._set_response_mode(mode)

    def _set_response_mode(self, mode, *, persist=True):
        mode = normalize_response_mode(mode, self.config.get("RESPONSE_MODE", "ids_only"))
        changed = mode != self.response_mode
        self.response_mode = mode
        automatic = response_dispatch(mode) == "enforce"
        for engine in (self.mitigator, self.quarantine):
            if engine is not None:
                engine.auto = automatic
        if persist:
            try:
                save_response_mode(self.config.get("RESPONSE_MODE_LEDGER"), mode)
            except (OSError, TypeError, ValueError) as exc:
                self.log.error("response mode persistence failed: %s: %s", type(exc).__name__, exc)
        for kind, button in getattr(self, "incident_action_buttons", ()):
            if kind == "block":
                button.setText("Block now" if automatic else "Queue block")
            elif kind == "quarantine":
                button.setText("Quarantine now" if automatic else "Queue quarantine")
        self._update_incident_action_buttons()
        if changed and hasattr(self, "audit_log"):
            self._write_alert(f"OPERATING MODE: {RESPONSE_MODE_LABELS[mode]}", "info")
        if hasattr(self, "policy_status"):
            self._refresh_enforcement()

    def _update_incident_action_buttons(self):
        row = self.selected_incident
        target_available = bool(row and row.get("target") not in {None, "", "system"})
        active = bool(row and row.get("status") not in {"Resolved", "Recovered", "Dismissed"})
        response_enabled = response_dispatch(self.response_mode) != "ignore"
        for kind, button in getattr(self, "incident_action_buttons", ()):
            if kind == "block":
                button.setEnabled(active and target_available and response_enabled and self.mitigator is not None)
            elif kind == "quarantine":
                button.setEnabled(active and target_available and response_enabled and self.quarantine is not None)
            else:
                button.setEnabled(active)

    def _incident_selected(self, index):
        row = index.data(Qt.ItemDataRole.UserRole)
        if not isinstance(row, dict):
            return
        self.selected_incident = row
        self.case_assignment.setText(row.get("assignment", ""))
        self.case_note.clear()
        self.case_closure_reason.setText(row.get("closure_reason", ""))
        self._refresh_case_audit(row["incident_id"])
        supporting = self.incidents.detections(row["incident_id"], limit=10)
        preview = json.dumps(supporting, indent=2, sort_keys=True)
        self.case_evidence.setPlainText(preview[:100_000] + (
            "\nPreview truncated; complete records remain in the security ledger."
            if len(preview) > 100_000 else ""
        ))
        detail = row.get("detail", "")
        meta = (
            f"{str(row.get('severity', '')).title()} · {row.get('confidence', '')} confidence · "
            f"{row.get('count', 0)} evidence event(s) · {row.get('status', '')}"
        )
        for title_label, detail_label, meta_label in (
            (self.overview_detail_title, self.overview_detail, self.overview_detail_meta),
            (self.incident_detail_title, self.incident_detail, self.incident_detail_meta),
        ):
            title_label.setText(row.get("title", "Incident"))
            detail_label.setText(detail)
            meta_label.setText(meta)
        self.investigation_focus.setText(f"{row.get('incident_id')} · {row.get('title')} · {row.get('target')}")
        self._update_incident_action_buttons()

    def _investigate_selected(self):
        if self.selected_incident is None:
            return
        self._show_page("Investigate")

    def _show_page(self, label):
        index = self.page_indices.get(label)
        if index is None:
            return
        self.page_stack.setCurrentIndex(index)
        self.nav_buttons[label].setChecked(True)

    def _open_incident_drilldown(self, scope="OPEN INCIDENTS"):
        self.incident_scope.setCurrentText(scope)
        self._refresh_incident_views()
        self._show_page("Incidents")
        self._select_first_incident()
        self.incident_table.setFocus()

    def _open_pending_drilldown(self):
        self._show_page("Enforcement")
        self._refresh_enforcement()
        for widget in (self.pending_list, self.q_pending_list):
            if widget.count():
                widget.setCurrentRow(0)
                widget.setFocus()
                break

    def _open_observed_drilldown(self):
        self.combo_scope.setCurrentText("ALL TRAFFIC")
        self.combo_nodes.setCurrentText("ALL SOURCES")
        self.combo_os.setCurrentText("ALL TTL")
        self.combo_alerts.setCurrentText("ALL EVENTS")
        self.combo_family.setCurrentText("ALL IP")
        self.combo_observation.setCurrentText("ALL CAPTURED")
        self._show_page("Traffic")
        self.traffic_table.setFocus()

    def _incident_scope_changed(self, scope):
        rows = filter_incident_rows(self.incidents.snapshot(), scope)
        self.incident_detail_model.replace(rows)
        self._select_first_incident()

    def _select_first_incident(self):
        if self.incident_detail_model.rowCount():
            index = self.incident_detail_model.index(0, 0)
            self.incident_table.setCurrentIndex(index)
            self.incident_table.scrollTo(index)
            self._incident_selected(index)
            return
        self.incident_table.clearSelection()
        self.selected_incident = None
        for title_label, detail_label, meta_label in (
            (self.overview_detail_title, self.overview_detail, self.overview_detail_meta),
            (self.incident_detail_title, self.incident_detail, self.incident_detail_meta),
        ):
            title_label.setText("No matching incident")
            detail_label.setText("No incidents match the selected operational scope.")
            meta_label.setText("")
        self.investigation_focus.setText("No incident selected")
        self._update_incident_action_buttons()

    def _block_selected_incident(self):
        row = self.selected_incident
        if (not row or self.mitigator is None or row.get("target") in {"", "system"}
                or response_dispatch(self.response_mode) == "ignore"):
            return

        def done(decision):
            if decision == "BLOCK":
                self.incidents.set_incident_status(row["incident_id"], "Contained", "Firewall block active")
                self._write_alert(f"MITIGATION: blocked {row['target']} (auto)", "recovered")
            elif decision == "PENDING_APPROVAL":
                self.incidents.set_incident_status(row["incident_id"], "Pending", "Firewall approval pending")
                self._write_alert(f"MITIGATION: pending approval for {row['target']}", "alert")
            self._mit_dirty = True
            self._refresh_incident_views()
            self._refresh_enforcement()

        self._effect(lambda: self.mitigator.request(row["target"], row.get("detail", row["title"])),
                     done, label="incident block request failed")

    def _quarantine_selected_incident(self):
        row = self.selected_incident
        if (not row or self.quarantine is None or row.get("target") in {"", "system"}
                or response_dispatch(self.response_mode) == "ignore"):
            return

        def done(decision):
            if decision == "QUARANTINE":
                self.incidents.set_incident_status(row["incident_id"], "Contained", "LAN quarantine active")
                self._write_alert(f"QUARANTINE: {row['target']} isolated (auto)", "recovered")
            elif decision == "PENDING_APPROVAL":
                self.incidents.set_incident_status(row["incident_id"], "Pending", "Quarantine approval pending")
                self._write_alert(f"QUARANTINE: pending approval for {row['target']}", "critical")
            self._mit_dirty = True
            self._refresh_incident_views()
            self._refresh_enforcement()

        self._effect(lambda: self.quarantine.request(row["target"], row.get("detail", row["title"])),
                     done, label="incident quarantine request failed")

    def _dismiss_selected_incident(self):
        if self.selected_incident is None:
            return
        try:
            self.incidents.set_incident_status(self.selected_incident["incident_id"], "Dismissed", "Dismissed by operator")
        except (ValueError, sqlite3.Error) as exc:
            self._write_alert(f"Case change failed: {exc}", "alert")
            return
        self._refresh_incident_views()

    def _case_call(self, call, done, error):
        """Attached-service case calls do blocking HTTP: run them off the GUI thread, buttons off meanwhile."""
        attached = self.service_client is not None
        if attached:
            self._case_inflight += 1
            for button in self.case_buttons:
                button.setEnabled(False)

        def finish(handler, value):
            if attached:
                self._case_inflight -= 1
                if not self._case_inflight:
                    for button in self.case_buttons:
                        button.setEnabled(True)
            handler(value)

        self._effect(call, lambda result: finish(done, result), lambda exc: finish(error, exc),
                     label="case call", inline=not attached)

    def _refresh_case_audit(self, incident_id):
        self._case_call(lambda: self.incidents.audit(incident_id),
                        lambda entries: self._show_case_audit(incident_id, entries),
                        lambda exc: self._show_case_audit(incident_id, []))

    def _show_case_audit(self, incident_id, entries):
        if self.selected_incident is not None and self.selected_incident.get("incident_id") != incident_id:
            return  # selection moved on while the history was loading
        if self.service_client is not None and not entries and self.service_client.state == "Disconnected / stale":
            self.case_audit.setPlainText("Service unreachable: case history unavailable")
            return
        self.case_audit.setPlainText("\n".join(
            f"{datetime.fromtimestamp(entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S')} "
            f"{entry['actor']} · "
            + ("Detection recorded" if entry["operation"] == "detection" else
               f"{entry['operation'].replace('_', ' ').title()} · "
               + "; ".join(f"{key}: {value}" for key, value in entry["body"].items()))
            for entry in entries[-300:]
        ))

    def _change_selected_case(self, **changes):
        if self.selected_incident is None:
            return
        incident_id = self.selected_incident["incident_id"]

        def done(_result):
            self.case_note.clear()
            self._refresh_incident_views()
            self._refresh_case_audit(incident_id)

        def failed(exc):
            if not isinstance(exc, ValueError | sqlite3.Error):
                self.log.error("case change failed: %s: %s", type(exc).__name__, exc)
            self._write_alert(f"Case change failed: {exc}", "alert")

        self._case_call(lambda: self.incidents.update_case(incident_id, actor="local-console", **changes),
                        done, failed)

    def _acknowledge_case(self):
        status = "Acknowledged" if self.selected_incident and self.selected_incident["status"] == "Open" else None
        self._change_selected_case(acknowledge=True, status=status)

    def _save_case(self):
        self._change_selected_case(assignment=self.case_assignment.text(),
                                   note=self.case_note.text().strip() or None)

    def _resolve_case(self):
        self._change_selected_case(status="Resolved", closure_reason=self.case_closure_reason.text().strip())

    def _set_filter(self, key, value):
        with self.filter_lock:
            self.filter_state[key] = value
        if hasattr(self, "drain_thread"):
            self.drain_thread.refilter()

    def _history_family_changed(self, text):
        if hasattr(self, "history_thread"):
            self.history_thread.set_family(text)

    def _history_page_changed(self, index):
        if not hasattr(self, "history_thread"):
            return
        if index == self.page_indices.get("Overview"):
            self.history_thread.set_mode("overview")
        elif index == self.page_indices.get("Investigate"):
            self.history_thread.set_mode("detail")
        else:
            self.history_thread.set_mode("off")

    def apply_render_batch(self, rows, total_ingested, replace=False):
        if self._closing:
            return
        if replace:
            self.traffic_model.replace(rows)
        else:
            self.traffic_model.prepend(rows)
        self.total_observed += int(total_ingested)
        self.volume_history.append(float(total_ingested))
        self._refresh_kpis()

    def apply_history_snapshot(self, snapshot):
        if self._closing:
            return
        error = snapshot.get("error")
        if error:
            self.history_status.setText("Ledger unavailable")
            self.log.warning("history refresh failed: %s", error)
            return
        values = [float(row.get("events", 0)) for row in snapshot.get("series", ())]
        if values:
            self.overview_chart.set_values(values)
            self.investigation_chart.set_values(values)
        if "talkers" in snapshot:
            self.talker_model.replace(snapshot["talkers"])
        summary = snapshot.get("summary", {})
        family = snapshot.get("family")
        family_text = f"IPv{family}" if family else "All IP"
        self.history_status.setText(
            f"Last 60 minutes · {family_text} · {int(summary.get('events') or 0):,} events · "
            f"{_human_bytes(summary.get('bytes') or 0)}"
        )

    def _effect(self, call, done, error=None, label="", inline=False):
        """Run call() on the single effector thread; done(result) / error(exc) run on the GUI thread."""
        if inline:
            try:
                result = call()
            except Exception as exc:
                self._effect_failed(exc, error, label)
            else:
                done(result)
            return
        self._effects_pending += 1
        self._effects.put((call, done, error, label))
        if self._effect_thread is None:
            self._effect_thread = threading.Thread(target=self._effect_loop, name="ui-effector", daemon=True)
            self._effect_thread.start()

    def _effects_saturated(self):
        """True when alert-driven work should be shed; alert_queue is already lossy upstream."""
        if self._effects_pending < self.EFFECT_BACKLOG_MAX:
            return False
        self._effects_shed += 1
        if self._effects_shed % 100 == 1:
            self.log.warning("effector backlog %d; alert response shed (%d total)",
                             self._effects_pending, self._effects_shed)
        return True

    def _effect_loop(self):
        while True:
            item = self._effects.get()
            if item is None:
                return
            call, done, error, label = item
            try:
                self.effect_done.emit(item, call(), None)
            except Exception as exc:
                self.effect_done.emit(item, None, exc)

    def _effect_failed(self, exc, error, label):
        if error is not None:
            error(exc)
        else:
            self.log.error("%s: %s: %s", label, type(exc).__name__, exc)

    def _effect_finished(self, item, result, exc):
        self._effects_pending -= 1
        if self._closing:
            return
        _call, done, error, label = item
        try:
            if exc is not None:
                self._effect_failed(exc, error, label)
            else:
                done(result)
        except Exception as bad:  # a slot must never raise into Qt
            self.log.error("%s handler failed: %s: %s", label or "effector", type(bad).__name__, bad)

    def _refresh_incident_views(self):
        if self._in_poll:  # one refresh per poll tick, not one per alert
            self._views_dirty = True
            return
        selected_id = self.selected_incident.get("incident_id") if self.selected_incident else None
        rows = self.incidents.snapshot()
        self.incident_model.replace(rows)
        scope = self.incident_scope.currentText() if hasattr(self, "incident_scope") else "OPEN INCIDENTS"
        self.incident_detail_model.replace(filter_incident_rows(rows, scope))
        if selected_id:
            self.selected_incident = next((row for row in rows if row["incident_id"] == selected_id), None)
        self._refresh_kpis()

    def _refresh_assets(self):
        self.asset_model.replace(load_inventory_snapshot(self.config.get("DEVICE_LEDGER", "telemetry_devices.json")))

    def _refresh_kpis(self):
        pending = 0
        active_blocks = 0
        active_quarantines = 0
        if self.mitigator is not None:
            pending += len(self.mitigator.pending)
            active_blocks = len(self.mitigator.active)
        if self.quarantine is not None:
            pending += len(self.quarantine.pending)
            active_quarantines = len(self.quarantine.active)
        self.card_open.set_value(self.incidents.open_count(), "requires triage")
        self.card_critical.set_value(self.incidents.critical_count(), "highest severity")
        self.card_pending.set_value(pending, "operator decisions")
        self.card_observed.set_value(f"{self.total_observed:,}", "since UI start")
        if hasattr(self, "nav_buttons"):
            self.nav_buttons["Incidents"].setText(f"Incidents ({self.incidents.open_count()})")
        self.card_blocks.set_value(active_blocks, "active")
        self.card_quarantines.set_value(active_quarantines, "active")
        self.card_enforcement_pending.set_value(pending, "review")

    def _write_alert(self, message, severity="alert"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        if hasattr(self, "audit_log"):
            self.audit_log.appendPlainText(f"{timestamp}  {severity.upper():9}  {message}")
        archive = self.alert_archive.warning if severity in {"alert", "anomaly", "critical"} else self.alert_archive.info
        archive("%s: %s", severity.upper(), str(message))

    def _record_incident(self, payload, severity=None):
        severity = severity or severity_for(payload.get("action"), payload.get("data"))
        row = None if self.service_client is not None else self.incidents.add(payload, severity=severity)
        if row:
            self._write_alert(row["detail"], severity)
            self._refresh_incident_views()
        return row

    def _set_health_label(self, label, text, healthy):
        label.setText(text)
        label.setObjectName("healthGood" if healthy else "healthBad")
        label.style().unpolish(label)
        label.style().polish(label)

    def _refresh_periodic_ui(self):
        if self._closing:
            return
        if self.service_client is not None:
            from netwatch_ui_state import service_connection_label

            label = service_connection_label(self.service_client)
            self.sensor_health.setText("● SERVICE  " + label)
            self.capture_health.setText("● CAPTURE  See service collection health")
            self.pipeline_health.setText("● RESPONSE  Preview only")
            with self.service_client._lock:
                mode = (self.service_client.data.get("health") or {}).get("response_mode")
            if mode in RESPONSE_MODE_LABELS and mode != self.response_mode:
                index = self.mode_selector.findData(mode)
                self.mode_selector.blockSignals(True)  # display only: never persist the service's mode locally
                self.mode_selector.setCurrentIndex(index)
                self.mode_selector.blockSignals(False)
                self._set_response_mode(mode, persist=False)
            health = self.service_client.source_health("RUNTIME:SERVICE") or {}
            self.source_health_label.setText(label + "\n" + json.dumps(health, sort_keys=True))
            for widget in (self.system_sniffer, self.system_core, self.system_db,
                           self.integrity_capture, self.integrity_core, self.integrity_db):
                widget.setText(label)
            self._refresh_kpis()
            self._refresh_incident_views()
            self._refresh_sources()
            self._refresh_evidence()
            return
        now = time.time()
        sniffer_label = heartbeat_label(self.last_sniffer_heartbeat, now, 8, self.sniffer_status)
        core_label = heartbeat_label(self.last_core_heartbeat, now, 8, self.core_status)
        db_label = heartbeat_label(self.last_db_heartbeat, now, self.db_heartbeat_timeout)
        sniffer_ok = sniffer_label in {"Active", "Idle"}
        core_ok = core_label in {"Active", "Idle"}
        db_ok = db_label == "Active"
        stats_fresh = (self.capture_stats.get("available") is True and
                       eve_freshness_status(self.capture_stats.get("timestamp"), now,
                                            max(10, 2 * float(self.config.get("PCAP_STATS_INTERVAL_SEC", 10)))) == "FRESH")
        capture_label = "Degraded" if self.capture_degraded else "Measured" if sniffer_ok and stats_fresh else "Unverified"
        source_status = "Disabled"
        source_ok = True
        if self.config.get("SURICATA_EVE_ENABLED"):
            source_status = str(self.suricata_health.get("status") or "Awaiting evidence")
            if now - self.last_suricata_heartbeat > max(8, 2 * float(self.config.get("SURICATA_HEARTBEAT_SEC", 5))):
                source_status = "Reader heartbeat stale" if self.last_suricata_heartbeat else "Awaiting evidence"
            elif source_status == "FRESH":
                source_status = eve_freshness_status(
                    self.suricata_health.get("last_stats_time"), now,
                    float(self.config.get("SURICATA_SOURCE_TIMEOUT_SEC", 60)),
                )
            source_ok = source_status == "FRESH"
        self.system_suricata.setText(f"Suricata: {source_status}")
        control_status = "Disabled"
        control = None
        if self.config.get("CONTROL_CAPTURE_ENABLED", True):
            source_key = f"CONTROL:{self.config.get('SENSOR_ID') or 'unknown'}:{self.config.get('NIC_INTERFACE') or 'unknown'}"
            control = self.incidents.source_health(source_key)
            control_status = "Awaiting collector"
            if control:
                fresh = eve_freshness_status(control.get("updated_at"), now,
                                             max(10, 3 * float(self.config.get("CONTROL_HEARTBEAT_SEC", 5))))
                control_status = str(control.get("status")) if fresh == "FRESH" else fresh
            source_ok = source_ok and control_status == "RUNNING"
        policy = (control or {}).get("policy", {})
        arp_status = "Disabled"
        if self.config.get("ARP_DETECTION_ENABLED", True):
            arp = self.incidents.source_health("ANALYSIS:ARP:v1")
            arp_status = "Awaiting analyzer"
            if arp:
                fresh = eve_freshness_status(arp.get("updated_at"), now, 15)
                arp_status = str(arp.get("status")) if fresh == "FRESH" else fresh
            source_ok = source_ok and arp_status == "RUNNING"
        missing_policy = ", ".join(name for name in ("dhcp", "ra", "dhcpv6") if not policy.get(name))
        self.source_health_label.setText(
            f"Suricata: {source_status}; reader health and engine freshness are separate.\n"
            f"ARP replay: {arp_status}.\n"
            f"Passive control: {control_status}; committed {(control or {}).get('accepted', 0)}, "
            f"dropped {(control or {}).get('dropped', 0)}, pending {(control or {}).get('backlog', 0)}. "
            + ("Native retention exceeds its quota target; protected or pending records remain. "
               if (control or {}).get("retention", {}).get("over_quota") else "")
            + (f"Identity policies unconfigured: {missing_policy}." if control and missing_policy else "")
        )
        self._set_health_label(
            self.sensor_health,
            f"● SENSOR  {self.sensor_name if sniffer_ok else 'Offline'}",
            sniffer_ok,
        )
        self._set_health_label(self.capture_health, f"● CAPTURE  {capture_label}", capture_label == "Measured")
        pipeline_ok = sniffer_ok and core_ok and db_ok and source_ok and capture_label == "Measured"
        self._set_health_label(self.pipeline_health, f"● PIPELINE  {'Nominal' if pipeline_ok else 'Degraded'}", pipeline_ok)
        self.system_sniffer.setText(f"Sniffer: {sniffer_label}")
        self.system_core.setText(f"Analytics core: {core_label}")
        self.system_db.setText(f"Database: {db_label}")
        self.integrity_capture.setText(f"Capture    {capture_label}")
        self.integrity_core.setText(f"Analytics  {core_label}")
        self.integrity_db.setText(f"Ledger     {db_label}")
        self._refresh_kpis()
        self._refresh_incident_views()
        self._refresh_sources()
        self._refresh_evidence()
        self._refresh_enforcement()

    def poll_queues(self):
        if self._closing or self.service_client is not None:
            return
        self._in_poll = True
        try:
            self._poll_queues()
        finally:
            self._in_poll = False
            if self._views_dirty:
                self._views_dirty = False
                self._refresh_incident_views()

    def _poll_queues(self):
        for _ in range(self.DRAIN_PER_TICK):
            try:
                payload = self.db_status_queue.get_nowait()
            except queue.Empty:
                break
            if not is_message_payload(payload) or payload["source"] != "DB_WORKER":
                continue
            if payload["action"] == "DB_HEARTBEAT":
                self.last_db_heartbeat = time.time()
                if self.db_fatal_triggered:
                    self.incidents.set_action_status(
                        "DB_HEARTBEAT_STALE", "Recovered", "Database worker heartbeat restored"
                    )
                    self._write_alert("Database worker heartbeat restored", "recovered")
                    self._refresh_incident_views()
                self.db_fatal_triggered = False
            elif payload["action"] == "DB_WRITE_FAILURE":
                self._record_incident(payload, "critical")

        for _ in range(self.DRAIN_PER_TICK):
            try:
                payload = self.worker_status_queue.get_nowait()
            except queue.Empty:
                break
            if not is_message_payload(payload):
                continue
            action = payload["action"]
            if action == "SENSOR_COVERAGE":
                data = payload["data"]
                try:
                    active = max(0, int(data.get("active_sources") or 0))
                    web = max(0, int(data.get("web_sources") or 0))
                    minutes = max(1, round(float(data.get("window_sec") or 900) / 60))
                except (TypeError, ValueError, OverflowError):
                    continue
                topology = str(data.get("topology") or "endpoint").lower()
                assertion = str(data.get("coverage_assertion") or "unverified").lower()
                if topology == "endpoint":
                    assertion = "partial"
                badge = {
                    "partial": "COVERAGE PARTIAL",
                    "complete": "COVERAGE COMPLETE",
                }.get(assertion, "COVERAGE UNVERIFIED")
                self.coverage_status.setText(
                    f"{badge} · {topology} sensor · {active} observed LAN source(s), "
                    f"{web} outbound-web source(s) in {minutes}m"
                )
                continue
            if action in {"EVIDENCE_SAVED", "EVIDENCE_FAILED"}:
                severity = severity_for(action, payload["data"])
                self._write_alert(payload["data"].get("message", action), severity)
                continue
            if action in {"CONTROL_REVIEW", "CONTROL_COLLECTION_GAP"}:
                self._record_incident(payload, severity_for(action, payload["data"]))
                continue
            if action == "CAPTURE_LOSS":
                self.capture_degraded = True
                self.integrity_loss.setText(payload["data"].get("message", "Capture loss detected"))
                self.system_capture.setText("Capture integrity: degraded")
                self._record_incident(payload, "anomaly")
                continue
            if action == "CAPTURE_RECOVERED":
                self.capture_degraded = False
                self.integrity_loss.setText("Packet loss  Recovered")
                self.system_capture.setText("Capture integrity: recovered")
                self.incidents.set_action_status("CAPTURE_LOSS", "Recovered", "Capture integrity recovered")
                self._record_incident(payload, "recovered")
                continue
            if action != "WORKER_HEARTBEAT":
                continue
            if payload["source"] == "SURICATA":
                self.last_suricata_heartbeat = time.time()
                self.suricata_health = dict(payload["data"])
                continue
            if payload["source"] == "IO_WORKER":
                self.sniffer_status = str(payload["data"].get("status") or "UNVERIFIED")
                stats = payload["data"].get("capture_stats")
                self.capture_stats = dict(stats) if isinstance(stats, dict) else {}
                self.last_sniffer_heartbeat = time.time()
                if self.sniffer_fatal_triggered:
                    self.incidents.set_action_status(
                        "SNIFFER_HEARTBEAT_STALE", "Recovered", "Sniffer heartbeat restored"
                    )
                    self._write_alert("Sniffer heartbeat restored", "recovered")
                    self._refresh_incident_views()
                self.sniffer_fatal_triggered = False
                if payload["data"].get("status") == "DEADLOCK_DETECTED":
                    self._record_incident(
                        make_message(
                            "UI_SHELL",
                            "SNIFFER_DEADLOCK",
                            "SYSTEM",
                            {"message": "Sniffer I/O worker stalled"},
                        ),
                        "critical",
                    )
            elif payload["source"] in self.core_heartbeats:
                status = str(payload["data"].get("status") or "UNVERIFIED")
                if payload["source"] == "DOD_CORE":
                    self.core_status = status
                if status != "DEADLOCK_DETECTED":  # a stalled loop (a merge waiting on a dead shard) is not alive
                    self.core_heartbeats[payload["source"]] = time.time()
                beats = self.core_heartbeats.values()
                self.last_core_heartbeat = None if None in beats else min(beats)
                if self.core_fatal_triggered and time.time() - (self.last_core_heartbeat or self.started_at) <= 8:
                    self.incidents.set_action_status(
                        "CORE_HEARTBEAT_STALE", "Recovered", "Analytics core heartbeat restored"
                    )
                    self._write_alert("Analytics core heartbeat restored", "recovered")
                    self._refresh_incident_views()
                    self.core_fatal_triggered = False

        now = time.time()
        if (now - (self.last_db_heartbeat or self.started_at) > self.db_heartbeat_timeout
                and not self.db_fatal_triggered):
            self.db_fatal_triggered = True
            self._record_incident(
                make_message(
                    "UI_SHELL",
                    "DB_HEARTBEAT_STALE",
                    "SYSTEM",
                    {"message": "Database worker heartbeat stale"},
                ),
                "critical",
            )
        if now - (self.last_sniffer_heartbeat or self.started_at) > 8 and not self.sniffer_fatal_triggered:
            self.sniffer_fatal_triggered = True
            self._record_incident(
                make_message(
                    "UI_SHELL",
                    "SNIFFER_HEARTBEAT_STALE",
                    "SYSTEM",
                    {"message": "Sniffer worker heartbeat stale"},
                ),
                "critical",
            )
        if now - (self.last_core_heartbeat or self.started_at) > 8 and not self.core_fatal_triggered:
            self.core_fatal_triggered = True
            self._record_incident(
                make_message(
                    "UI_SHELL",
                    "CORE_HEARTBEAT_STALE",
                    "SYSTEM",
                    {"message": "Analytics core heartbeat stale"},
                ),
                "critical",
            )

        for _ in range(self.ALERTS_PER_TICK):
            try:
                payload = self.alert_queue.get_nowait()
            except queue.Empty:
                break
            if not is_message_payload(payload):
                continue
            if payload["action"] == "SIGNATURE_UPDATE_RECOVERED":
                self.incidents.set_action_status(
                    "SIGNATURE_UPDATE_FAILED",
                    "Recovered",
                    "Threat signatures restored",
                )
            severity = severity_for(payload["action"], payload["data"])
            self._record_incident(payload, severity)
            if payload["action"] == "POLICY_DECISION":
                self.policy_decisions.appendleft(dict(payload["data"]))
            self._handle_mitigation(payload)
            self._handle_quarantine_alert(payload)

        if self.policy_queue is not None:
            for _ in range(self.DRAIN_PER_TICK):
                try:
                    payload = self.policy_queue.get_nowait()
                except queue.Empty:
                    break
                if is_message_payload(payload) and payload["action"] == "POLICY_DECISION":
                    self._handle_policy_decision(payload)

        if self.mitigator is not None or self.quarantine is not None:
            refresh = self._mit_dirty
            if now - self.last_reconcile >= 1 and not self._reconcile_inflight:
                self.last_reconcile = now
                self._reconcile_inflight = True
                self._effect(self._reconcile_work, self._reconcile_done, self._reconcile_failed, "reconcile")
            if refresh:
                self._mit_dirty = False
                self._refresh_incident_views()
                self._refresh_enforcement()

    def _reconcile_work(self):
        out = {"mit": None, "q": None, "current": None}
        if self.mitigator is not None:
            try:
                out["mit"] = list(self.mitigator.reconcile())
            except Exception as exc:
                self.log.error("mitigation reconcile failed: %s: %s", type(exc).__name__, exc)
        if self.quarantine is not None:
            try:
                out["q"] = list(self.quarantine.reconcile())
                # the engine's own thread (TTL expiry, failsafe) releases without telling us
                out["current"] = {row["ip"] for row in self.quarantine.snapshot()}
            except Exception as exc:
                self.log.error("quarantine reconcile failed: %s: %s", type(exc).__name__, exc)
        return out

    def _reconcile_failed(self, exc):
        self._reconcile_inflight = False
        self.log.error("reconcile failed: %s: %s", type(exc).__name__, exc)

    def _reconcile_done(self, out):
        self._reconcile_inflight = False
        for ip in out["mit"] or ():
            self.incidents.set_target_status(ip, "Resolved", "Firewall block expired")
            self._write_alert(f"MITIGATION: lifted expired block {ip}", "info")
        if out["q"] is not None:
            for ip in out["q"]:
                self._q_seen.discard(ip)
                self.incidents.set_target_status(ip, "Resolved", "Quarantine expired")
                self._write_alert(f"QUARANTINE: expired, released {ip}", "info")
            current = out["current"]
            for ip in sorted(self._q_seen - current):
                self.incidents.set_target_status(ip, "Resolved", "Quarantine released by engine")
                self._write_alert(f"QUARANTINE: released {ip} by engine (expiry or failsafe)", "info")
            self._q_seen = current
        self._mit_dirty = False
        self._refresh_incident_views()
        self._refresh_enforcement()

    def _build_mitigator(self):
        if not self.config.get("MITIGATION_ENABLED"):
            return None
        try:
            from netwatch_mitigation import DEFAULT_ALLOWLIST_PREFIXES, Mitigator, WindowsFirewall

            firewall = WindowsFirewall(dry_run=bool(self.config.get("MITIGATION_DRY_RUN", True)))
            protected_v4 = tuple(dict.fromkeys(
                (*DEFAULT_ALLOWLIST_PREFIXES, *self.config.get("LOCAL_PREFIXES", ()))
            ))
            engine = Mitigator(
                effector=firewall,
                auto=response_dispatch(self.response_mode) == "enforce",
                block_ttl_sec=int(self.config.get("MITIGATION_TTL_SEC", 3600)),
                allowlist_prefixes=protected_v4,
                allowlist_ips=self.config.get("ALLOWLIST_IPS") or (),
                allowlist_networks=self.config.get("LOCAL_PREFIXES6", ()),
                ledger_path=self.config.get("BLOCK_LEDGER"),
            )
            engine.reconcile()
            return engine
        except Exception as exc:
            self.log.error("mitigation disabled — init failed: %s: %s", type(exc).__name__, exc)
            return None

    def _build_quarantine(self):
        if not self.config.get("QUARANTINE_ENABLED"):
            return None
        try:
            from netwatch_quarantine import ArpQuarantineEffector, Quarantine

            interface = self.config.get("QUARANTINE_IFACE") or self.config.get("NIC_INTERFACE")
            effector = ArpQuarantineEffector(
                interface,
                sink_mac=self.config.get("QUARANTINE_SINK_MAC") or "02:00:00:00:de:ad",
                dry_run=bool(self.config.get("QUARANTINE_DRY_RUN", True)),
                logger=self.log,
            )
            engine = Quarantine(
                effector,
                gateway_ip=self.config.get("GATEWAY_IP", ""),
                own_ip=detect_own_ipv4(),
                allowlist_ips=self.config.get("ALLOWLIST_IPS") or (),
                auto=response_dispatch(self.response_mode) == "enforce",
                ttl_sec=int(self.config.get("QUARANTINE_TTL_SEC", 1800)),
                max_active=int(self.config.get("QUARANTINE_MAX_ACTIVE", 64)),
                bidirectional=bool(self.config.get("QUARANTINE_BIDIRECTIONAL", True)),
                reassert_sec=float(self.config.get("QUARANTINE_REASSERT_SEC", 2.0)),
                ledger_path=self.config.get("QUARANTINE_LEDGER"),
                logger=self.log,
                shutdown_event=self.shutdown_event,
            )
            if not engine.gateway_ip:
                self.log.error("quarantine disabled — no gateway IP known")
                return None
            engine.start()
            return engine
        except Exception as exc:
            self.log.error("quarantine disabled — init failed: %s: %s", type(exc).__name__, exc)
            return None

    def _handle_mitigation(self, payload):
        dispatch = response_dispatch(self.response_mode)
        if self.mitigator is None or payload["action"] != "ALERT" or dispatch == "ignore":
            return
        target = payload.get("target_id")
        if not isinstance(target, bytes | bytearray):
            return
        import ipaddress

        try:
            ip = str(ipaddress.ip_address(bytes(target)))
        except ValueError as exc:
            self.log.error("mitigation request failed: %s: %s", type(exc).__name__, exc)
            return
        if self._effects_saturated():
            return

        def done(decision):
            if decision == "BLOCK":
                self.incidents.set_target_status(ip, "Contained", "Firewall block active")
                self._write_alert(f"MITIGATION: blocked {ip} (auto)", "recovered")
                self._mit_dirty = True
            elif decision == "PENDING_APPROVAL":
                self.incidents.set_target_status(ip, "Pending", "Firewall approval pending")
                self._write_alert(f"MITIGATION: pending approval for {ip}", "alert")
                self._mit_dirty = True

        self._effect(
            lambda: self.mitigator.request(ip, payload["data"].get("message", "ALERT"), auto=dispatch == "enforce"),
            done, label="mitigation request failed")

    def _handle_policy_decision(self, payload):
        data = payload["data"]
        dispatch = response_dispatch(self.response_mode)
        if data.get("configured_action") != "block" or dispatch == "ignore":
            return
        target = payload.get("target_id")
        if not isinstance(target, bytes | bytearray):
            return
        import ipaddress

        try:
            ip = str(ipaddress.ip_address(bytes(target)))
        except ValueError as exc:
            self.log.error("policy response failed: %s: %s", type(exc).__name__, exc)
            return
        reason = data.get("message", "Policy block")
        lateral = data.get("direction") == "lateral"
        engine = self.quarantine if lateral else self.mitigator
        if engine is None:
            return
        response_kind = "quarantine" if lateral else "firewall block"

        def done(result):
            if dispatch == "enforce":
                if result:
                    dry_run = bool(getattr(engine.effector, "dry_run", False))
                    status = "Simulated" if dry_run else ("Quarantined" if lateral else "Contained")
                    response = f"Policy {response_kind} simulated" if dry_run else f"Policy {response_kind} active"
                    self.incidents.set_target_status(ip, status, response)
                    verb = "simulated" if dry_run else "enforced"
                    self._write_alert(f"POLICY: {verb} block for {ip}", "recovered")
                    self._mit_dirty = True
            elif result == "PENDING_APPROVAL":
                self.incidents.set_target_status(ip, "Pending", f"Policy {response_kind} approval pending")
                self._write_alert(f"POLICY: pending block approval for {ip}", "alert")
                self._mit_dirty = True

        call = (lambda: engine.enforce(ip, reason)) if dispatch == "enforce" \
            else (lambda: engine.request(ip, reason, auto=False))
        self._effect(call, done, label="policy response failed")

    def _handle_quarantine_alert(self, payload):
        dispatch = response_dispatch(self.response_mode)
        if (self.quarantine is None or not self.config.get("QUARANTINE_ON_ARP_ANOMALY", True)
                or dispatch == "ignore"):
            return
        if payload["action"] != "ARP_ANOMALY":
            return
        data = payload["data"]
        # offender_ip is the contested (victim) address; quarantine the offender's own IP.
        owned = data.get("offender_owned_ips") or []
        if len(owned) != 1:
            self._write_alert(f"QUARANTINE: no single attributable IP for {data.get('offender_mac')}; nothing queued", "alert")
            return
        ip = owned[0]
        if self._effects_saturated():
            return

        def done(decision):
            if decision == "PENDING_APPROVAL":
                self.incidents.set_target_status(ip, "Pending", "Quarantine approval pending")
                self._write_alert(f"QUARANTINE: pending approval for {ip}", "critical")
                self._mit_dirty = True

        # the engine resolves the offender's MAC over ARP, which blocks: keep it off the GUI thread
        self._effect(
            lambda: self.quarantine.request(ip, data.get("message", "ARP anomaly"),
                                            mac=data.get("offender_mac"), auto=False),
            done, label="quarantine request failed")

    @staticmethod
    def _fmt_remaining(seconds):
        seconds = int(max(0, seconds))
        if seconds >= 3600:
            return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"
        if seconds >= 60:
            return f"{seconds // 60}m{seconds % 60:02d}s"
        return f"{seconds}s"

    @staticmethod
    def _selected_ip(widget):
        item = widget.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item is not None else None

    def _repopulate_list(self, widget, rows):
        previous = self._selected_ip(widget)
        widget.clear()
        for ip, text in rows:
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, ip)
            widget.addItem(item)
            if ip == previous:
                widget.setCurrentItem(item)

    def _refresh_enforcement(self):
        self._refresh_kpis()
        policy_enabled = bool(self.config.get("POLICY_ENABLED", True))
        policy_mode = str(self.config.get("POLICY_MODE", "monitor")).upper()
        dispatch = response_dispatch(self.response_mode)
        runtime = RESPONSE_MODE_LABELS[self.response_mode]
        self.policy_status.setText(
            f"{'ACTIVE' if policy_enabled else 'DISABLED'} · {policy_mode} DISPATCH · {runtime} · "
            f"{len(self.policy_decisions)} recent decision(s)"
        )
        self.policy_list.clear()
        for row in self.policy_decisions:
            self.policy_list.addItem(
                f"{str(row.get('configured_action', '')).upper():5}  {row.get('rule_id', 'default')}  "
                f"{row.get('direction', 'any')}  {row.get('protocol', '')}/{row.get('destination_port', 0)}"
            )
        if self.mitigator is None:
            self.mit_status.setText("Disabled · set MITIGATION_ENABLED to enable firewall response")
            for button in (self.btn_approve, self.btn_deny, self.btn_approve_all, self.btn_unblock):
                button.setEnabled(False)
            self.pending_list.clear()
            self.active_list.clear()
        else:
            self.btn_approve.setEnabled(dispatch != "ignore")
            self.btn_approve_all.setEnabled(dispatch != "ignore")
            self.btn_deny.setEnabled(True)
            self.btn_unblock.setEnabled(True)
            mode = {"ignore": "STANDBY", "queue": "READY", "enforce": "AUTO"}[dispatch]
            run = "DRY RUN" if getattr(self.mitigator.effector, "dry_run", False) else "LIVE"
            self.mit_status.setText(f"{mode} · {run} · watcher initialized · reversible Windows Firewall controls")
            now = time.time()
            self._repopulate_list(self.pending_list, [
                (ip, f"{ip}   {str(meta.get('reason', ''))[:70]}")
                for ip, meta in sorted(self.mitigator.pending.items())
            ])
            self._repopulate_list(self.active_list, [
                (ip, f"{ip}   {self._fmt_remaining(meta.get('expires_ts', now) - now)}   {str(meta.get('reason', ''))[:48]}")
                for ip, meta in sorted(self.mitigator.active.items())
            ])
        if self.quarantine is None:
            self.q_status.setText("Disabled · set QUARANTINE_ENABLED to enable LAN isolation")
            for button in (self.btn_q_approve, self.btn_q_deny, self.btn_q_release):
                button.setEnabled(False)
            self.q_pending_list.clear()
            self.q_active_list.clear()
        else:
            self.btn_q_approve.setEnabled(dispatch != "ignore")
            self.btn_q_deny.setEnabled(True)
            self.btn_q_release.setEnabled(True)
            mode = {"ignore": "STANDBY", "queue": "READY", "enforce": "AUTO"}[dispatch]
            run = "DRY RUN" if getattr(self.quarantine.effector, "dry_run", False) else "LIVE"
            self.q_status.setText(f"{mode} · {run} · watcher initialized · corrective release on expiry")
            self._repopulate_list(self.q_pending_list, [
                (ip, f"{ip}   {str(meta.get('reason', ''))[:70]}")
                for ip, meta in sorted(self.quarantine.pending.items())
            ])
            self._repopulate_list(self.q_active_list, [
                (row["ip"], f"{row['ip']}   {self._fmt_remaining(row['remaining'])}   {str(row['reason'])[:48]}")
                for row in self.quarantine.snapshot(time.time())
            ])

    def _approve_selected(self):
        if response_dispatch(self.response_mode) == "ignore":
            return
        ip = self._selected_ip(self.pending_list)
        if not (ip and self.mitigator):
            return

        def done(approved):
            if approved:
                self.incidents.set_target_status(ip, "Contained", "Firewall block active")
                self._write_alert(f"MITIGATION: approved block {ip}", "recovered")
                self._refresh_incident_views()
                self._refresh_enforcement()

        self._effect(lambda: self.mitigator.approve(ip), done, label="approve block failed")

    def _deny_selected(self):
        ip = self._selected_ip(self.pending_list)
        if not (ip and self.mitigator):
            return

        def done(denied):
            if denied:
                self.incidents.set_target_status(ip, "Dismissed", "Block denied by operator")
                self._write_alert(f"MITIGATION: denied block {ip}", "info")
                self._refresh_incident_views()
                self._refresh_enforcement()

        self._effect(lambda: self.mitigator.deny(ip), done, label="deny block failed")

    def _approve_all(self):
        if self.mitigator is None or response_dispatch(self.response_mode) == "ignore":
            return

        def work():
            return [ip for ip in list(self.mitigator.pending) if self.mitigator.approve(ip)]

        def done(approved):
            for ip in approved:
                self.incidents.set_target_status(ip, "Contained", "Firewall block active")
            if approved:
                self._write_alert(f"MITIGATION: approved {len(approved)} pending block(s)", "recovered")
                self._refresh_incident_views()
                self._refresh_enforcement()

        self._effect(work, done, label="approve all failed")

    def _unblock_selected(self):
        ip = self._selected_ip(self.active_list)
        if not (ip and self.mitigator):
            return

        def done(lifted):
            if lifted:
                self.incidents.set_target_status(ip, "Resolved", "Firewall block lifted")
                self._write_alert(f"MITIGATION: unblocked {ip}", "info")
                self._refresh_incident_views()
                self._refresh_enforcement()

        def failed(exc):
            if not isinstance(exc, FirewallError):
                raise exc
            # entry stays in the ledger so the operator can retry
            self._write_alert(f"MITIGATION: unblock of {ip} failed, block kept: {exc}", "alert")

        self._effect(lambda: self.mitigator.unblock(ip), done, failed)

    def _q_approve_selected(self):
        if response_dispatch(self.response_mode) == "ignore":
            return
        ip = self._selected_ip(self.q_pending_list)
        if not (ip and self.quarantine):
            return

        def done(approved):
            if approved:
                self.incidents.set_target_status(ip, "Contained", "LAN quarantine active")
                self._write_alert(f"QUARANTINE: isolated {ip}", "recovered")
                self._refresh_incident_views()
                self._refresh_enforcement()

        self._effect(lambda: self.quarantine.approve(ip), done, label="quarantine approve failed")

    def _q_deny_selected(self):
        ip = self._selected_ip(self.q_pending_list)
        if not (ip and self.quarantine):
            return

        def done(denied):
            if denied:
                self.incidents.set_target_status(ip, "Dismissed", "Quarantine denied by operator")
                self._write_alert(f"QUARANTINE: dismissed {ip}", "info")
                self._refresh_incident_views()
                self._refresh_enforcement()

        self._effect(lambda: self.quarantine.deny(ip), done, label="quarantine deny failed")

    def _q_release_selected(self):
        ip = self._selected_ip(self.q_active_list)
        if not (ip and self.quarantine):
            return

        def done(released):
            if released:
                self._q_seen.discard(ip)
                self.incidents.set_target_status(ip, "Resolved", "LAN quarantine released")
                self._write_alert(f"QUARANTINE: released {ip}", "info")
                self._refresh_incident_views()
                self._refresh_enforcement()

        self._effect(lambda: self.quarantine.release(ip), done, label="quarantine release failed")

    def closeEvent(self, event):
        if self._closing:
            super().closeEvent(event)
            return
        self._closing = True
        for timer in (self.poll_timer, self.ui_timer, self.asset_timer):
            timer.stop()
        self.log.info("shutting down")
        if self.shutdown_event is not None and self.shutdown_callback is None:
            self.shutdown_event.set()
        self.drain_thread.stop()
        if not self.drain_thread.wait(3000):
            self.log.warning("render drain thread did not stop in 3 s")
        self.history_thread.stop()
        if not self.history_thread.wait(5000):
            self.log.warning("history thread did not stop in 5 s")
        self._effects.put(None)
        if self.quarantine is not None and not self.quarantine.stop(timeout=3.0):
            self.log.warning("quarantine re-assert thread did not stop in time")
        if self.shutdown_callback is not None:
            try:
                report = self.shutdown_callback()
                if not report.get("ordered_drain"):
                    self.incidents.add(make_message("UI_SHELL", "RUNTIME_COLLECTION_GAP", "SYSTEM", {
                        "message": "Monitoring shutdown could not verify an ordered drain; queued telemetry may be missing",
                        "shutdown": report, "count": None, "severity": "anomaly", "containment_eligible": False,
                    }))
            except Exception as exc:
                self.log.error("ordered worker shutdown failed: %s", exc)
        for process in (() if self.shutdown_callback is not None else self.workers):
            try:
                process.join(timeout=3)
                if process.is_alive():
                    self.log.warning("worker %s did not exit in time; terminating", process.name)
                    process.terminate()
            except Exception as exc:
                self.log.error("worker shutdown failed: %s: %s", type(exc).__name__, exc)
        if self.evidence_task is not None:
            self.evidence_task.wait()
        self.evidence_catalog.close()
        self.incidents.close()
        super().closeEvent(event)
