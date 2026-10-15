import { useEffect, useState } from "react";
import { Severity, when } from "./CasesTable";
import { CaseDetail, getJson, NodeView } from "./gateway";
import { RequestResponse } from "./RequestResponse";
import { Triage } from "./Triage";

function summary(body: Record<string, unknown>) {
  return Object.entries(body)
    .map(([key, value]) => `${key}: ${typeof value === "object" ? JSON.stringify(value) : String(value)}`)
    .join(" · ");
}

export function CaseFlyout({
  node,
  id,
  version,
  sensor,
  onClose,
}: {
  node: string;
  id: string;
  version: number;
  sensor?: NodeView;
  onClose: () => void;
}) {
  const [requesting, setRequesting] = useState(false);
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [tab, setTab] = useState<"detections" | "history">("detections");
  const [open, setOpen] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    setDetail(null);
    setFailed(false);
  }, [node, id]);

  useEffect(() => setRequesting(false), [node, id]);

  useEffect(() => {
    let live = true;
    getJson<CaseDetail>(`/api/case?node=${encodeURIComponent(node)}&id=${encodeURIComponent(id)}`)
      .then((d) => live && (setDetail(d), setFailed(false)))
      .catch(() => live && setFailed(true));
    return () => {
      live = false;
    };
  }, [node, id, version]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const c = detail?.case;
  return (
    <aside className="flyout" role="dialog" aria-label="Case detail">
      <header>
        {c && <Severity level={c.severity} />}
        <h2>{c?.title ?? (failed ? "Case unavailable" : "Loading…")}</h2>
        <button className="close" onClick={onClose} aria-label="Close">
          ×
        </button>
      </header>
      {c && (
        <dl className="facts">
          <dt>Target</dt>
          <dd className="mono">{c.target}</dd>
          <dt>Status</dt>
          <dd>{c.status}</dd>
          <dt>Confidence</dt>
          <dd>{c.confidence}</dd>
          <dt>Hits</dt>
          <dd>{c.count}</dd>
          <dt>First seen</dt>
          <dd>{when(c.first_seen)}</dd>
          <dt>Last seen</dt>
          <dd>{when(c.last_seen)}</dd>
          <dt>Owner</dt>
          <dd>{c.assignment ?? "—"}</dd>
          <dt>Sensor</dt>
          <dd>{node}</dd>
          <dt>Case</dt>
          <dd className="mono">{id}</dd>
        </dl>
      )}
      {c?.detail ? <p className="detail">{String(c.detail)}</p> : null}
      {c && <Triage node={node} c={c} />}
      {c &&
        (requesting ? (
          <RequestResponse node={node} c={c} sensor={sensor} onDone={() => setRequesting(false)} />
        ) : (
          <button className="request" onClick={() => setRequesting(true)}>
            Request response…
          </button>
        ))}
      <nav className="tabs">
        <button className={tab === "detections" ? "on" : ""} onClick={() => setTab("detections")}>
          Detections {detail ? `(${detail.detections.length})` : ""}
        </button>
        <button className={tab === "history" ? "on" : ""} onClick={() => setTab("history")}>
          History {detail ? `(${detail.history.length})` : ""}
        </button>
      </nav>
      <div className="tab-body">
        {tab === "detections" &&
          detail?.detections
            .slice()
            .reverse()
            .map((d) => (
              <div key={d.event_id} className="event" onClick={() => setOpen(open === d.event_id ? null : d.event_id)}>
                <div className="event-line">
                  <span className="time">{when(d.received_at)}</span>
                  <span className="source">{d.source}</span>
                  <span className="text">{String(d.payload.data?.message ?? d.payload.action ?? "")}</span>
                </div>
                {open === d.event_id && <pre>{JSON.stringify(d.payload, null, 2)}</pre>}
              </div>
            ))}
        {tab === "history" &&
          detail?.history
            .slice()
            .reverse()
            .map((h) => (
              <div key={h.sequence} className="event">
                <div className="event-line">
                  <span className="time">{when(h.timestamp)}</span>
                  <span className="source">{h.actor}</span>
                  <span className="text">
                    <b>{h.operation}</b> {summary(h.body)}
                  </span>
                </div>
              </div>
            ))}
      </div>
    </aside>
  );
}
