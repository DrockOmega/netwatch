import { useEffect, useState } from "react";
import { when } from "./CasesTable";
import { getJson, NodeView, restartSensor, sendWrite } from "./gateway";

type Health = Record<string, unknown> & { status?: string; updated_at?: number };
interface SensorDetailData {
  node: NodeView;
  health: { service: Health & { workers?: Record<string, string> }; actions?: string };
  "collection-health": Record<string, Health>;
  gaps: { incident_id: string; title: string; detail: string; count: number; last_seen: number; status: string }[];
  connection_gaps: { at: number; reason: string }[];
}

const OK = new Set(["RUNNING", "OK", "ALIVE", "HEALTHY", "FRESH"]);

function facts(row: Health) {
  return Object.entries(row)
    .filter(([key, value]) => key !== "status" && key !== "updated_at" && (typeof value !== "object" || value === null))
    .map(([key, value]) => `${key.replace(/_/g, " ")} ${typeof value === "number" ? value.toLocaleString() : String(value)}`)
    .join(" · ");
}

function ago(epoch: number | undefined, now: number) {
  if (!epoch) return "—";
  const s = Math.max(0, Math.round(now - epoch));
  return s < 120 ? `${s} s ago` : s < 7200 ? `${Math.round(s / 60)} min ago` : s < 172800 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} d ago`;
}

function Restart({ node, name }: { node: string; name: string }) {
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const go = async () => {
    setBusy(true);
    try {
      const result = await restartSensor(node, typed.trim());
      setMessage(
        result.outcome === "accepted"
          ? "Restart sent. The sensor comes back with a new service run within seconds."
          : result.outcome === "refused"
            ? "The restart command failed on the sensor."
            : "No answer from the sensor; watch the tile before trying again.",
      );
      setOpen(false);
      setTyped("");
    } catch (error) {
      setMessage(String(error));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="restart">
      {open ? (
        <div className="confirm" role="alertdialog" aria-label="Restart sensor">
          <p>
            Restart the NetWatch service on <b>{name}</b>? Collection pauses for a few seconds.
          </p>
          <input autoFocus value={typed} placeholder={`Type ${name} to confirm`} onChange={(e) => setTyped(e.target.value)} />
          <div className="triage-row">
            <button className="danger" disabled={busy || typed.trim() !== name} onClick={go}>
              Restart {name}
            </button>
            <button onClick={() => setOpen(false)}>Cancel</button>
          </div>
        </div>
      ) : (
        <button onClick={() => setOpen(true)}>Restart service…</button>
      )}
      {message && <p className="outcome">{message}</p>}
    </div>
  );
}

const MODES = [
  { mode: "ids_only", label: "IDS only", effect: "Detect and record. No response requests are made." },
  { mode: "ready", label: "IDS + IPS ready", effect: "Each alerting address gets a block request that waits for approval." },
  { mode: "autonomous", label: "IPS autonomous", effect: "Each alerting address is blocked at once, without approval." },
];

function ModeSwitch({ node, name, current, recordingOnly }: { node: string; name: string; current: string | null; recordingOnly: boolean }) {
  const [target, setTarget] = useState<string | null>(null);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const chosen = MODES.find((m) => m.mode === target);
  const needsTyped = target === "autonomous";
  const go = async () => {
    setBusy(true);
    try {
      const result = await sendWrite("/api/response-mode", node, { mode: target });
      setMessage(result.outcome === "accepted" ? `${name} is now ${chosen?.label}.` : result.outcome === "refused" ? "The sensor refused the change." : "No answer from the sensor; check the mode before trying again.");
      setTarget(null);
      setTyped("");
    } catch (error) {
      setMessage(String(error));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="mode">
      <div className="segmented" role="radiogroup" aria-label="Response mode">
        {MODES.map((m) => (
          <button key={m.mode} role="radio" aria-checked={current === m.mode} className={current === m.mode ? "on" : ""} disabled={busy} onClick={() => current !== m.mode && setTarget(m.mode)}>
            {m.label}
          </button>
        ))}
      </div>
      {chosen && (
        <div className="confirm" role="alertdialog" aria-label="Change response mode">
          <p>
            Switch <b>{name}</b> to <b>{chosen.label}</b>? {chosen.effect}
            {recordingOnly && " This sensor only records responses, so nothing is enforced on the network."}
          </p>
          {needsTyped && <input autoFocus value={typed} placeholder="Type autonomous to confirm" onChange={(e) => setTyped(e.target.value)} />}
          <div className="triage-row">
            <button className={needsTyped ? "danger" : "primary"} disabled={busy || (needsTyped && typed.trim() !== "autonomous")} onClick={go}>
              Switch to {chosen.label}
            </button>
            <button onClick={() => setTarget(null)}>Cancel</button>
          </div>
        </div>
      )}
      {message && <p className="outcome">{message}</p>}
    </div>
  );
}

export function SensorDetail({ node }: { node: string }) {
  const [data, setData] = useState<SensorDetailData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setData(null);
    setError(null);
    let live = true;
    const load = () =>
      getJson<SensorDetailData>(`/api/sensor?node=${encodeURIComponent(node)}`)
        .then((d) => live && (setData(d), setError(null)))
        .catch(() => live && setError("Sensor unreachable; showing the last reading."));
    load();
    const timer = setInterval(load, 3000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [node]);

  const now = Date.now() / 1000;
  const service = data?.health.service;
  const sources = Object.entries(data?.["collection-health"] ?? {}).sort(([a], [b]) => a.localeCompare(b));
  return (
    <section className="sensor">
      <div className="toolbar">
        <h1>Sensor · {data?.node.sensor_id ?? node}</h1>
        {error && <span className="error">{error}</span>}
      </div>
      {service && (
        <div className="panel">
          <h2>Service</h2>
          <div className="kv">
            <span>Status</span>
            <span className={OK.has(String(service.status)) ? "ok" : "bad"}>{String(service.status)}</span>
            <span>Capture</span>
            <span>{String(service.capture ?? "—")}</span>
            <span>Responses</span>
            <span>{data?.health.actions ?? "—"}</span>
            <span>Mode</span>
            <ModeSwitch
              node={node}
              name={data?.node.sensor_id ?? node}
              current={data?.node.response_mode ?? null}
              recordingOnly={data?.health.actions === "recording-only"}
            />
            <span>Workers</span>
            <span>
              {Object.entries(service.workers ?? {}).map(([name, state]) => (
                <span key={name} className={`chip ${OK.has(state) ? "ok" : "bad"}`}>
                  {name} {state}
                </span>
              ))}
            </span>
            <span>Updated</span>
            <span>{ago(service.updated_at, now)}</span>
          </div>
          {data?.node.can_restart && <Restart node={node} name={data.node.sensor_id ?? node} />}
        </div>
      )}
      <div className="panel grow">
        <h2>Collection health</h2>
        <div className="health-row grid-head">
          <span>Source</span>
          <span>Status</span>
          <span>Updated</span>
          <span>Details</span>
        </div>
        <div className="grid-body">
          {sources.map(([key, row]) => (
            <div key={key} className="health-row">
              <span className="mono" title={key}>{key}</span>
              <span className={OK.has(String(row.status)) ? "ok" : "bad"}>{String(row.status ?? "—")}</span>
              <span>{ago(row.updated_at, now)}</span>
              <span title={facts(row)}>{facts(row)}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="panel">
        <h2>Gaps ({(data?.gaps.length ?? 0) + (data?.connection_gaps.length ?? 0)})</h2>
        {data?.gaps.map((gap) => (
          <div key={gap.incident_id} className="gap-row">
            <span>{when(gap.last_seen)}</span>
            <span>{gap.title}</span>
            <span title={gap.detail}>{gap.detail}</span>
            <span className="num">{gap.count}×</span>
          </div>
        ))}
        {data?.connection_gaps.map((gap) => (
          <div key={gap.at} className="gap-row">
            <span>{when(gap.at)}</span>
            <span>Console connection gap</span>
            <span>{gap.reason}</span>
            <span />
          </div>
        ))}
      </div>
    </section>
  );
}
