import { useEffect, useState } from "react";
import { getJson, NodeView } from "./gateway";

interface Row {
  host?: string;
  domain?: string;
  country?: string;
  events: number;
  bytes?: number;
}
interface TrafficData {
  window: number;
  summary: { events: number; sources: number; destinations: number; bytes: number | null; first_ts: number | null; last_ts: number | null };
  sources: Row[];
  destinations: Row[];
  domains: Row[];
  countries: Row[];
  timeline: { bucket: number; events: number; bytes: number }[];
}

const WINDOWS = [
  { label: "15 min", window: 900, bucket: 30 },
  { label: "1 hour", window: 3600, bucket: 60 },
  { label: "6 hours", window: 21600, bucket: 300 },
];

export function bytes(n: number | null | undefined) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
}

function Timeline({ data, window }: { data: TrafficData["timeline"]; window: number }) {
  const max = Math.max(1, ...data.map((d) => d.bytes));
  const end = Date.now() / 1000;
  const start = end - window;
  const W = 1000;
  const H = 160;
  const width = Math.max(1, (W / data.length) * 0.8);
  return (
    <svg className="timeline" viewBox={`0 0 ${W} ${H + 18}`} preserveAspectRatio="none" role="img" aria-label="Bytes over time">
      {data.map((d) => {
        const h = (d.bytes / max) * H;
        return (
          <rect key={d.bucket} x={((d.bucket - start) / window) * W} y={H - h} width={width} height={h}>
            <title>{`${new Date(d.bucket * 1000).toLocaleTimeString()} · ${bytes(d.bytes)} · ${d.events.toLocaleString()} packets`}</title>
          </rect>
        );
      })}
      <text x="0" y={H + 14}>{new Date(start * 1000).toLocaleTimeString()}</text>
      <text x={W} y={H + 14} textAnchor="end">now</text>
      <text x="4" y="12">{bytes(max)} peak</text>
    </svg>
  );
}

function Top({ title, rows, label }: { title: string; rows: Row[]; label: (r: Row) => string }) {
  const max = Math.max(1, ...rows.map((r) => r.bytes ?? r.events));
  return (
    <div className="panel top">
      <h2>{title}</h2>
      {rows.map((r) => (
        <div key={label(r)} className="top-row">
          <span className="mono" title={label(r)}>{label(r)}</span>
          <span className="bar"><span style={{ width: `${((r.bytes ?? r.events) / max) * 100}%` }} /></span>
          <span className="num">{r.bytes !== undefined ? bytes(r.bytes) : r.events.toLocaleString()}</span>
        </div>
      ))}
      {!rows.length && <p className="note">No traffic in this window.</p>}
    </div>
  );
}

export function Traffic({ nodes }: { nodes: NodeView[] }) {
  const [node, setNode] = useState(nodes[0]?.node ?? "");
  const [choice, setChoice] = useState(WINDOWS[1]);
  const [data, setData] = useState<TrafficData | null>(null);
  const [state, setState] = useState<"loading" | "ok" | "error">("loading");

  useEffect(() => {
    if (!node && nodes[0]) setNode(nodes[0].node);
  }, [nodes, node]);

  useEffect(() => {
    if (!node) return;
    let live = true;
    const load = () => {
      setState((s) => (s === "ok" ? s : "loading"));
      getJson<TrafficData>(`/api/traffic?node=${encodeURIComponent(node)}&window=${choice.window}&bucket=${choice.bucket}`)
        .then((d) => live && (setData(d), setState("ok")))
        .catch(() => live && setState("error"));
    };
    setData(null);
    setState("loading");
    load();
    const timer = setInterval(load, Math.max(30000, choice.bucket * 1000));
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [node, choice]);

  const s = data?.summary;
  return (
    <section className="traffic">
      <div className="toolbar">
        <h1>Traffic</h1>
        <select value={node} onChange={(e) => setNode(e.target.value)} aria-label="Sensor">
          {nodes.map((n) => (
            <option key={n.node} value={n.node}>
              {n.sensor_id ?? n.node}
            </option>
          ))}
        </select>
        <nav className="tabs">
          {WINDOWS.map((w) => (
            <button key={w.window} className={choice === w ? "on" : ""} onClick={() => setChoice(w)}>
              {w.label}
            </button>
          ))}
        </nav>
        {state === "loading" && <span className="note">Querying the sensor…</span>}
        {state === "error" && <span className="error">The sensor could not answer.</span>}
      </div>
      {s && (
        <div className="cards">
          <div className="card"><span>Packets</span><b>{s.events.toLocaleString()}</b></div>
          <div className="card"><span>Volume</span><b>{bytes(s.bytes)}</b></div>
          <div className="card"><span>Sources</span><b>{s.sources.toLocaleString()}</b></div>
          <div className="card"><span>Destinations</span><b>{s.destinations.toLocaleString()}</b></div>
        </div>
      )}
      {data && (
        <div className="panel">
          <h2>Volume over time</h2>
          <Timeline data={data.timeline} window={data.window} />
        </div>
      )}
      {data && (
        <div className="tops">
          <Top title="Top sources" rows={data.sources} label={(r) => r.host ?? ""} />
          <Top title="Top destinations" rows={data.destinations} label={(r) => r.host ?? ""} />
          <Top title="Top domains (packets)" rows={data.domains} label={(r) => r.domain ?? ""} />
          <Top title="Top countries" rows={data.countries} label={(r) => r.country ?? ""} />
        </div>
      )}
    </section>
  );
}
