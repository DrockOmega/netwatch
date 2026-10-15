import { useEffect, useMemo, useRef, useState } from "react";
import { CaseRow } from "./gateway";

const ROW_HEIGHT = 30;
const CLOSED = new Set(["Resolved", "Recovered", "Dismissed"]);
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function when(epoch: number | null | undefined) {
  return epoch ? new Date(epoch * 1000).toLocaleString(undefined, { dateStyle: "short", timeStyle: "medium" }) : "—";
}

export function Severity({ level }: { level: string }) {
  return <span className={`sev sev-${level}`}>{level}</span>;
}

export function CasesTable({
  cases,
  selected,
  onSelect,
}: {
  cases: CaseRow[];
  selected: string | null;
  onSelect: (row: CaseRow) => void;
}) {
  const [showClosed, setShowClosed] = useState(false);
  const [query, setQuery] = useState("");
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(600);
  const body = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const observer = new ResizeObserver(([entry]) => setHeight(entry.contentRect.height));
    if (body.current) observer.observe(body.current);
    return () => observer.disconnect();
  }, []);

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return cases
      .filter((row) => showClosed || !CLOSED.has(row.status))
      .filter((row) => !needle || `${row.title} ${row.target} ${row.node}`.toLowerCase().includes(needle))
      .sort(
        (a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) || b.last_seen - a.last_seen,
      );
  }, [cases, showClosed, query]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      if (["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName) || (e.key !== "j" && e.key !== "k")) return;
      const at = rows.findIndex((row) => `${row.node}/${row.incident_id}` === selected);
      const next = Math.min(rows.length - 1, Math.max(0, at + (e.key === "j" ? 1 : -1)));
      if (!rows[next]) return;
      onSelect(rows[next]);
      const el = body.current;
      if (el && (next * ROW_HEIGHT < el.scrollTop || (next + 1) * ROW_HEIGHT > el.scrollTop + el.clientHeight)) {
        el.scrollTop = next * ROW_HEIGHT - el.clientHeight / 2;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [rows, selected, onSelect]);

  const first = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - 10);
  const visible = rows.slice(first, first + Math.ceil(height / ROW_HEIGHT) + 20);

  return (
    <section className="cases">
      <div className="toolbar">
        <h1>Cases</h1>
        <span className="count">{rows.length.toLocaleString()} shown</span>
        <input placeholder="Filter title, target, sensor" value={query} onChange={(e) => setQuery(e.target.value)} />
        <label>
          <input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} /> Include closed
        </label>
      </div>
      <div className="grid-head row">
        <span>Severity</span>
        <span>Case</span>
        <span>Target</span>
        <span>Status</span>
        <span className="num">Hits</span>
        <span>Last seen</span>
        <span>Sensor</span>
        <span>Owner</span>
      </div>
      <div
        className="grid-body"
        ref={body}
        onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
      >
        <div style={{ height: rows.length * ROW_HEIGHT, position: "relative" }}>
          {visible.map((row, index) => (
            <div
              key={`${row.node}/${row.incident_id}`}
              className={`row ${selected === `${row.node}/${row.incident_id}` ? "selected" : ""}`}
              onClick={() => onSelect(row)}
              style={{ position: "absolute", top: (first + index) * ROW_HEIGHT, height: ROW_HEIGHT }}
            >
              <span>
                <Severity level={row.severity} />
              </span>
              <span title={row.title}>{row.title}</span>
              <span className="mono">{row.target}</span>
              <span>{row.status}</span>
              <span className="num">{row.count}</span>
              <span>{when(row.last_seen)}</span>
              <span>{row.node}</span>
              <span>{row.assignment ?? "—"}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
