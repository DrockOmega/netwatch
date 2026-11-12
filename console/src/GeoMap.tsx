import { useEffect, useMemo, useState } from "react";
import { geoMercator, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import type { Topology, GeometryCollection } from "topojson-specification";
import land110 from "world-atlas/land-110m.json";
import { bytes } from "./Traffic";
import { getJson } from "./gateway";

interface Point {
  ip: string;
  lat: number;
  lon: number;
  city: string | null;
  country: string;
  domain: string | null;
  bytes: number;
  events: number;
  dir: "in" | "out";
  noise: boolean;
  flags: string[];
}

const W = 960;
const H = 560;
const projection = geoMercator().scale(152).translate([W / 2, H / 2 + 90]).clipExtent([[0, 0], [W, H]]);
const path = geoPath(projection);
const topo = land110 as unknown as Topology<{ land: GeometryCollection }>;
const LAND = path(feature(topo, topo.objects.land)) ?? "";

export function GeoMap({ node, window }: { node: string; window: number }) {
  const [points, setPoints] = useState<Point[]>([]);
  const [note, setNote] = useState<string | null>(null);
  const [all, setAll] = useState(false);
  const [hot, setHot] = useState<string | null>(null);

  useEffect(() => {
    if (!node) return;
    let live = true;
    const load = () =>
      getJson<{ points: Point[]; note?: string }>(`/api/geo?node=${encodeURIComponent(node)}&window=${window}`)
        .then((d) => live && (setPoints(d.points), setNote(d.note ?? null)))
        .catch(() => live && setNote("The sensor could not answer."));
    load();
    const timer = setInterval(load, 60000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [node, window]);

  const shown = useMemo(() => {
    const keep = points.filter((p) => all || !p.noise);
    const max = Math.max(1, ...keep.map((p) => p.bytes));
    // Flagged last so their rings sit on top.
    return keep
      .map((p) => ({ p, xy: projection([p.lon, p.lat]), r: 2 + 8 * Math.sqrt(p.bytes / max) }))
      .filter((d) => d.xy)
      .sort((a, b) => a.p.flags.length - b.p.flags.length || b.r - a.r);
  }, [points, all]);

  const hover = shown.find((d) => d.p.ip === hot);
  // Nearest point within 10 map units of its edge: the native SVG <title> never shows in the Tauri webview.
  const track = (e: React.MouseEvent<SVGSVGElement>) => {
    const box = e.currentTarget.getBoundingClientRect();
    const x = ((e.clientX - box.left) * W) / box.width;
    const y = ((e.clientY - box.top) * H) / box.height;
    let best: string | null = null;
    let gap = 10;
    for (const { p, xy, r } of shown) {
      const g = Math.hypot(xy![0] - x, xy![1] - y) - r;
      if (g <= gap) [best, gap] = [p.ip, g];
    }
    setHot(best);
  };

  const counts = { out: shown.filter((d) => d.p.dir === "out").length, in: shown.filter((d) => d.p.dir === "in").length };
  return (
    <div className="panel geomap">
      <div className="toolbar">
        <h2>WAN map</h2>
        <nav className="tabs">
          <button className={all ? "" : "on"} onClick={() => setAll(false)}>Signal</button>
          <button className={all ? "on" : ""} onClick={() => setAll(true)}>All</button>
        </nav>
        <span className="note">
          <span className="dot out" /> out {counts.out} <span className="dot in" /> in {counts.in}
          {!all && ` · ${points.length - shown.length} known-benign hidden`}
        </span>
        {note && <span className="note">{note}</span>}
      </div>
      <div className="mapwrap">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Remote endpoints by location" onMouseMove={track} onMouseLeave={() => setHot(null)}>
        <path className="land" d={LAND} />
        <text className="credit" x={W - 6} y={H - 6} textAnchor="end">IP geolocation by DB-IP.com (CC BY 4.0)</text>
        {shown.map(({ p, xy, r }) => (
          <circle key={p.ip} cx={xy![0]} cy={xy![1]} r={r}
            className={`pt ${p.dir}${p.flags.length ? " flagged" : ""}${p.ip === hot ? " hot" : ""}`} />
        ))}
      </svg>
      {hover && (
        <div
          className="tip"
          style={{
            left: `${(hover.xy![0] / W) * 100}%`,
            top: `${(hover.xy![1] / H) * 100}%`,
            transform: `translate(${hover.xy![0] < W * 0.2 ? "0" : hover.xy![0] > W * 0.8 ? "-100%" : "-50%"}, ${
              hover.xy![1] < H * 0.3 ? `${hover.r + 8}px` : `calc(-100% - ${hover.r + 8}px)`})`,
          }}
        >
          <b>{hover.p.ip}</b>
          {hover.p.domain && <div>{hover.p.domain}</div>}
          <div>{hover.p.city ? `${hover.p.city}, ` : ""}{hover.p.country}</div>
          <div>{hover.p.dir === "in" ? "inbound" : "outbound"} · {bytes(hover.p.bytes)} · {hover.p.events} events</div>
          {hover.p.flags.length > 0 && <div className="flag">flagged: {hover.p.flags.join(", ")}</div>}
          {hover.p.noise && <div className="muted">known-benign</div>}
        </div>
      )}
      </div>
    </div>
  );
}
