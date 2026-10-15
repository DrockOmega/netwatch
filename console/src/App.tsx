import { useEffect, useRef, useState } from "react";
import { CaseFlyout } from "./CaseFlyout";
import { CasesTable } from "./CasesTable";
import { CaseRow, getJson, NodeView, ResponseAction } from "./gateway";
import { Responses } from "./Responses";
import { SensorDetail } from "./SensorDetail";
import { TerminalPanel } from "./TerminalPanel";
import { Traffic } from "./Traffic";

const STATE_LABEL = { never: "Never seen", online: "Online", stale: "Stale", offline: "Offline" };
const MODE_LABEL: Record<string, string> = {
  ids_only: "IDS only",
  ready: "IDS + IPS ready",
  autonomous: "IPS autonomous",
};

function NodeTile({ node, selected, onOpen }: { node: NodeView; selected: boolean; onOpen: () => void }) {
  return (
    <article className={`tile state-${node.state} ${selected ? "selected" : ""}`} onClick={onOpen}>
      <header>
        <span className="dot" aria-hidden />
        <h2>{node.sensor_id ?? node.node}</h2>
        <span className="badge">{STATE_LABEL[node.state]}</span>
      </header>
      <dl>
        <dt>Response mode</dt>
        <dd>{node.response_mode ? MODE_LABEL[node.response_mode] ?? node.response_mode : "—"}</dd>
        <dt>Last contact</dt>
        <dd>{node.seen_seconds_ago === null ? "—" : `${Math.round(node.seen_seconds_ago)} s ago`}</dd>
        <dt>Open cases</dt>
        <dd>{node.open_cases.toLocaleString()}</dd>
        <dt>Tunnel</dt>
        <dd>{node.node}</dd>
        {node.feed_error && (
          <>
            <dt>Feed</dt>
            <dd className="bad">{node.feed_error}</dd>
          </>
        )}
      </dl>
    </article>
  );
}

export default function App() {
  const [nodes, setNodes] = useState<NodeView[]>([]);
  const [gatewayError, setGatewayError] = useState<string | null>(null);
  const [cases, setCases] = useState<CaseRow[]>([]);
  const casesVersion = useRef(-1);
  const [version, setVersion] = useState(0);
  const [selected, setSelected] = useState<{ node: string; id: string } | null>(null);
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [view, setView] = useState<"cases" | "responses" | "traffic" | "sensor">("cases");
  const [sensor, setSensor] = useState<string | null>(null);
  const [terminalOpen, setTerminalOpen] = useState(true);

  useEffect(() => {
    const toggle = (event: KeyboardEvent) => {
      if (event.ctrlKey && event.key === "`") {
        event.preventDefault();
        setTerminalOpen((open) => !open);
      }
    };
    window.addEventListener("keydown", toggle, true);
    return () => window.removeEventListener("keydown", toggle, true);
  }, []);

  useEffect(() => {
    let live = true;
    const refresh = () =>
      getJson<{ version: number; nodes: NodeView[] }>("/api/nodes")
        .then(async (body) => {
          if (!live) return;
          setNodes(body.nodes);
          setGatewayError(null);
          if (body.version !== casesVersion.current) {
            const [latest, latestActions] = await Promise.all([
              getJson<{ version: number; cases: CaseRow[] }>("/api/cases"),
              getJson<{ actions: ResponseAction[] }>("/api/actions"),
            ]);
            casesVersion.current = latest.version;
            if (live) {
              setCases(latest.cases);
              setActions(latestActions.actions);
              setVersion(latest.version);
            }
          }
        })
        .catch((error: unknown) => live && setGatewayError(String(error)));
    refresh();
    const timer = setInterval(refresh, 2000); // shortcut: 2 s polling of a loopback gateway; move to server-sent events if it ever costs CPU
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, []);

  return (
    <div className="shell">
      <header className="topbar">
        <span className="brand">NETWATCH</span>
        <span className="subtitle">Command Console</span>
        <nav className="views">
          <button className={view === "cases" ? "on" : ""} onClick={() => setView("cases")}>
            Cases
          </button>
          <button className={view === "responses" ? "on" : ""} onClick={() => setView("responses")}>
            Responses
            {actions.some((a) => a.state === "requested") && (
              <span className="pill">{actions.filter((a) => a.state === "requested").length}</span>
            )}
          </button>
          <button className={view === "traffic" ? "on" : ""} onClick={() => setView("traffic")}>
            Traffic
          </button>
        </nav>
        <nav className="views">
          <button className={terminalOpen ? "on" : ""} onClick={() => setTerminalOpen((open) => !open)} title="Ctrl+`">
            Terminal
          </button>
        </nav>
        <span className={`gateway ${gatewayError ? "down" : "up"}`}>
          Gateway {gatewayError ? "unreachable" : "connected"}
        </span>
      </header>
      <div className="body">
        <aside className="sidebar">
          <h1>Sensors</h1>
          {gatewayError && <p className="error">{gatewayError}</p>}
          {nodes.map((node) => (
            <NodeTile
              key={node.node}
              node={node}
              selected={view === "sensor" && sensor === node.node}
              onOpen={() => {
                setSensor(node.node);
                setView("sensor");
              }}
            />
          ))}
        </aside>
        <main>
          {view === "cases" ? (
            <CasesTable
              cases={cases}
              selected={selected && `${selected.node}/${selected.id}`}
              onSelect={(row) => setSelected({ node: row.node, id: row.incident_id })}
            />
          ) : view === "responses" ? (
            <Responses actions={actions} />
          ) : view === "traffic" ? (
            <Traffic nodes={nodes} />
          ) : (
            sensor && <SensorDetail node={sensor} />
          )}
        </main>
        {view === "cases" && selected && (
          <CaseFlyout
            node={selected.node}
            id={selected.id}
            version={version}
            sensor={nodes.find((n) => n.node === selected.node)}
            onClose={() => setSelected(null)}
          />
        )}
      </div>
      <TerminalPanel open={terminalOpen} />
    </div>
  );
}
