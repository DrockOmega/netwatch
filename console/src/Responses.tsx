import { useEffect, useState } from "react";
import { when } from "./CasesTable";
import { KIND_LABEL, ResponseAction, sendWrite } from "./gateway";

type Tab = "pending" | "active" | "history";
const TAB_STATES: Record<Tab, ResponseAction["state"][]> = {
  pending: ["requested"],
  active: ["approved", "applied"],
  history: ["denied", "failed", "released", "expired"],
};
const VERB = { approve: "Approve", deny: "Deny", release: "Release" } as const;
type Verb = keyof typeof VERB;

function remaining(expires: number, now: number) {
  const left = Math.max(0, Math.round(expires - now));
  return `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
}

export function Responses({ actions }: { actions: ResponseAction[] }) {
  const [tab, setTab] = useState<Tab>("pending");
  const [now, setNow] = useState(Date.now() / 1000);
  const [pending, setPending] = useState<{ verb: Verb; action: ResponseAction } | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(timer);
  }, []);

  const rows = actions.filter((a) => TAB_STATES[tab].includes(a.state));
  const count = (t: Tab) => actions.filter((a) => TAB_STATES[t].includes(a.state)).length;
  const verbs: Record<Tab, Verb[]> = { pending: ["approve", "deny"], active: ["release"], history: [] };

  const decide = async () => {
    if (!pending) return;
    setBusy(true);
    try {
      const result = await sendWrite("/api/action", pending.action.node, { op: pending.verb, id: pending.action.id });
      setMessage(
        result.outcome === "accepted"
          ? `${VERB[pending.verb]}d.`
          : result.outcome === "refused"
            ? "The sensor refused this decision."
            : "No reply from the sensor; the list will show whether it took effect.",
      );
      setPending(null);
    } catch (error) {
      setMessage(String(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="responses">
      <div className="toolbar">
        <h1>Responses</h1>
        <nav className="tabs">
          {(["pending", "active", "history"] as Tab[]).map((t) => (
            <button key={t} className={tab === t ? "on" : ""} onClick={() => setTab(t)}>
              {t[0].toUpperCase() + t.slice(1)} ({count(t)})
            </button>
          ))}
        </nav>
        {message && <span className="outcome">{message}</span>}
      </div>
      {pending && (
        <div className="confirm" role="alertdialog" aria-label="Confirm decision">
          <p>
            {VERB[pending.verb]} <b>{KIND_LABEL[pending.action.kind].toLowerCase()}</b> of{" "}
            <b className="mono">{pending.action.target}</b> on <b>{pending.action.node}</b>?
          </p>
          <div className="triage-row">
            <button className={pending.verb === "approve" ? "danger" : "primary"} disabled={busy} onClick={decide}>
              {VERB[pending.verb]}
            </button>
            <button onClick={() => setPending(null)}>Cancel</button>
          </div>
        </div>
      )}
      <div className="action-row grid-head">
        <span>Response</span>
        <span>Target</span>
        <span>Sensor</span>
        <span>State</span>
        <span>Reason</span>
        <span>Requested</span>
        <span>{tab === "active" ? "Expires in" : "Expires"}</span>
        <span />
      </div>
      <div className="grid-body">
        {rows.map((a) => (
          <div key={`${a.node}/${a.id}`} className="action-row">
            <span>{KIND_LABEL[a.kind]}</span>
            <span className="mono">{a.target}</span>
            <span>{a.node}</span>
            <span className={`state state-${a.state}`}>{a.state}</span>
            <span title={a.reason}>{a.reason}</span>
            <span>{when(a.requested_at)}</span>
            <span>{tab === "active" ? remaining(a.expires_at, now) : when(a.expires_at)}</span>
            <span className="actions">
              {/* The lifecycle releases only applied actions; an approved one closes at expiry. */}
              {verbs[tab].filter((verb) => verb !== "release" || a.state === "applied").map((verb) => (
                <button key={verb} onClick={() => setPending({ verb, action: a })}>
                  {VERB[verb]}
                </button>
              ))}
            </span>
          </div>
        ))}
        {!rows.length && <p className="note empty">Nothing here.</p>}
      </div>
    </section>
  );
}
