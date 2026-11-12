import { useEffect, useState } from "react";
import { CaseRow, sendWrite } from "./gateway";

const STATUSES = ["Open", "Acknowledged", "Pending", "Contained", "Resolved", "Recovered", "Dismissed"];
const NEEDS_REASON = new Set(["Resolved", "Dismissed"]);
const OUTCOME_TEXT = {
  accepted: "Saved on the sensor.",
  refused: "The sensor refused this change.",
  unknown: "No reply from the sensor. It may have applied the change; watch the history before trying again.",
};

function typing(target: EventTarget | null) {
  return target instanceof HTMLElement && ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName);
}

export function Triage({ node, c }: { node: string; c: CaseRow }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [owner, setOwner] = useState(c.assignment ?? "");
  const [closing, setClosing] = useState<string | null>(null);
  const [reason, setReason] = useState("");

  useEffect(() => {
    setOwner(c.assignment ?? "");
    setMessage(null);
    setClosing(null);
  }, [c.incident_id, c.assignment]);

  const send = async (changes: Record<string, unknown>) => {
    setBusy(true);
    try {
      const result = await sendWrite("/api/case", node, { case: c.incident_id, ...changes });
      setMessage(OUTCOME_TEXT[result.outcome]);
      return result.outcome === "accepted";
    } catch (error) {
      setMessage(String(error));
      return false;
    } finally {
      setBusy(false);
    }
  };

  const setStatus = (status: string) => (NEEDS_REASON.has(status) ? setClosing(status) : send({ status }));

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (typing(e.target) || busy || e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key !== "a" && e.key !== "e") return;
      e.preventDefault(); // keep the shortcut letter out of the reason box that opens
      if (e.key === "a" && !c.acknowledged_by) send({ acknowledge: true });
      if (e.key === "e") setClosing("Resolved");
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  return (
    <section className="triage">
      <div className="triage-row">
        <button disabled={busy || !!c.acknowledged_by} onClick={() => send({ acknowledge: true })}>
          {c.acknowledged_by ? "Acknowledged" : "Acknowledge (a)"}
        </button>
        <select value={c.status} disabled={busy} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          {STATUSES.map((status) => (
            <option key={status}>{status}</option>
          ))}
        </select>
        <button disabled={busy} onClick={() => setClosing("Resolved")}>
          Close (e)
        </button>
      </div>
      <div className="triage-row">
        <input value={owner} placeholder="Owner" onChange={(e) => setOwner(e.target.value)} aria-label="Owner" />
        <button disabled={busy || !owner.trim() || owner === c.assignment} onClick={() => send({ assignment: owner.trim() })}>
          Assign
        </button>
      </div>
      <div className="triage-row">
        <input value={note} placeholder="Add a note" onChange={(e) => setNote(e.target.value)} aria-label="Note" />
        <button disabled={busy || !note.trim()} onClick={async () => (await send({ note: note.trim() })) && setNote("")}>
          Add note
        </button>
      </div>
      {closing && (
        <div className="confirm" role="alertdialog" aria-label="Close case">
          <p>
            Close <b>{c.title}</b> on <b>{node}</b> ({c.target}) as{" "}
            <select value={closing} onChange={(e) => setClosing(e.target.value)} aria-label="Closing status">
              {[...NEEDS_REASON].map((status) => (
                <option key={status}>{status}</option>
              ))}
            </select>
          </p>
          <input autoFocus value={reason} placeholder="Reason (required)" onChange={(e) => setReason(e.target.value)} />
          <div className="triage-row">
            <button
              className="primary"
              disabled={busy || !reason.trim()}
              onClick={async () => {
                if (await send({ status: closing, closure_reason: reason.trim() })) {
                  setClosing(null);
                  setReason("");
                }
              }}
            >
              Close case
            </button>
            <button onClick={() => setClosing(null)}>Cancel</button>
          </div>
        </div>
      )}
      {message && <p className="outcome">{message}</p>}
    </section>
  );
}
