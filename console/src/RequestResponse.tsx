import { useState } from "react";
import { CaseRow, KIND_LABEL, NodeView, ResponseAction, sendWrite } from "./gateway";

const EXPIRY_MINUTES = [15, 30, 60];
const IP = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]+:[0-9a-f:]*)$/i;

/** Request a response for a case; nothing is enforced until someone approves it. */
export function RequestResponse({ node, c, sensor, onDone }: { node: string; c: CaseRow; sensor?: NodeView; onDone: () => void }) {
  const kinds = Object.keys(KIND_LABEL) as ResponseAction["kind"][];
  const [kind, setKind] = useState<ResponseAction["kind"]>("block_ip");
  const [target, setTarget] = useState(IP.test(c.target) ? c.target : "");
  // Quarantine names the device by MAC; the sensor also needs the victim's IP as its scope.
  const [scope, setScope] = useState(IP.test(c.target) ? c.target : "");
  const [reason, setReason] = useState("");
  const [minutes, setMinutes] = useState(60);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true);
    try {
      const body: Record<string, unknown> = { op: "request", kind, target: target.trim(), reason: reason.trim(), case: c.incident_id };
      if (kind === "quarantine_mac") body.scope = scope.trim();
      if (minutes < 60) body.expires_at = Date.now() / 1000 + minutes * 60;
      const result = await sendWrite("/api/action", node, body);
      if (result.outcome === "accepted") return onDone();
      setMessage(
        result.outcome === "refused"
          ? "The sensor refused this request (protected or invalid target)."
          : "No reply from the sensor. Check the Responses list before asking again.",
      );
    } catch (error) {
      setMessage(String(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="confirm" role="alertdialog" aria-label="Request response">
      <p>
        Request a response on <b>{sensor?.sensor_id ?? node}</b> for <b>{c.title}</b>.
      </p>
      {sensor?.actions_mode === "recording-only" && (
        <p className="note">This sensor records decisions only: approving will not block anything.</p>
      )}
      <div className="triage-row">
        <select value={kind} onChange={(e) => setKind(e.target.value as ResponseAction["kind"])} aria-label="Response">
          {kinds.map((k) => (
            <option key={k} value={k}>
              {KIND_LABEL[k]}
            </option>
          ))}
        </select>
        <input value={target} placeholder={kind === "block_ip" ? "IP address" : "MAC address"} onChange={(e) => setTarget(e.target.value)} aria-label="Target" />
        {kind === "quarantine_mac" && (
          <input value={scope} placeholder="Device IP address" onChange={(e) => setScope(e.target.value)} aria-label="Device IP" />
        )}
      </div>
      <input value={reason} placeholder="Reason (required)" onChange={(e) => setReason(e.target.value)} aria-label="Reason" />
      <div className="triage-row">
        <label className="note">Expires after</label>
        <select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))} aria-label="Expiry">
          {EXPIRY_MINUTES.map((m) => (
            <option key={m} value={m}>
              {m === 60 ? "1 hour" : `${m} minutes`}
            </option>
          ))}
        </select>
      </div>

      <div className="triage-row">
        <button
          className="primary"
          disabled={busy || !target.trim() || !reason.trim() || (kind === "quarantine_mac" && !IP.test(scope.trim()))}
          onClick={submit}
        >
          Request {KIND_LABEL[kind].toLowerCase()} of {target || "…"}
        </button>
        <button onClick={onDone}>Cancel</button>
      </div>
      {message && <p className="outcome">{message}</p>}
    </div>
  );
}
