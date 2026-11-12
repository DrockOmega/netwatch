import { invoke } from "@tauri-apps/api/core";

const GATEWAY = "http://127.0.0.1:8766";
let token: Promise<string> | null = null;

// A rejected lookup is dropped so the next call retries instead of failing until restart.
function gatewayToken(): Promise<string> {
  token ??= invoke<string>("gateway_token").catch((e) => {
    token = null;
    throw e;
  });
  return token;
}

export type NodeState = "never" | "online" | "stale" | "offline";

export interface NodeView {
  node: string;
  state: NodeState;
  seen_seconds_ago: number | null;
  sensor_id: string | null;
  response_mode: string | null;
  actions_mode: string | null;
  can_restart: boolean;
  gaps: { at: number; reason: string }[];
  instance: string | null;
  open_cases: number;
  feed_error: string | null;
}

export interface CaseRow {
  node: string;
  incident_id: string;
  title: string;
  target: string;
  severity: string;
  status: string;
  confidence: string;
  count: number;
  first_seen: number;
  last_seen: number;
  action: string;
  assignment: string | null;
  acknowledged_by: string | null;
}

export async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(GATEWAY + path, { headers: { Authorization: `Bearer ${await gatewayToken()}` } });
  if (!response.ok) throw new Error(`gateway answered ${response.status}`);
  return response.json() as Promise<T>;
}

export interface Detection {
  event_id: string;
  source: string;
  sensor_id: string;
  received_at: number;
  payload: { action?: string; data?: Record<string, unknown> };
}

export interface AuditRow {
  sequence: number;
  timestamp: number;
  actor: string;
  operation: string;
  body: Record<string, unknown>;
}

export interface CaseDetail {
  node: string;
  case: Record<string, unknown> & CaseRow;
  detections: Detection[];
  history: AuditRow[];
}

export interface WriteResult {
  write: number;
  outcome: "accepted" | "refused" | "unknown";
  reply: unknown;
}

/** One attempt only: an unknown outcome is settled by the feed, never by resending. */
export async function sendWrite(path: "/api/case" | "/api/action" | "/api/response-mode", node: string, body: object): Promise<WriteResult> {
  return post(path, { node, body });
}

export async function restartSensor(node: string, confirm: string): Promise<WriteResult> {
  return post("/api/restart", { node, confirm });
}

async function post(path: string, payload: object): Promise<WriteResult> {
  const response = await fetch(GATEWAY + path, {
    method: "POST",
    headers: { Authorization: `Bearer ${await gatewayToken()}`, "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (response.status === 400 || response.status === 401) throw new Error(`gateway refused the request (${response.status})`);
  return response.json() as Promise<WriteResult>;
}

export interface ResponseAction {
  node: string;
  id: string;
  case_id: string | null;
  kind: "block_ip" | "quarantine_mac";
  target: string;
  scope: string;
  requested_by: string;
  reason: string;
  state: "requested" | "approved" | "denied" | "applied" | "failed" | "released" | "expired";
  requested_at: number;
  decided_at: number | null;
  applied_at: number | null;
  closed_at: number | null;
  expires_at: number;
  readback: string;
}

export const KIND_LABEL: Record<ResponseAction["kind"], string> = {
  block_ip: "Block IP",
  quarantine_mac: "Quarantine device",
};
