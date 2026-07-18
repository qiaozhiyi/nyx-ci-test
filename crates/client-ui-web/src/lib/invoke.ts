/**
 * Typed Tauri invoke wrappers. Thin layer over @tauri-apps/api invoke.
 * Also provides typed event listeners for the poll-loop emissions.
 */
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type { SessionView, ResultView, JsonCommand } from './types';

/** Connect to a team server. Throws on auth failure. */
export function connect(server: string, bearer: string): Promise<void> {
  return invoke('connect', { server, bearer });
}

export function disconnect(): Promise<void> {
  return invoke('disconnect');
}

/**
 * Send a command to a session. The frontend builds the JsonCommand;
 * the Rust backend forwards it verbatim to POST /api/task.
 * Returns the assigned task_id.
 */
export function sendCommand(
  session: string,
  command: JsonCommand,
  commandLabel: string,
): Promise<number> {
  return invoke('send_command', { session, command, commandLabel });
}

/** Subscribe to session list updates (emitted by the 2s poll loop). */
export function onSessions(cb: (s: SessionView[]) => void): Promise<UnlistenFn> {
  return listen<SessionView[]>('nyx://sessions', (e) => cb(e.payload));
}

/** Subscribe to individual task results. */
export function onResult(cb: (r: ResultView) => void): Promise<UnlistenFn> {
  return listen<ResultView>('nyx://result', (e) => cb(e.payload));
}

/** Payload of the `nyx://task-submitted` ack (emitted before send_command resolves). */
export interface TaskSubmitted {
  task_id: number;
  session: string;
  chan?: number;
}

/** Subscribe to task-submitted acks (immediate feedback on enqueue). */
export function onTaskSubmitted(cb: (t: TaskSubmitted) => void): Promise<UnlistenFn> {
  return listen<TaskSubmitted>('nyx://task-submitted', (e) => cb(e.payload));
}

/** Subscribe to backend errors (e.g. auth failure, network). */
export function onError(cb: (msg: string) => void): Promise<UnlistenFn> {
  return listen<string>('nyx://error', (e) => cb(e.payload));
}

// ===== Credentials =====

/** CredRecord from server (crates/store/src/model.rs). */
export interface CredRecord {
  realm: string;
  user: string;
  kind: string;       // hash | password | ticket | key
  secret: string;     // "********" unless reveal=true
  source?: string;
  beacon?: string | null;
  collected_at?: number;
  notes?: string;
}

export function listCreds(reveal = false, kind?: string): Promise<CredRecord[]> {
  return invoke('list_creds', { reveal, kind });
}

export function addCred(cred: CredRecord): Promise<unknown> {
  return invoke('add_cred', { cred });
}

export function deleteCred(realm: string, user: string, kind: string): Promise<unknown> {
  return invoke('delete_cred', { realm, user, kind });
}

// ===== Audit =====

export interface AuditRecord {
  seq: number;
  ts: number;
  operator: string;
  action: string;
  target: string;
  detail: unknown;
  prev_hash: string;
  hash: string;
}

export function fetchAudit(params?: Record<string, string | number>): Promise<AuditRecord[]> {
  return invoke('fetch_audit', { params: params ?? {} });
}

export function verifyAudit(): Promise<{ ok: boolean; broken_at: number | null }> {
  return invoke('verify_audit');
}

// ===== Implant =====

export interface GenerateRequest {
  callback: string;
  port?: number;
  format?: string;     // dll | shellcode | exe
  uri?: string;
  sleep?: number;
  jitter?: number;
  tls?: boolean;
  features?: number;
  expires?: string;
  notes?: string;
  deliver?: string;    // "inline" for base64 binary
}

export interface GenerateResponse {
  ok: boolean;
  implant_pub: string;
  sha256: string;
  size_bytes: number;
  format: string;
  message?: string;
  binary?: string;     // base64, only if deliver=inline
}

export interface ImplantSummary {
  id: number;
  implant_pub: string;
  auth_token_used: boolean;
  created_at: string;
  callback_host: string;
  callback_port: number;
  format: string;
  revoked: boolean;
  expires_at?: string | null;
}

export function generateImplant(req: GenerateRequest): Promise<GenerateResponse> {
  return invoke('generate_implant', { req });
}

export function listImplants(): Promise<{ ok: boolean; implants: ImplantSummary[] }> {
  return invoke('list_implants');
}

export function revokeImplant(implantPub: string): Promise<{ ok: boolean; revoked: number }> {
  return invoke('revoke_implant', { implantPub });
}

// ===== Profile =====

export interface ProfileView {
  loaded: boolean;
  http_get_uri?: string | null;
  http_post_uri?: string | null;
  useragent?: string | null;
}

// @deprecated: zero callers, kept for future profile API
export function fetchProfile(): Promise<ProfileView> {
  return invoke('fetch_profile');
}
