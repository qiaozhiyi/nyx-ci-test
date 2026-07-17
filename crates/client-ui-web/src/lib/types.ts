/**
 * Wire types — mirror nyx_rest (crates/rest/src/lib.rs) exactly.
 * Single source of truth for the shapes the team server emits.
 * DO NOT drift from the Rust definitions.
 */

export interface SessionView {
  id: string;          // hex 32B pubkey
  beacon_id: number;
  hostname: string;
  username: string;
  os: string;
  arch: number;        // 0=x64, 1=arm64, 2=x86
  pid: number;
  is_admin: number;    // 0/1
  pending: number;
  age_secs: number;
  ja3?: string;
  ja4?: string;
  stale: boolean;
}

export interface TaskAck {
  task_id: number;
  chan?: number;
}

export interface ResultView {
  task_id: number;
  kind: string;        // output|ok|error|file|bof|channel|image
  text: string;
  data_hex?: string;
  seq?: number;
  eof?: number;
}

export interface TaskView {
  task_id: number;
  command: string;
}

export function archName(a: number): string {
  return a === 0 ? 'x64' : a === 1 ? 'arm64' : a === 2 ? 'x86' : '?';
}

/**
 * JsonCommand — the server's tagged enum (`#[serde(tag="type", rename_all="lowercase")]`).
 * Frontend constructs these; `send_command` forwards verbatim to POST /api/task.
 * Only the 6 MVP commands are typed here; others can be added as needed.
 */
export type JsonCommand =
  | { type: 'ping' }
  | { type: 'shell'; args: string }
  | { type: 'exit' }
  | { type: 'sleep'; seconds: number; jitter_pct: number }
  | { type: 'download'; path: string }
  | { type: 'fileop'; op: 'ls' | 'cd' | 'mkdir' | 'rm' | 'mv' | 'cp'; path: string; dest?: string };

/** OS classification for icon rendering in the topology view. */
export type OsKind =
  | 'windows' | 'win-server'
  | 'ubuntu' | 'debian' | 'fedora' | 'kali' | 'alpine' | 'arch' | 'rhel'
  | 'macos' | 'unknown';

/** Map the server's `os` string (from SessionView) to an OsKind for icon rendering. */
export function classifyOs(osStr: string): OsKind {
  const s = osStr.toLowerCase();
  if (s.includes('windows server') || s.includes('win server')) return 'win-server';
  if (s.includes('windows') || s.includes('win')) return 'windows';
  if (s.includes('ubuntu')) return 'ubuntu';
  if (s.includes('debian')) return 'debian';
  if (s.includes('fedora')) return 'fedora';
  if (s.includes('kali')) return 'kali';
  if (s.includes('alpine')) return 'alpine';
  if (s.includes('arch')) return 'arch';
  if (s.includes('redhat') || s.includes('rhel') || s.includes('red hat')) return 'rhel';
  if (s.includes('macos') || s.includes('mac os') || s.includes('darwin')) return 'macos';
  return 'unknown';
}
