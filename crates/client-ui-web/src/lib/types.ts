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
 * All 30 server-side command variants are typed here.
 */
export type JsonCommand =
  // basic
  | { type: 'ping' }
  | { type: 'shell'; args: string }
  | { type: 'exit' }
  | { type: 'sleep'; seconds: number; jitter_pct: number }
  // files
  | { type: 'download'; path: string }
  | { type: 'upload'; name: string; data_hex: string }
  | { type: 'fileop'; op: 'ls' | 'cd' | 'mkdir' | 'rm' | 'mv' | 'cp'; path: string; dest?: string }
  | { type: 'driveinfo' }
  // recon / collection
  | { type: 'screenshot'; monitor: number }
  | { type: 'screenwatch'; interval_secs: number }
  | { type: 'portscan'; host: string; ports: string }
  | { type: 'net'; query: string }
  | { type: 'clipboard' }
  | { type: 'env'; name: string }
  | { type: 'keylog'; action: number }     // 0=start 1=stop 2=dump
  // credentials / tokens
  | { type: 'hashdump'; method: number }   // 0=LSASS 1=shadow
  | { type: 'stealtoken'; pid: number }
  | { type: 'maketoken'; domain: string; user: string; password: string; logon_type: number }
  | { type: 'rev2self' }
  | { type: 'getuid' }
  // execution / injection
  | { type: 'bof'; name: string; args: string[]; data_hex: string }
  | { type: 'inject'; method: number; pid: number; spawn_to: string; sc_hex: string }
  | { type: 'trex' }
  // channels / pivots
  | { type: 'connect'; host: string; port: number }
  | { type: 'socks'; chan: number; op: number; addr: string; port: number }
  | { type: 'channeldata'; chan: number; data_hex: string }
  | { type: 'channelclose'; chan: number }
  | { type: 'setchannel'; channel: number };

/** OS classification for icon rendering in the topology view. */
export type OsKind =
  // Windows family
  | 'windows' | 'win-server' | 'win11' | 'win10' | 'win7' | 'winxp' | 'win95'
  // Linux distributions
  | 'ubuntu' | 'debian' | 'mint' | 'fedora' | 'rhel' | 'centos' | 'rocky' | 'alma'
  | 'opensuse' | 'arch' | 'manjaro' | 'kali' | 'alpine' | 'gentoo' | 'slackware'
  // BSD family
  | 'freebsd' | 'openbsd' | 'netbsd'
  // Other
  | 'macos' | 'reactos' | 'unknown';

/** Map the server's `os` string (from SessionView) to an OsKind for icon rendering. */
export function classifyOs(osStr: string): OsKind {
  const s = osStr.toLowerCase();
  // Windows — check versions before generic windows
  if (s.includes('windows server') || s.includes('win server') || s.includes('server 202')) return 'win-server';
  if (s.includes('windows 11') || s.includes('win11')) return 'win11';
  if (s.includes('windows 10') || s.includes('win10')) return 'win10';
  if (s.includes('windows 7') || s.includes('win7')) return 'win7';
  if (s.includes('windows xp') || s.includes('winxp')) return 'winxp';
  if (s.includes('windows 95') || s.includes('win95')) return 'win95';
  // macOS must precede the generic 'win' fallback — "darwin" contains "win".
  if (s.includes('macos') || s.includes('mac os') || s.includes('darwin')) return 'macos';
  if (s.includes('windows') || s.includes('win')) return 'windows';
  // Linux distributions
  if (s.includes('ubuntu')) return 'ubuntu';
  if (s.includes('linux mint') || s.includes('linuxmint')) return 'mint';
  if (s.includes('debian')) return 'debian';
  if (s.includes('fedora')) return 'fedora';
  if (s.includes('centos')) return 'centos';
  if (s.includes('rocky')) return 'rocky';
  if (s.includes('alma')) return 'alma';
  if (s.includes('opensuse') || s.includes('suse')) return 'opensuse';
  if (s.includes('manjaro')) return 'manjaro';
  if (s.includes('arch')) return 'arch';
  if (s.includes('kali')) return 'kali';
  if (s.includes('alpine')) return 'alpine';
  if (s.includes('gentoo')) return 'gentoo';
  if (s.includes('slackware')) return 'slackware';
  if (s.includes('redhat') || s.includes('rhel') || s.includes('red hat')) return 'rhel';
  // BSD
  if (s.includes('freebsd')) return 'freebsd';
  if (s.includes('openbsd')) return 'openbsd';
  if (s.includes('netbsd')) return 'netbsd';
  // Other
  if (s.includes('reactos')) return 'reactos';
  return 'unknown';
}
