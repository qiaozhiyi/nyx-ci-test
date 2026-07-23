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
import type { JsonCommand, SessionView } from '../lib/types';
import './CommandInput.css';

export interface CommandInputProps {
  session: SessionView;
  onSubmit: (command: JsonCommand, label: string, opsec: boolean) => void;
}

/** Known MVP command names (ls is parsed into a fileop on submit). */
const KNOWN_COMMANDS = [
  'ping', 'shell', 'exit', 'sleep',
  'download', 'upload', 'ls', 'cd', 'mkdir', 'rm', 'cp', 'mv', 'driveinfo',
  'screenshot', 'screenwatch', 'portscan', 'net', 'clipboard', 'env', 'keylog',
  'hashdump', 'stealtoken', 'steal', 'maketoken', 'rev2self', 'getuid',
  'bof', 'connect', 'setchannel', 'trex',
  'inject', 'socks', 'channelclose',
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
  const draftRef = useRef('');
  const inputRef = useRef<HTMLInputElement>(null);

  const tokens = value.trim().split(/\s+/).filter(Boolean);
  const cmdName = tokens.length > 0 ? tokens[0].toLowerCase() : '';
  const known = cmdName === '' || KNOWN_COMMANDS.includes(cmdName as (typeof KNOWN_COMMANDS)[number]);
  const opsec = OPSEC_PATTERNS.test(value);

  function handleSubmit() {
    const trimmed = value.trim();
    if (!trimmed) return;
    const parsed = parseCommand(trimmed);
    if (!parsed) return; // unknown command — refuse to submit, hint already shown
    pushHistory(session.id, trimmed);
    onSubmit(parsed.command, parsed.label, opsec);
    setValue('');
    setHistIdx(null);
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
              输入命令… ping / shell / exit / sleep / download / cd / ls
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

      <div className="cmdinput__hints">
        {!known && (
          <span className="cmdinput__hint cmdinput__hint--err">
            未知命令。常用: ping / shell / sleep / download / ls / cd / net / screenshot …
          </span>
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

/**
 * Parse a raw input line into a JsonCommand + display label.
 * Returns null for unknown / malformed commands (caller shows a hint).
 *
 * Grammar (MVP 6 commands):
 *   ping
 *   shell <args...>          args joined back into one string
 *   exit
 *   sleep <sec> [jitter]
 *   download <path>
 *   cd <path>
 *   ls [path]                 -> emitted as a fileop (see note below)
 *
 * NOTE: types.ts's JsonCommand `fileop` op union is 'cd'|'mkdir'|'rm'|'mv'|'cp'
 * and we are not permitted to edit lib/. A real `ls` op presumably lives on the
 * backend; for MVP we widen via `as` so the wire payload carries op:'ls' to the
 * server verbatim. The integration step / backend can extend the union later.
 */
export function parseCommand(line: string): ParsedCommand | null {
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
        if (Number.isFinite(j)) jitter = j;
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
      return {
        command: { type: 'screenshot', monitor: Number.isFinite(monitor) ? monitor : 0 },
        label: `screenshot ${monitor}`,
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
      if (args.length < 2) return null;
      return {
        command: {
          type: 'maketoken',
          domain: args[0].split('\\')[0] || '',
          user: args[0].includes('\\') ? args[0].split('\\').slice(1).join('\\') : args[0],
          password: args[1],
          logon_type: args.length > 2 ? parseInt(args[2], 10) || 2 : 2,
        },
        label: `maketoken ${args[0]}`,
      };
    }

    case 'rev2self':
      return { command: { type: 'rev2self' }, label: 'rev2self' };

    case 'getuid':
      return { command: { type: 'getuid' }, label: 'getuid' };

    // --- execution ---
    case 'bof': {
      // bof <name> [args...] — data_hex empty (BOF upload via separate flow)
      if (args.length === 0) return null;
      return {
        command: { type: 'bof', name: args[0], args: args.slice(1), data_hex: '' },
        label: `bof ${args[0]}`,
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
      return {
        command: { type: 'connect', host: args[0], port: parseInt(args[1], 10) || 0 },
        label: `connect ${args[0]}:${args[1]}`,
      };
    }

    case 'setchannel': {
      if (args.length === 0) return null;
      const ch = parseInt(args[0], 10);
      if (!Number.isFinite(ch)) return null;
      return { command: { type: 'setchannel', channel: ch }, label: `setchannel ${ch}` };
    }

    case 'trex':
      return { command: { type: 'trex' }, label: 'trex' };

    // --- injection ---
    case 'inject': {
      // inject <method> <pid> <spawn_to> <hex_shellcode>
      // method: 0=pool_party 1=threadless 2=module_stomp
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
      return {
        command: {
          type: 'socks',
          chan: parseInt(args[0], 10) || 0,
          op: parseInt(args[1], 10) || 0,
          addr: args[2],
          port: parseInt(args[3], 10) || 0,
        },
        label: `socks chan=${args[0]} op=${args[1]} ${args[2]}:${args[3]}`,
      };
    }

    case 'channelclose': {
      // channelclose <chan>
      if (args.length === 0) return null;
      const chan = parseInt(args[0], 10);
      if (!Number.isFinite(chan)) return null;
      return { command: { type: 'channelclose', chan }, label: `channelclose ${chan}` };
    }

    // --- file upload (hex data inline; for GUI file-picker upload see upload button) ---
    case 'upload': {
      // upload <name> <hex_data>
      if (args.length < 2) return null;
      const name = args[0];
      const data_hex = args.slice(1).join('');
      return {
        command: { type: 'upload', name, data_hex },
        label: `upload ${name} (${data_hex.length / 2} bytes)`,
      };
    }

    default:
      return null;
  }
}
