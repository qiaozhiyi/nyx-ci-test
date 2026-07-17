/**
 * CommandInput — semantic command entry for the active session.
 *
 * Design (Raijin-inspired): the first token (command name) is recognized and
 * rendered purple; remaining args render white. Unknown commands get a red
 * wavy underline + a hint. A static OPSEC rule warns on lsass-touching intent
 * (mimikatz / lsass) without blocking — MVP only ships 6 commands, so those
 * inputs naturally fall through to the unknown-command path.
 *
 * Implementation: a translucent <input> sits on top of a styled overlay layer
 * that mirrors its text token-by-token. The input holds the value and cursor;
 * the overlay does the coloring. This avoids contentEditable's quirks while
 * still giving per-token color.
 */
import { useState, useRef, type KeyboardEvent, type ChangeEvent } from 'react';
import type { JsonCommand, SessionView } from '../lib/types';
import './CommandInput.css';

export interface CommandInputProps {
  session: SessionView;
  onSubmit: (command: JsonCommand, label: string) => void;
}

/** Known MVP command names (ls is parsed into a fileop on submit). */
const KNOWN_COMMANDS = ['ping', 'shell', 'exit', 'sleep', 'download', 'cd', 'ls'] as const;

/** Static OPSEC trip: lsass-touching tooling. UI warning only, never blocks. */
const OPSEC_PATTERNS = /\b(mimikatz|lsass|procdump.*lsass|sekurlsa)\b/i;

export function CommandInput({ session, onSubmit }: CommandInputProps) {
  const [value, setValue] = useState('');
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
    onSubmit(parsed.command, parsed.label);
    setValue('');
  }

  function handleKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleSubmit();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      setValue('');
    }
  }

  function handleChange(e: ChangeEvent<HTMLInputElement>) {
    setValue(e.target.value);
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
            未知命令，可用: ping/shell/exit/sleep/download/cd/ls
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

    default:
      return null;
  }
}
