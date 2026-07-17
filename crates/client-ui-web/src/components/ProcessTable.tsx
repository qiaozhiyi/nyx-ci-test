/**
 * ProcessTable — structured rendering of a `ps` result.
 *
 * Standby component (not yet wired into TaskBlock). Columns: PID | 进程名 |
 * 架构 | 会话 | 操作(inject / kill). Once the backend exposes a `ps` op and a
 * structured result, TaskBlock can route a `ps` task's output here via
 * parsePsLines; for MVP it's built and ready.
 *
 * Action buttons (inject / kill) are UI-only stubs: they call the optional
 * onAction callback and rely on the parent to construct the real JsonCommand.
 */
import './ProcessTable.css';

export interface ProcessEntry {
  pid: number;
  name: string;
  arch: string;
  session: string;
}

export interface ProcessTableProps {
  entries?: ProcessEntry[];
  /** Raw text lines from a `ps` output to best-effort parse. */
  lines?: string[];
  /** Fired when inject/kill is clicked; parent decides what to send. */
  onAction?: (action: 'inject' | 'kill', proc: ProcessEntry) => void;
}

export function ProcessTable({ entries, lines, onAction }: ProcessTableProps) {
  const rows = entries ?? parsePsLines(lines ?? []);
  if (rows.length === 0) {
    return <div className="proctable proctable--empty mono">(无进程数据)</div>;
  }

  return (
    <div className="proctable">
      <div className="proctable__row proctable__row--head">
        <span className="proctable__pid">PID</span>
        <span className="proctable__name">进程名</span>
        <span className="proctable__arch">架构</span>
        <span className="proctable__session">会话</span>
        <span className="proctable__ops">操作</span>
      </div>
      {rows.map((p) => (
        <div key={`${p.pid}-${p.name}`} className="proctable__row">
          <span className="proctable__pid mono">{p.pid}</span>
          <span className="proctable__name mono">{p.name}</span>
          <span className="proctable__arch mono">{p.arch}</span>
          <span className="proctable__session mono">{p.session}</span>
          <span className="proctable__ops">
            <button
              type="button"
              className="proctable__btn proctable__btn--inject mono"
              onClick={() => onAction?.('inject', p)}
            >
              inject
            </button>
            <button
              type="button"
              className="proctable__btn proctable__btn--kill mono"
              onClick={() => onAction?.('kill', p)}
            >
              kill
            </button>
          </span>
        </div>
      ))}
    </div>
  );
}

/**
 * Best-effort parse of `ps`-style output. Tolerates a few layouts:
 *   - "PID  NAME       ARCH  SESSION"  header + rows
 *   - Windows tasklist:  "1234  cmd.exe  Console  1"
 *   - GNU ps-ish:        " 1234  cmd.exe    x64   1"
 * Returns rows with safe defaults for any missing column.
 */
export function parsePsLines(lines: string[]): ProcessEntry[] {
  const out: ProcessEntry[] = [];
  let sawHeader = false;
  for (const raw of lines) {
    const line = raw.replace(/\r$/, '').trim();
    if (!line) continue;
    const lower = line.toLowerCase();
    if (!sawHeader && (lower.startsWith('pid') || lower.includes('image name'))) {
      sawHeader = true;
      continue;
    }
    const tok = line.split(/\s+/);
    const pid = parseInt(tok[0] ?? '', 10);
    if (!Number.isFinite(pid)) continue;
    const name = tok[1] ?? '';
    // arch heuristic: x64 / arm64 / x86 / 32 / 64 token
    const archTok = tok.find((t) => /^(x64|x86|arm64|32|64)/i.test(t)) ?? '';
    const arch = archTok === '64' ? 'x64' : archTok === '32' ? 'x86' : archTok;
    const session = tok[tok.length - 1] ?? '';
    out.push({ pid, name, arch, session });
    sawHeader = true;
  }
  return out;
}
