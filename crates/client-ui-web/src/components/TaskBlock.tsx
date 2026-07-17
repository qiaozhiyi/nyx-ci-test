/**
 * TaskBlock — a single command's lifecycle in the console task flow.
 *
 * C2 is an async queue: a command goes queued -> processing -> completed/error
 * as the beacon checks in (every ~30s) and results drain back. This block is
 * the visual unit of that lifecycle, plus the result renderer.
 *
 * Shared with CommandConsole via the exported `TaskEntry` interface.
 * `ls` task results render as a FileTable whose row actions (进入 / 下载)
 * submit follow-up commands through the `onCommand` prop.
 */
import type { JsonCommand, ResultView } from '../lib/types';
import { FileTable, parseLsLines } from './FileTable';
import './TaskBlock.css';

/** Lifecycle of a single submitted command. Shared across console + block. */
export interface TaskEntry {
  /** Server-assigned task id (matches ResultView.task_id). */
  task_id: number;
  /** Human label shown in the header, e.g. "shell whoami" or "sleep 30 10". */
  command_label: string;
  /** Drives the status pill + border color. */
  status: 'queued' | 'processing' | 'completed' | 'error';
  /** Ordered results drained from onResult for this task_id. */
  results: ResultView[];
  /** Session id this task belongs to (for filtering in multi-session views). */
  session: string;
  /** Optional OPSEC tag surfaced when the operator flagged high-risk intent. */
  opsec?: boolean;
}

export interface TaskBlockProps {
  task: TaskEntry;
  /** Submit a follow-up command (FileTable row actions on `ls` results). */
  onCommand?: (command: JsonCommand, label: string) => void;
}

export function TaskBlock({ task, onCommand }: TaskBlockProps) {
  const { task_id, command_label, status, results, opsec } = task;

  return (
    <div className={`taskblock taskblock--${status}`}>
      <div className="taskblock__head">
        <span className="taskblock__id mono">#{task_id}</span>
        <span className="taskblock__cmd mono">{command_label}</span>
        {opsec && <span className="taskblock__opsec">OPSEC</span>}
        <span className="taskblock__status">
          <StatusPill status={status} />
        </span>
      </div>

      {status === 'processing' && (
        <div className="taskblock__async mono">
          命令已下发，进入队列。等待 beacon check-in。
        </div>
      )}

      {results.length > 0 && (
        <div className="taskblock__body">
          {results.map((r, i) => (
            <ResultLine
              key={`${r.task_id}-${i}-${r.seq ?? 0}`}
              result={r}
              commandLabel={command_label}
              onCommand={onCommand}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function StatusPill({ status }: { status: TaskEntry['status'] }) {
  switch (status) {
    case 'queued':
      return <span className="pill pill--queued">⏱ queued</span>;
    case 'processing':
      return <span className="pill pill--processing">● processing</span>;
    case 'completed':
      return <span className="pill pill--completed">✓ done</span>;
    case 'error':
      return <span className="pill pill--error">✕ error</span>;
  }
}

/**
 * Result renderer for the 7 wire `kind` values.
 * Fully renders: output | bof | ok | error | file; `ls` output goes structured
 * via FileTable when it parses into rows (plain <pre> fallback otherwise).
 * TODO (later agents): image -> screenshot preview, channel -> SOCKS/rportfwd monitor.
 */
function ResultLine({
  result,
  commandLabel,
  onCommand,
}: {
  result: ResultView;
  commandLabel: string;
  onCommand?: (command: JsonCommand, label: string) => void;
}) {
  switch (result.kind) {
    case 'output': {
      // Structured path: an `ls` task's output parses into a FileTable.
      if (isLsLabel(commandLabel)) {
        const rows = parseLsLines(result.text.split('\n'));
        if (rows.length > 0) {
          const base = lsBasePath(commandLabel);
          return (
            <FileTable
              entries={rows}
              onEnter={onCommand ? (dir) => {
                const path = resolveLsPath(base, dir);
                onCommand({ type: 'fileop', op: 'cd', path }, `cd ${path}`);
              } : undefined}
              onDownload={onCommand ? (file) => {
                const path = resolveLsPath(base, file);
                onCommand({ type: 'download', path }, `download ${path}`);
              } : undefined}
            />
          );
        }
      }
      return <pre className="result result--text mono">{result.text}</pre>;
    }
    case 'bof':
      return <pre className="result result--text mono">{result.text}</pre>;
    case 'ok':
      return <div className="result result--ok mono">✓ {result.text}</div>;
    case 'error':
      return <pre className="result result--error mono">{result.text}</pre>;
    case 'file':
      // MVP: plain status. TODO: aggregate FileChunk into a download manager.
      return (
        <div className="result result--file mono">
          文件下载中… {result.text}
        </div>
      );
    case 'image':
      // TODO: render base64/data_hex into an <img> preview gallery.
      return <div className="result result--todo mono">[截图] {result.text}</div>;
    case 'channel':
      // TODO: SOCKS / reverse-portfwd channel monitor with byte counters.
      return <div className="result result--todo mono">[通道数据] {result.text}</div>;
    default:
      // Unknown kind: never silently drop — surface the raw kind so it is visible.
      return (
        <pre className="result result--text mono">
          [{result.kind}] {result.text}
        </pre>
      );
  }
}

/* ----------------------------- ls path helpers ----------------------------- */

/** True when the task label is an `ls` invocation ("ls" or "ls <path>"). */
function isLsLabel(label: string): boolean {
  return /^ls(\s|$)/.test(label.trim());
}

/**
 * Directory an `ls` label listed, or null when it listed the implant's cwd
 * ("ls" / "ls .") — relative names then work as-is for cd/download.
 */
function lsBasePath(label: string): string | null {
  const m = label.trim().match(/^ls(?:\s+(.*))?$/);
  if (!m) return null;
  const p = (m[1] ?? '').trim();
  return p === '' || p === '.' ? null : p;
}

/** Join a listed name onto the ls'd directory (Windows- or POSIX-style). */
function resolveLsPath(base: string | null, name: string): string {
  if (!base) return name;
  if (/[\\/]$/.test(base)) return base + name;
  const sep = base.includes('\\') ? '\\' : '/';
  return base + sep + name;
}
