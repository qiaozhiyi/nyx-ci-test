/**
 * TaskBlock — a single command's lifecycle in the console task flow.
 *
 * C2 is an async queue: a command goes queued -> processing -> completed/error
 * as the beacon checks in (every ~30s) and results drain back. This block is
 * the visual unit of that lifecycle, plus the result renderer.
 *
 * Shared with CommandConsole via the exported `TaskEntry` interface.
 */
import type { ResultView } from '../lib/types';
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
}

export function TaskBlock({ task }: TaskBlockProps) {
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
            <ResultLine key={`${r.task_id}-${i}-${r.seq ?? 0}`} result={r} />
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
 * MVP fully renders: output | bof | ok | error | file.
 * TODO (later agents): image -> screenshot preview, channel -> SOCKS/rportfwd monitor.
 */
function ResultLine({ result }: { result: ResultView }) {
  switch (result.kind) {
    case 'output':
    case 'bof':
      return <pre className="result result--text mono">{result.text}</pre>;
    case 'ok':
      return <div className="result result--ok mono">✓ {result.text}</div>;
    case 'error':
      return <pre className="result result--error mono">{result.text}</pre>;
    case 'file':
      // MVP: plain status. TODO: aggregate FileChunk into a download manager
      // (see FileTable.tsx for the structured file list direction).
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
