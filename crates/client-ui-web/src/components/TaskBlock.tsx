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
import { useEffect, useMemo } from 'react';
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

  // `file` results are FileChunks (seq/eof) that arrive across multiple drains;
  // aggregate them into one download view instead of a line per chunk.
  const fileChunks = useMemo(() => results.filter((r) => r.kind === 'file'), [results]);

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
          {fileChunks.length > 0 && <FileDownloadView chunks={fileChunks} />}
          {results
            .filter((r) => r.kind !== 'file')
            .map((r, i) => (
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
 * Fully renders: output | bof | ok | error | file | image | channel. `ls`
 * output goes structured via FileTable when it parses into rows (plain <pre>
 * fallback otherwise); `file` chunks aggregate at the TaskBlock level; `image`
 * decodes data_hex into an inline preview; `channel` shows a byte counter.
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
      // FileChunks are aggregated at the TaskBlock level (FileDownloadView);
      // this branch only fires for stray file results with no data_hex.
      return (
        <div className="result result--file mono">
          文件下载中… {result.text}
        </div>
      );
    case 'image':
      // Screenshots arrive as raw bytes hex-encoded in data_hex (BMP from the
      // implant's capture_bmp, possibly PNG from other sources). Decode into a
      // base64 data URL and render an inline preview.
      return <ImagePreview result={result} />;
    case 'channel':
      // SOCKS / reverse-portfwd relay: show the byte count carried by this
      // frame (data_hex = hex-encoded bytes) plus the server summary text.
      return <ChannelMonitor result={result} />;
    default:
      // Unknown kind: never silently drop — surface the raw kind so it is visible.
      return (
        <pre className="result result--text mono">
          [{result.kind}] {result.text}
        </pre>
      );
  }
}

/* ----------------------------- image / file / channel ---------------------- */

/** Decode a hex string into bytes (valid hex guaranteed by the server). */
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Base64-encode bytes for a data: URL (WebView-safe, no Buffer dependency). */
function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

/** Image result renderer: decode data_hex into an inline <img> preview. */
function ImagePreview({ result }: { result: ResultView }) {
  const hex = result.data_hex ?? '';
  // Memoize the decode: a 1080p BMP is ~12MB of hex, and hexToBytes +
  // bytesToBase64 are synchronous hundreds-of-ms work. Without this, ANY
  // task-store change (every screenwatch frame) re-decoded every historical
  // screenshot and progressively froze the console.
  const src = useMemo(() => {
    if (hex.length < 2) return null;
    const bytes = hexToBytes(hex);
    // BMP magic "BM" (implant capture_bmp), else assume PNG.
    const mime = bytes.length >= 2 && bytes[0] === 0x42 && bytes[1] === 0x4d ? 'image/bmp' : 'image/png';
    return `data:${mime};base64,${bytesToBase64(bytes)}`;
  }, [hex]);
  if (!src) {
    return <div className="result result--todo mono">[截图] {result.text}</div>;
  }
  return (
    <div className="result result--image">
      <img className="result--image-img" src={src} alt="screenshot" />
      <div className="result--image-meta mono">{result.text}</div>
    </div>
  );
}

/** Channel result renderer: byte counter monitor for SOCKS/rportfwd frames. */
function ChannelMonitor({ result }: { result: ResultView }) {
  const nBytes = result.data_hex ? result.data_hex.length / 2 : 0;
  return (
    <div className="result result--channel mono">
      [通道数据] {result.text}
      {nBytes > 0 && <span className="result--channel-bytes"> · {nBytes} B</span>}
    </div>
  );
}

/**
 * FileChunk aggregator: chunks (seq/eof) arrive across several drains; join
 * them in seq order into one Blob and offer a download link once eof lands.
 * The Blob URL is created lazily (only on completion) and revoked on unmount.
 */
function FileDownloadView({ chunks }: { chunks: ResultView[] }) {
  const done = chunks.some((c) => c.eof === 1);
  const totalBytes = chunks.reduce((n, c) => n + (c.data_hex ? c.data_hex.length / 2 : 0), 0);
  const name = chunks.find((c) => c.text)?.text.replace(/^<chunk\s+/, '').replace(/#\d+>$/, '') ?? 'download';
  // 内存治理可能已剥离部分 chunk 的 data_hex(见 taskStore 的 enforceSessionLimits);
  // 此时拼出的 Blob 是残缺的,不建下载链接,只显示完成信息。
  const stripped = chunks.some((c) => !c.data_hex);

  const blobUrl = useMemo(() => {
    if (!done || stripped) return null;
    const ordered = [...chunks].sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
    const hex = ordered.map((c) => c.data_hex ?? '').join('');
    const bytes = hexToBytes(hex);
    // TS 5.7+ lib types make hexToBytes' Uint8Array<ArrayBufferLike> not
    // assignable to BlobPart; the runtime value is a plain Uint8Array.
    return URL.createObjectURL(new Blob([bytes as BlobPart], { type: 'application/octet-stream' }));
  }, [chunks, done, stripped]);

  // Revoke the object URL when it is replaced or the view unmounts.
  useEffect(() => () => {
    if (blobUrl) URL.revokeObjectURL(blobUrl);
  }, [blobUrl]);

  if (!done) {
    return (
      <div className="result result--file mono">
        文件下载中… {totalBytes.toLocaleString()} B 已接收
      </div>
    );
  }
  return (
    <div className="result result--file mono">
      {blobUrl ? (
        <a className="result--file-link" href={blobUrl} download={name}>
          ⬇ 下载 {name}（{totalBytes.toLocaleString()} B）
        </a>
      ) : (
        `文件接收完成（${totalBytes.toLocaleString()} B）`
      )}
    </div>
  );
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
