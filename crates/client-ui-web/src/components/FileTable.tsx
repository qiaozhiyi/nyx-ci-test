/**
 * FileTable — structured rendering of an `ls` result.
 *
 * Wired into TaskBlock's result renderer: an `ls` task's `output` text is fed
 * through parseLsLines and, when it yields rows, shown here instead of a <pre>.
 * Row actions fire the optional onEnter / onDownload callbacks; the parent
 * (TaskBlock via CommandConsole) turns them into `cd` / `download` commands.
 *
 * Accepts either pre-parsed `entries` or raw `lines` (typically the joined
 * result.text of an `output`-kind result). Raw lines are best-effort parsed:
 * rows ending in `/` or containing `<DIR>` are treated as directories.
 */
import './FileTable.css';

export interface FileEntry {
  name: string;
  size: string;
  isDir: boolean;
  modified: string;
}

export interface FileTableProps {
  /** Pre-parsed entries take precedence over raw lines. */
  entries?: FileEntry[];
  /** Raw text lines from an `ls` output to best-effort parse. */
  lines?: string[];
  /** Row action: enter a directory (name relative to the ls'd path). */
  onEnter?: (dirName: string) => void;
  /** Row action: download a file (name relative to the ls'd path). */
  onDownload?: (fileName: string) => void;
}

export function FileTable({ entries, lines, onEnter, onDownload }: FileTableProps) {
  const rows = entries ?? parseLsLines(lines ?? []);
  if (rows.length === 0) {
    return <div className="filetable filetable--empty mono">(空目录或无输出)</div>;
  }

  // directories first, then files, each alpha (case-insensitive)
  const sorted = [...rows].sort((a, b) => {
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
    return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
  });

  return (
    <div className="filetable">
      <div className="filetable__row filetable__row--head">
        <span className="filetable__name">名称</span>
        <span className="filetable__modified">修改</span>
        <span className="filetable__size">大小</span>
        <span className="filetable__ops" />
      </div>
      {sorted.map((r) => (
        <div key={`${r.isDir ? 'd' : 'f'}:${r.name}`} className="filetable__row">
          <span className="filetable__name mono">
            <span className={`filetable__icon${r.isDir ? ' filetable__icon--dir' : ''}`}>
              {r.isDir ? '▸' : '📄'}
            </span>
            <span className={r.isDir ? 'filetable__dirname' : ''}>{r.name}</span>
          </span>
          <span className="filetable__modified mono">{r.modified}</span>
          <span className="filetable__size mono">{r.isDir ? '—' : r.size}</span>
          <span className="filetable__ops">
            <button
              type="button"
              className="filetable__op mono"
              disabled={r.isDir ? !onEnter : !onDownload}
              onClick={() => (r.isDir ? onEnter?.(r.name) : onDownload?.(r.name))}
            >
              {r.isDir ? '进入' : '下载'}
            </button>
          </span>
        </div>
      ))}
    </div>
  );
}

/**
 * Best-effort parse of raw ls output lines into FileEntry rows.
 * Recognizes the two common textual conventions:
 *   - Unix-style trailing slash:   Documents/
 *   - Windows-style <DIR> marker:  2024-01-02  03:04PM  <DIR>   Documents
 * Anything else is treated as a flat filename.
 */
export function parseLsLines(lines: string[]): FileEntry[] {
  const out: FileEntry[] = [];
  for (const raw of lines) {
    const line = raw.replace(/\r$/, '').trimEnd();
    if (!line) continue;
    // header / total lines from GNU ls
    if (/^(total\s+\d+|总计\s+\d+|Directory of|Volume|Volume in drive)/i.test(line)) continue;

    const dirWin = /<DIR>/i.test(line);
    // Trailing slash is a directory marker — even when the name has spaces.
    const dirSlash = /\/\s*$/.test(line);

    if (dirWin) {
      // e.g. "01/02/2024  03:04 PM    <DIR>   Documents"
      const m = line.match(/^(.*?)\s+(?:[AP]M)?\s*<DIR>\s+(.+)$/i);
      if (m) {
        out.push({ name: m[2].trim(), size: '', isDir: true, modified: m[1].trim() });
        continue;
      }
    }

    if (dirSlash) {
      // strip the '/' marker: names feed path resolution for cd/download
      out.push({ name: line.trim().replace(/\/+$/, ''), size: '', isDir: true, modified: '' });
      continue;
    }

    // try "size date... name" or "date size name" — very loose
    const tok = line.split(/\s+/);
    if (tok.length >= 3 && /^\d+/.test(tok[tok.length - 2] ?? '')) {
      const size = tok[tok.length - 2] ?? '';
      const modified = tok.slice(0, tok.length - 2).join(' ');
      out.push({ name: tok[tok.length - 1] ?? line, size, isDir: false, modified });
      continue;
    }

    out.push({ name: line.trim(), size: '', isDir: false, modified: '' });
  }
  return out;
}
