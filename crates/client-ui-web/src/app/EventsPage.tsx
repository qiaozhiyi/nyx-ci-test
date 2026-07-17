/**
 * EventsPage — audit log / event stream panel.
 *
 * Pulls the tamper-evident audit log via fetchAudit() and renders it as a
 * vertical timeline (newest first). The toolbar exposes a manual refresh, a
 * hash-chain verification (verifyAudit), and action/operator filters.
 *
 * Records are not a plain table: each row sits on a left gutter rail with a
 * per-action colored marker, the timestamp anchored on the left, the action
 * badge + operator + target in the middle, and seq/hash on the right.
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import type { AuditRecord } from '../lib/invoke';
import { fetchAudit, verifyAudit } from '../lib/invoke';
import './EventsPage.css';

/** Actions exposed in the filter dropdown. The server may emit others; "all"
 *  is the default and shows everything regardless of label. */
const ACTION_FILTERS = [
  'all',
  'task',
  'cred_add',
  'cred_delete',
  'implant_generated',
  'implant_revoked',
] as const;

type ActionFilter = (typeof ACTION_FILTERS)[number];

/** Badge color class per action. Falls back to a neutral style for unknown. */
function badgeClass(action: string): string {
  switch (action) {
    case 'task': return 'badge-task';
    case 'cred_add': return 'badge-cred_add';
    case 'cred_delete': return 'badge-cred_delete';
    case 'implant_generated': return 'badge-implant_generated';
    case 'implant_revoked': return 'badge-implant_revoked';
    default: return 'badge-task';
  }
}

/** Row marker class — drives the colored dot on the rail. */
function rowClass(action: string): string {
  switch (action) {
    case 'task': return 'is-task';
    case 'cred_add': return 'is-cred_add';
    case 'cred_delete': return 'is-cred_delete';
    case 'implant_generated': return 'is-implant_generated';
    case 'implant_revoked': return 'is-implant_revoked';
    default: return 'is-task';
  }
}

/** A short, human label for a detail object. task records carry a command
 *  summary; otherwise we fall back to a compact JSON rendering. The server
 *  masks secret fields, so this is safe to display verbatim. */
function summarizeDetail(action: string, detail: unknown): string {
  // task detail commonly carries a { command, ... } shape — surface it first.
  if (action === 'task' && detail && typeof detail === 'object') {
    const d = detail as Record<string, unknown>;
    const cmd = d.command ?? d.cmd ?? d.label ?? d.summary;
    if (typeof cmd === 'string' && cmd.length > 0) {
      let line = `command: ${cmd}`;
      // Append a couple of common secondary fields if present.
      const task_id = d.task_id ?? d.id;
      if (typeof task_id === 'number') line += `\ntask_id: ${task_id}`;
      return line;
    }
  }
  if (detail === null || detail === undefined) return '';
  if (typeof detail === 'string') return detail;
  if (typeof detail === 'number' || typeof detail === 'boolean') {
    return JSON.stringify(detail);
  }
  return JSON.stringify(detail, null, 2);
}

type VerifyState =
  | { kind: 'idle' }
  | { kind: 'pending' }
  | { kind: 'ok' }
  | { kind: 'broken'; brokenAt: number };

export function EventsPage() {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [actionFilter, setActionFilter] = useState<ActionFilter>('all');
  const [operatorFilter, setOperatorFilter] = useState('');

  const [verify, setVerify] = useState<VerifyState>({ kind: 'idle' });

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Default: most recent 500, newest first (server returns ascending by seq,
      // so we reverse for a newest-first timeline).
      const rows = await fetchAudit({ limit: 500 });
      setRecords([...rows].sort((a, b) => b.seq - a.seq));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setRecords([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const runVerify = useCallback(async () => {
    setVerify({ kind: 'pending' });
    try {
      const res = await verifyAudit();
      setVerify(
        res.ok
          ? { kind: 'ok' }
          : { kind: 'broken', brokenAt: res.broken_at ?? -1 },
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setVerify({ kind: 'idle' });
    }
  }, []);

  // Apply client-side filters (action + operator substring, case-insensitive).
  const visible = useMemo(() => {
    const op = operatorFilter.trim().toLowerCase();
    return records.filter((r) => {
      if (actionFilter !== 'all' && r.action !== actionFilter) return false;
      if (op && !r.operator.toLowerCase().includes(op)) return false;
      return true;
    });
  }, [records, actionFilter, operatorFilter]);

  return (
    <div className="events-root">
      <div className="audit-toolbar">
        <div className="audit-toolbar-left">
          <span className="audit-title">Audit Log</span>
          <span className="audit-count">
            {loading ? '…' : `${visible.length} / ${records.length}`}
          </span>
        </div>

        <div className="audit-toolbar-right">
          {verify.kind === 'ok' && (
            <span className="audit-verify ok" title="Hash chain intact">
              <span className="audit-verify-dot" />
              链完整 ✓
            </span>
          )}
          {verify.kind === 'broken' && (
            <span
              className="audit-verify broken"
              title="A record's stored hash does not match recomputed value"
            >
              <span className="audit-verify-dot" />
              链在 seq #{verify.brokenAt} 处断裂 ✕
            </span>
          )}

          <button
            type="button"
            className="audit-btn primary"
            onClick={() => void runVerify()}
            disabled={verify.kind === 'pending' || loading}
          >
            {verify.kind === 'pending' ? '验证中…' : '验证哈希链'}
          </button>

          <select
            className="audit-select"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value as ActionFilter)}
            aria-label="Filter by action"
          >
            {ACTION_FILTERS.map((a) => (
              <option key={a} value={a}>
                {a === 'all' ? '全部动作' : a}
              </option>
            ))}
          </select>

          <input
            type="text"
            className="audit-input"
            placeholder="操作员…"
            value={operatorFilter}
            onChange={(e) => setOperatorFilter(e.target.value)}
            spellCheck={false}
            autoComplete="off"
          />

          <button
            type="button"
            className="audit-btn"
            onClick={() => void load()}
            disabled={loading}
          >
            {loading ? '加载中…' : '刷新'}
          </button>
        </div>
      </div>

      {error ? (
        <div className="audit-status">
          <div className="audit-error" role="alert">{error}</div>
        </div>
      ) : loading && records.length === 0 ? (
        <div className="audit-status">加载审计记录中…</div>
      ) : visible.length === 0 ? (
        <div className="audit-status">
          <div className="audit-empty">
            <span>暂无审计记录。</span>
            <span className="audit-empty-sub">
              {records.length > 0 ? '当前筛选无匹配项。' : '操作产生事件后将出现在此。'}
            </span>
          </div>
        </div>
      ) : (
        <div className="audit-body">
          <div className="audit-timeline">
            {visible.map((r) => (
              <EventRow key={r.seq} record={r} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/** A single timeline row. Extracted so the parent map stays readable. */
function EventRow({ record }: { record: AuditRecord }) {
  const {
    seq,
    ts,
    operator,
    action,
    target,
    detail,
    hash,
  } = record;

  const summary = summarizeDetail(action, detail);
  const isSystem = operator === 'system' || operator.length === 0;
  const time = new Date(ts * 1000).toLocaleTimeString();

  return (
    <div className={`audit-row ${rowClass(action)}`}>
      <time className="audit-time" dateTime={new Date(ts * 1000).toISOString()}>
        {time}
      </time>

      <div className="audit-main">
        <div className="audit-line">
          <span className={`audit-badge ${badgeClass(action)}`}>{action}</span>
          <span className={`audit-operator ${isSystem ? 'is-system' : ''}`}>
            {isSystem ? 'system' : operator}
          </span>
          <span className="audit-arrow" aria-hidden>→</span>
          <span className="audit-target">{target}</span>
        </div>

        {summary && <div className="audit-detail">{summary}</div>}
      </div>

      <div className="audit-meta">
        <span className="audit-seq">#{seq}</span>
        <span className="audit-hash" title={hash}>
          {hash.slice(0, 8)}
        </span>
      </div>
    </div>
  );
}

export default EventsPage;
