import { useMemo, useState } from 'react';
import type { SessionView } from '../lib/types';
import { archName, classifyOs } from '../lib/types';
import { listAllSessionMeta, useSessionMeta } from '../hooks/sessionMeta';
import './SessionTable.css';

export interface SessionTableProps {
  sessions: SessionView[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

type FilterKey = 'all' | 'admin' | 'da' | 'x64' | 'alive' | 'starred';

const FILTERS: { key: FilterKey; label: string; title?: string }[] = [
  { key: 'all', label: '全部' },
  { key: 'admin', label: 'admin' },
  { key: 'da', label: 'DA' },
  { key: 'x64', label: 'x64' },
  { key: 'alive', label: '●活跃', title: '本次服务器生命周期内已回连' },
  { key: 'starred', label: '★', title: '仅显示已标星的 session' },
];

/** Elevated context: explicit admin flag OR username mentions admin. */
function isAdmin(s: SessionView): boolean {
  return s.is_admin === 1 || /admin/i.test(s.username);
}

/**
 * Domain-admin heuristic. SessionView carries no explicit DA field, so we treat
 * a privileged account on a Windows Server (DC-like) host as DA for badge/filter.
 */
function isDA(s: SessionView): boolean {
  return s.is_admin === 1 && classifyOs(s.os) === 'win-server';
}

/** age_secs is seconds since FIRST check-in — render it as session lifetime. */
function formatAlive(secs: number): string {
  if (secs < 60) return '存活 <1m';
  const m = Math.round(secs / 60);
  if (m < 60) return `存活 ${m}m`;
  const h = Math.round(m / 60);
  return `存活 ${h}h`;
}

function staleMinutes(secs: number): number {
  return Math.max(1, Math.round(secs / 60));
}

export function SessionTable({ sessions, selectedId, onSelect }: SessionTableProps) {
  const [filter, setFilter] = useState<FilterKey>('all');
  // Snapshot all metadata once per render; cheap (single localStorage index read)
  // and lets us sort/filter without each row subscribing individually.
  const allMeta = useMemo(() => listAllSessionMeta(), [sessions, selectedId, filter]);

  const aliveCount = sessions.filter((s) => !s.stale).length;
  const staleCount = sessions.length - aliveCount;
  const starredCount = sessions.filter((s) => allMeta[s.id]?.starred).length;

  const visible = useMemo(() => {
    const filtered = sessions.filter((s) => {
      switch (filter) {
        case 'admin': return isAdmin(s);
        case 'da': return isDA(s);
        case 'x64': return s.arch === 0;
        case 'alive': return !s.stale;
        case 'starred': return Boolean(allMeta[s.id]?.starred);
        default: return true;
      }
    });
    // Starred first (by last-edit recency), then unstarred in original order.
    return filtered.sort((a, b) => {
      const sa = allMeta[a.id]?.starred ? 1 : 0;
      const sb = allMeta[b.id]?.starred ? 1 : 0;
      if (sa !== sb) return sb - sa;
      if (sa === 1 && sb === 1) {
        return (allMeta[b.id]?.updated_at ?? 0) - (allMeta[a.id]?.updated_at ?? 0);
      }
      return 0;
    });
  }, [sessions, filter, allMeta]);

  return (
    <div className="session-table">
      <div className="st-header">
        <span className="st-title">Sessions</span>
        <span className="st-count mono">
          {sessions.length === 0
            ? '—'
            : `${aliveCount} 活跃${staleCount ? ` · ${staleCount} 未回连` : ''}${starredCount ? ` · ${starredCount}★` : ''}`}
        </span>
      </div>

      <div className="st-filters">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            type="button"
            className={'st-chip' + (filter === f.key ? ' on' : '')}
            title={f.title}
            onClick={() => setFilter(f.key)}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div className="st-list">
        {visible.length === 0 ? (
          <div className="st-empty">
            <p>等待 session 回连…</p>
            <p className="st-empty-sub">启动 agent-dev 或投递 payload</p>
          </div>
        ) : (
          visible.map((s) => (
            <SessionRow
              key={s.id}
              session={s}
              active={s.id === selectedId}
              onSelect={onSelect}
            />
          ))
        )}
      </div>
    </div>
  );
}

interface SessionRowProps {
  session: SessionView;
  active: boolean;
  onSelect: (id: string) => void;
}

function SessionRow({ session, active, onSelect }: SessionRowProps) {
  const { meta, toggleStar, update, addTag, removeTag, reset } = useSessionMeta(session.id);
  const [tagDraft, setTagDraft] = useState('');
  const da = isDA(session);
  const admin = !da && isAdmin(session);
  const userTags = meta.tags;

  const displayName = meta.alias && meta.alias.length > 0 ? meta.alias : session.hostname;

  const onStarClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    toggleStar();
  };

  const onTagKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (tagDraft.trim()) {
        addTag(tagDraft);
        setTagDraft('');
      }
    } else if (e.key === 'Escape') {
      setTagDraft('');
    }
  };

  return (
    <div className={'st-row-wrap' + (active ? ' active' : '')}>
      <button
        type="button"
        className={'st-row' + (active ? ' active' : '') + (meta.starred ? ' starred' : '')}
        onClick={() => onSelect(session.id)}
      >
        <div className="st-row-top">
          <span className={'st-dot' + (session.stale ? ' stale' : '')} />
          <span className="st-host mono" title={meta.alias ? `${session.hostname} → ${meta.alias}` : session.hostname}>
            {displayName}
          </span>
          {meta.starred && <span className="st-star" title="已标星">★</span>}
          {da && <span className="st-tag tag-da">DA</span>}
          {admin && <span className="st-tag tag-admin">admin</span>}
          {!da && !admin && <span className="st-tag tag-user">user</span>}
          <span
            role="button"
            tabIndex={0}
            className={'st-star-btn' + (meta.starred ? ' on' : '')}
            title={meta.starred ? '取消标星' : '标星（置顶）'}
            onClick={onStarClick}
            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleStar(); } }}
          >
            {meta.starred ? '★' : '☆'}
          </span>
        </div>
        <div className="st-row-bot mono">
          <span>{session.username}</span>
          <Sep />
          <span>{archName(session.arch)}</span>
          <Sep />
          <span>{formatAlive(session.age_secs)}</span>
          {session.stale && (
            <span className="st-stale" title="服务器重启后尚未回连">
              stale {staleMinutes(session.age_secs)}m
            </span>
          )}
          {userTags.map((t) => (
            <span key={t} className="st-usertag" title={`tag: ${t}`}>#{t}</span>
          ))}
        </div>
      </button>

      {active && (
        <div className="st-meta" onClick={(e) => e.stopPropagation()}>
          <label className="st-meta-field">
            <span className="st-meta-label">别名</span>
            <input
              className="st-meta-input mono"
              type="text"
              placeholder={session.hostname}
              value={meta.alias ?? ''}
              onChange={(e) => update({ alias: e.target.value })}
              maxLength={64}
            />
          </label>

          <div className="st-meta-field">
            <span className="st-meta-label">标签</span>
            <div className="st-tag-edit">
              {userTags.map((t) => (
                <span key={t} className="st-tag-pill">
                  #{t}
                  <button
                    type="button"
                    className="st-tag-x"
                    title={`移除 ${t}`}
                    onClick={() => removeTag(t)}
                  >
                    ×
                  </button>
                </span>
              ))}
              <input
                className="st-tag-input mono"
                type="text"
                placeholder={userTags.length === 0 ? '回车添加…' : '+'}
                value={tagDraft}
                onChange={(e) => setTagDraft(e.target.value)}
                onKeyDown={onTagKey}
                maxLength={24}
              />
            </div>
          </div>

          <label className="st-meta-field">
            <span className="st-meta-label">备注</span>
            <textarea
              className="st-meta-notes mono"
              placeholder="操作员备注（仅本地保存）"
              value={meta.notes ?? ''}
              onChange={(e) => update({ notes: e.target.value })}
              rows={2}
              maxLength={500}
            />
          </label>

          <div className="st-meta-actions">
            <button
              type="button"
              className="st-meta-reset"
              title="清空此 session 的本地元数据"
              onClick={reset}
            >
              清空元数据
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function Sep() {
  return <span className="st-sep" aria-hidden>·</span>;
}
