import { useState } from 'react';
import type { SessionView } from '../lib/types';
import { archName, classifyOs } from '../lib/types';
import './SessionTable.css';

export interface SessionTableProps {
  sessions: SessionView[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

type FilterKey = 'all' | 'admin' | 'da' | 'x64' | 'alive';

const FILTERS: { key: FilterKey; label: string; title?: string }[] = [
  { key: 'all', label: '全部' },
  { key: 'admin', label: 'admin' },
  { key: 'da', label: 'DA' },
  { key: 'x64', label: 'x64' },
  { key: 'alive', label: '●活跃', title: '本次服务器生命周期内已回连' },
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

  const aliveCount = sessions.filter((s) => !s.stale).length;
  const staleCount = sessions.length - aliveCount;

  const visible = sessions.filter((s) => {
    switch (filter) {
      case 'admin': return isAdmin(s);
      case 'da': return isDA(s);
      case 'x64': return s.arch === 0;
      case 'alive': return !s.stale;
      default: return true;
    }
  });

  return (
    <div className="session-table">
      <div className="st-header">
        <span className="st-title">Sessions</span>
        <span className="st-count mono">
          {sessions.length === 0
            ? '—'
            : `${aliveCount} 活跃${staleCount ? ` · ${staleCount} 未回连` : ''}`}
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
          visible.map((s) => {
            const active = s.id === selectedId;
            const da = isDA(s);
            const admin = !da && isAdmin(s);
            return (
              <button
                key={s.id}
                type="button"
                className={'st-row' + (active ? ' active' : '')}
                onClick={() => onSelect(s.id)}
              >
                <div className="st-row-top">
                  <span className={'st-dot' + (s.stale ? ' stale' : '')} />
                  <span className="st-host mono">{s.hostname}</span>
                  {da && <span className="st-tag tag-da">DA</span>}
                  {admin && <span className="st-tag tag-admin">admin</span>}
                  {!da && !admin && <span className="st-tag tag-user">user</span>}
                </div>
                <div className="st-row-bot mono">
                  <span>{s.username}</span>
                  <Sep />
                  <span>{archName(s.arch)}</span>
                  <Sep />
                  <span>{formatAlive(s.age_secs)}</span>
                  {s.stale && (
                    <span className="st-stale" title="服务器重启后尚未回连">
                      stale {staleMinutes(s.age_secs)}m
                    </span>
                  )}
                </div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}

function Sep() {
  return <span className="st-sep" aria-hidden>·</span>;
}
