/**
 * CredsPage — Credential Vault panel.
 *
 * Container responsibility:
 *   - Load credentials via listCreds() into local state.
 *   - Toolbar: kind dropdown filter + reveal toggle (reloads with reveal=true)
 *     + inline "add credential" form.
 *   - Render CredRecord[] as a table with colored kind badges, monospace secret
 *     (grey when masked), formatted collected_at, and per-row delete action.
 *
 * Visual language mirrors SessionTable (dark --panel rows, hover, mono data).
 */
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import {
  addCred,
  deleteCred,
  listCreds,
  type CredRecord,
} from '../lib/invoke';
import './CredsPage.css';

type KindFilter = 'all' | 'hash' | 'password' | 'ticket' | 'key';

const KIND_OPTIONS: { value: KindFilter; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'hash', label: 'hash' },
  { value: 'password', label: 'password' },
  { value: 'ticket', label: 'ticket' },
  { value: 'key', label: 'key' },
];

/** CSS class per known kind; falls back to ck-other for unknown values. */
const KIND_CLASS: Record<string, string> = {
  hash: 'ck-hash',
  password: 'ck-password',
  ticket: 'ck-ticket',
  key: 'ck-key',
};

/** Format a Unix-seconds timestamp as a local string. */
function formatTs(ts?: number): string {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString();
}

/** Server masks secrets as "********"; detect to render them grey/faint. */
function isMasked(secret: string): boolean {
  return /^\*+$/.test(secret);
}

/** Stable identity of a cred row (the server deletes by the same triple). */
function credKey(c: CredRecord): string {
  return `${c.realm}\\${c.user}\\${c.kind}`;
}

export function CredsPage() {
  const [creds, setCreds] = useState<CredRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reveal, setReveal] = useState(false);
  const [kindFilter, setKindFilter] = useState<KindFilter>('all');
  const [showAdd, setShowAdd] = useState(false);
  const [deletingKey, setDeletingKey] = useState<string | null>(null);

  // Monotonic request id: only the latest reload may touch state, so a slow
  // earlier response can't overwrite a newer filter/reveal selection.
  const reqSeq = useRef(0);

  const reload = useCallback(async () => {
    const seq = ++reqSeq.current;
    setLoading(true);
    setError(null);
    try {
      const data = await listCreds(
        reveal,
        kindFilter === 'all' ? undefined : kindFilter,
      );
      if (seq === reqSeq.current) setCreds(data);
    } catch (e) {
      if (seq === reqSeq.current) {
        setError(e instanceof Error ? e.message : String(e));
      }
    } finally {
      if (seq === reqSeq.current) setLoading(false);
    }
  }, [reveal, kindFilter]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const handleDelete = async (c: CredRecord) => {
    if (!window.confirm(`删除凭据 ${c.realm}\\${c.user} (${c.kind})?`)) return;
    const key = credKey(c);
    setDeletingKey(key);
    try {
      await deleteCred(c.realm, c.user, c.kind);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setDeletingKey(null);
    }
  };

  const handleAdd = async (cred: CredRecord) => {
    try {
      await addCred(cred);
      setShowAdd(false);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="creds-page">
      <div className="cv-header">
        <div className="cv-title-group">
          <span className="cv-title">凭据库</span>
          <span className="cv-count mono">
            {loading ? '…' : creds.length}
          </span>
        </div>
        <div className="cv-toolbar">
          <label className="cv-filter">
            <span className="cv-filter-label">kind</span>
            <select
              className="cv-select"
              value={kindFilter}
              onChange={(e) => setKindFilter(e.target.value as KindFilter)}
            >
              {KIND_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className={'cv-reveal' + (reveal ? ' on' : '')}
            onClick={() => setReveal((v) => !v)}
            aria-pressed={reveal}
            title="重新加载并显示明文"
          >
            <span className="cv-reveal-led" aria-hidden />
            显示明文
          </button>
          <button
            type="button"
            className="cv-add"
            onClick={() => setShowAdd((v) => !v)}
          >
            {showAdd ? '取消添加' : '+ 添加凭据'}
          </button>
        </div>
      </div>

      {error && <div className="cv-error">{error}</div>}

      {showAdd && (
        <AddCredForm
          onCancel={() => setShowAdd(false)}
          onSubmit={handleAdd}
        />
      )}

      <div className="cv-body">
        {loading && creds.length === 0 ? (
          <div className="cv-empty">加载中…</div>
        ) : creds.length === 0 ? (
          <div className="cv-empty">
            <p>暂无凭据。</p>
            <p className="cv-empty-sub">
              通过 hashdump 命令或手动添加收集凭据。
            </p>
          </div>
        ) : (
          <table className="cv-table">
            <thead>
              <tr>
                <th>realm</th>
                <th>user</th>
                <th>kind</th>
                <th>secret</th>
                <th>source</th>
                <th>collected</th>
                <th className="cv-th-actions" aria-label="操作" />
              </tr>
            </thead>
            <tbody>
              {creds.map((c, i) => {
                const masked = isMasked(c.secret);
                const sourceLabel = c.source ?? c.beacon ?? '—';
                const deleting = deletingKey === credKey(c);
                return (
                  <tr key={`${c.realm}\\${c.user}\\${c.kind}\\${i}`}>
                    <td className="mono">{c.realm}</td>
                    <td className="mono">{c.user}</td>
                    <td>
                      <span
                        className={
                          'cv-kind ' + (KIND_CLASS[c.kind] ?? 'ck-other')
                        }
                      >
                        {c.kind}
                      </span>
                    </td>
                    <td
                      className={
                        'mono cv-secret' + (masked ? ' masked' : '')
                      }
                      title={c.secret}
                    >
                      {c.secret}
                    </td>
                    <td className="mono cv-source" title={sourceLabel}>
                      {sourceLabel}
                    </td>
                    <td className="mono cv-ts">
                      {formatTs(c.collected_at)}
                    </td>
                    <td className="cv-actions">
                      <button
                        type="button"
                        className="cv-del"
                        onClick={() => handleDelete(c)}
                        disabled={deleting}
                        title="删除凭据"
                      >
                        {deleting ? '…' : '删除'}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

interface AddCredFormProps {
  onCancel: () => void;
  onSubmit: (cred: CredRecord) => void;
}

/** Inline add-credential form. Submits a CredRecord up to the parent. */
function AddCredForm({ onCancel, onSubmit }: AddCredFormProps) {
  const [realm, setRealm] = useState('');
  const [user, setUser] = useState('');
  const [kind, setKind] = useState<CredRecord['kind']>('password');
  const [secret, setSecret] = useState('');
  const [notes, setNotes] = useState('');

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!realm.trim() || !user.trim() || !secret.trim()) return;
    onSubmit({
      realm: realm.trim(),
      user: user.trim(),
      kind,
      secret: secret.trim(),
      notes: notes.trim() || undefined,
    });
  };

  return (
    <form className="cv-add-form" onSubmit={submit}>
      <input
        className="cv-input"
        placeholder="realm"
        value={realm}
        onChange={(e) => setRealm(e.target.value)}
        autoFocus
      />
      <input
        className="cv-input"
        placeholder="user"
        value={user}
        onChange={(e) => setUser(e.target.value)}
      />
      <select
        className="cv-select"
        aria-label="kind"
        value={kind}
        onChange={(e) => setKind(e.target.value as CredRecord['kind'])}
      >
        <option value="hash">hash</option>
        <option value="password">password</option>
        <option value="ticket">ticket</option>
        <option value="key">key</option>
      </select>
      <input
        className="cv-input mono"
        placeholder="secret"
        value={secret}
        onChange={(e) => setSecret(e.target.value)}
      />
      <input
        className="cv-input"
        placeholder="notes (可选)"
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
      />
      <button type="submit" className="cv-add-submit">
        添加
      </button>
      <button type="button" className="cv-add-cancel" onClick={onCancel}>
        取消
      </button>
    </form>
  );
}

export default CredsPage;
