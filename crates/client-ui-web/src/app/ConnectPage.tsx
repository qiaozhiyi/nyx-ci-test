import { useState } from 'react';
import type { FormEvent } from 'react';
import { connect } from '../lib/invoke';
import './ConnectPage.css';

export interface ConnectPageProps {
  /** Called after a successful connect(). */
  onConnected: () => void;
  /** Optional error surfaced by the shell (e.g. dropped connection). */
  error?: string | null;
}

export function ConnectPage({ onConnected, error: externalError }: ConnectPageProps) {
  const [server, setServer] = useState('http://127.0.0.1:8443');
  const [bearer, setBearer] = useState('');
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  // 外部错误（如掉线）是 prop 无法直接清掉；记录已确认的值，点开始连接或
  // 修改输入后不再显示，直到 shell 推来一个不同的新错误。
  const [dismissedError, setDismissedError] = useState<string | null>(null);

  // A local connect failure takes precedence over a shell-supplied error.
  const shownExternal =
    externalError && externalError !== dismissedError ? externalError : null;
  const error = localError ?? shownExternal;
  const canSubmit = !loading && server.trim().length > 0 && bearer.trim().length > 0;

  function dismissExternal() {
    if (externalError) setDismissedError(externalError);
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setLoading(true);
    setLocalError(null);
    dismissExternal();
    try {
      await connect(server.trim(), bearer.trim());
      onConnected();
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="connect">
      <form className="connect-card" onSubmit={handleSubmit}>
        <div className="brand">
          <div className="brand-logo" aria-hidden>N</div>
          <div className="brand-text">
            <h1>Nyx Operator</h1>
            <p className="brand-sub">仅限授权红队使用</p>
          </div>
        </div>

        <label className="field">
          <span className="field-label">服务器地址</span>
          <input
            type="text"
            className="field-input mono"
            value={server}
            onChange={(e) => {
              setServer(e.target.value);
              dismissExternal();
            }}
            placeholder="http://127.0.0.1:8443"
            spellCheck={false}
            autoComplete="off"
            autoCapitalize="off"
          />
        </label>

        <label className="field">
          <span className="field-label">Bearer 令牌</span>
          <input
            type="password"
            className="field-input mono"
            value={bearer}
            onChange={(e) => {
              setBearer(e.target.value);
              dismissExternal();
            }}
            placeholder="name:secret"
            spellCheck={false}
            autoComplete="off"
            autoCapitalize="off"
          />
        </label>

        {error && <div className="connect-error" role="alert">{error}</div>}

        <button type="submit" className="connect-btn" disabled={!canSubmit}>
          {loading ? '连接中…' : '连接'}
        </button>
      </form>
    </div>
  );
}
