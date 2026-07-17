/**
 * ImplantPage — implant generation + management surface.
 *
 * Top: build form (calls generateImplant), shows a result card on success
 * with copyable pub key / sha256 and a base64 binary download when inline.
 * Bottom: list of generated implants with revoke action (listImplants).
 *
 * Imports only the shared contract in lib/invoke.ts; visuals reference
 * styles/tokens.css via ImplantPage.css.
 */
import { useCallback, useEffect, useState } from 'react';
import type { ChangeEvent, FormEvent } from 'react';
import {
  generateImplant,
  listImplants,
  revokeImplant,
} from '../lib/invoke';
import type {
  GenerateRequest,
  GenerateResponse,
  ImplantSummary,
} from '../lib/invoke';
import './ImplantPage.css';

const FORMATS = ['dll', 'shellcode', 'exe'] as const;
type FormatOption = (typeof FORMATS)[number];

interface FormState {
  callback: string;
  port: string;
  format: FormatOption;
  uri: string;
  sleep: string;
  jitter: string;
  tls: boolean;
  notes: string;
  inline: boolean;
}

const DEFAULTS: FormState = {
  callback: '',
  port: '8443',
  format: 'dll',
  uri: '/beacon',
  sleep: '60',
  jitter: '20',
  tls: true,
  notes: '',
  inline: false,
};

/**
 * Decode a base64 string into an octet-stream Blob and trigger a browser
 * download with the given filename. Used for the inline binary payload.
 */
function downloadBase64(b64: string, filename: string): void {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const blob = new Blob([bytes], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/** Copy text to the clipboard, returning whether it succeeded. */
async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** Pick a sensible download filename for the given format. */
function binaryFilename(format: string, pub: string): string {
  const short = pub.slice(0, 8) || 'implant';
  const ext = format === 'exe' ? 'exe' : format === 'shellcode' ? 'bin' : 'dll';
  return `implant-${short}.${ext}`;
}

export function ImplantPage() {
  const [form, setForm] = useState<FormState>(DEFAULTS);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<GenerateResponse | null>(null);

  const [implants, setImplants] = useState<ImplantSummary[]>([]);
  const [listLoading, setListLoading] = useState(false);
  const [listError, setListError] = useState<string | null>(null);
  const [revokingPub, setRevokingPub] = useState<string | null>(null);
  const [copied, setCopied] = useState<'pub' | 'sha' | null>(null);

  const refreshList = useCallback(async () => {
    setListLoading(true);
    setListError(null);
    try {
      const res = await listImplants();
      setImplants(res.implants ?? []);
    } catch (err) {
      setListError(err instanceof Error ? err.message : String(err));
    } finally {
      setListLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshList();
  }, [refreshList]);

  function update<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  function onText(key: keyof FormState) {
    return (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
      update(key, e.target.value as FormState[typeof key]);
    };
  }

  function onCheck(key: 'tls' | 'inline') {
    return (e: ChangeEvent<HTMLInputElement>) => update(key, e.target.checked);
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const callback = form.callback.trim();
    if (!callback) {
      setError('Callback host is required.');
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const req: GenerateRequest = {
        callback,
        port: Number(form.port) || undefined,
        format: form.format,
        uri: form.uri.trim() || undefined,
        sleep: Number(form.sleep) || undefined,
        jitter: Number(form.jitter) || undefined,
        tls: form.tls,
        notes: form.notes.trim() || undefined,
        deliver: form.inline ? 'inline' : undefined,
      };
      const res = await generateImplant(req);
      if (!res.ok) {
        setError(res.message || 'Generation failed.');
      } else {
        setResult(res);
        // A new implant exists now; refresh the list.
        void refreshList();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleCopy(kind: 'pub' | 'sha', text: string) {
    const ok = await copyText(text);
    if (ok) {
      setCopied(kind);
      window.setTimeout(() => setCopied((c) => (c === kind ? null : c)), 1200);
    }
  }

  async function handleRevoke(implant: ImplantSummary) {
    const host = `${implant.callback_host}:${implant.callback_port}`;
    const ok = window.confirm(
      `吊销 implant #${implant.id} (${host})？\n吊销后该 implant 将无法回连。`,
    );
    if (!ok) return;
    setRevokingPub(implant.implant_pub);
    try {
      await revokeImplant(implant.implant_pub);
      await refreshList();
    } catch (err) {
      setListError(err instanceof Error ? err.message : String(err));
    } finally {
      setRevokingPub(null);
    }
  }

  const canSubmit = !loading && form.callback.trim().length > 0;

  return (
    <div className="implant-page">
      <section className="implant-gen">
        <form className="implant-form" onSubmit={handleSubmit}>
          <div className="implant-form-head">
            <h2 className="implant-section-title">Generate Implant</h2>
            <span className="implant-section-sub">
              Build a callback payload for the current team server.
            </span>
          </div>

          <div className="implant-grid">
            <label className="ip-field ip-field-grow">
              <span className="ip-label">Callback host *</span>
              <input
                type="text"
                className="ip-input mono"
                value={form.callback}
                onChange={onText('callback')}
                placeholder="10.0.0.1"
                spellCheck={false}
                autoComplete="off"
                autoCapitalize="off"
              />
            </label>

            <label className="ip-field">
              <span className="ip-label">Port</span>
              <input
                type="number"
                className="ip-input mono"
                value={form.port}
                onChange={onText('port')}
                min={1}
                max={65535}
              />
            </label>

            <label className="ip-field">
              <span className="ip-label">Format</span>
              <select
                className="ip-select"
                value={form.format}
                onChange={onText('format')}
              >
                {FORMATS.map((f) => (
                  <option key={f} value={f}>{f}</option>
                ))}
              </select>
            </label>

            <label className="ip-field">
              <span className="ip-label">URI</span>
              <input
                type="text"
                className="ip-input mono"
                value={form.uri}
                onChange={onText('uri')}
                placeholder="/beacon"
                spellCheck={false}
                autoComplete="off"
              />
            </label>

            <label className="ip-field">
              <span className="ip-label">Sleep (s)</span>
              <input
                type="number"
                className="ip-input mono"
                value={form.sleep}
                onChange={onText('sleep')}
                min={0}
              />
            </label>

            <label className="ip-field">
              <span className="ip-label">Jitter (%)</span>
              <input
                type="number"
                className="ip-input mono"
                value={form.jitter}
                onChange={onText('jitter')}
                min={0}
                max={100}
              />
            </label>

            <label className="ip-check">
              <input
                type="checkbox"
                checked={form.tls}
                onChange={onCheck('tls')}
              />
              <span className="ip-check-label">TLS</span>
            </label>

            <label className="ip-check">
              <input
                type="checkbox"
                checked={form.inline}
                onChange={onCheck('inline')}
              />
              <span className="ip-check-label">Inline binary (download)</span>
            </label>
          </div>

          <label className="ip-field">
            <span className="ip-label">Notes</span>
            <textarea
              className="ip-textarea"
              value={form.notes}
              onChange={onText('notes')}
              rows={2}
              placeholder="optional operator note"
              spellCheck={false}
            />
          </label>

          {error && <div className="ip-error" role="alert">{error}</div>}

          <button type="submit" className="ip-primary" disabled={!canSubmit}>
            {loading ? 'Generating…' : 'Generate'}
          </button>
        </form>

        {result && (
          <div className="implant-result" role="status">
            <div className="implant-result-head">
              <span className="implant-result-title">Generated</span>
              <span className="implant-result-badge">{result.format}</span>
            </div>

            <div className="ip-kv">
              <span className="ip-kv-key">implant_pub</span>
              <div className="ip-kv-val">
                <code className="mono ip-kv-mono">{result.implant_pub}</code>
                <button
                  type="button"
                  className="ip-copy"
                  onClick={() => handleCopy('pub', result.implant_pub)}
                >
                  {copied === 'pub' ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>

            <div className="ip-kv">
              <span className="ip-kv-key">sha256</span>
              <div className="ip-kv-val">
                <code className="mono ip-kv-mono">{result.sha256}</code>
                <button
                  type="button"
                  className="ip-copy"
                  onClick={() => handleCopy('sha', result.sha256)}
                >
                  {copied === 'sha' ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>

            <div className="ip-meta">
              <span className="ip-meta-item">
                <span className="ip-meta-key">size</span>
                <span className="mono">{result.size_bytes.toLocaleString()} B</span>
              </span>
              <span className="ip-meta-item">
                <span className="ip-meta-key">format</span>
                <span className="mono">{result.format}</span>
              </span>
              {result.binary && (
                <button
                  type="button"
                  className="ip-download"
                  onClick={() =>
                    downloadBase64(result.binary!, binaryFilename(result.format, result.implant_pub))
                  }
                >
                  Download binary
                </button>
              )}
            </div>

            {result.message && (
              <p className="ip-result-msg">{result.message}</p>
            )}
          </div>
        )}
      </section>

      <section className="implant-list">
        <div className="implant-form-head">
          <h2 className="implant-section-title">Generated Implants</h2>
          <div className="implant-section-actions">
            <span className="implant-section-sub">
              {listLoading ? 'loading…' : `${implants.length} total`}
            </span>
            <button
              type="button"
              className="ip-ghost"
              onClick={() => void refreshList()}
              disabled={listLoading}
            >
              Refresh
            </button>
          </div>
        </div>

        {listError && <div className="ip-error" role="alert">{listError}</div>}

        <div className="ip-table-wrap">
          {implants.length === 0 ? (
            <div className="ip-empty">
              <p>暂无 implant 记录。</p>
              <p className="ip-empty-sub">使用上方表单生成第一个 implant。</p>
            </div>
          ) : (
            <table className="ip-table">
              <thead>
                <tr>
                  <th>id</th>
                  <th>callback</th>
                  <th>format</th>
                  <th>created</th>
                  <th>expires</th>
                  <th>status</th>
                  <th className="ip-th-action">action</th>
                </tr>
              </thead>
              <tbody>
                {implants.map((imp) => (
                  <tr key={imp.implant_pub} className={imp.revoked ? 'is-revoked' : ''}>
                    <td className="mono">#{imp.id}</td>
                    <td className="mono">
                      {imp.callback_host}<span className="ip-dim">:</span>{imp.callback_port}
                    </td>
                    <td className="mono">{imp.format}</td>
                    <td>{formatTs(imp.created_at)}</td>
                    <td>{imp.expires_at ? formatTs(imp.expires_at) : <span className="ip-dim">—</span>}</td>
                    <td>
                      {imp.revoked ? (
                        <span className="ip-state ip-state-revoked">已吊销</span>
                      ) : (
                        <span className="ip-state ip-state-active">活跃</span>
                      )}
                    </td>
                    <td className="ip-td-action">
                      <button
                        type="button"
                        className="ip-revoke"
                        onClick={() => void handleRevoke(imp)}
                        disabled={imp.revoked || revokingPub === imp.implant_pub}
                      >
                        {revokingPub === imp.implant_pub
                          ? '…'
                          : imp.revoked
                            ? 'revoked'
                            : '吊销'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  );
}

/** Safe timestamp formatter tolerant of ISO strings or epoch seconds/ms. */
function formatTs(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === '') {
    return '—';
  }
  let d: Date;
  if (typeof value === 'number') {
    // Treat numbers < 1e12 as seconds (epoch seconds), otherwise ms.
    d = new Date(value < 1e12 ? value * 1000 : value);
  } else {
    d = new Date(value);
  }
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
}
