import { useEffect, useState } from 'react';
import {
  connect,
  disconnect,
  fetchProfile,
  fetchReport,
  kernelWindow,
} from '../lib/invoke';
import type { KernelWindowReply, ProfileView } from '../lib/invoke';
import { useTaskStore } from './taskStore';
import './SettingsPage.css';

/**
 * 设置 — connection details, the loaded Malleable C2 profile, and the
 * engagement report export (M3 报告闭环). Previously a disabled dock item
 * ("后续版本"); wired now.
 */
export function SettingsPage() {
  const [server, setServer] = useState('');
  const [bearer, setBearer] = useState('');
  const [profile, setProfile] = useState<ProfileView | null>(null);
  const [profileErr, setProfileErr] = useState<string | null>(null);
  const [reconnecting, setReconnecting] = useState(false);
  const [reporting, setReporting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [kernelPid, setKernelPid] = useState('');
  const [kernelBusy, setKernelBusy] = useState<'open' | 'close' | null>(null);
  const [kernelReply, setKernelReply] = useState<KernelWindowReply | null>(null);
  const { clearAll } = useTaskStore();

  useEffect(() => {
    let cancelled = false;
    fetchProfile()
      .then((p) => {
        if (!cancelled) setProfile(p);
      })
      .catch((e) => {
        if (!cancelled) setProfileErr(String(e));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function onReconnect() {
    if (!server.trim() || !bearer.trim()) {
      setNotice('需要 server URL 与 bearer 才能重连');
      return;
    }
    setReconnecting(true);
    setNotice(null);
    try {
      // Drop the current link, then reconnect to the new endpoint.
      await disconnect();
      await connect(server.trim(), bearer.trim());
      // disconnect() cleared the BACKEND pending queue; mirror it in the
      // frontend or every in-flight block would sit at 'processing' forever
      // (no more drains, no expiry path runs for them).
      clearAll();
      setNotice('已重新连接');
    } catch (e) {
      setNotice(`重连失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setReconnecting(false);
    }
  }

  function parseKernelPid(): number | null {
    const n = parseInt(kernelPid, 10);
    if (!Number.isInteger(n) || n <= 0 || n > 0xffffffff) return null;
    return n;
  }

  async function onKernelWindow(phase: 'open' | 'close') {
    setKernelBusy(phase);
    setNotice(null);
    try {
      const reply = await kernelWindow(phase, parseKernelPid());
      setKernelReply(reply);
    } catch (e) {
      setKernelReply(null);
      setNotice(`内核时间窗失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setKernelBusy(null);
    }
  }

  async function onExportReport() {
    setReporting(true);
    setNotice(null);
    try {
      const md = await fetchReport();
      const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      a.href = url;
      a.download = `nyx-report-${ts}.md`;
      a.click();
      URL.revokeObjectURL(url);
      setNotice('报告已导出（.md）');
    } catch (e) {
      setNotice(`导出失败: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setReporting(false);
    }
  }

  return (
    <div className="settings-page">
      <h2 className="settings-title">设置</h2>

      <section className="settings-card">
        <h3>连接</h3>
        <label className="settings-field">
          <span>Server URL</span>
          <input
            className="settings-input mono"
            value={server}
            onChange={(e) => setServer(e.target.value)}
            placeholder="http://127.0.0.1:8443"
            spellCheck={false}
          />
        </label>
        <label className="settings-field">
          <span>Bearer</span>
          <input
            className="settings-input mono"
            type="password"
            value={bearer}
            onChange={(e) => setBearer(e.target.value)}
            placeholder="name:secret"
            spellCheck={false}
          />
        </label>
        <button
          type="button"
          className="settings-btn"
          disabled={reconnecting}
          onClick={onReconnect}
        >
          {reconnecting ? '重连中…' : '重连'}
        </button>
      </section>

      <section className="settings-card">
        <h3>Malleable C2 profile</h3>
        {profileErr && <p className="settings-muted">profile 不可用: {profileErr}</p>}
        {profile && (
          <dl className="settings-dl">
            <dt>已加载</dt>
            <dd>{profile.loaded ? '是' : '否'}</dd>
            {profile.http_get_uri && (
              <>
                <dt>http-get uri</dt>
                <dd className="mono">{profile.http_get_uri}</dd>
              </>
            )}
            {profile.http_post_uri && (
              <>
                <dt>http-post uri</dt>
                <dd className="mono">{profile.http_post_uri}</dd>
              </>
            )}
            {profile.useragent && (
              <>
                <dt>useragent</dt>
                <dd className="mono">{profile.useragent}</dd>
              </>
            )}
          </dl>
        )}
        {!profile && !profileErr && <p className="settings-muted">读取中…</p>}
      </section>

      <section className="settings-card">
        <h3>内核时间窗</h3>
        <p className="settings-muted">
          操作员发起（非 implant 信令）。open 失败即停；close 尽最大努力。当前 kit
          无 undo，<span className="mono">restored: false / no undo op</span> 是诚实返回，不是
          GUI 错误。inject / hashdump 下发前会尽力先 open；daemon 未配置（404）时任务仍下发。
        </p>
        <label className="settings-field">
          <span>EDR PID（可选，neutralize freeze）</span>
          <input
            className="settings-input mono"
            type="number"
            min={1}
            step={1}
            value={kernelPid}
            onChange={(e) => setKernelPid(e.target.value)}
            placeholder="例如 1234"
          />
        </label>
        <div className="settings-btn-row">
          <button
            type="button"
            className="settings-btn"
            disabled={kernelBusy !== null}
            onClick={() => onKernelWindow('open')}
          >
            {kernelBusy === 'open' ? '打开中…' : '打开'}
          </button>
          <button
            type="button"
            className="settings-btn settings-btn-secondary"
            disabled={kernelBusy !== null}
            onClick={() => onKernelWindow('close')}
          >
            {kernelBusy === 'close' ? '关闭中…' : '关闭'}
          </button>
        </div>
        {kernelReply && (
          <>
            <p className="settings-muted mono">HTTP {kernelReply.status}</p>
            <pre className="settings-json mono">
              {JSON.stringify(kernelReply.body, null, 2)}
            </pre>
          </>
        )}
      </section>

      <section className="settings-card">
        <h3>报告导出</h3>
        <p className="settings-muted">
          导出当前演练状态的 Markdown 快照（会话 / 凭据统计 / 审计尾部）。
        </p>
        <button
          type="button"
          className="settings-btn"
          disabled={reporting}
          onClick={onExportReport}
        >
          {reporting ? '生成中…' : '导出报告 (.md)'}
        </button>
      </section>

      {notice && <p className="settings-notice">{notice}</p>}
    </div>
  );
}
