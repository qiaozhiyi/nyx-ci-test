import { lazy, Suspense, useEffect, useMemo, useState } from 'react';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { SessionView } from '../lib/types';
import { ConnectPage } from './ConnectPage';
import { Workspace } from './Workspace';
import { CredsPage } from './CredsPage';
import { ImplantPage } from './ImplantPage';
import { EventsPage } from './EventsPage';
import { SettingsPage } from './SettingsPage';
import { Dock } from '../components/Dock';
import { TaskStoreProvider, useTaskStore } from './taskStore';
import { disconnect, onError, onSessions } from '../lib/invoke';
import './App.css';

// Topology is the only consumer of three.js; lazy-load it so the 3D engine
// splits out of the initial chunk (vite manualChunks 'three' keeps the vendor
// lib in its own async chunk too).
const TopologyPage = lazy(() => import('./TopologyPage'));

/** The surfaces reachable from the Dock. */
export type Page = 'workspace' | 'topology' | 'creds' | 'implant' | 'events' | 'settings';

/**
 * App — top-level shell.
 *
 * Wraps everything in the TaskStoreProvider so per-session task history
 * survives session switches (and lives for the whole app lifetime); the
 * inner component consumes it to clear history on explicit disconnect.
 */
export function App() {
  return (
    <TaskStoreProvider>
      <AppInner />
    </TaskStoreProvider>
  );
}

function AppInner() {
  const { clearAll, tasksBySession } = useTaskStore();
  // Derive the topology panel's task index (sessionId -> {id, label}[]) from
  // the App-level TaskStore so the '最近任务' section shows real entries.
  const topoTasks = useMemo(() => {
    const out: Record<string, { id: number; label: string }[]> = {};
    for (const [sid, tasks] of Object.entries(tasksBySession)) {
      if (tasks.length > 0) {
        out[sid] = tasks.map((t) => ({ id: t.task_id, label: t.command_label }));
      }
    }
    return out;
  }, [tasksBySession]);
  const [connected, setConnected] = useState(false);
  const [activePage, setActivePage] = useState<Page>('workspace');
  const [error, setError] = useState<string | null>(null);

  // Sessions live at the top level: both Workspace and Topology consume them.
  const [sessions, setSessions] = useState<SessionView[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Backend-level errors (auth/network) mean the team-server link is
  // degraded — NOT that the operator should be logged out. The poll loop
  // only emits after 3 consecutive fetch failures and keeps retrying; it
  // recovers on its own when the server comes back. So: surface a banner,
  // keep the connection and ALL task history. Tearing down here used to
  // wipe every session's console on a 6-second network blip.
  useEffect(() => {
    let unlisten: UnlistenFn | null = null;
    let cancelled = false;
    onError((msg) => {
      setError(msg);
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Session list updates from the 2s poll loop (emitted by the Rust backend).
  useEffect(() => {
    if (!connected) {
      setSessions([]);
      setSelectedId(null);
      return;
    }
    let unlisten: UnlistenFn | null = null;
    let cancelled = false;
    onSessions((s) => {
      setSessions(s);
      // Sessions arrive: server is reachable again — clear any outage banner.
      setError(null);
      // Auto-select: keep the current pick while it exists; otherwise land on
      // the first LIVE (non-stale) session, not blindly s[0] — the server
      // returns oldest-first, so s[0] is typically a stale restored session
      // and commands sent to it can never come back.
      setSelectedId((cur) => {
        if (cur && s.some((x) => x.id === cur)) return cur;
        const live = s.find((x) => !x.stale);
        return (live ?? s[0])?.id ?? null;
      });
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, [connected]);

  // Drop the team-server link and return to the connect page. Even if the
  // backend call fails we still leave — the session state is cleared either way.
  async function handleDisconnect() {
    try {
      await disconnect();
    } catch (err) {
      console.error('disconnect failed:', err);
    }
    // Explicit disconnect: forget per-session history (mirrors the backend
    // clearing its pending queue). Session SWITCHES do not reset it.
    clearAll();
    setConnected(false);
    setActivePage('workspace');
    setSessions([]);
    setSelectedId(null);
  }

  if (!connected) {
    return (
      <ConnectPage
        error={error}
        onConnected={() => {
          setError(null);
          setConnected(true);
        }}
      />
    );
  }

  return (
    <div className="app-shell">
      <Dock activePage={activePage} onPageChange={setActivePage} onDisconnect={handleDisconnect} />
      <main className="app-main">
        {error && (
          <div className="app-banner" role="alert">
            <span className="app-banner-text">连接异常（自动重试中）: {error}</span>
            <button type="button" className="app-banner-x" onClick={() => setError(null)}>
              ×
            </button>
          </div>
        )}
        {activePage === 'workspace' && (
          <Workspace
            sessions={sessions}
            selectedId={selectedId}
            onSelect={setSelectedId}
          />
        )}
        {activePage === 'topology' && (
          <Suspense fallback={<div className="app-loading mono">加载拓扑视图…</div>}>
            <TopologyPage sessions={sessions} tasksBySession={topoTasks} />
          </Suspense>
        )}
        {activePage === 'creds' && <CredsPage />}
        {activePage === 'implant' && <ImplantPage />}
        {activePage === 'events' && <EventsPage />}
        {activePage === 'settings' && <SettingsPage />}
      </main>
    </div>
  );
}
