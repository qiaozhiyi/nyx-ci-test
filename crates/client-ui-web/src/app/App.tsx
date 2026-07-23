import { useEffect, useState } from 'react';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { SessionView } from '../lib/types';
import { ConnectPage } from './ConnectPage';
import { Workspace } from './Workspace';
import { TopologyPage } from './TopologyPage';
import { CredsPage } from './CredsPage';
import { ImplantPage } from './ImplantPage';
import { EventsPage } from './EventsPage';
import { Dock } from '../components/Dock';
import { disconnect, onError, onSessions } from '../lib/invoke';
import './App.css';

/** The surfaces reachable from the Dock. */
export type Page = 'workspace' | 'topology' | 'creds' | 'implant' | 'events';

export function App() {
  const [connected, setConnected] = useState(false);
  const [activePage, setActivePage] = useState<Page>('workspace');
  const [error, setError] = useState<string | null>(null);

  // Sessions live at the top level: both Workspace and Topology consume them.
  const [sessions, setSessions] = useState<SessionView[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Backend-level errors (auth/network) imply the team-server link is gone.
  useEffect(() => {
    let unlisten: UnlistenFn | null = null;
    let cancelled = false;
    onError((msg) => {
      setError(msg);
      setConnected(false);
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
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
      // Auto-select the first session if none is selected yet.
      setSelectedId((cur) => cur ?? (s.length > 0 ? s[0].id : null));
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
        {activePage === 'workspace' && (
          <Workspace
            sessions={sessions}
            selectedId={selectedId}
            onSelect={setSelectedId}
          />
        )}
        {activePage === 'topology' && <TopologyPage sessions={sessions} />}
        {activePage === 'creds' && <CredsPage />}
        {activePage === 'implant' && <ImplantPage />}
        {activePage === 'events' && <EventsPage />}
      </main>
    </div>
  );
}
