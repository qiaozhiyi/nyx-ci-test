/**
 * TopologyInfoPanel — right-side floating detail panel.
 * Renders all metadata for the currently-selected node: OS/arch/user/privilege,
 * channel, sleep, the pivot chain it belongs to, and recent tasks.
 * Frosted-glass surface (backdrop-filter) overlaying the canvas.
 */
import type { TopologyNode } from '../lib/topology-scene';
import type { SessionView } from '../lib/types';
import { archName, classifyOs } from '../lib/types';
import { OS_COLORS, OS_LABELS } from '../lib/os-icons';
import './TopologyOverlays.css';

export interface TopologyInfoPanelProps {
  /** Selected topology node (may be mock or derived from a real session). */
  node: TopologyNode | null;
  /** Optional live session that matches `node.id` — enables real metadata. */
  session?: SessionView;
  /** Pivot chain (ordered list of hostnames) leading to this node from server. */
  pivotChain?: string[];
  /** Recent task labels for this node. */
  tasks?: { id: number; label: string }[];
}

const PRIV_LABEL: Record<string, string> = {
  server: 'Team Server',
  admin: 'ADMIN / DA',
  user: 'Standard User',
};

export function TopologyInfoPanel({
  node,
  session,
  pivotChain,
  tasks,
}: TopologyInfoPanelProps) {
  if (!node) {
    return (
      <aside className="topo-panel topo-info topo-info-empty">
        <div className="topo-info-empty-glyph" aria-hidden>◇</div>
        <div className="topo-info-empty-title">No node selected</div>
        <div className="topo-info-empty-hint">
          Click a node in the topology to inspect its metadata, pivot chain, and tasks.
        </div>
      </aside>
    );
  }

  const osKind = session ? classifyOs(session.os) : node.os;
  const osColor = OS_COLORS[osKind];
  const osLabel = OS_LABELS[osKind];
  const arch = session ? archName(session.arch) : 'x64';
  const user = session ? session.username : (node.priv === 'server' ? 'nyx' : 'operator');
  const hostname = session ? session.hostname : node.label;
  const sleep = '8s ± 15%';
  const channel = node.priv === 'server' ? 'loopback' : 'HTTPS egress';

  return (
    <aside className="topo-panel topo-info">
      <header className="topo-info-header">
        <div className="topo-info-os" style={{ color: osColor }}>{osLabel}</div>
        <h2 className="topo-info-host" title={hostname}>{hostname}</h2>
        <div className={`topo-info-priv topo-info-priv--${node.priv}`}>
          {PRIV_LABEL[node.priv] ?? node.priv}
        </div>
      </header>

      <dl className="topo-info-grid">
        <Row k="Architecture" v={arch} mono />
        <Row k="User" v={user} mono />
        <Row k="Channel" v={channel} />
        <Row k="Sleep" v={sleep} mono />
        {session && <Row k="Beacon" v={`#${session.beacon_id}`} mono />}
        {session && <Row k="Age" v={`${Math.round(session.age_secs / 60)}m`} mono />}
        {session?.ja3 && <Row k="JA3" v={session.ja3} mono />}
      </dl>

      <section className="topo-info-section">
        <h3 className="topo-info-section-title">Pivot chain</h3>
        {pivotChain && pivotChain.length > 0 ? (
          <ol className="topo-chain">
            {pivotChain.map((hop, i) => (
              <li key={`${hop}-${i}`} className="topo-chain-hop">
                <span className="topo-chain-idx">{i + 1}</span>
                <span className="topo-chain-name">{hop}</span>
              </li>
            ))}
          </ol>
        ) : (
          <div className="topo-info-empty-inline">Direct egress — no pivot hops.</div>
        )}
      </section>

      <section className="topo-info-section">
        <h3 className="topo-info-section-title">Recent tasks</h3>
        {tasks && tasks.length > 0 ? (
          <ul className="topo-tasks">
            {tasks.map((t) => (
              <li key={t.id} className="topo-task">
                <span className="topo-task-id">#{t.id}</span>
                <span className="topo-task-label">{t.label}</span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="topo-info-empty-inline">No tasks queued for this node.</div>
        )}
      </section>
    </aside>
  );
}

function Row({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="topo-info-row">
      <dt className="topo-info-k">{k}</dt>
      <dd className={`topo-info-v ${mono ? 'mono' : ''}`}>{v}</dd>
    </div>
  );
}

export default TopologyInfoPanel;
