/**
 * TopologyStats — bottom-right overlay.
 * Live counts across the currently-rendered node set.
 */
import type { TopologyNode, TopologyEdge } from '../lib/topology-scene';
import './TopologyOverlays.css';

export interface TopologyStatsProps {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

export function TopologyStats({ nodes, edges }: TopologyStatsProps) {
  const total = nodes.length;
  const active = nodes.filter((n) => n.active || (n.priv !== 'server' && !n.stale)).length;
  const stale = nodes.filter((n) => n.stale).length;
  // pivot = session→session edges (smb + tcp), https is server→session egress
  const pivots = edges.filter((e) => e.kind === 'smb' || e.kind === 'tcp').length;

  return (
    <aside className="topo-panel topo-stats">
      <Stat value={active} label="Active" tone="ok" />
      <Stat value={total} label="Total" tone="default" />
      <Stat value={pivots} label="Pivots" tone="warn" />
      <Stat value={stale} label="Stale" tone="dim" />
    </aside>
  );
}

function Stat({
  value,
  label,
  tone,
}: {
  value: number;
  label: string;
  tone: 'ok' | 'warn' | 'dim' | 'default';
}) {
  return (
    <div className={`topo-stat topo-stat--${tone}`}>
      <div className="topo-stat-value mono">{value}</div>
      <div className="topo-stat-label">{label}</div>
    </div>
  );
}

export default TopologyStats;
