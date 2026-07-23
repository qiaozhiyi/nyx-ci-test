/**
 * TopologyStats — bottom-right overlay.
 * Live counts across the currently-rendered node set.
 *
 * Visibility is driven by the `visible` prop (parent owns the toggle); the
 * fade/translate is a CSS transition so there is no mount/unmount flicker.
 */
import type { TopologyNode, TopologyEdge } from '../lib/topology-scene';
import './TopologyOverlays.css';

export interface TopologyStatsProps {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  /** Whether the panel is shown. Parent owns this; fade is handled by CSS. */
  visible?: boolean;
  /** Ask the parent to hide the panel (close button). */
  onClose?: () => void;
}

export function TopologyStats({ nodes, edges, visible = true, onClose }: TopologyStatsProps) {
  const total = nodes.length;
  const active = nodes.filter((n) => n.active || (n.priv !== 'server' && !n.stale)).length;
  const stale = nodes.filter((n) => n.stale).length;
  // pivot = session→session edges (smb + tcp), https is server→session egress
  const pivots = edges.filter((e) => e.kind === 'smb' || e.kind === 'tcp').length;

  return (
    <aside
      className={`topo-panel topo-stats ${visible ? 'is-visible' : 'is-hidden'}`}
      aria-hidden={!visible}
    >
      {onClose && (
        <button
          type="button"
          className="topo-panel-close"
          onClick={onClose}
          aria-label="关闭统计面板"
          title="关闭统计"
        >
          ✕
        </button>
      )}
      <Stat value={active} label="活跃" tone="ok" />
      <Stat value={total} label="总数" tone="default" />
      <Stat value={pivots} label="Pivots" tone="warn" />
      <Stat value={stale} label="失联" tone="dim" />
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
