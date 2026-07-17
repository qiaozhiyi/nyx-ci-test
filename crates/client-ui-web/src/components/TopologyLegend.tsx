/**
 * TopologyLegend — bottom-left overlay.
 * Three groups: OS color swatches, status dot meanings, channel types.
 */
import { OS_COLORS, OS_LABELS } from '../lib/os-icons';
import type { OsKind } from '../lib/types';
import type { ChannelKind } from '../lib/topology-scene';
import { CHANNEL_LABEL } from '../lib/topology-scene';
import './TopologyOverlays.css';

const LEGEND_OSES: OsKind[] = [
  'windows', 'win-server', 'ubuntu', 'debian', 'macos', 'kali',
];

const CHANNEL_COLOR: Record<ChannelKind, string> = {
  https: '#3b82f6',
  smb: '#d9a036',
  tcp: '#a78bfa',
};

const STATUSES: { color: string; label: string }[] = [
  { color: '#3fb68b', label: 'Active' },
  { color: '#6b7280', label: 'Stale' },
  { color: '#f87171', label: 'Admin / DA' },
];

export function TopologyLegend() {
  return (
    <aside className="topo-panel topo-legend">
      <h3 className="topo-legend-title">Legend</h3>

      <section className="topo-legend-group">
        <div className="topo-legend-group-title">Operating systems</div>
        <ul className="topo-legend-list">
          {LEGEND_OSES.map((os) => (
            <li key={os} className="topo-legend-item">
              <span
                className="topo-swatch"
                style={{ background: OS_COLORS[os] }}
              />
              <span className="topo-legend-label">{OS_LABELS[os]}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="topo-legend-group">
        <div className="topo-legend-group-title">Status</div>
        <ul className="topo-legend-list">
          {STATUSES.map((s) => (
            <li key={s.label} className="topo-legend-item">
              <span
                className="topo-dot"
                style={{ background: s.color }}
              />
              <span className="topo-legend-label">{s.label}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="topo-legend-group">
        <div className="topo-legend-group-title">Channels</div>
        <ul className="topo-legend-list">
          {(Object.keys(CHANNEL_LABEL) as ChannelKind[]).map((k) => (
            <li key={k} className="topo-legend-item">
              <span
                className="topo-line"
                style={{ background: CHANNEL_COLOR[k] }}
              />
              <span className="topo-legend-label">{CHANNEL_LABEL[k]}</span>
            </li>
          ))}
        </ul>
      </section>
    </aside>
  );
}

export default TopologyLegend;
