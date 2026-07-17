/**
 * TopologyLegend — bottom-left overlay.
 * Three groups: OS color swatches, status dot meanings, channel types.
 * Channel colors come from CHANNEL_COLORS in topology-scene (single source
 * of truth shared with the 3D edge materials).
 */
import { OS_COLORS, OS_LABELS } from '../lib/os-icons';
import type { OsKind } from '../lib/types';
import type { ChannelKind } from '../lib/topology-scene';
import { CHANNEL_COLORS, CHANNEL_LABEL } from '../lib/topology-scene';
import './TopologyOverlays.css';

const LEGEND_OSES: OsKind[] = [
  'windows', 'win-server', 'ubuntu', 'debian', 'macos', 'kali',
];

const STATUSES: { color: string; label: string }[] = [
  { color: '#3fb68b', label: '活跃' },
  { color: '#6b7280', label: '失联' },
  { color: '#f87171', label: '管理员' },
];

export function TopologyLegend() {
  return (
    <aside className="topo-panel topo-legend">
      <h3 className="topo-legend-title">图例</h3>

      <section className="topo-legend-group">
        <div className="topo-legend-group-title">操作系统</div>
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
        <div className="topo-legend-group-title">状态</div>
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
        <div className="topo-legend-group-title">通道</div>
        <ul className="topo-legend-list">
          {(Object.keys(CHANNEL_LABEL) as ChannelKind[]).map((k) => (
            <li key={k} className="topo-legend-item">
              <span
                className="topo-line"
                style={{ background: CHANNEL_COLORS[k].css }}
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
