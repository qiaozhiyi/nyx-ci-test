/**
 * TopologyInfoPanel — right-side floating detail panel.
 * Renders only the metadata actually carried by the selected node/session:
 * hostname, OS, arch, user, privilege, state, channel (when an upstream edge
 * exists) and pending task count. Nothing is fabricated — unknown values
 * render as "—".
 * Frosted-glass surface (backdrop-filter) overlaying the canvas.
 *
 * Visibility is driven by the `visible` prop (parent owns the toggle). When
 * hidden the panel is kept mounted but faded + translated off-screen via CSS
 * transition so there is no mount/unmount flicker. A small close button in the
 * header calls `onClose` to ask the parent to hide it.
 */
import type { TopologyNode, ChannelKind } from '../lib/topology-scene';
import { CHANNEL_LABEL } from '../lib/topology-scene';
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
  /** Upstream channel kind — only when an actual edge terminates at the node. */
  channel?: ChannelKind;
  /** Recent task labels for this node (real data only). */
  tasks?: { id: number; label: string }[];
  /** Whether the panel is shown. Parent owns this; fade is handled by CSS. */
  visible?: boolean;
  /** Ask the parent to hide the panel (close button). */
  onClose?: () => void;
}

const PRIV_LABEL: Record<string, string> = {
  server: 'Team Server',
  admin: '管理员',
  user: '普通用户',
};

export function TopologyInfoPanel({
  node,
  session,
  pivotChain,
  channel,
  tasks,
  visible = true,
  onClose,
}: TopologyInfoPanelProps) {
  return (
    <aside
      className={`topo-panel topo-info ${node ? '' : 'topo-info-empty'} ${visible ? 'is-visible' : 'is-hidden'}`}
      aria-hidden={!visible}
    >
      {/* Close button — always rendered so it works in both empty & filled states.
          Small translucent circle, top-right of the panel. */}
      {onClose && (
        <button
          type="button"
          className="topo-panel-close"
          onClick={onClose}
          aria-label="关闭详情面板"
          title="关闭详情"
        >
          ✕
        </button>
      )}

      {!node ? (
        <>
          <div className="topo-info-empty-glyph" aria-hidden>◇</div>
          <div className="topo-info-empty-title">未选择节点</div>
          <div className="topo-info-empty-hint">
            点击拓扑中的节点，查看其元数据、Pivot 链路与任务。
          </div>
        </>
      ) : (
        <>
          <header className="topo-info-header">
            <div className="topo-info-os" style={{ color: OS_COLORS[session ? classifyOs(session.os) : node.os] }}>
              {OS_LABELS[session ? classifyOs(session.os) : node.os]}
            </div>
            <h2 className="topo-info-host" title={session ? session.hostname : node.label}>
              {session ? session.hostname : node.label}
            </h2>
            <div className={`topo-info-priv topo-info-priv--${node.priv}`}>
              {PRIV_LABEL[node.priv] ?? node.priv}
            </div>
          </header>

          <dl className="topo-info-grid">
            <Row k="架构" v={session ? archName(session.arch) : '—'} mono />
            <Row k="用户" v={session?.username ? session.username : '—'} mono />
            <Row k="状态" v={node.stale ? '失联' : node.active ? '活跃' : '—'} />
            <Row k="通道" v={channel ? CHANNEL_LABEL[channel] : '—'} />
            <Row k="待办任务" v={session ? String(session.pending) : '—'} mono />
            {session && <Row k="Beacon" v={`#${session.beacon_id}`} mono />}
            {session && <Row k="上线时长" v={`${Math.round(session.age_secs / 60)} 分钟`} mono />}
            {session?.ja3 && <Row k="JA3" v={session.ja3} mono />}
          </dl>

          <section className="topo-info-section">
            <h3 className="topo-info-section-title">Pivot 链路</h3>
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
              <div className="topo-info-empty-inline">直连 egress — 无 Pivot 跳点。</div>
            )}
          </section>

          <section className="topo-info-section">
            <h3 className="topo-info-section-title">最近任务</h3>
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
              <div className="topo-info-empty-inline">该节点暂无排队任务。</div>
            )}
          </section>
        </>
      )}
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
