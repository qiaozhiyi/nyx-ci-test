/**
 * TopologyPage — 3D network topology view.
 *
 * Container responsibility:
 *   - Own the full-screen canvas div ref and the createTopologyScene lifecycle.
 *   - Own React state: selected node, autoRotate/showLabels/showOsIcons/showEdges.
 *   - Render the React overlay UI (top toggle bar, info panel, legend, stats).
 *
 * The 3D logic itself lives in lib/topology-scene.ts. This file only bridges
 * React state ↔ the scene handle.
 *
 * The scene is created exactly once per mount; session updates flow through
 * handle.update() (incremental diff), so camera orbit, selection and toggles
 * all survive live data refreshes.
 *
 * Animation policy inherited from topology-scene: no CSS @keyframes. The toggle
 * switches here use a plain solid indicator (no blink).
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import {
  createTopologyScene,
  MOCK_NODES,
  MOCK_EDGES,
  sessionsToNodes,
  type TopologyNode,
  type TopologyEdge,
  type TopologySceneHandle,
  type ChannelKind,
} from '../lib/topology-scene';
import type { SessionView } from '../lib/types';
import { TopologyInfoPanel } from '../components/TopologyInfoPanel';
import { TopologyLegend } from '../components/TopologyLegend';
import { TopologyStats } from '../components/TopologyStats';
import './TopologyPage.css';

export interface TopologyPageProps {
  /** Live sessions. When provided (and non-empty) the page uses real nodes;
   *  otherwise it falls back to mock data for the demo. */
  sessions?: SessionView[];
  /** Optional task index: sessionId -> recent task labels. */
  tasksBySession?: Record<string, { id: number; label: string }[]>;
}

interface ToggleState {
  autoRotate: boolean;
  osIcons: boolean;
  edges: boolean;
  labels: boolean;
}

const DEFAULT_TOGGLES: ToggleState = {
  autoRotate: true,
  osIcons: true,
  edges: true,
  labels: true,
};

export function TopologyPage({ sessions, tasksBySession }: TopologyPageProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const handleRef = useRef<TopologySceneHandle | null>(null);
  const [selected, setSelected] = useState<TopologyNode | null>(null);
  const [toggles, setToggles] = useState<ToggleState>(DEFAULT_TOGGLES);
  /** Set when WebGL init throws — renders a fallback panel instead of crashing. */
  const [sceneError, setSceneError] = useState(false);
  // Panel visibility — both panels start open but can be collapsed by the user.
  // The toolbar's 详情/统计 toggles re-open them.
  const [showInfo, setShowInfo] = useState(true);
  const [showStats, setShowStats] = useState(true);

  // Decide node/edge set: prefer real sessions, fall back to mock.
  const { nodes, edges, usingMock } = useMemo<{
    nodes: TopologyNode[];
    edges: TopologyEdge[];
    usingMock: boolean;
  }>(() => {
    if (sessions && sessions.length > 0) {
      // No pivot edges available from the server in MVP — just egress lines.
      const ns = sessionsToNodes(sessions);
      const srv: TopologyNode = {
        id: '__srv__',
        label: 'nyx-srv',
        os: 'debian',
        priv: 'server',
        pos: [0, 0, 0],
        size: 1.6,
        isServer: true,
      };
      const es: TopologyEdge[] = ns.map((n) => ({
        from: '__srv__',
        to: n.id,
        kind: 'https' as const,
      }));
      return { nodes: [srv, ...ns], edges: es, usingMock: false };
    }
    return { nodes: MOCK_NODES, edges: MOCK_EDGES, usingMock: true };
  }, [sessions]);

  // Create the scene exactly once per mount. Later data changes go through
  // handle.update() below — the scene is never rebuilt on a sessions event.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    let handle: TopologySceneHandle;
    try {
      handle = createTopologyScene(el, nodes, edges, {
        onSelect: (n) => setSelected(n),
        // the scene stops auto-rotate on its own when the user picks/clears a
        // node — mirror that back into the toolbar toggle
        onAutoRotateChange: (v) =>
          setToggles((prev) => (prev.autoRotate === v ? prev : { ...prev, autoRotate: v })),
      });
    } catch (err) {
      // WebGL unavailable (outdated WebView / blocked GPU) — fail soft.
      console.error('[topology] 3D scene init failed:', err);
      setSceneError(true);
      return;
    }
    handleRef.current = handle;
    return () => {
      handle.dispose();
      handleRef.current = null;
    };
    // mount-only by design — initial data is read once, updates use handle.update
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Incremental data updates — camera, selection and toggles survive.
  useEffect(() => {
    handleRef.current?.update(nodes, edges);
  }, [nodes, edges]);

  // Drive toggle changes into the scene.
  useEffect(() => {
    handleRef.current?.setAutoRotate(toggles.autoRotate);
  }, [toggles.autoRotate]);
  useEffect(() => {
    handleRef.current?.setShowOsIcons(toggles.osIcons);
  }, [toggles.osIcons]);
  useEffect(() => {
    handleRef.current?.setShowEdges(toggles.edges);
  }, [toggles.edges]);
  useEffect(() => {
    handleRef.current?.setShowLabels(toggles.labels);
  }, [toggles.labels]);

  const setToggle = (key: keyof ToggleState, value: boolean) =>
    setToggles((prev) => ({ ...prev, [key]: value }));

  // Resolve the matching live session for the selected node (best-effort).
  const selectedSession = selected && !usingMock && sessions
    ? sessions.find((s) => s.id === selected.id)
    : undefined;
  // Only real task data — never invent entries for the panel.
  const selectedTasks = selected ? tasksBySession?.[selected.id] : undefined;
  const pivotChain = selected ? pivotChainFor(selected, nodes, edges) : undefined;
  // Channel is known only when an actual edge terminates at the node.
  const selectedChannel: ChannelKind | undefined = selected
    ? edges.find((e) => e.to === selected.id)?.kind
    : undefined;

  return (
    <div className="topo-root">
      <div className="topo-canvas-bg" aria-hidden />
      <div ref={containerRef} className="topo-canvas" />

      {sceneError && (
        <div className="topo-fallback" role="alert">
          <div className="topo-fallback-title">3D 初始化失败</div>
          <div className="topo-fallback-hint">
            无法创建 WebGL 渲染环境。请更新系统 WebView 或显卡驱动后重试。
          </div>
        </div>
      )}

      {/* Top floating toolbar */}
      <div className="topo-toolbar">
        <div className="topo-toolbar-brand">
          <span className="topo-toolbar-brand-mark" aria-hidden>◆</span>
          <span className="topo-toolbar-brand-text">Nyx 拓扑</span>
          {usingMock && <span className="topo-toolbar-tag">演示数据</span>}
        </div>
        <div className="topo-toolbar-toggles">
          <Toggle
            label="自动旋转"
            active={toggles.autoRotate}
            onClick={() => setToggle('autoRotate', !toggles.autoRotate)}
          />
          <Toggle
            label="OS 图标"
            active={toggles.osIcons}
            onClick={() => setToggle('osIcons', !toggles.osIcons)}
          />
          <Toggle
            label="连线"
            active={toggles.edges}
            onClick={() => setToggle('edges', !toggles.edges)}
          />
          <Toggle
            label="标签"
            active={toggles.labels}
            onClick={() => setToggle('labels', !toggles.labels)}
          />
          {/* Panel visibility toggles — re-open a panel after it's been closed. */}
          <Toggle
            label="详情"
            active={showInfo}
            onClick={() => setShowInfo((v) => !v)}
          />
          <Toggle
            label="统计"
            active={showStats}
            onClick={() => setShowStats((v) => !v)}
          />
        </div>
      </div>

      {/* Right detail panel */}
      <TopologyInfoPanel
        node={selected}
        session={selectedSession}
        pivotChain={pivotChain}
        channel={selectedChannel}
        tasks={selectedTasks}
        visible={showInfo}
        onClose={() => setShowInfo(false)}
      />

      {/* Bottom-left legend */}
      <TopologyLegend />

      {/* Bottom-right stats */}
      <TopologyStats
        nodes={nodes}
        edges={edges}
        visible={showStats}
        onClose={() => setShowStats(false)}
      />

      {/* Hint footer */}
      <div className="topo-hint">
        拖拽旋转 · 滚轮缩放 · 右键平移 · 点击节点查看详情
      </div>
    </div>
  );
}

function Toggle({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className={`topo-toggle ${active ? 'is-on' : 'is-off'}`}
      onClick={onClick}
      aria-pressed={active}
    >
      <span className="topo-toggle-led" aria-hidden />
      <span className="topo-toggle-label">{label}</span>
    </button>
  );
}

export default TopologyPage;

// --- helpers ---------------------------------------------------------------

/** Walk edges back to the server to produce an ordered pivot chain. */
function pivotChainFor(
  target: TopologyNode,
  nodes: TopologyNode[],
  edges: TopologyEdge[],
): string[] {
  if (target.priv === 'server') return [];
  // BFS from target back to any server node.
  const labelById = new Map(nodes.map((n) => [n.id, n.label]));
  const incoming = new Map<string, string[]>();
  for (const e of edges) {
    const arr = incoming.get(e.to) ?? [];
    arr.push(e.from);
    incoming.set(e.to, arr);
  }
  const chain: string[] = [target.label];
  let frontier: string | undefined = target.id;
  const seen = new Set<string>([target.id]);
  while (frontier) {
    const preds = incoming.get(frontier);
    if (!preds || preds.length === 0) break;
    const next = preds[0];
    if (seen.has(next)) break;
    seen.add(next);
    const lbl = labelById.get(next);
    if (lbl) chain.unshift(lbl);
    frontier = next;
  }
  return chain;
}
