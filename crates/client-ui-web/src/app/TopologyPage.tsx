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
  // Panel visibility — both panels start open but can be collapsed by the user.
  // The toolbar's "Details"/"Stats" toggles re-open them.
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

  // Build the scene once per node/edge set change.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const handle = createTopologyScene(el, nodes, edges, {
      onSelect: (n) => setSelected(n),
    });
    handleRef.current = handle;
    return () => {
      handle.dispose();
      handleRef.current = null;
    };
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
  const selectedTasks = selected
    ? tasksBySession?.[selected.id] ?? mockTasksFor(selected.id)
    : undefined;
  const pivotChain = selected ? mockPivotChain(selected, nodes, edges) : undefined;

  return (
    <div className="topo-root">
      <div className="topo-canvas-bg" aria-hidden />
      <div ref={containerRef} className="topo-canvas" />

      {/* Top floating toolbar */}
      <div className="topo-toolbar">
        <div className="topo-toolbar-brand">
          <span className="topo-toolbar-brand-mark" aria-hidden>◆</span>
          <span className="topo-toolbar-brand-text">Nyx Topology</span>
          {usingMock && <span className="topo-toolbar-tag">demo data</span>}
        </div>
        <div className="topo-toolbar-toggles">
          <Toggle
            label="Auto-rotate"
            active={toggles.autoRotate}
            onClick={() => setToggle('autoRotate', !toggles.autoRotate)}
          />
          <Toggle
            label="OS icons"
            active={toggles.osIcons}
            onClick={() => setToggle('osIcons', !toggles.osIcons)}
          />
          <Toggle
            label="Edges"
            active={toggles.edges}
            onClick={() => setToggle('edges', !toggles.edges)}
          />
          <Toggle
            label="Labels"
            active={toggles.labels}
            onClick={() => setToggle('labels', !toggles.labels)}
          />
          {/* Panel visibility toggles — re-open a panel after it's been closed. */}
          <Toggle
            label="Details"
            active={showInfo}
            onClick={() => setShowInfo((v) => !v)}
          />
          <Toggle
            label="Stats"
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
        Drag to orbit · Scroll to zoom · Right-drag to pan · Click a node to inspect
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

// --- demo helpers (only used when no live data) ---------------------------

/** Mock recent tasks for a node id. */
function mockTasksFor(id: string): { id: number; label: string }[] {
  if (id === 'srv' || id === '__srv__') return [];
  return [
    { id: 1, label: 'whoami /groups' },
    { id: 2, label: 'sleep 8 15' },
  ];
}

/** Walk edges back to the server to produce an ordered pivot chain. */
function mockPivotChain(
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
