/**
 * topology-scene.ts — Three.js scene logic for the 3D network topology page.
 *
 * Pure TypeScript (no React). Exposes a single factory `createTopologyScene`
 * that owns the entire three.js lifecycle (scene/camera/renderer/controls/
 * nodes/edges/particles/lighting/raycast/animation) and returns a small handle
 * the React layer can drive.
 *
 * Animation policy: every continuous effect (particle flow, server-ring spin,
 * halo pulse, select scale-feedback) is driven by numeric interpolation inside
 * the single requestAnimationFrame loop. NO CSS @keyframes are used anywhere —
 * that pattern caused refresh-time flicker in an earlier iteration.
 *
 * Data policy: the scene is built once; live data changes flow through
 * `handle.update(nodes, edges)`, which diffs by node id (and edge
 * from→to→kind), adding/removing/updating objects in place. Camera orbit,
 * selection and toggle states all survive updates.
 *
 * Resource policy: every Geometry/Material/Texture created here is tracked and
 * disposed — scene-level resources in `dispose()`, per-node/per-edge resources
 * when the diff removes them — so the React page can mount/unmount and live
 * sessions can churn without leaking GPU memory.
 */
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';
import { OutputPass } from 'three/examples/jsm/postprocessing/OutputPass.js';
import { drawOsIcon } from './os-icons';
import { OS_COLORS } from './os-icons';
import type { OsKind } from './types';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type Privilege = 'server' | 'admin' | 'user';
export type ChannelKind = 'https' | 'smb' | 'tcp';

export interface TopologyNode {
  id: string;
  label: string;
  os: OsKind;
  priv: Privilege;
  pos: [number, number, number];
  size: number;
  isServer?: boolean;
  active?: boolean;
  stale?: boolean;
}

export interface TopologyEdge {
  from: string;
  to: string;
  kind: ChannelKind;
}

export interface TopologySceneCallbacks {
  /** Called whenever the user picks (or clears) a node via raycast. */
  onSelect: (node: TopologyNode | null) => void;
  /** Called when the scene itself stops auto-rotate (user picked/cleared a
   *  node) so the React toolbar toggle can stay in sync. */
  onAutoRotateChange?: (v: boolean) => void;
}

export interface TopologySceneHandle {
  /** Tear down everything: cancel RAF, remove listeners, dispose GPU resources. */
  dispose: () => void;
  /** Incrementally reconcile the scene with a new node/edge set (diff by node
   *  id, edge from→to→kind). Camera, selection and toggles are untouched. */
  update: (nodes: TopologyNode[], edges: TopologyEdge[]) => void;
  /** Programmatically select a node by id (null clears). */
  setSelected: (id: string | null) => void;
  /** Toggle OrbitControls auto-rotate. */
  setAutoRotate: (enabled: boolean) => void;
  /** Show/hide hostname label sprites. */
  setShowLabels: (enabled: boolean) => void;
  /** Show/hide edge lines + their flowing particles. */
  setShowEdges: (enabled: boolean) => void;
  /** Show/hide OS icon inside node cards (swaps cached textures). */
  setShowOsIcons: (enabled: boolean) => void;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Node canvas texture is square at this resolution; plenty for a sprite. */
const NODE_TEX = 256;

/**
 * Channel colors — single source of truth. `num` feeds three.js materials,
 * `css` feeds React/DOM overlays (the legend). Keep the two in lockstep.
 */
export const CHANNEL_COLORS: Record<ChannelKind, { num: number; css: string }> = {
  https: { num: 0x3b82f6, css: '#3b82f6' },
  smb: { num: 0xd9a036, css: '#d9a036' },
  tcp: { num: 0xa78bfa, css: '#a78bfa' },
};
const CHANNEL_OPACITY: Record<ChannelKind, number> = {
  https: 0.6,
  smb: 0.5,
  tcp: 0.6,
};
export const CHANNEL_LABEL: Record<ChannelKind, string> = {
  https: 'HTTPS egress',
  smb: 'SMB pivot',
  tcp: 'TCP pivot',
};

/**
 * Tube edge parameters — tuned so edges read as glowing energy filaments.
 * With AdditiveBlending + bloom, these values sit clearly above the bloom
 * threshold while staying thinner than the node cards.
 */
const TUBE_RADIUS = 0.06; // thick enough to read at distance, not chunky
const TUBE_TUBULAR_SEGMENTS = 20; // straight filaments: modest tessellation
const TUBE_RADIAL_SEGMENTS = 8; // round cross-section

/** UnrealBloom — "cosmic star-map" glow. Strength kept moderate so overall
 *  brightness is dominated by material colors (stable across zoom) rather
 *  than the bloom pass (which varies with on-screen element size). */
const BLOOM_STRENGTH = 0.65;
const BLOOM_RADIUS = 0.4;
const BLOOM_THRESHOLD = 0.5;

const SELECT_COLOR = 0x7c5cff; // accent purple (matches tokens --accent)

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Decide a node's "theme color" — drives glow ring + card stroke + halo. */
function nodeThemeColor(n: TopologyNode): number {
  if (n.isServer) return 0x7c5cff;
  if (n.priv === 'admin') return 0xf87171;
  if (n.stale) return 0x525866;
  return hexToNum(OS_COLORS[n.os] ?? OS_COLORS.unknown);
}

function hexToNum(hex: string): number {
  return parseInt(hex.replace('#', ''), 16);
}

function statusDotColor(n: TopologyNode): string {
  if (n.priv === 'admin') return '#f87171'; // red — admin/DA
  if (n.stale) return '#6b7280'; // gray
  if (n.active) return '#3fb68b'; // green
  return '#3a3f4a'; // dim default
}

/**
 * Paint a node card onto a canvas and return it as a THREE.Texture.
 * Layout (canvas is NODE_TEX × NODE_TEX):
 *   1. outer radial glow halo (theme color)
 *   2. main disc: dark radial gradient + theme-color stroke
 *   3. central OS icon (clipped to disc), optional
 *   4. selection: extra purple ring outside the disc
 *   5. status dot in the top-right
 */
function createNodeTexture(
  n: TopologyNode,
  opts: { selected: boolean; showOsIcon: boolean },
): THREE.CanvasTexture {
  const c = document.createElement('canvas');
  c.width = NODE_TEX;
  c.height = NODE_TEX;
  const ctx = c.getContext('2d')!;

  const cx = NODE_TEX / 2;
  const cy = NODE_TEX / 2;
  const themeHex = '#' + nodeThemeColor(n).toString(16).padStart(6, '0');
  const discR = NODE_TEX * 0.36; // ~92px

  // 1. outer glow — radial gradient from theme color to transparent
  const glow = ctx.createRadialGradient(cx, cy, discR * 0.4, cx, cy, NODE_TEX * 0.5);
  glow.addColorStop(0, hexA(themeHex, 0.45));
  glow.addColorStop(0.45, hexA(themeHex, 0.18));
  glow.addColorStop(1, hexA(themeHex, 0));
  ctx.fillStyle = glow;
  ctx.fillRect(0, 0, NODE_TEX, NODE_TEX);

  // 4. selection ring (drawn under the disc so the disc edge sits on top)
  if (opts.selected) {
    const selHex = '#' + SELECT_COLOR.toString(16).padStart(6, '0');
    ctx.beginPath();
    ctx.arc(cx, cy, discR + 14, 0, Math.PI * 2);
    ctx.strokeStyle = selHex;
    ctx.lineWidth = 5;
    ctx.shadowColor = selHex;
    ctx.shadowBlur = 18;
    ctx.stroke();
    ctx.shadowBlur = 0;
  }

  // 2. main disc — dark radial gradient + theme-color stroke
  const disc = ctx.createRadialGradient(cx, cy - 12, 6, cx, cy, discR);
  disc.addColorStop(0, '#11151f');
  disc.addColorStop(0.65, '#0a0f1a');
  disc.addColorStop(1, '#040507');
  ctx.beginPath();
  ctx.arc(cx, cy, discR, 0, Math.PI * 2);
  ctx.fillStyle = disc;
  ctx.fill();
  ctx.lineWidth = 3;
  ctx.strokeStyle = hexA(themeHex, 0.85);
  ctx.stroke();

  // 3. central OS icon, clipped to the disc
  if (opts.showOsIcon) {
    ctx.save();
    ctx.beginPath();
    ctx.arc(cx, cy, discR - 4, 0, Math.PI * 2);
    ctx.clip();
    drawOsIcon(ctx, n.os, cx, cy, discR * 1.15);
    ctx.restore();
  }

  // 5. status dot — top right of the disc
  const dotR = 10;
  const dotX = cx + discR * 0.72;
  const dotY = cy - discR * 0.72;
  ctx.beginPath();
  ctx.arc(dotX, dotY, dotR + 2, 0, Math.PI * 2);
  ctx.fillStyle = 'rgba(8,9,12,0.95)';
  ctx.fill();
  ctx.beginPath();
  ctx.arc(dotX, dotY, dotR - 2, 0, Math.PI * 2);
  ctx.fillStyle = statusDotColor(n);
  ctx.fill();

  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.anisotropy = 4;
  tex.needsUpdate = true;
  return tex;
}

/** Build the hostname label sprite texture (text + drop shadow on transparent). */
function createLabelTexture(label: string): THREE.CanvasTexture {
  const w = 256;
  const h = 64;
  const c = document.createElement('canvas');
  c.width = w;
  c.height = h;
  const ctx = c.getContext('2d')!;
  ctx.font = '600 22px Inter, "Segoe UI", sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.shadowColor = 'rgba(0,0,0,0.85)';
  ctx.shadowBlur = 8;
  ctx.shadowOffsetY = 1;
  ctx.fillStyle = '#e4e4e7';
  ctx.fillText(label.slice(0, 18), w / 2, h / 2);
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

/** Convert "#rrggbb" + alpha (0..1) into an rgba() string. */
function hexA(hex: string, a: number): string {
  const n = parseInt(hex.replace('#', ''), 16);
  const r = (n >> 16) & 255;
  const g = (n >> 8) & 255;
  const b = n & 255;
  return `rgba(${r},${g},${b},${a})`;
}

// ---------------------------------------------------------------------------
// Internal runtime records
// ---------------------------------------------------------------------------

interface NodeRecord {
  node: TopologyNode;
  sprite: THREE.Sprite;
  baseScale: number;
  halo: THREE.Mesh[];
  rings: THREE.Mesh[]; // server-only torus rings
  label: THREE.Sprite;
  /** Distance from the node origin to the label center (clears the card). */
  labelOffset: number;
  texIcon: THREE.Texture; // cached card texture WITH os icon (unselected)
  texPlain: THREE.Texture; // cached card texture WITHOUT os icon (unselected)
  /** Geometries/materials/label textures owned by this node. texIcon/texPlain
   *  and any one-off selected texture are disposed explicitly instead. */
  disposables: { dispose(): void }[];
  /** scale-pulse animation state, >=0 means animating; phase in [0,1]. */
  pulseStart: number;
}

interface EdgeRecord {
  edge: TopologyEdge;
  /** Tube mesh replacing the old THREE.Line — has real volume so edges read in 3D. */
  line: THREE.Mesh;
  particles: { sprite: THREE.Sprite; offset: number }[]; // 2 per edge
  from: THREE.Vector3;
  to: THREE.Vector3;
  /** Materials owned by this edge (tube geometry is disposed via the mesh). */
  disposables: { dispose(): void }[];
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Build the topology scene inside `container`. Returns a handle for the React
 * layer to drive selection, toggles, incremental data updates, and disposal.
 */
export function createTopologyScene(
  container: HTMLElement,
  nodes: TopologyNode[],
  edges: TopologyEdge[],
  callbacks: TopologySceneCallbacks,
): TopologySceneHandle {
  // --- renderer -----------------------------------------------------------
  const renderer = new THREE.WebGLRenderer({
    antialias: true,
    alpha: true,
    powerPreference: 'high-performance',
  });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setSize(container.clientWidth, container.clientHeight, false);
  renderer.setClearColor(0x000000, 0); // CSS paints the radial-gradient backdrop
  // Reinhard tone mapping: smoother luminance transitions than ACES when the
  // camera distance changes (less perceived "dimming on zoom-out"). Materials
  // use toneMapped:false so they write linear values; OutputPass applies this
  // mapping once at the end of the post chain.
  renderer.toneMapping = THREE.ReinhardToneMapping;
  renderer.toneMappingExposure = 1.4;
  renderer.domElement.style.display = 'block';
  renderer.domElement.style.width = '100%';
  renderer.domElement.style.height = '100%';
  container.appendChild(renderer.domElement);

  // --- scene + fog --------------------------------------------------------
  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x06080d, 0.018);

  // --- camera -------------------------------------------------------------
  const camera = new THREE.PerspectiveCamera(
    55,
    container.clientWidth / container.clientHeight,
    0.1,
    500,
  );
  // Camera pulled back from [0,12,34] -> [0,18,52] so the wider (≈1.8x) node
  // envelope fits in the default viewport without the user having to zoom out.
  camera.position.set(0, 18, 52);

  // --- controls -----------------------------------------------------------
  const controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true;
  controls.dampingFactor = 0.08;
  controls.rotateSpeed = 0.7;
  // Zoom range widened + speed bumped so users can read a single card up close
  // (minDistance 4) and still pull back to see the whole spread-out graph
  // (maxDistance 120). Pan enabled — without it "zoom" feels broken when the
  // focus point is off-center.
  controls.enablePan = true;
  controls.zoomSpeed = 1.2;
  controls.minDistance = 4;
  controls.maxDistance = 120;
  controls.autoRotate = true;
  controls.autoRotateSpeed = 0.45;
  controls.target.set(0, 0, 0);

  // --- lighting -----------------------------------------------------------
  scene.add(new THREE.AmbientLight(0xb9c2ff, 0.55));
  const key = new THREE.PointLight(0x7c5cff, 1.4, 120);
  key.position.set(10, 18, 12);
  scene.add(key);
  const fill = new THREE.PointLight(0x3b82f6, 0.7, 120);
  fill.position.set(-14, -6, -10);
  scene.add(fill);

  // --- starfield (700 background points) ----------------------------------
  const starGeo = new THREE.BufferGeometry();
  const STAR_COUNT = 700;
  const starPos = new Float32Array(STAR_COUNT * 3);
  for (let i = 0; i < STAR_COUNT; i++) {
    // distribute in a spherical shell far from the camera
    const r = 90 + Math.random() * 80;
    const theta = Math.random() * Math.PI * 2;
    const phi = Math.acos(2 * Math.random() - 1);
    starPos[i * 3 + 0] = r * Math.sin(phi) * Math.cos(theta);
    starPos[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
    starPos[i * 3 + 2] = r * Math.cos(phi);
  }
  starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
  const starMat = new THREE.PointsMaterial({
    color: 0xc7cbe0,
    size: 0.55,
    sizeAttenuation: true,
    transparent: true,
    opacity: 0.7,
    depthWrite: false,
    toneMapped: false,
    // stars sit 90–170 units out where FogExp2 leaves only ~4% visibility —
    // they are a backdrop and must ignore fog
    fog: false,
  });
  const stars = new THREE.Points(starGeo, starMat);
  scene.add(stars);

  // --- grid floor ---------------------------------------------------------
  const grid = new THREE.GridHelper(120, 60, 0x2a2f45, 0x141826);
  (grid.material as THREE.Material).transparent = true;
  (grid.material as THREE.Material).opacity = 0.32;
  (grid.material as THREE.Material).toneMapped = false;
  grid.position.y = -10;
  scene.add(grid);

  // --- shared state -------------------------------------------------------
  const nodeGroup = new THREE.Group();
  scene.add(nodeGroup);
  const nodeMap = new Map<string, NodeRecord>();
  const edgeGroup = new THREE.Group();
  scene.add(edgeGroup);
  const edgeMap = new Map<string, EdgeRecord>();
  const idToPos = new Map<string, THREE.Vector3>();
  // Scene-level resources (shared, live for the whole mount). Per-node and
  // per-edge resources are tracked on their records instead.
  const disposables: { dispose(): void }[] = [
    starGeo,
    starMat,
    grid.geometry,
    grid.material as THREE.Material,
  ];
  // Toggle state — read when the diff adds new objects so late arrivals
  // respect the current toggles instead of resetting them.
  let showOsIcons = true;
  let showEdges = true;
  let showLabels = true;
  let currentSelectedId: string | null = null;

  // small round particle texture (shared by all edge particles)
  const partCanvas = document.createElement('canvas');
  partCanvas.width = 64;
  partCanvas.height = 64;
  const pctx = partCanvas.getContext('2d')!;
  const partGrad = pctx.createRadialGradient(32, 32, 0, 32, 32, 32);
  partGrad.addColorStop(0, 'rgba(255,255,255,1)');
  partGrad.addColorStop(0.35, 'rgba(255,255,255,0.7)');
  partGrad.addColorStop(1, 'rgba(255,255,255,0)');
  pctx.fillStyle = partGrad;
  pctx.fillRect(0, 0, 64, 64);
  const partTex = new THREE.CanvasTexture(partCanvas);
  partTex.colorSpace = THREE.SRGBColorSpace;
  disposables.push(partTex);

  // --- node lifecycle -----------------------------------------------------

  function addNode(n: TopologyNode): void {
    // card sprite — both cached variants are painted up front; the icon
    // toggle then just swaps `map` instead of repainting
    const texIcon = createNodeTexture(n, { selected: false, showOsIcon: true });
    const texPlain = createNodeTexture(n, { selected: false, showOsIcon: false });
    const cardMat = new THREE.SpriteMaterial({
      map: showOsIcons ? texIcon : texPlain,
      transparent: true,
      depthWrite: false,
      depthTest: true,
      toneMapped: false,
      fog: false, // emissive overlay — FogExp2 would dim it at distance
    });
    const recDisposables: { dispose(): void }[] = [cardMat];
    const sprite = new THREE.Sprite(cardMat);
    // Larger baseline so cards dominate their connecting filaments; server nodes
    // get an extra boost so they read as the central gravity well.
    const baseScale = n.size * 4.6 * (n.isServer ? 1.18 : 1);
    sprite.scale.set(baseScale, baseScale, 1);
    sprite.position.set(n.pos[0], n.pos[1], n.pos[2]);
    sprite.userData.nodeId = n.id;
    nodeGroup.add(sprite);

    // halo: 3 transparent BackSide spheres. Opacities trimmed slightly so the
    // additive bloom does not wash out the node cards.
    const halo: THREE.Mesh[] = [];
    const haloRadii = [n.size * 2.6, n.size * 3.4, n.size * 4.3];
    const haloOpacities = [0.13, 0.06, 0.03];
    for (let i = 0; i < haloRadii.length; i++) {
      const g = new THREE.SphereGeometry(haloRadii[i], 24, 16);
      const m = new THREE.MeshBasicMaterial({
        color: nodeThemeColor(n),
        transparent: true,
        opacity: haloOpacities[i],
        side: THREE.BackSide,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
        toneMapped: false,
        fog: false, // additive overlay — fog would tint it towards the fog color
      });
      recDisposables.push(g, m);
      const mesh = new THREE.Mesh(g, m);
      mesh.position.copy(sprite.position);
      scene.add(mesh);
      halo.push(mesh);
    }

    // server-only torus rings (2, different orientations, purple)
    const rings: THREE.Mesh[] = [];
    if (n.isServer) {
      const ringConfigs: { r: number; tube: number; rot: [number, number, number] }[] = [
        { r: n.size * 2.0, tube: 0.045, rot: [Math.PI / 2, 0, 0] },
        { r: n.size * 2.4, tube: 0.04, rot: [Math.PI / 2.4, Math.PI / 4, 0] },
      ];
      for (const cfg of ringConfigs) {
        const g = new THREE.TorusGeometry(cfg.r, cfg.tube, 12, 80);
        const m = new THREE.MeshBasicMaterial({
          color: SELECT_COLOR,
          transparent: true,
          opacity: 0.55,
          depthWrite: false,
          blending: THREE.AdditiveBlending,
          toneMapped: false,
          fog: false,
        });
        recDisposables.push(g, m);
        const mesh = new THREE.Mesh(g, m);
        mesh.position.copy(sprite.position);
        mesh.rotation.set(cfg.rot[0], cfg.rot[1], cfg.rot[2]);
        scene.add(mesh);
        rings.push(mesh);
      }
    }

    // hostname label sprite
    const labelTex = createLabelTexture(n.label);
    const labelMat = new THREE.SpriteMaterial({
      map: labelTex,
      transparent: true,
      depthWrite: false,
      depthTest: true,
      toneMapped: false,
      fog: false, // text must stay readable at any distance
    });
    recDisposables.push(labelTex, labelMat);
    const label = new THREE.Sprite(labelMat);
    const labelScale = n.size * 3.6;
    label.scale.set(labelScale, labelScale * 0.25, 1);
    // Clear the card's lower edge: card half-height is baseScale/2 (≈ size*2.3),
    // the label's own half-height is (labelScale*0.25)/2 — the old fixed
    // size*2.0 offset overlapped the card.
    const labelOffset = baseScale / 2 + (labelScale * 0.25) / 2 + n.size * 0.25;
    label.position.set(n.pos[0], n.pos[1] - labelOffset, n.pos[2]);
    label.visible = showLabels;
    scene.add(label);

    nodeMap.set(n.id, {
      node: n,
      sprite,
      baseScale,
      halo,
      rings,
      label,
      labelOffset,
      texIcon,
      texPlain,
      disposables: recDisposables,
      pulseStart: -1,
    });
  }

  function removeNode(id: string): void {
    const rec = nodeMap.get(id);
    if (!rec) return;
    nodeGroup.remove(rec.sprite);
    scene.remove(rec.label);
    for (const h of rec.halo) scene.remove(h);
    for (const r of rec.rings) scene.remove(r);
    // dispose the one-off selected texture if it happens to be bound
    const bound = (rec.sprite.material as THREE.SpriteMaterial).map;
    if (bound && bound !== rec.texIcon && bound !== rec.texPlain) bound.dispose();
    rec.texIcon.dispose();
    rec.texPlain.dispose();
    for (const d of rec.disposables) d.dispose();
    nodeMap.delete(id);
  }

  /** Re-position an existing node record in place (sprite + halo + rings + label). */
  function moveNode(rec: NodeRecord, n: TopologyNode): void {
    rec.sprite.position.set(n.pos[0], n.pos[1], n.pos[2]);
    for (const h of rec.halo) h.position.copy(rec.sprite.position);
    for (const r of rec.rings) r.position.copy(rec.sprite.position);
    rec.label.position.set(n.pos[0], n.pos[1] - rec.labelOffset, n.pos[2]);
  }

  /** Repaint the cached card textures after OS/priv/status changes — theme
   *  stroke, status dot and halo tint all derive from those fields. */
  function repaintNodeCard(rec: NodeRecord): void {
    const mat = rec.sprite.material as THREE.SpriteMaterial;
    const bound = mat.map;
    if (bound && bound !== rec.texIcon && bound !== rec.texPlain) bound.dispose();
    rec.texIcon.dispose();
    rec.texPlain.dispose();
    rec.texIcon = createNodeTexture(rec.node, { selected: false, showOsIcon: true });
    rec.texPlain = createNodeTexture(rec.node, { selected: false, showOsIcon: false });
    mat.map = rec.node.id === currentSelectedId
      ? createNodeTexture(rec.node, { selected: true, showOsIcon: showOsIcons })
      : showOsIcons ? rec.texIcon : rec.texPlain;
    mat.needsUpdate = true;
    const theme = nodeThemeColor(rec.node);
    for (const h of rec.halo) (h.material as THREE.MeshBasicMaterial).color.setHex(theme);
  }

  /** Swap a card between its cached unselected texture and an on-demand
   *  selected (ring) variant. Only ever runs for the previously- and
   *  newly-selected node — the whole scene is never repainted on a click. */
  function bindCardTexture(rec: NodeRecord, selected: boolean): void {
    const mat = rec.sprite.material as THREE.SpriteMaterial;
    const bound = mat.map;
    mat.map = selected
      ? createNodeTexture(rec.node, { selected: true, showOsIcon: showOsIcons })
      : showOsIcons ? rec.texIcon : rec.texPlain;
    mat.needsUpdate = true;
    // the replaced one-off selected texture is disposed immediately instead
    // of accumulating in the disposables list
    if (bound && bound !== rec.texIcon && bound !== rec.texPlain) bound.dispose();
  }

  function applySelectedVisual(id: string | null) {
    if (id === currentSelectedId) return;
    const prevRec = currentSelectedId ? nodeMap.get(currentSelectedId) : undefined;
    const nextRec = id ? nodeMap.get(id) : undefined;
    if (id && !nextRec) return; // unknown id — leave the current selection alone
    currentSelectedId = id;
    if (prevRec) bindCardTexture(prevRec, false);
    if (nextRec) {
      bindCardTexture(nextRec, true);
      nextRec.pulseStart = performance.now();
    }
  }

  // --- edge lifecycle -----------------------------------------------------

  /** Stable edge identity for diffing: endpoints + channel kind. */
  function edgeKey(e: TopologyEdge): string {
    return `${e.from}→${e.to}→${e.kind}`;
  }

  function addEdge(e: TopologyEdge): void {
    const from = idToPos.get(e.from);
    const to = idToPos.get(e.to);
    if (!from || !to) return; // endpoint node missing — skip
    const color = CHANNEL_COLORS[e.kind].num;
    const opacity = CHANNEL_OPACITY[e.kind];

    // tube edge — a thin glowing filament with real volume. Built from a
    // CatmullRomCurve3 (straight two-point) so tubularSegments can stay low.
    // Additive blending makes the colour saturate where filaments cross and
    // lifts edges clearly above the bloom threshold so they glow.
    const curve = new THREE.CatmullRomCurve3([from.clone(), to.clone()]);
    const geo = new THREE.TubeGeometry(curve, TUBE_TUBULAR_SEGMENTS, TUBE_RADIUS, TUBE_RADIAL_SEGMENTS, false);
    const mat = new THREE.MeshBasicMaterial({
      color,
      transparent: true,
      opacity,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      toneMapped: false,
      fog: false, // additive filament — fog would tint it at distance
    });
    const line = new THREE.Mesh(geo, mat);
    edgeGroup.add(line);

    // 2 particles with phase offset 0.5
    const particles: { sprite: THREE.Sprite; offset: number }[] = [];
    const recDisposables: { dispose(): void }[] = [mat];
    for (let i = 0; i < 2; i++) {
      const pm = new THREE.SpriteMaterial({
        map: partTex,
        color,
        transparent: true,
        opacity: 0.95,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
        toneMapped: false,
        fog: false,
      });
      recDisposables.push(pm);
      const sp = new THREE.Sprite(pm);
      const sc = 0.55;
      sp.scale.set(sc, sc, 1);
      edgeGroup.add(sp);
      particles.push({ sprite: sp, offset: i * 0.5 });
    }
    // The tube geometry is tracked on the mesh itself (retessellated when an
    // endpoint moves); partTex is shared and owned by the scene-level list.
    edgeMap.set(edgeKey(e), {
      edge: e,
      line,
      particles,
      from: from.clone(),
      to: to.clone(),
      disposables: recDisposables,
    });
  }

  function removeEdge(key: string): void {
    const rec = edgeMap.get(key);
    if (!rec) return;
    edgeGroup.remove(rec.line);
    for (const p of rec.particles) edgeGroup.remove(p.sprite);
    rec.line.geometry.dispose();
    for (const d of rec.disposables) d.dispose();
    edgeMap.delete(key);
  }

  // --- incremental data update ---------------------------------------------

  /**
   * Reconcile the scene with a new node/edge set. Nodes diff by id, edges by
   * from→to→kind: new objects are added, departed ones removed (their GPU
   * resources disposed), changed ones updated in place. Camera, selection
   * and toggle states are untouched.
   */
  function updateNodesEdges(nextNodes: TopologyNode[], nextEdges: TopologyEdge[]): void {
    // --- nodes: add / update ---
    const seen = new Set<string>();
    for (const n of nextNodes) {
      seen.add(n.id);
      const rec = nodeMap.get(n.id);
      if (!rec) {
        addNode(n);
        continue;
      }
      const prev = rec.node;
      // size/label/isServer drive the sprite scale, halo/ring radii and the
      // label texture — rebuilding the record is cheaper than retessellating.
      if (prev.size !== n.size || prev.label !== n.label || !!prev.isServer !== !!n.isServer) {
        const wasSelected = currentSelectedId === n.id;
        removeNode(n.id);
        addNode(n);
        if (wasSelected) {
          // re-apply the ring on the rebuilt record (no pulse — not a click)
          const fresh = nodeMap.get(n.id);
          if (fresh) bindCardTexture(fresh, true);
        }
        continue;
      }
      rec.node = n;
      if (prev.pos[0] !== n.pos[0] || prev.pos[1] !== n.pos[1] || prev.pos[2] !== n.pos[2]) {
        moveNode(rec, n);
      }
      if (prev.os !== n.os || prev.priv !== n.priv || !!prev.stale !== !!n.stale || !!prev.active !== !!n.active) {
        repaintNodeCard(rec);
      }
    }
    // --- nodes: remove departed ---
    for (const id of [...nodeMap.keys()]) {
      if (seen.has(id)) continue;
      if (currentSelectedId === id) {
        // the selected node left the graph — clear the React-side panel too
        currentSelectedId = null;
        callbacks.onSelect(null);
      }
      removeNode(id);
    }

    // --- edges ---
    idToPos.clear();
    for (const n of nextNodes) {
      idToPos.set(n.id, new THREE.Vector3(n.pos[0], n.pos[1], n.pos[2]));
    }
    const seenEdges = new Set<string>();
    for (const e of nextEdges) {
      const key = edgeKey(e);
      seenEdges.add(key);
      const from = idToPos.get(e.from);
      const to = idToPos.get(e.to);
      if (!from || !to) continue; // endpoint node missing — skip
      const rec = edgeMap.get(key);
      if (!rec) {
        addEdge(e);
        continue;
      }
      rec.edge = e;
      if (!rec.from.equals(from) || !rec.to.equals(to)) {
        // endpoint moved — retessellate the tube; particles follow in tick()
        const curve = new THREE.CatmullRomCurve3([from.clone(), to.clone()]);
        rec.line.geometry.dispose();
        rec.line.geometry = new THREE.TubeGeometry(curve, TUBE_TUBULAR_SEGMENTS, TUBE_RADIUS, TUBE_RADIAL_SEGMENTS, false);
        rec.from.copy(from);
        rec.to.copy(to);
      }
    }
    for (const key of [...edgeMap.keys()]) {
      if (!seenEdges.has(key)) removeEdge(key);
    }
  }

  // initial data load — same code path as every later incremental update
  updateNodesEdges(nodes, edges);

  // --- raycast click handling --------------------------------------------
  const raycaster = new THREE.Raycaster();
  const pointer = new THREE.Vector2();
  let pointerDownAt: { x: number; y: number; t: number } | null = null;

  /** Scene-initiated auto-rotate stop — notify React so the toggle stays honest. */
  function stopAutoRotate() {
    if (!controls.autoRotate) return;
    controls.autoRotate = false;
    callbacks.onAutoRotateChange?.(false);
  }

  function setPointer(ev: PointerEvent) {
    const rect = renderer.domElement.getBoundingClientRect();
    pointer.x = ((ev.clientX - rect.left) / rect.width) * 2 - 1;
    pointer.y = -((ev.clientY - rect.top) / rect.height) * 2 + 1;
  }

  function onPointerDown(ev: PointerEvent) {
    pointerDownAt = { x: ev.clientX, y: ev.clientY, t: performance.now() };
  }

  function onClick(ev: MouseEvent) {
    // Guard: ignore if this was a drag (pointer moved much or held long).
    // OrbitControls may swallow pointerup during a drag, so we listen on the
    // native `click` event which only fires for genuine clicks.
    if (!pointerDownAt) {
      // pointerdown was lost (e.g. started on a different element); still
      // attempt the pick from the click coordinates.
      pointerDownAt = { x: ev.clientX, y: ev.clientY, t: performance.now() };
    }
    const dx = ev.clientX - pointerDownAt.x;
    const dy = ev.clientY - pointerDownAt.y;
    const moved = Math.hypot(dx, dy);
    const dt = performance.now() - pointerDownAt.t;
    pointerDownAt = null;
    // treat as a click only when pointer barely moved + was quick
    if (moved > 6 || dt > 800) return;

    setPointer(ev as unknown as PointerEvent);
    raycaster.setFromCamera(pointer, camera);
    // Recursive: hit any descendant. Filter to Sprites that carry a nodeId,
    // since halo/ring meshes live on the scene (not nodeGroup) but we
    // defensive-filter anyway.
    const hits = raycaster.intersectObjects(nodeGroup.children, true);
    const nodeHit = hits.find((h) => {
      const o = h.object as THREE.Object3D;
      return o.userData && typeof o.userData.nodeId === 'string';
    });
    if (!nodeHit) {
      // click on empty space (or non-node mesh) clears selection
      if (currentSelectedId !== null) {
        applySelectedVisual(null);
        callbacks.onSelect(null);
        stopAutoRotate(); // stays off once user has interacted
      }
      return;
    }
    const id = (nodeHit.object as THREE.Object3D).userData.nodeId as string;
    const rec = nodeMap.get(id);
    if (!rec) return;
    applySelectedVisual(id);
    // re-clicking the selected node still pulses (applySelectedVisual no-ops there)
    rec.pulseStart = performance.now();
    // picking a node turns off auto-rotate (explicit user focus)
    stopAutoRotate();
    callbacks.onSelect(rec.node);
  }

  renderer.domElement.addEventListener('pointerdown', onPointerDown);
  renderer.domElement.addEventListener('click', onClick);

  // --- resize -------------------------------------------------------------
  const resize = () => {
    const w = container.clientWidth;
    const h = container.clientHeight;
    if (w === 0 || h === 0) return;
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(w, h, false);
    composer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    composer.setSize(w, h);
  };
  const ro = new ResizeObserver(resize);
  ro.observe(container);

  // --- post-processing: UnrealBloom "star-map" pipeline -------------------
  // RenderPass draws the scene into an HDR target, UnrealBloomPass lifts the
  // bright filaments / node glows / stars into a soft halo, and OutputPass
  // applies ACES tone mapping + sRGB transfer at the very end (so tone mapping
  // happens AFTER bloom — that is what makes highlights bloom, not get crushed).
  const composer = new EffectComposer(renderer);
  composer.addPass(new RenderPass(scene, camera));
  const bloomPass = new UnrealBloomPass(
    new THREE.Vector2(container.clientWidth || 1, container.clientHeight || 1),
    BLOOM_STRENGTH,
    BLOOM_RADIUS,
    BLOOM_THRESHOLD,
  );
  composer.addPass(bloomPass);
  composer.addPass(new OutputPass());

  // --- animation loop ------------------------------------------------------
  let rafId = 0;
  const tmp = new THREE.Vector3();

  function tick() {
    const now = performance.now() / 1000;

    // server torus rings: continuous spin
    for (const rec of nodeMap.values()) {
      for (let i = 0; i < rec.rings.length; i++) {
        const ring = rec.rings[i];
        const dir = i === 0 ? 1 : -1;
        ring.rotation.z += dir * 0.006;
        ring.rotation.x += dir * 0.0024;
      }
      // subtle halo breathing
      const breathe = 1 + Math.sin(now * 1.1 + rec.node.pos[0]) * 0.025;
      for (let i = 0; i < rec.halo.length; i++) {
        rec.halo[i].scale.setScalar(breathe);
      }
      // select scale-feedback (1.25 -> 1 over 220ms)
      if (rec.pulseStart > 0) {
        const elapsed = performance.now() - rec.pulseStart;
        const DUR = 220;
        if (elapsed >= DUR) {
          rec.sprite.scale.set(rec.baseScale, rec.baseScale, 1);
          rec.pulseStart = -1;
        } else {
          const t = elapsed / DUR;
          // ease-out cubic from 1.25 to 1.0
          const k = 1.25 - 0.25 * (1 - Math.pow(1 - t, 3));
          rec.sprite.scale.set(rec.baseScale * k, rec.baseScale * k, 1);
        }
      }
    }

    // flowing particles along edges
    if (showEdges) {
      for (const er of edgeMap.values()) {
        for (const p of er.particles) {
          const u = ((now * 0.18) + p.offset) % 1;
          tmp.copy(er.from).lerp(er.to, u);
          p.sprite.position.copy(tmp);
        }
      }
    }

    // slow starfield rotation for parallax
    stars.rotation.y += 0.0002;

    controls.update();
    composer.render();
    rafId = requestAnimationFrame(tick);
  }
  rafId = requestAnimationFrame(tick);

  // --- handle -------------------------------------------------------------
  const handle: TopologySceneHandle = {
    dispose() {
      cancelAnimationFrame(rafId);
      ro.disconnect();
      renderer.domElement.removeEventListener('pointerdown', onPointerDown);
      renderer.domElement.removeEventListener('click', onClick);
      // per-node + per-edge resources (records delete themselves from the maps)
      for (const id of [...nodeMap.keys()]) removeNode(id);
      for (const key of [...edgeMap.keys()]) removeEdge(key);
      // dispose every tracked scene-level resource
      for (const d of disposables) {
        try {
          d.dispose();
        } catch {
          /* some geometries share disposers — ignore */
        }
      }
      controls.dispose();
      // free pass-level resources (bloom render targets/materials), then the
      // composer's own render targets
      for (const p of composer.passes) p.dispose();
      composer.dispose();
      renderer.dispose();
      // release the WebGL context itself so repeated mount/unmount cannot
      // accumulate live contexts
      if (typeof renderer.forceContextLoss === 'function') renderer.forceContextLoss();
      if (renderer.domElement.parentElement === container) {
        container.removeChild(renderer.domElement);
      }
    },
    update(nextNodes: TopologyNode[], nextEdges: TopologyEdge[]) {
      updateNodesEdges(nextNodes, nextEdges);
    },
    setSelected(id: string | null) {
      if (id === currentSelectedId) return;
      applySelectedVisual(id);
      if (id) {
        const rec = nodeMap.get(id);
        if (rec) callbacks.onSelect(rec.node);
      } else {
        callbacks.onSelect(null);
      }
    },
    setAutoRotate(enabled: boolean) {
      controls.autoRotate = enabled;
    },
    setShowLabels(enabled: boolean) {
      showLabels = enabled;
      for (const rec of nodeMap.values()) rec.label.visible = enabled;
    },
    setShowEdges(enabled: boolean) {
      showEdges = enabled;
      edgeGroup.visible = enabled;
    },
    setShowOsIcons(enabled: boolean) {
      if (enabled === showOsIcons) return;
      showOsIcons = enabled;
      // swap each card between its cached icon/plain textures — no repaints
      for (const rec of nodeMap.values()) {
        bindCardTexture(rec, rec.node.id === currentSelectedId);
      }
    },
  };

  return handle;
}

// ---------------------------------------------------------------------------
// Mock data (MVP demo). Real sessions can be passed in by the React page.
// ---------------------------------------------------------------------------

export const MOCK_NODES: TopologyNode[] = [
  // size hierarchy: server (central gravity well) >> admin > user, so the
  // hierarchy reads at a glance. Effective card scale spans ~3x.
  // Positions spread ~1.8x wider than the original ±11 envelope so cards do
  // not overlap at the default zoom (server stays at the origin).
  { id: 'srv', label: 'nyx-srv', os: 'debian', priv: 'server', pos: [0, 0, 0], size: 2.2, isServer: true },
  { id: 'dc01', label: 'DC-01', os: 'win-server', priv: 'admin', pos: [14.4, 3.6, -10.8], size: 1.4, active: true },
  { id: 'win7', label: 'WIN-7F3A', os: 'windows', priv: 'user', pos: [-16.2, 5.4, -7.2], size: 0.85 },
  { id: 'db', label: 'DB-SRV', os: 'ubuntu', priv: 'user', pos: [12.6, -7.2, 14.4], size: 0.85 },
  { id: 'web', label: 'WEB-EDGE', os: 'debian', priv: 'user', pos: [-12.6, -5.4, 16.2], size: 0.8 },
  { id: 'fs', label: 'FS-01', os: 'windows', priv: 'user', pos: [19.8, -1.8, 9], size: 0.8 },
  { id: 'mac', label: 'DEV-MAC', os: 'macos', priv: 'user', pos: [-5.4, 10.8, 10.8], size: 0.78, stale: true },
  { id: 'kali', label: 'PWN-01', os: 'kali', priv: 'user', pos: [5.4, 12.6, -14.4], size: 0.78 },
];

export const MOCK_EDGES: TopologyEdge[] = [
  { from: 'srv', to: 'dc01', kind: 'https' },
  { from: 'srv', to: 'win7', kind: 'https' },
  { from: 'srv', to: 'db', kind: 'https' },
  { from: 'srv', to: 'web', kind: 'https' },
  { from: 'srv', to: 'mac', kind: 'https' },
  { from: 'srv', to: 'kali', kind: 'https' },
  { from: 'dc01', to: 'fs', kind: 'smb' },
  { from: 'web', to: 'fs', kind: 'tcp' },
];

// ---------------------------------------------------------------------------
// Optional helper: convert live SessionView[] into topology nodes.
// Exported for the React page; the page decides whether to use mock or real.
// ---------------------------------------------------------------------------

import type { SessionView } from './types';
import { classifyOs, archName } from './types';

/** Spherical random distribution for live sessions (no pivot edges available). */
export function sessionsToNodes(sessions: SessionView[]): TopologyNode[] {
  return sessions.map((s, i) => {
    const phi = Math.acos(1 - 2 * (i + 0.5) / Math.max(sessions.length, 1));
    const theta = Math.PI * (1 + Math.sqrt(5)) * (i + 0.5);
    // Sphere radius enlarged from 10 -> 19 so live-session nodes spread out to
    // match the wider mock-data envelope (cards no longer overlap at default zoom).
    const r = 19;
    return {
      id: s.id,
      label: s.hostname || s.id.slice(0, 8),
      os: classifyOs(s.os),
      priv: s.is_admin ? 'admin' : 'user',
      pos: [r * Math.sin(phi) * Math.cos(theta), r * Math.cos(phi) - 2, r * Math.sin(phi) * Math.sin(theta)],
      // mirror the mock hierarchy: admins read larger than regular users
      size: s.is_admin ? 1.4 : 0.85,
      active: !s.stale,
      stale: s.stale,
    };
  });
}

/** Re-export so callers can render arch without an extra import hop. */
export { archName };
