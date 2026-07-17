/**
 * Official OS SVG path data (from Simple Icons / official sources).
 * Used by the 3D topology to render pixel-accurate OS logos onto nodes
 * via Path2D + Canvas → Three.js texture.
 *
 * viewBox is 0 0 24 24 for all (Simple Icons convention).
 */
import type { OsKind } from './types';

export const OS_PATHS: Record<OsKind, string> = {
  // Windows 11 four-squares (official Microsoft geometry, normalized to 24x24 viewBox)
  windows: 'M0 0h11.38v11.38H0zm12.62 0H24v11.38H12.62zM0 12.62h11.38V24H0zm12.62 0H24V24H12.62z',
  'win-server': 'M0 0h11.38v11.38H0zm12.62 0H24v11.38H12.62zM0 12.62h11.38V24H0zm12.62 0H24V24H12.62z',
  // Ubuntu (official Simple Icons — three "friend" circles)
  ubuntu: 'M17.61.455a3.41 3.41 0 0 0-3.41 3.41 3.41 3.41 0 0 0 3.41 3.41 3.41 3.41 0 0 0 3.41-3.41 3.41 3.41 0 0 0-3.41-3.41zM1.844 9.926a3.41 3.41 0 1 0 0 6.82 3.41 3.41 0 0 0 0-6.82zm15.288 8.169a3.41 3.41 0 1 0 3.287 3.407 3.41 3.41 0 0 0-3.287-3.407z',
  // Debian (official Simple Icons swirl)
  debian: 'M13.88 12.685c-.4 0 .08.2.601.28.14-.1.27-.22.39-.33a3.001 3.001 0 01-.99.05m2.14-.53c.23-.33.4-.69.47-1.06-.06.27-.2.57-.35.86-.78.49-1.65.28-1.94-.27-.04-.12-.07-.25-.08-.38-.27.51-.69.86-1.18.86-.91 0-1.65-.86-1.65-1.92 0-.51.18-.97.47-1.31-.31.16-.69.55-.84 1.13-.15.58-.05 1.19.18 1.71.23.52.59.96 1.02 1.26.43.3.94.46 1.46.43.52-.03 1.05-.25 1.45-.7l.04-.05c.16-.21.29-.46.36-.73',
  // Apple (official Simple Icons silhouette — bitten apple + leaf)
  macos: 'M12.152 6.896c-.948 0-2.415-1.078-3.96-1.04-2.04.027-3.91 1.183-4.961 3.014-2.117 3.675-.546 9.103 1.519 12.09 1.013 1.454 2.208 3.09 3.792 3.039 1.52-.065 2.09-.987 3.935-.987 1.831 0 2.35.987 3.96.948 1.637-.026 2.676-1.48 3.676-2.948 1.156-1.688 1.636-3.325 1.662-3.415-.039-.013-3.182-1.221-3.182-4.859 0-3.013 2.458-4.458 2.573-4.536-1.405-2.063-3.587-2.295-4.353-2.352zM15.062 4.627c.83-.987 1.389-2.362 1.236-3.73-1.196.052-2.644.797-3.501 1.783-.77.872-1.444 2.266-1.262 3.617 1.331.104 2.696-.676 3.527-1.67z',
  // Kali Linux (official Simple Icons dragon mark)
  kali: 'M12.778 5.943s-1.97-.13-5.327.92c-3.42 1.07-5.36 2.587-5.36 2.587s5.098-2.847 10.852-3.008zm7.351 3.095l.257-.017s-1.67-1.487-3.781-2.355c0 0 .724 1.489.724 2.355l1.8.722zm-1.753-.692s-.026-1.111-.654-2.139c0 0-2.804-.87-5.687-.043 0 0-.626 1.435-.626 2.182 0 0 .56-.26 3.088-.26 3.654 0 6.06 1.637 6.06 1.637s-.026-.766-.181-1.377zm-1.06 8.394c.088.043.337.034.337.034l.99-.394-.447-.394-.882.754zm-3.262-3.17c.05-.043.402-.45.864-.45.46 0 .585.497.585.497l-1.45-.047zm-3.72 4.477c0 .793.389 1.629.389 1.629l1.25-.567-.389-1.062-1.25 0zm-3.57-6.058s1.69-.566 3.5-.566l.587-1.543s-1.69-.07-3.5.566l-.587 1.543zm5.95-1.28l-.587 1.37s3.05.142 4.66 1.033l.67-1.283s-1.9-.83-4.74-1.12zm-7.4 2.51l-.587 1.37s2.16.142 3.77 1.033l.67-1.283s-1.0-.83-3.85-1.12zm10.35 2.4l-.587 1.37s1.16.142 2.77 1.033l.67-1.283s-2-.83-2.85-1.12z',
  // Fedora (official Simple Icons)
  fedora: 'M12.001 0C5.376 0 .008 5.369.004 11.992H.002v9.287h.002A2.726 2.726 0 0 0 2.73 24h9.275c6.626-.004 11.993-5.372 11.993-11.998C24 5.375 18.628.001 12.001 0z',
  // Alpine (official Simple Icons hexagon mountain)
  alpine: 'M12 1.607L2 19.393h20L12 1.607zm0 4.186l6.5 11.6H5.5L12 5.793z',
  // Arch (official Simple Icons triangular A)
  arch: 'M11.39.605C10.376 3.092 9.764 4.72 8.635 7.132c.693.734 1.543 1.589 2.923 2.554-1.484-.61-2.496-1.224-3.252-1.86C6.86 10.836 5.08 14.05 1.605 20.196c2.746-1.586 4.877-2.564 6.858-2.936a5.41 5.41 0 01-.14-1.268l.004-.094c.047-1.834.999-3.246 2.13-3.15 1.13.096 2.013 1.66 1.966 3.494a5.06 5.06 0 01-.112.978c1.957.385 4.062 1.36 6.776 2.936-.534-.984-1.012-1.871-1.467-2.718',
  // Red Hat (official Simple Icons)
  rhel: 'M16.009 13.386c1.577 0 3.86-.326 3.86-2.202a1.765 1.765 0 0 0-.04-.431l-.94-4.08c-.216-.898-.406-1.305-1.982-2.093-1.221-.624-3.878-1.646-4.668-1.646-.732 0-.947.946-1.821.946-.842 0-1.467-.706-2.255-.706-.756 0-1.252.515-1.63 1.574 0 0-1.06 2.99-1.197 3.422-.024.094-.024.18-.024.275 0 1.294 5.096 5.541 11.867 5.541z',
  unknown: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm-1 5h2v6h-2zm0 8h2v2h-2z',
};

export const OS_COLORS: Record<OsKind, string> = {
  windows: '#0078d4',
  'win-server': '#00a4ef',
  ubuntu: '#e95420',
  debian: '#a81d33',
  macos: '#9ca3af',
  kali: '#2fa8d8',
  fedora: '#51a2da',
  alpine: '#0d597f',
  arch: '#1793d1',
  rhel: '#ee0000',
  unknown: '#525866',
};

export const OS_LABELS: Record<OsKind, string> = {
  windows: 'Windows',
  'win-server': 'Windows Server',
  ubuntu: 'Ubuntu',
  debian: 'Debian',
  macos: 'macOS',
  kali: 'Kali Linux',
  fedora: 'Fedora',
  alpine: 'Alpine',
  arch: 'Arch',
  rhel: 'RHEL',
  unknown: 'Unknown',
};

/**
 * Render an OS icon onto a 2D canvas context at the given position/size.
 * Used both by the 3D topology (canvas→texture) and could be reused for 2D lists.
 */
export function drawOsIcon(
  ctx: CanvasRenderingContext2D,
  os: OsKind,
  cx: number,
  cy: number,
  size: number,
): void {
  const pathData = OS_PATHS[os] || OS_PATHS.unknown;
  const color = OS_COLORS[os] || OS_COLORS.unknown;
  ctx.save();
  ctx.translate(cx - size / 2, cy - size / 2);
  ctx.scale(size / 24, size / 24);
  const p = new Path2D(pathData);
  ctx.fillStyle = color;
  ctx.fill(p);
  ctx.restore();
}
