import type { Page } from '../app/App';
import './Dock.css';

export interface DockProps {
  activePage: Page;
  onPageChange: (p: Page) => void;
  /** Drop the team-server link and return to the connect page. */
  onDisconnect: () => void;
}

interface NavItem {
  id: string;
  icon: string;
  label: string;
  disabled?: boolean;
  badge?: number;
}

// workspace & topology are the two live surfaces; the rest are gated for now.
const NAV: NavItem[] = [
  { id: 'workspace', icon: '⌘', label: '工作区 — 会话与控制台' },
  { id: 'topology', icon: '◈', label: '拓扑 — 3D beacon 图' },
  { id: 'creds', icon: '🔑', label: '凭据库' },
  { id: 'events', icon: '≡', label: '审计 / 事件日志' },
  { id: 'implant', icon: '⚙', label: 'Implant 构建器' },
];

export function Dock({ activePage, onPageChange, onDisconnect }: DockProps) {
  return (
    <nav className="dock" aria-label="主导航">
      <div className="dock-logo" aria-hidden>N</div>

      <div className="dock-nav">
        {NAV.map((item) => {
          const active = !item.disabled && item.id === activePage;
          const classes = ['dock-item'];
          if (active) classes.push('active');
          if (item.disabled) classes.push('disabled');
          return (
            <button
              key={item.id}
              type="button"
              className={classes.join(' ')}
              title={item.label}
              aria-label={item.label}
              disabled={item.disabled}
              onClick={() => {
                if (item.disabled) return;
                onPageChange(item.id as Page);
              }}
            >
              <span className="dock-icon" aria-hidden>{item.icon}</span>
              {!!item.badge && <span className="dock-badge">{item.badge}</span>}
            </button>
          );
        })}
      </div>

      <div className="dock-footer">
        <button
          type="button"
          className="dock-item dock-item--danger"
          title="断开连接"
          aria-label="断开连接"
          onClick={onDisconnect}
        >
          <span className="dock-icon" aria-hidden>⏻</span>
        </button>
        <button
          type="button"
          className="dock-item disabled"
          title="设置（后续版本）"
          aria-label="设置"
          disabled
        >
          <span className="dock-icon" aria-hidden>⋮</span>
        </button>
      </div>
    </nav>
  );
}
