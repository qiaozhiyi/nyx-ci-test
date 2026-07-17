import type { Page } from '../app/App';
import './Dock.css';

export interface DockProps {
  activePage: Page;
  onPageChange: (p: Page) => void;
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
  { id: 'workspace', icon: '⌘', label: 'Workspace — Sessions & Console' },
  { id: 'topology', icon: '◈', label: 'Topology — 3D beacon graph' },
  { id: 'creds', icon: '🔑', label: 'Credentials (later release)', disabled: true },
  { id: 'downloads', icon: '📁', label: 'Downloads (later release)', disabled: true, badge: 3 },
  { id: 'events', icon: '≡', label: 'Event stream (later release)', disabled: true },
  { id: 'implant', icon: '⚙', label: 'Implant builder (later release)', disabled: true },
];

export function Dock({ activePage, onPageChange }: DockProps) {
  return (
    <nav className="dock" aria-label="Primary navigation">
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
          className="dock-item disabled"
          title="Settings (later release)"
          aria-label="Settings"
          disabled
        >
          <span className="dock-icon" aria-hidden>⋮</span>
        </button>
      </div>
    </nav>
  );
}
