/**
 * Workspace — the primary operator surface.
 *
 * Left: SessionTable (list of live sessions from the 2s poll loop)
 * Right: CommandConsole for the selected session
 *
 * Sessions state lives here (fed by the onSessions event listener); the
 * selected session id is local state. The same sessions array is also
 * surfaced up to App for the Topology page.
 */
import type { SessionView } from '../lib/types';
import { SessionTable } from '../components/SessionTable';
import { CommandConsole } from '../components/CommandConsole';
import './Workspace.css';

export interface WorkspaceProps {
  sessions: SessionView[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

export function Workspace({ sessions, selectedId, onSelect }: WorkspaceProps) {
  const selected = sessions.find((s) => s.id === selectedId) ?? null;

  return (
    <div className="workspace">
      <SessionTable
        sessions={sessions}
        selectedId={selectedId}
        onSelect={onSelect}
      />
      <div className="workspace-main">
        {selected ? (
          <CommandConsole session={selected} />
        ) : (
          <div className="workspace-empty">
            <div className="workspace-empty-title">未选择 session</div>
            <div className="workspace-empty-hint">
              从左侧选择一个 session 开始交互，或投递 payload 等待回连。
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
