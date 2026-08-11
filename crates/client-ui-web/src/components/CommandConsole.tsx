/**
 * CommandConsole — the active session's main workspace.
 *
 * Layout: a sticky header (target metadata) + a scrolling task flow
 * (TaskBlock list) + a fixed command input (CommandInput) at the bottom.
 *
 * Async model: commands enqueue immediately on submit (status 'queued'),
 * flip to 'processing' once the task-submitted ack arrives, then resolve to
 * 'completed' (or 'error' if any result has kind==='error') as results drain
 * in — which only fires when the beacon checks in (~30s). Task/result state
 * lives in the App-level TaskStore keyed by session id, so switching sessions
 * preserves each session's command history instead of resetting it.
 *
 * Race note: the backend emits `nyx://task-submitted` BEFORE the send_command
 * invoke promise resolves, so an ack can arrive while its optimistic block
 * doesn't exist yet. Those early acks are stashed in the TaskStore and
 * consumed by handleSubmit when the entry is inserted.
 */
import { useEffect, useRef } from 'react';
import type { JsonCommand, SessionView } from '../lib/types';
import { sendCommand } from '../lib/invoke';
import { archName, classifyOs } from '../lib/types';
import { OS_LABELS } from '../lib/os-icons';
import { useTaskStore } from '../app/taskStore';
import { TaskBlock, type TaskEntry } from './TaskBlock';
import { CommandInput } from './CommandInput';
import './CommandConsole.css';

// 下发失败块的本地 id：模块级递增负计数器，保证唯一且不与服务器正 id 冲突
// （之前用 Date.now()，同毫秒两次失败会被 addTask 去重丢掉）。
let nextLocalErrorId = -1;

export interface CommandConsoleProps {
  session: SessionView;
}

export function CommandConsole({ session }: CommandConsoleProps) {
  const { tasksBySession, dispatch, consumeEarlyAck } = useTaskStore();
  const tasks = tasksBySession[session.id] ?? [];
  const flowRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to the bottom when a new task/result lands — but only if the
  // operator is already near the bottom. Yanking the view down while they
  // scroll back through history (screenwatch frames keep arriving) made the
  // console unreadable.
  useEffect(() => {
    const el = flowRef.current;
    if (el && el.scrollHeight - el.scrollTop - el.clientHeight < 120) {
      el.scrollTop = el.scrollHeight;
    }
  }, [tasks]);

  // Submit handler: send to backend, then insert an optimistic entry. If the
  // task-submitted ack already arrived (see header race note), skip 'queued'
  // and go straight to 'processing'.
  async function handleSubmit(command: JsonCommand, label: string, opsec = false) {
    let taskId = -1;
    try {
      taskId = await sendCommand(session.id, command, label);
    } catch {
      // Surface as an immediate error block so the operator sees the failure.
      const errorTask: TaskEntry = {
        task_id: nextLocalErrorId--,
        command_label: label,
        status: 'error',
        results: [
          {
            task_id: -1,
            kind: 'error',
            text: '下发失败：无法连接 team server 或命令被拒绝。',
          },
        ],
        session: session.id,
        opsec,
      };
      dispatch({ type: 'addTask', session: session.id, entry: errorTask });
      return;
    }
    const earlyAck = consumeEarlyAck(session.id, taskId);
    const entry: TaskEntry = {
      task_id: taskId,
      command_label: label,
      status: earlyAck ? 'processing' : 'queued',
      results: [],
      session: session.id,
      opsec,
    };
    dispatch({ type: 'addTask', session: session.id, entry });
  }

  const osKind = classifyOs(session.os);
  const osLabel = OS_LABELS[osKind] ?? session.os;
  const isAdmin = session.is_admin === 1;

  return (
    <div className="console">
      <header className="console__head">
        <div className="console__ident">
          <span className="console__host mono">{session.hostname}</span>
          <span className="console__user mono">{session.username}</span>
          <span
            className={`pill pill--perm${isAdmin ? ' pill--perm-admin' : ''}`}
            title={isAdmin ? '高权限会话' : '普通权限'}
          >
            {isAdmin ? 'admin' : 'user'}
          </span>
          <span className="pill pill--os" title={session.os}>
            {osLabel}
          </span>
        </div>
        <div className="console__meta mono">
          {/* pending = queued task count on the server; surfaces the async nature */}
          {session.pending > 0 && (
            <span className="console__pending" title="队列中待 beacon 拉取的任务数">
              ◇ {session.pending} queued
            </span>
          )}
          <span className="console__arch" title="架构">
            {archName(session.arch)}
          </span>
          <span className="console__pid" title="PID">
            pid {session.pid}
          </span>
        </div>
      </header>

      <div className="console__flow" ref={flowRef}>
        {tasks.length === 0 ? (
          <div className="console__empty">
            <div className="console__empty-title mono">
              {session.hostname} #
            </div>
            <div className="console__empty-hint">
              没有任务。在下方输入命令开始操作这个 beacon。
            </div>
            <div className="console__empty-async mono">
              命令下发后进入队列，等待 beacon check-in（约 30s）后执行回流。
            </div>
          </div>
        ) : (
          tasks.map((t) => <TaskBlock key={t.task_id} task={t} onCommand={handleSubmit} />)
        )}
      </div>

      <div className="console__input">
        <CommandInput session={session} onSubmit={handleSubmit} />
      </div>
    </div>
  );
}
