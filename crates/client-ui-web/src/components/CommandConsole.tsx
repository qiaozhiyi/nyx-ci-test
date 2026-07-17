/**
 * CommandConsole — the active session's main workspace.
 *
 * Layout: a sticky header (target metadata) + a scrolling task flow
 * (TaskBlock list) + a fixed command input (CommandInput) at the bottom.
 *
 * Async model: commands enqueue immediately on submit (status 'queued'),
 * flip to 'processing' once the task-submitted ack arrives, then resolve to
 * 'completed' (or 'error' if any result has kind==='error') as results drain
 * in from onResult — which only fires when the beacon checks in (~30s). The
 * task list is scoped to the currently selected session and resets on switch.
 *
 * Race note: the backend emits `nyx://task-submitted` BEFORE the send_command
 * invoke promise resolves, so an ack can arrive while its optimistic block
 * doesn't exist yet. Those early acks are stashed in ackStash and consumed
 * by handleSubmit when the entry is inserted.
 */
import { useEffect, useRef, useState } from 'react';
import type { JsonCommand, SessionView } from '../lib/types';
import { sendCommand, onResult, onTaskSubmitted, type TaskSubmitted } from '../lib/invoke';
import { archName, classifyOs } from '../lib/types';
import { OS_LABELS } from '../lib/os-icons';
import { TaskBlock, type TaskEntry } from './TaskBlock';
import { CommandInput } from './CommandInput';
import './CommandConsole.css';

export interface CommandConsoleProps {
  session: SessionView;
}

export function CommandConsole({ session }: CommandConsoleProps) {
  const [tasks, setTasks] = useState<TaskEntry[]>([]);
  const flowRef = useRef<HTMLDivElement>(null);
  // Acks that arrived before their optimistic block was inserted (see header).
  const ackStash = useRef(new Map<number, TaskSubmitted>());
  // Mirror of tasks for synchronous checks inside event handlers (the
  // setTasks updater runs later, so it can't answer "does this block exist?").
  const tasksRef = useRef<TaskEntry[]>([]);
  useEffect(() => {
    tasksRef.current = tasks;
  });

  // Reset the task flow whenever the selected session changes — each console
  // only shows the current session's command history.
  useEffect(() => {
    setTasks([]);
    ackStash.current.clear();
  }, [session.id]);

  // Auto-scroll to the bottom when a new task/result lands.
  useEffect(() => {
    const el = flowRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [tasks]);

  // Listen for task-submitted acks: if it belongs to this session, mark the
  // matching queued task as 'processing' (it's been enqueued server-side).
  useEffect(() => {
    let unsub: (() => void) | undefined;
    let cancelled = false;
    onTaskSubmitted((ack) => {
      if (ack.session !== session.id) return;
      // Ack beat the send_command promise: no block exists yet — stash it so
      // handleSubmit can flip the entry to 'processing' at insertion time.
      if (!tasksRef.current.some((t) => t.task_id === ack.task_id)) {
        ackStash.current.set(ack.task_id, ack);
      }
      setTasks((prev) =>
        prev.map((t) =>
          t.task_id === ack.task_id && t.status === 'queued'
            ? { ...t, status: 'processing' }
            : t,
        ),
      );
    }).then((u) => {
      if (cancelled) u();
      else unsub = u;
    });
    return () => {
      cancelled = true;
      if (unsub) unsub();
    };
  }, [session.id]);

  // Listen for results: attach to the matching task and resolve its status.
  useEffect(() => {
    let unsub: (() => void) | undefined;
    let cancelled = false;
    onResult((r) => {
      setTasks((prev) => {
        // Only the task for THIS session is tracked here; but results carry no
        // session field, so we match by task_id within our local list.
        const idx = prev.findIndex((t) => t.task_id === r.task_id);
        if (idx === -1) return prev; // belongs to another console / unknown
        const task = prev[idx];
        const results = [...task.results, r];
        const status: TaskEntry['status'] =
          r.kind === 'error' ? 'error' : 'completed';
        const next = [...prev];
        next[idx] = { ...task, results, status };
        return next;
      });
    }).then((u) => {
      if (cancelled) u();
      else unsub = u;
    });
    return () => {
      cancelled = true;
      if (unsub) unsub();
    };
  }, []);

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
        task_id: Date.now(),
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
      setTasks((prev) => [...prev, errorTask]);
      return;
    }
    const earlyAck = ackStash.current.get(taskId);
    if (earlyAck) ackStash.current.delete(taskId);
    const entry: TaskEntry = {
      task_id: taskId,
      command_label: label,
      status: earlyAck ? 'processing' : 'queued',
      results: [],
      session: session.id,
      opsec,
    };
    setTasks((prev) => [...prev, entry]);
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
