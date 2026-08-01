/**
 * TaskStore — App-level task/result state, keyed by session id.
 *
 * CommandConsole used to own the task list locally and reset it on every
 * session switch, losing each session's history. This provider lifts that
 * state up so a session's command flow survives switching back and forth.
 *
 * Routing: the Rust poll loop emits `nyx://result` events stamped with
 * `session_id` (see src-tauri/src/poll.rs); results are applied to the
 * matching session's list by (session_id, task_id).
 *
 * Race note: the backend emits `nyx://task-submitted` BEFORE the send_command
 * invoke promise resolves, so an ack can arrive while its optimistic block
 * doesn't exist yet. Early acks are stashed here and consumed by the console
 * when it inserts the entry.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  type Dispatch,
  type ReactNode,
} from 'react';
import type { ResultView } from '../lib/types';
import type { TaskEntry } from '../components/TaskBlock';
import {
  onResult,
  onTaskSubmitted,
  type TaskSubmitted,
} from '../lib/invoke';

/** Per-session task flows, keyed by session id. */
export type TaskMap = Record<string, TaskEntry[]>;

type TaskAction =
  | { type: 'addTask'; session: string; entry: TaskEntry }
  | { type: 'ack'; session: string; taskId: number }
  | { type: 'result'; session: string; result: ResultView }
  | { type: 'clear' };

function taskReducer(state: TaskMap, action: TaskAction): TaskMap {
  switch (action.type) {
    case 'addTask': {
      const list = state[action.session] ?? [];
      // Guard against duplicate inserts (e.g. retried submit with same id).
      if (list.some((t) => t.task_id === action.entry.task_id)) return state;
      return { ...state, [action.session]: [...list, action.entry] };
    }
    case 'ack': {
      const list = state[action.session];
      if (!list) return state;
      const next = list.map((t) =>
        t.task_id === action.taskId && t.status === 'queued'
          ? { ...t, status: 'processing' as const }
          : t,
      );
      return next === list ? state : { ...state, [action.session]: next };
    }
    case 'result': {
      const list = state[action.session];
      if (!list) return state;
      const idx = list.findIndex((t) => t.task_id === action.result.task_id);
      if (idx === -1) return state; // task not issued here — ignore
      const task = list[idx];
      const results = [...task.results, action.result];
      const status: TaskEntry['status'] =
        action.result.kind === 'error' ? 'error' : 'completed';
      const next = [...list];
      next[idx] = { ...task, results, status };
      return { ...state, [action.session]: next };
    }
    case 'clear':
      return {};
  }
}

export interface TaskStoreValue {
  /** All session task flows; read `tasksBySession[sessionId] ?? []`. */
  tasksBySession: TaskMap;
  dispatch: Dispatch<TaskAction>;
  /** Pop (and delete) a stashed early ack for the given task, if any. */
  consumeEarlyAck: (session: string, taskId: number) => TaskSubmitted | undefined;
  /** Forget every session's history (used on explicit disconnect). */
  clearAll: () => void;
}

const TaskStoreContext = createContext<TaskStoreValue | null>(null);

export function TaskStoreProvider({ children }: { children: ReactNode }) {
  const [tasksBySession, dispatch] = useReducer(taskReducer, {});
  // Acks that arrived before their optimistic block was inserted (see header).
  const ackStash = useRef(new Map<string, TaskSubmitted>());
  // Mirror of the task map for synchronous existence checks inside event
  // handlers (the reducer runs later, so state can't answer "does this block
  // exist?" at event time).
  const tasksRef = useRef<TaskMap>({});
  useEffect(() => {
    tasksRef.current = tasksBySession;
  });

  // Listen once for the lifetime of the app: both events are session-stamped
  // by the backend, so a single subscription routes into any session's flow.
  useEffect(() => {
    let unsubAck: (() => void) | undefined;
    let unsubResult: (() => void) | undefined;
    let cancelled = false;

    onTaskSubmitted((ack) => {
      const key = `${ack.session}:${ack.task_id}`;
      const exists = (tasksRef.current[ack.session] ?? []).some(
        (t) => t.task_id === ack.task_id,
      );
      if (!exists) {
        // Ack beat the send_command promise: no block exists yet — stash it so
        // the console can flip the entry to 'processing' at insertion time.
        ackStash.current.set(key, ack);
        return;
      }
      dispatch({ type: 'ack', session: ack.session, taskId: ack.task_id });
    }).then((u) => {
      if (cancelled) u();
      else unsubAck = u;
    });

    onResult((evt) => {
      const { session_id, ...result } = evt;
      dispatch({ type: 'result', session: session_id, result });
    }).then((u) => {
      if (cancelled) u();
      else unsubResult = u;
    });

    return () => {
      cancelled = true;
      if (unsubAck) unsubAck();
      if (unsubResult) unsubResult();
    };
  }, []);

  const consumeEarlyAck = useCallback((session: string, taskId: number) => {
    const key = `${session}:${taskId}`;
    const ack = ackStash.current.get(key);
    if (ack) ackStash.current.delete(key);
    return ack;
  }, []);

  const clearAll = useCallback(() => {
    ackStash.current.clear();
    dispatch({ type: 'clear' });
  }, []);

  const value = useMemo<TaskStoreValue>(
    () => ({ tasksBySession, dispatch, consumeEarlyAck, clearAll }),
    [tasksBySession, consumeEarlyAck, clearAll],
  );

  return (
    <TaskStoreContext.Provider value={value}>{children}</TaskStoreContext.Provider>
  );
}

export function useTaskStore(): TaskStoreValue {
  const ctx = useContext(TaskStoreContext);
  if (!ctx) throw new Error('useTaskStore must be used within TaskStoreProvider');
  return ctx;
}
