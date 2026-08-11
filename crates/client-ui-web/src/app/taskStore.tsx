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

/**
 * 内存治理阈值(审计发现 #3):results 只增不减,截图/下载的 data_hex 单条可达
 * 12MB(字节),全留 React state 会让长时间 screenwatch 的 WebView 膨胀到崩溃。
 * MAX_TASKS_PER_SESSION — 每会话最多保留的任务块数。任务块高度不定、虚拟化
 * 收益低风险高,故不引入;300 块对长时间操作仍留有充足历史,超出丢弃最旧块,
 * 顺带控制 DOM 规模。MAX_RESULT_BYTES_PER_SESSION — 每会话全部结果的 data_hex
 * 字节总预算。单张 1080p BMP 约 12MB,64MB 约可保留最近 5 张截图外加若干下载
 * 块;超预算时从最旧块开始剥离 data_hex(text 追加丢弃标记)直到回到预算内。
 */
const MAX_TASKS_PER_SESSION = 300;
const MAX_RESULT_BYTES_PER_SESSION = 64 * 1024 * 1024;

/** Per-session task flows, keyed by session id. */
export type TaskMap = Record<string, TaskEntry[]>;

/** 剥离单个结果的 data_hex;text 已有内容不动,追加丢弃标记。 */
function stripDataHex(r: ResultView): ResultView {
  return {
    ...r,
    data_hex: undefined,
    text: `${r.text} [大结果已丢弃以释放内存]`,
  };
}

/** 对一个会话的任务列表执行上限治理:块数上限 + data_hex 字节预算。 */
function enforceSessionLimits(list: TaskEntry[]): TaskEntry[] {
  // 块数上限:超出的最旧块整体丢弃。
  const capped =
    list.length > MAX_TASKS_PER_SESSION
      ? list.slice(list.length - MAX_TASKS_PER_SESSION)
      : list;
  // data_hex 字节预算:超预算时从最旧块开始剥离,直到回到预算内。
  let bytes = 0;
  for (const t of capped) {
    for (const r of t.results) if (r.data_hex) bytes += r.data_hex.length / 2;
  }
  if (bytes <= MAX_RESULT_BYTES_PER_SESSION) return capped;
  const next: TaskEntry[] = [];
  for (const t of capped) {
    if (bytes <= MAX_RESULT_BYTES_PER_SESSION) {
      next.push(t);
      continue;
    }
    let changed = false;
    const results = t.results.map((r) => {
      if (bytes <= MAX_RESULT_BYTES_PER_SESSION || !r.data_hex) return r;
      bytes -= r.data_hex.length / 2;
      changed = true;
      return stripDataHex(r);
    });
    next.push(changed ? { ...t, results } : t);
  }
  return next;
}

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
      return { ...state, [action.session]: enforceSessionLimits([...list, action.entry]) };
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
      return { ...state, [action.session]: enforceSessionLimits(next) };
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
