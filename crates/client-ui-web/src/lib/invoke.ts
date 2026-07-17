/**
 * Typed Tauri invoke wrappers. Thin layer over @tauri-apps/api invoke.
 * Also provides typed event listeners for the poll-loop emissions.
 */
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type { SessionView, ResultView, JsonCommand } from './types';

/** Connect to a team server. Throws on auth failure. */
export function connect(server: string, bearer: string): Promise<void> {
  return invoke('connect', { server, bearer });
}

export function disconnect(): Promise<void> {
  return invoke('disconnect');
}

/**
 * Send a command to a session. The frontend builds the JsonCommand;
 * the Rust backend forwards it verbatim to POST /api/task.
 * Returns the assigned task_id.
 */
export function sendCommand(
  session: string,
  command: JsonCommand,
  commandLabel: string,
): Promise<number> {
  return invoke('send_command', { session, command, commandLabel });
}

/** Subscribe to session list updates (emitted by the 2s poll loop). */
export function onSessions(cb: (s: SessionView[]) => void): Promise<UnlistenFn> {
  return listen<SessionView[]>('nyx://sessions', (e) => cb(e.payload));
}

/** Subscribe to individual task results. */
export function onResult(cb: (r: ResultView) => void): Promise<UnlistenFn> {
  return listen<ResultView>('nyx://result', (e) => cb(e.payload));
}

/** Subscribe to task-submitted acks (immediate feedback on enqueue). */
export function onTaskSubmitted(cb: (t: { task_id: number; session: string; chan?: number }) => void): Promise<UnlistenFn> {
  return listen('nyx://task-submitted', (e) => cb(e.payload as any));
}

/** Subscribe to backend errors (e.g. auth failure, network). */
export function onError(cb: (msg: string) => void): Promise<UnlistenFn> {
  return listen<string>('nyx://error', (e) => cb(e.payload));
}
