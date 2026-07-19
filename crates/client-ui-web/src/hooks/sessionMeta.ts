/**
 * Session metadata overlay — operator-local annotations.
 *
 * The team server has no session rename/tag/star API, and metadata like this
 * is operator-local context (which box is the DC, which is the foothold),
 * not data the server needs to track. So we persist to localStorage keyed by
 * session id. This keeps the overlay instant, offline-capable, and free of a
 * backend round-trip.
 *
 * Key layout: `nyx:session-meta:{sessionId}` -> JSON SessionMeta (v1).
 * A separate index key `nyx:session-meta:index` lists known session ids so we
 * can enumerate metadata without scanning every localStorage key.
 */
import { useCallback, useEffect, useState } from 'react';

const KEY_PREFIX = 'nyx:session-meta:';
const INDEX_KEY = 'nyx:session-meta:index';
const SCHEMA_VERSION = 1;

export interface SessionMeta {
  /** Schema version for forward-compatible migration. */
  v: number;
  /** Operator-chosen display name. When set, replaces hostname in the table. */
  alias?: string;
  /** Free-form tags, rendered as badges. Lowercased on store for dedup. */
  tags: string[];
  /** Pinned to top of the session list when true. */
  starred: boolean;
  /** Free-text operator notes. */
  notes?: string;
  /** ms timestamp of last edit — used for tie-breaking starred sort. */
  updated_at?: number;
}

export const EMPTY_META: SessionMeta = { v: SCHEMA_VERSION, tags: [], starred: false };

function storageKey(sessionId: string): string {
  return KEY_PREFIX + sessionId;
}

function isBrowser(): boolean {
  return typeof window !== 'undefined' && typeof window.localStorage !== 'undefined';
}

function safeParse(raw: string | null): SessionMeta | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<SessionMeta>;
    // Migrate / normalize: ensure required fields exist.
    return {
      v: parsed.v ?? SCHEMA_VERSION,
      alias: typeof parsed.alias === 'string' && parsed.alias.length > 0 ? parsed.alias : undefined,
      tags: Array.isArray(parsed.tags)
        ? parsed.tags.filter((t) => typeof t === 'string' && t.length > 0).map((t) => t.toLowerCase())
        : [],
      starred: Boolean(parsed.starred),
      notes: typeof parsed.notes === 'string' && parsed.notes.length > 0 ? parsed.notes : undefined,
      updated_at: typeof parsed.updated_at === 'number' ? parsed.updated_at : undefined,
    };
  } catch {
    return null;
  }
}

function readRaw(sessionId: string): SessionMeta {
  if (!isBrowser()) return EMPTY_META;
  const parsed = safeParse(window.localStorage.getItem(storageKey(sessionId)));
  return parsed ?? EMPTY_META;
}

function writeRaw(sessionId: string, meta: SessionMeta): void {
  if (!isBrowser()) return;
  const next = { ...meta, v: SCHEMA_VERSION, updated_at: Date.now() };
  window.localStorage.setItem(storageKey(sessionId), JSON.stringify(next));
  bumpIndex(sessionId);
}

/** Keep the id index in sync so listAll can enumerate without key scanning. */
function bumpIndex(sessionId: string): void {
  if (!isBrowser()) return;
  try {
    const raw = window.localStorage.getItem(INDEX_KEY);
    const ids: string[] = raw ? (JSON.parse(raw) as string[]) : [];
    if (!ids.includes(sessionId)) {
      ids.push(sessionId);
      window.localStorage.setItem(INDEX_KEY, JSON.stringify(ids));
    }
  } catch {
    // Corrupt index is non-fatal — metadata still works per-session.
  }
}

/** Return metadata for every session id we have ever annotated. */
export function listAllSessionMeta(): Record<string, SessionMeta> {
  if (!isBrowser()) return {};
  const out: Record<string, SessionMeta> = {};
  try {
    const raw = window.localStorage.getItem(INDEX_KEY);
    const ids: string[] = raw ? (JSON.parse(raw) as string[]) : [];
    for (const id of ids) {
      const meta = readRaw(id);
      if (meta !== EMPTY_META) out[id] = meta;
    }
  } catch {
    // ignore
  }
  return out;
}

/** Clear metadata for one session (used by forget/clear actions). */
export function clearSessionMeta(sessionId: string): void {
  if (!isBrowser()) return;
  window.localStorage.removeItem(storageKey(sessionId));
  try {
    const raw = window.localStorage.getItem(INDEX_KEY);
    const ids: string[] = raw ? (JSON.parse(raw) as string[]) : [];
    const next = ids.filter((id) => id !== sessionId);
    window.localStorage.setItem(INDEX_KEY, JSON.stringify(next));
  } catch {
    // ignore
  }
}

/**
 * React hook: read/write one session's metadata. Persists on every mutation
 * and re-renders subscribers. Listens for cross-window `storage` events so
 * two operator windows on the same profile stay in sync.
 */
export function useSessionMeta(sessionId: string | null) {
  const [meta, setMeta] = useState<SessionMeta>(() => (sessionId ? readRaw(sessionId) : EMPTY_META));

  // Reload whenever the session id changes.
  useEffect(() => {
    if (!sessionId) {
      setMeta(EMPTY_META);
      return;
    }
    setMeta(readRaw(sessionId));
  }, [sessionId]);

  // Cross-tab/cross-window sync via the storage event.
  useEffect(() => {
    if (!isBrowser() || !sessionId) return;
    const onStorage = (e: StorageEvent) => {
      if (e.key === storageKey(sessionId)) {
        setMeta(safeParse(e.newValue) ?? EMPTY_META);
      }
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, [sessionId]);

  const update = useCallback(
    (patch: Partial<Omit<SessionMeta, 'v' | 'updated_at'>>) => {
      if (!sessionId) return;
      setMeta((prev) => {
        const merged: SessionMeta = {
          ...prev,
          ...patch,
          v: SCHEMA_VERSION,
        };
        // Normalize tags on write.
        if (patch.tags !== undefined) {
          merged.tags = patch.tags
            .map((t) => t.trim().toLowerCase())
            .filter((t) => t.length > 0);
          // de-dup preserving order
          merged.tags = Array.from(new Set(merged.tags));
        }
        if (patch.alias !== undefined) {
          const a = patch.alias.trim();
          merged.alias = a.length > 0 ? a : undefined;
        }
        if (patch.notes !== undefined) {
          const n = patch.notes.trim();
          merged.notes = n.length > 0 ? n : undefined;
        }
        writeRaw(sessionId, merged);
        return merged;
      });
    },
    [sessionId],
  );

  const toggleStar = useCallback(() => {
    if (!sessionId) return;
    setMeta((prev) => {
      const merged: SessionMeta = { ...prev, starred: !prev.starred, v: SCHEMA_VERSION };
      writeRaw(sessionId, merged);
      return merged;
    });
  }, [sessionId]);

  const addTag = useCallback(
    (tag: string) => {
      const t = tag.trim().toLowerCase();
      if (!t || !sessionId) return;
      setMeta((prev) => {
        if (prev.tags.includes(t)) return prev;
        const merged: SessionMeta = { ...prev, tags: [...prev.tags, t], v: SCHEMA_VERSION };
        writeRaw(sessionId, merged);
        return merged;
      });
    },
    [sessionId],
  );

  const removeTag = useCallback((tag: string) => {
    if (!sessionId) return;
    setMeta((prev) => {
      const merged: SessionMeta = {
        ...prev,
        tags: prev.tags.filter((t) => t !== tag),
        v: SCHEMA_VERSION,
      };
      writeRaw(sessionId, merged);
      return merged;
    });
  }, []);

  const reset = useCallback(() => {
    if (!sessionId) return;
    setMeta(() => {
      writeRaw(sessionId, EMPTY_META);
      return EMPTY_META;
    });
  }, [sessionId]);

  return { meta, update, toggleStar, addTag, removeTag, reset };
}
