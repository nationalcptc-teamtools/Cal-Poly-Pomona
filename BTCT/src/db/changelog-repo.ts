import { v4 as uuidv4 } from 'uuid';
import { db } from './database';
import type { ChangeAction, ChangeTarget, ChangeLogEntry } from '@/types';
import { pickPruneIds } from '@/lib/change-log-policy';

export interface LogAuthor {
  userId: number | null;
  userName: string | null;
  userColor: string | null;
}

export interface LogDelta {
  field?: string | null;
  prevValue?: string | null;
  newValue?: string | null;
  reversible?: boolean;
}

export const changeLogRepo = {
  /**
   * Record a single entry. Author is captured at write time so older logs
   * survive a user being renamed or deleted. `delta` carries the field-level
   * old/new values that make an entry reversible.
   */
  async add(
    workspaceId: string,
    action: ChangeAction,
    target: ChangeTarget,
    targetId: string,
    summary: string,
    author: LogAuthor = { userId: null, userName: null, userColor: null },
    delta: LogDelta = {},
  ): Promise<ChangeLogEntry> {
    const entry: ChangeLogEntry = {
      id: uuidv4(),
      workspaceId,
      action,
      target,
      targetId,
      summary,
      timestamp: Date.now(),
      userId: author.userId,
      userName: author.userName,
      userColor: author.userColor,
      field: delta.field ?? null,
      prevValue: delta.prevValue ?? null,
      newValue: delta.newValue ?? null,
      reversible: delta.reversible ?? false,
    };
    // No automatic prune here. The log is part of what a backup, an export
    // and a re-import carry, and a writer-side cap of 2000 deleted 4000 of
    // a reimported 6000-entry log on its first edit, delete snapshots
    // included. Growth is held down by coalescing content saves
    // (shouldLogContentSave); trimming stays an explicit call to prune().
    await db.changeLogs.add(entry);
    return entry;
  },

  /**
   * Trim a workspace's log to `CHANGE_LOG_CAP` entries: once it is past the
   * cap plus some slack, delete the excess in one transaction, oldest
   * non-reversible entries first (see `pickPruneIds`). Nothing calls this on
   * its own: deleting history needs an operator's decision.
   */
  async prune(workspaceId: string): Promise<number> {
    const entries = await db.changeLogs.where('workspaceId').equals(workspaceId).toArray();
    const ids = pickPruneIds(entries);
    await db.changeLogs.bulkDelete(ids);
    return ids.length;
  },

  async getByWorkspace(workspaceId: string, limit = 200): Promise<ChangeLogEntry[]> {
    return db.changeLogs
      .where('workspaceId')
      .equals(workspaceId)
      .reverse()
      .sortBy('timestamp')
      .then((entries) => entries.slice(0, limit));
  },

  /** Latest entry that touched a specific entity (any field). */
  async latestForTarget(workspaceId: string, target: ChangeTarget, targetId: string): Promise<ChangeLogEntry | null> {
    const all = await db.changeLogs
      .where('workspaceId').equals(workspaceId)
      .toArray();
    const matches = all.filter((e) => e.target === target && e.targetId === targetId);
    if (matches.length === 0) return null;
    matches.sort((a, b) => b.timestamp - a.timestamp);
    return matches[0] ?? null;
  },

  async clear(workspaceId: string): Promise<void> {
    await db.changeLogs.where('workspaceId').equals(workspaceId).delete();
  },
};
