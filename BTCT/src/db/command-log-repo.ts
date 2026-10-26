/**
 * Read-only repo for command-log entries in the shared doc's live window.
 *
 * Clients NEVER create these: the server ingest endpoint (POST
 * /api/cmdlog/events) writes them into both SQLite and the `commandLogs` Y.Map
 * as btct-cmdlog agents ship commands. This repo just reads the live window;
 * the full durable archive is fetched over REST (GET /api/cmdlog/query).
 *
 * Like typst assets, these are plain last-writer-wins JSON records with no
 * Y.Text fields, so the Y.Text invariant (CLAUDE.md #1) doesn't apply.
 */
import { db } from './database';
import type { CommandLogEntry, ID } from '@/types';

export const commandLogRepo = {
  async getByWorkspace(workspaceId: ID): Promise<CommandLogEntry[]> {
    const all = await db.commandLogs.where('workspaceId').equals(workspaceId).toArray();
    // Newest first: matches the REST archive order and the viewer's default.
    return all.sort((a, b) => b.startedAt - a.startedAt);
  },

  /** Purge the live window for a workspace (admin action; also clears SQLite via REST). */
  async clear(workspaceId: ID): Promise<void> {
    const rows = await db.commandLogs.where('workspaceId').equals(workspaceId).toArray();
    for (const r of rows) await db.commandLogs.delete(r.id);
  },
};
