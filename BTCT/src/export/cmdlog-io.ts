import { API_URL, useAuthStore } from '@/auth/auth-store';
import type { CommandLogEntry } from '@/types';

// ─────────────────────────────────────────────────────────────────────────
// The command-log archive over REST, uncapped, for the workspace export and
// import. The Command Log tab's own query stops at 5000 rows; these two
// routes do not.
// ─────────────────────────────────────────────────────────────────────────

function authHeaders(): Record<string, string> {
  const token = useAuthStore.getState().token;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/** Every command-log row of a workspace (GET /api/cmdlog/export?format=json), oldest first. */
export async function fetchCommandLogArchive(workspaceId: string): Promise<CommandLogEntry[]> {
  const qs = new URLSearchParams({ workspaceId, format: 'json' });
  const res = await fetch(`${API_URL}/api/cmdlog/export?${qs}`, { headers: authHeaders() });
  if (!res.ok) {
    const data = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(data.error || `command log export failed (${res.status})`);
  }
  const rows = (await res.json()) as unknown;
  if (!Array.isArray(rows)) throw new Error('command log export returned something other than a list');
  return rows as CommandLogEntry[];
}

/** How many rows the archive holds for a workspace (GET /api/cmdlog/export?format=count). */
export async function countCommandLogArchive(workspaceId: string): Promise<number> {
  const qs = new URLSearchParams({ workspaceId, format: 'count' });
  const res = await fetch(`${API_URL}/api/cmdlog/export?${qs}`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`command log count failed (${res.status})`);
  const data = (await res.json()) as { total?: number };
  return typeof data.total === 'number' ? data.total : 0;
}

/** Download URL of the server-side CSV or JSON of the whole archive. */
export function commandLogExportUrl(workspaceId: string, format: 'csv' | 'json'): string {
  return `${API_URL}/api/cmdlog/export?${new URLSearchParams({ workspaceId, format })}`;
}

export interface CommandLogImportResult {
  imported: number;
  remapped: number;
  skipped: number;
}

export const CMDLOG_IMPORT_BATCH = 500;

/**
 * POST /api/cmdlog/import in batches. Idempotent on the server: a row is
 * keyed by its id, and a row whose id already belongs to another workspace
 * gets an id derived from (workspace, id), so running the same import twice
 * writes nothing new.
 */
export async function importCommandLogs(
  workspaceId: string,
  rows: CommandLogEntry[],
  onProgress?: (done: number, total: number) => void,
): Promise<CommandLogImportResult> {
  const total: CommandLogImportResult = { imported: 0, remapped: 0, skipped: 0 };
  for (let i = 0; i < rows.length; i += CMDLOG_IMPORT_BATCH) {
    const batch = rows.slice(i, i + CMDLOG_IMPORT_BATCH);
    const res = await fetch(`${API_URL}/api/cmdlog/import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ workspaceId, logs: batch }),
    });
    const data = (await res.json().catch(() => ({}))) as Partial<CommandLogImportResult> & { error?: string };
    if (!res.ok) throw new Error(data.error || `command log import failed (${res.status})`);
    total.imported += data.imported ?? 0;
    total.remapped += data.remapped ?? 0;
    total.skipped += data.skipped ?? 0;
    onProgress?.(Math.min(i + batch.length, rows.length), rows.length);
  }
  return total;
}
