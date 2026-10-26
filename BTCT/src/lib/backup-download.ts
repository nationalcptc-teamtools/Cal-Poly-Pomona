// Save a server backup ZIP (GET /api/backup/archives/<name>, admin only) to
// this computer.
//
// With the system save dialog (save-dialog.ts) the response body is piped
// straight into the picked file: a 200+ MB archive never sits in page
// memory. Without it (Firefox, or the preference off) the browser downloads
// the route itself through a plain link, which cannot send the
// Authorization header, so the link carries a one-time ticket from
// POST /api/backup/archives/<name>/ticket (60 s, this archive only), never
// the session token.
import { API_URL, useAuthStore } from '@/auth/auth-store';
import { downloadUrl } from './download';
import { pickSaveTarget, type SaveOutcome, type SaveTarget } from './save-dialog';

export interface BackupSaveOptions {
  /** A target picked before the work started ("back up now and save"). */
  target?: SaveTarget | 'unavailable';
  /** Bytes written so far and the archive's size (0 when unknown). */
  onProgress?: (written: number, total: number) => void;
  signal?: AbortSignal;
}

function archivePath(name: string): string {
  return `/api/backup/archives/${encodeURIComponent(name)}`;
}

function authHeader(): Record<string, string> {
  const token = useAuthStore.getState().token;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function errorText(res: Response): Promise<string> {
  const data = (await res.json().catch(() => ({}))) as { error?: string };
  return data.error || `request failed (${res.status})`;
}

/** Download through a plain link with a one-time ticket (the browser streams it to disk). */
export async function downloadBackupViaLink(name: string): Promise<void> {
  const res = await fetch(`${API_URL}${archivePath(name)}/ticket`, { method: 'POST', headers: authHeader() });
  if (!res.ok) throw new Error(await errorText(res));
  const { ticket } = (await res.json()) as { ticket: string };
  downloadUrl(`${API_URL}${archivePath(name)}?ticket=${encodeURIComponent(ticket)}`, name);
}

/** UTC `btct-backup-YYYYMMDD-HHMMSS.zip`, the server's name format, as the dialog's suggestion. */
export function suggestedBackupName(at: Date = new Date()): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `btct-backup-${at.getUTCFullYear()}${p(at.getUTCMonth() + 1)}${p(at.getUTCDate())}`
    + `-${p(at.getUTCHours())}${p(at.getUTCMinutes())}${p(at.getUTCSeconds())}.zip`;
}

/**
 * Save the backup `name` to this computer. 'saved' when it was written
 * through the save dialog, 'downloaded' when the browser took it as a plain
 * download, 'cancelled' when the user closed the dialog.
 */
export async function saveBackupArchive(name: string, opts: BackupSaveOptions = {}): Promise<SaveOutcome> {
  const target = opts.target ?? await pickSaveTarget(name, 'application/zip');
  if (target === 'cancelled') return 'cancelled';
  if (target === 'unavailable') {
    await downloadBackupViaLink(name);
    return 'downloaded';
  }
  let body: ReadableStream<Uint8Array>;
  let total: number;
  try {
    const res = await fetch(`${API_URL}${archivePath(name)}`, { headers: authHeader(), signal: opts.signal });
    if (!res.ok || !res.body) throw new Error(await errorText(res));
    body = res.body;
    total = Number(res.headers.get('Content-Length')) || 0;
  } catch (e) {
    await target.discard();
    throw e;
  }
  try {
    await target.writeStream(body, (n) => opts.onProgress?.(n, total), opts.signal);
  } catch (e) {
    // The aborted write kept nothing; drop the empty file the dialog made.
    await target.discard();
    throw e;
  }
  return 'saved';
}
