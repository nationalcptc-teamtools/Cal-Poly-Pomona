// ─────────────────────────────────────────────────────────────────────────
// Client for the server-side page version history (server/history.mjs).
//
// Versions are metadata rows; the bytes that matter are the page's GC-off
// history twin (one Yjs update, downloaded once per History tab) and each
// version's small Yjs snapshot. Restore goes through `restoreFromState` in
// page-snapshots.ts, then records a `restore` version so the rollback is
// itself part of the timeline.
// ─────────────────────────────────────────────────────────────────────────
import * as Y from 'yjs';
import { API_URL, useAuthStore } from '@/auth/auth-store';
import { base64ToBytes } from '@/db';
import type { PageVersion, PageVersionUser } from '@/types';

function authHeaders(): Record<string, string> {
  const token = useAuthStore.getState().token;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function readJson<T>(res: Response): Promise<T> {
  const data = (await res.json().catch(() => ({}))) as { error?: string } & Record<string, unknown>;
  if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
  return data as T;
}

export interface VersionListResponse {
  versions: PageVersion[];
  users: Record<string, PageVersionUser>;
  /** The page room is open on the server, so new versions can be recorded. */
  tracked: boolean;
  /** Edits since the last version. */
  dirty: boolean;
  twinExists: boolean;
}

export async function listVersions(pageId: string): Promise<VersionListResponse> {
  const res = await fetch(`${API_URL}/api/pages/${encodeURIComponent(pageId)}/versions`, { headers: authHeaders() });
  return readJson<VersionListResponse>(res);
}

export async function createVersion(
  pageId: string,
  opts: { name?: string | null; trigger?: 'named' | 'restore' } = {},
): Promise<PageVersion> {
  const res = await fetch(`${API_URL}/api/pages/${encodeURIComponent(pageId)}/versions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ name: opts.name ?? null, trigger: opts.trigger ?? 'named' }),
  });
  return (await readJson<{ version: PageVersion }>(res)).version;
}

export interface VersionBytes {
  version: PageVersion;
  /** Twin snapshot (diffable versions). */
  snapshot: Uint8Array | null;
  /** Full document state; always present (derived from the twin when needed). */
  state: Uint8Array | null;
}

export async function getVersion(pageId: string, versionId: string): Promise<VersionBytes> {
  const res = await fetch(
    `${API_URL}/api/pages/${encodeURIComponent(pageId)}/versions/${encodeURIComponent(versionId)}`,
    { headers: authHeaders() },
  );
  const data = await readJson<{ version: PageVersion; snapshot: string | null; state: string | null }>(res);
  return {
    version: data.version,
    snapshot: data.snapshot ? base64ToBytes(data.snapshot) : null,
    state: data.state ? base64ToBytes(data.state) : null,
  };
}

export async function deleteVersion(pageId: string, versionId: string): Promise<void> {
  const res = await fetch(
    `${API_URL}/api/pages/${encodeURIComponent(pageId)}/versions/${encodeURIComponent(versionId)}`,
    { method: 'DELETE', headers: authHeaders() },
  );
  await readJson<{ ok: true }>(res);
}

export async function renameVersion(pageId: string, versionId: string, name: string): Promise<PageVersion> {
  const res = await fetch(
    `${API_URL}/api/pages/${encodeURIComponent(pageId)}/versions/${encodeURIComponent(versionId)}/name`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ name }),
    },
  );
  return (await readJson<{ version: PageVersion }>(res)).version;
}

/** The GC-off twin as one Yjs update. Throws when the page has no history yet. */
export async function fetchTwin(pageId: string): Promise<Uint8Array> {
  const res = await fetch(`${API_URL}/api/pages/${encodeURIComponent(pageId)}/history/twin`, { headers: authHeaders() });
  if (!res.ok) {
    const data = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(data.error || `request failed (${res.status})`);
  }
  return new Uint8Array(await res.arrayBuffer());
}

// ── Attribution ──────────────────────────────────────────────────────────
// Each client maps its clientID to the account id in the doc's `users` map
// (Y.PermanentUserData) and records the delete sets of its own transactions
// there. The server twin reads the same map to credit versions, and the
// History tab reads it to colour insertions and deletions per user. Run
// once the doc has synced so two tabs of one account do not race to create
// the same user entry.

const puds = new WeakMap<Y.Doc, Y.PermanentUserData>();

export function attachUserMapping(doc: Y.Doc): void {
  const user = useAuthStore.getState().user;
  if (!user) return;
  let pud = puds.get(doc);
  if (!pud) {
    pud = new Y.PermanentUserData(doc);
    puds.set(doc, pud);
  }
  const description = String(user.id);
  if (pud.getUserByClientId(doc.clientID) === description) return;
  pud.setUserMapping(doc, doc.clientID, description);
}
