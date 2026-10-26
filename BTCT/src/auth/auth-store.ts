/**
 * Auth client: thin wrappers around the server's REST endpoints plus a
 * persistent token store. Token + user info are kept in localStorage so a
 * page reload doesn't drop you back to the login screen.
 */
import { create } from 'zustand';
import { disposeSharedDoc } from '@/realtime/shared-doc';
import { disposeAllPageDocs } from '@/realtime/yjs-providers';
import type { EditorPrefs } from '@/lib/editor-prefs';
import type { CommandLogEntry } from '@/types';

// Default to same-origin so the same build works on any host. Set
// VITE_API_URL / VITE_WS_URL only when the API lives on a different host.
function defaultApiUrl(): string {
  if (typeof window === 'undefined') return 'http://127.0.0.1:1234';
  return window.location.origin;
}
function defaultWsUrl(): string {
  if (typeof window === 'undefined') return 'ws://127.0.0.1:1234';
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}`;
}

export const API_URL =
  (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, '') ||
  defaultApiUrl();

export const WS_URL =
  (import.meta.env.VITE_WS_URL as string | undefined)?.replace(/\/$/, '') ||
  defaultWsUrl();

const TOKEN_KEY = 'btct.auth.token';
const USER_KEY = 'btct.auth.user';

export interface RetentionStatus {
  days: number;
  lastRunAt: number | null;
  lastPruned: { ran: boolean; days: number; versions: number; assets: number; at: number } | null;
  dueVersionCount: number;
}

export interface AuthUser {
  id: number;
  username: string;
  color: string;
  isAdmin: boolean;
  // Per-account editor preferences (code-block accent + custom keybinds).
  // May be a partial blob from the server; merge with defaults via
  // `resolvePrefs` before use.
  prefs?: Partial<EditorPrefs> | null;
}

export interface AdminUserRow {
  id: number;
  username: string;
  color: string;
  isAdmin: boolean;
  createdAt: number;
}

/** Command-log ingest config (admin). `token` is the agent's bearer. */
export interface CmdlogConfig {
  enabled: boolean;
  configured: boolean;
  token: string | null;
  whitelist: string[];
  workspaceId: string | null;
}
/** Backup engine (server/backup.mjs): what a run covers. */
export interface BackupIncludes {
  sqlite: boolean;
  yjsShared: boolean;
  yjsPages: boolean;
  assets: boolean;
  history: boolean;
}

export interface BackupConfig {
  enabled: boolean;
  fullIntervalMin: number;
  includes: BackupIncludes;
  /** Keep only the newest N complete runs; 0 keeps every run. */
  keepLast: number;
  dir: string;
  /** Host folder bind-mounted at `dir` (BACKUP_HOST_DIR), for display; null outside compose. */
  hostDir?: string | null;
  token: string | null;
  configured: boolean;
  instanceId: string;
}

export interface BackupConfigInput {
  enabled?: boolean;
  fullIntervalMin?: number;
  includes?: Partial<BackupIncludes>;
  keepLast?: number;
}

export interface BackupLast {
  name: string;
  bytes: number;
  /** Bytes the run added on disk (the whole ZIP; older folder runs hard-linked unchanged assets). */
  newBytes?: number;
  /** Rooms the run could not read; they are missing from that backup. */
  failedRooms?: string[];
  files: number;
  docs?: number;
  assets?: number;
  at: number;
  trigger: string;
  durationMs?: number;
}

export interface BackupStatus {
  enabled: boolean;
  fullIntervalMin: number;
  includes: BackupIncludes;
  dir: string;
  /** Host folder bind-mounted at `dir` (BACKUP_HOST_DIR), for display; null outside compose. */
  hostDir?: string | null;
  dirWritable: boolean;
  keepLast: number;
  freeBytes: number | null;
  running: boolean;
  runningSince: number | null;
  lastRunAt: number | null;
  lastSuccessAt: number | null;
  lastDurationMs: number | null;
  lastError: string | null;
  nextRunAt: number | null;
  lastBackup: BackupLast | null;
  usage: { count: number; totalBytes: number; newBytes?: number };
}

export interface BackupEntry {
  /** `btct-backup-YYYYMMDD-HHMMSS.zip`, or a folder name for runs written before 2026-10-12. */
  name: string;
  /** `zip` for a run of this build, `folder` for an older one. */
  format?: 'zip' | 'folder';
  createdAt: string;
  bytes: number;
  newBytes?: number;
  files: number;
  includes: BackupIncludes | null;
  trigger: string | null;
  failedRooms?: number;
  partial: boolean;
}

export interface BackupRunResult {
  ran: boolean;
  reason?: string;
  name?: string;
  bytes?: number;
  newBytes?: number;
  files?: number;
  failedRooms?: string[];
  durationMs?: number;
}

export interface CmdlogConfigInput {
  enabled?: boolean;
  whitelist?: string[];
  workspaceId?: string | null;
}

/** Storage writes can throw (site data blocked, quota): the session then lives in memory only. */
function safeSet(k: string, v: string): void {
  try { localStorage.setItem(k, v); } catch { /* blocked or full: in-memory only */ }
}
function safeRemove(k: string): void {
  try { localStorage.removeItem(k); } catch { /* ignore */ }
}

function loadStoredToken(): string | null {
  try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
}
function loadStoredUser(): AuthUser | null {
  try {
    const raw = localStorage.getItem(USER_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed.id === 'number' && typeof parsed.username === 'string') {
      // Older builds may have a stale `avatar` field: strip it.
      if ('avatar' in parsed) delete parsed.avatar;
      return parsed as AuthUser;
    }
  } catch { /* fallthrough */ }
  return null;
}

async function postJson<T>(path: string, body: unknown, token?: string | null): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  const data = (await res.json().catch(() => ({}))) as { error?: string } & Record<string, unknown>;
  if (!res.ok) {
    throw new Error(data.error || `request failed (${res.status})`);
  }
  return data as T;
}

async function getJson<T>(path: string, token?: string | null): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  });
  const data = (await res.json().catch(() => ({}))) as { error?: string } & Record<string, unknown>;
  if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
  return data as T;
}

async function patchJson<T>(path: string, body: unknown, token?: string | null): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  const data = (await res.json().catch(() => ({}))) as { error?: string } & Record<string, unknown>;
  if (!res.ok) {
    throw new Error(data.error || `request failed (${res.status})`);
  }
  return data as T;
}

async function deleteJson<T>(path: string, token?: string | null): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    method: 'DELETE',
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  });
  const data = (await res.json().catch(() => ({}))) as { error?: string } & Record<string, unknown>;
  if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
  return data as T;
}

interface AuthResponse {
  token: string;
  user: AuthUser;
}

interface AuthState {
  user: AuthUser | null;
  token: string | null;
  status: 'unknown' | 'authenticated' | 'unauthenticated';
  error: string | null;
  bootstrap: () => Promise<void>;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  // Admin-only operations (will fail with 403 for non-admin tokens).
  adminListUsers: () => Promise<AdminUserRow[]>;
  adminCreateUser: (username: string, password: string, isAdmin: boolean) => Promise<AdminUserRow>;
  adminDeleteUser: (id: number) => Promise<void>;
  adminResetPassword: (id: number, password: string) => Promise<void>;
  adminRenameUser: (id: number, username: string) => Promise<AdminUserRow>;
  // Self-service profile editing for any authenticated user.
  updateProfile: (changes: { color?: string; prefs?: EditorPrefs }) => Promise<AuthUser>;
  // Command-log ingest config (admin only) + archive query (any user).
  cmdlogGetConfig: () => Promise<CmdlogConfig>;
  cmdlogSaveConfig: (patch: CmdlogConfigInput) => Promise<CmdlogConfig>;
  cmdlogRegenerateToken: () => Promise<{ token: string }>;
  cmdlogQuery: (params: CmdlogQueryParams) => Promise<CommandLogEntry[]>;
  cmdlogAddManual: (entry: CmdlogManualInput) => Promise<CommandLogEntry>;
  // Backups (admin only; status/run also accept the backup token server-side).
  backupGetConfig: () => Promise<BackupConfig>;
  backupSaveConfig: (patch: BackupConfigInput) => Promise<BackupConfig>;
  backupRegenerateToken: () => Promise<{ token: string }>;
  backupStatus: () => Promise<BackupStatus>;
  backupRun: () => Promise<BackupRunResult>;
  retentionGetConfig: () => Promise<RetentionStatus>;
  retentionSaveConfig: (patch: { days: number }) => Promise<RetentionStatus>;
  retentionRun: () => Promise<{ ran: boolean; days: number; versions: number; assets: number }>;
  retentionPruneHistoryRange: (after: number, before: number) => Promise<{ deleted: number }>;
  backupList: () => Promise<BackupEntry[]>;
  backupDelete: (name: string) => Promise<void>;
}

/** A hand-entered command-log record (manual add). */
export interface CmdlogManualInput {
  workspaceId: string;
  operator: string;
  command: string;
  tool?: string;
  host?: string;
  cwd?: string;
  startedAt?: number;
  exitCode?: number | null;
  durationMs?: number | null;
}

/** Filters for the durable command-log archive (all optional but workspaceId). */
export interface CmdlogQueryParams {
  workspaceId: string;
  operator?: string;
  tool?: string;
  host?: string;
  from?: number;
  to?: number;
  q?: string;
  status?: 'all' | 'success' | 'failed' | 'running';
  limit?: number;
}

/** Backoff between /api/me retries while the server is unreachable: 1 s doubling to 30 s. */
export function bootstrapRetryDelay(attempt: number): number {
  return Math.min(30_000, 1000 * 2 ** Math.min(attempt, 5));
}

export type MeVerdict =
  | { kind: 'ok'; user: AuthUser }
  | { kind: 'rejected' }
  | { kind: 'unreachable' };

/**
 * Ask the server who `token` belongs to. Only 401 and 403 say the token is
 * bad; anything else (fetch rejected, 5xx, a proxy's HTML error page) means
 * the answer is unknown, and must never log anyone out.
 */
export async function checkMe(token: string): Promise<MeVerdict> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}/api/me`, { headers: { Authorization: `Bearer ${token}` } });
  } catch {
    return { kind: 'unreachable' };
  }
  if (res.status === 401 || res.status === 403) return { kind: 'rejected' };
  if (!res.ok) return { kind: 'unreachable' };
  try {
    const data = (await res.json()) as { user?: AuthUser };
    return data.user ? { kind: 'ok', user: data.user } : { kind: 'unreachable' };
  } catch {
    return { kind: 'unreachable' };
  }
}

/** The connection monitor's probe: is the current session's token still accepted? */
export async function probeSession(): Promise<'ok' | 'rejected' | 'unreachable'> {
  const token = useAuthStore.getState().token;
  if (!token) return 'rejected';
  return (await checkMe(token)).kind;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: loadStoredUser(),
  token: loadStoredToken(),
  status: 'unknown',
  error: null,

  // Validate a stored token against the server. Only a 401/403 means the
  // token is bad and logs out. A network error or a 5xx (a redeploy, a proxy
  // hiccup) keeps the stored session: with a stored user the app opens from
  // the offline cache at once, and the check retries with backoff until the
  // server answers either way.
  bootstrap: async () => {
    const token = get().token;
    if (!token) {
      set({ status: 'unauthenticated' });
      return;
    }
    const attempt = async (): Promise<boolean> => {
      if (get().token !== token) return true; // logged out or in again meanwhile
      const verdict = await checkMe(token);
      if (get().token !== token) return true;
      if (verdict.kind === 'ok') {
        safeSet(USER_KEY, JSON.stringify(verdict.user));
        set({ user: verdict.user, status: 'authenticated', error: null });
        return true;
      }
      if (verdict.kind === 'rejected') {
        safeRemove(TOKEN_KEY);
        safeRemove(USER_KEY);
        set({ user: null, token: null, status: 'unauthenticated', error: null });
        return true;
      }
      // Unreachable: keep the session. A stored user lets the shell render
      // from cache; without one the loading screen says what is happening.
      set(get().user
        ? { status: 'authenticated', error: null }
        : { status: 'unknown', error: 'Server unreachable, retrying…' });
      return false;
    };
    if (await attempt()) return;
    for (let i = 0; ; i++) {
      await new Promise((r) => setTimeout(r, bootstrapRetryDelay(i)));
      if (await attempt()) return;
    }
  },

  login: async (username, password) => {
    set({ error: null });
    // Defensive cleanup: if a previous session's Yjs providers were left
    // around (token-expiry path, or a stale singleton from before this
    // tab's reload), tear them down so the new session rebuilds them
    // with the current token instead of reconnecting under the old one.
    disposeAllPageDocs();
    disposeSharedDoc();
    const data = await postJson<AuthResponse>('/api/login', { username, password });
    safeSet(TOKEN_KEY, data.token);
    safeSet(USER_KEY, JSON.stringify(data.user));
    set({ token: data.token, user: data.user, status: 'authenticated' });
  },

  logout: () => {
    // Tear down every Yjs provider before clearing the token so the next
    // session always builds fresh providers tied to the current auth
    // token. Without this the WebsocketProvider keeps the old token in
    // its query string and the new session's edits never propagate.
    disposeAllPageDocs();
    disposeSharedDoc();
    safeRemove(TOKEN_KEY);
    safeRemove(USER_KEY);
    set({ token: null, user: null, status: 'unauthenticated' });
  },

  adminListUsers: async () => {
    const token = get().token;
    const data = await getJson<{ users: AdminUserRow[] }>('/api/admin/users', token);
    return data.users;
  },

  adminCreateUser: async (username, password, isAdmin) => {
    const token = get().token;
    const data = await postJson<{ user: AdminUserRow }>(
      '/api/admin/users',
      { username, password, isAdmin },
      token,
    );
    return data.user;
  },

  adminDeleteUser: async (id) => {
    const token = get().token;
    await deleteJson<{ ok: true }>(`/api/admin/users/${id}`, token);
  },

  adminResetPassword: async (id, password) => {
    const token = get().token;
    await postJson<{ ok: true }>(`/api/admin/users/${id}/password`, { password }, token);
  },

  adminRenameUser: async (id, username) => {
    const token = get().token;
    const data = await patchJson<{ user: AdminUserRow }>(`/api/admin/users/${id}`, { username }, token);
    // Renaming yourself changes what's shown in the sidebar profile immediately;
    // the JWT's own username claim stays stale until next login, but auth checks
    // re-fetch the user by id, never trust that claim, so this is display-only.
    const me = get().user;
    if (me && me.id === id) {
      const updated = { ...me, username: data.user.username };
      safeSet(USER_KEY, JSON.stringify(updated));
      set({ user: updated });
    }
    return data.user;
  },

  updateProfile: async (changes) => {
    const token = get().token;
    const data = await postJson<{ user: AuthUser }>('/api/me/profile', changes, token);
    safeSet(USER_KEY, JSON.stringify(data.user));
    set({ user: data.user });
    return data.user;
  },

  cmdlogGetConfig: async () => {
    return getJson<CmdlogConfig>('/api/cmdlog/config', get().token);
  },
  cmdlogSaveConfig: async (patch) => {
    return postJson<CmdlogConfig>('/api/cmdlog/config', patch, get().token);
  },
  cmdlogRegenerateToken: async () => {
    return postJson<{ token: string }>('/api/cmdlog/token', {}, get().token);
  },
  cmdlogQuery: async (params) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '' && !(k === 'status' && v === 'all')) {
        qs.set(k, String(v));
      }
    }
    const data = await getJson<{ logs: CommandLogEntry[] }>(`/api/cmdlog/query?${qs.toString()}`, get().token);
    return data.logs;
  },
  cmdlogAddManual: async (entry) => {
    const data = await postJson<{ log: CommandLogEntry }>('/api/cmdlog/manual', entry, get().token);
    return data.log;
  },

  backupGetConfig: async () => getJson<BackupConfig>('/api/backup/config', get().token),
  backupSaveConfig: async (patch) => postJson<BackupConfig>('/api/backup/config', patch, get().token),
  backupRegenerateToken: async () => postJson<{ token: string }>('/api/backup/token', {}, get().token),
  backupStatus: async () => getJson<BackupStatus>('/api/backup/status', get().token),
  backupRun: async () => postJson<BackupRunResult>('/api/backup/run', {}, get().token),
  retentionGetConfig: async () => getJson<RetentionStatus>('/api/retention/config', get().token),
  retentionSaveConfig: async (patch) => postJson<RetentionStatus>('/api/retention/config', patch, get().token),
  retentionRun: async () => postJson<{ ran: boolean; days: number; versions: number; assets: number }>('/api/retention/run', {}, get().token),
  retentionPruneHistoryRange: async (after, before) => postJson<{ deleted: number }>('/api/retention/history-range', { after, before }, get().token),
  backupList: async () => (await getJson<{ backups: BackupEntry[] }>('/api/backup/list', get().token)).backups,
  backupDelete: async (name) => {
    await deleteJson<{ ok: boolean }>(`/api/backup/archives/${encodeURIComponent(name)}`, get().token);
  },
}));
