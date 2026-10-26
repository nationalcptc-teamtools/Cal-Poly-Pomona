import { useEffect, useState } from 'react';
import { Shield, Trash2, Plus, KeyRound, Pencil, Copy, RefreshCw, Terminal, HardDrive, Play, EyeOff, Timer, Download } from 'lucide-react';
import { Dialog } from '@/components/ui/Dialog';
import { Banner } from '@/components/ui/Banner';
import { Tabs } from '@/components/ui/Tabs';
import { Button, IconButton } from '@/components/ui/Button';
import { Checkbox, Input, Select, Textarea } from '@/components/ui/Field';
import { Badge } from '@/components/ui/Badge';

/** One section per tab, users first (it used to sit at the bottom of one long scroll). */
const ADMIN_TABS = [
  { id: 'users', label: 'Users' },
  { id: 'cmdlog', label: 'Command log' },
  { id: 'backups', label: 'Backups' },
  { id: 'blur', label: 'Blur' },
  { id: 'retention', label: 'Retention' },
] as const;
type AdminTab = (typeof ADMIN_TABS)[number]['id'];
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import {
  useAuthStore,
  type AdminUserRow,
  type CmdlogConfig,
  type BackupConfig,
  type BackupConfigInput,
  type BackupStatus,
  type BackupEntry,
  type RetentionStatus,
} from '@/auth/auth-store';
import { useAppStore } from '@/stores';
import { useThemeStore } from '@/stores/theme-store';
import { pollWhileVisible } from '@/lib/visible-poll';
import { saveBackupArchive, suggestedBackupName, type BackupSaveOptions } from '@/lib/backup-download';
import { pickSaveTarget } from '@/lib/save-dialog';
import { FirefoxSaveHint } from '@/components/ui/SaveLocationSetting';

/**
 * Admin-only modal panel for managing user accounts. Lists every user, lets
 * an admin create new accounts, rename any account (including their own),
 * reset passwords, and delete users (except themselves and the last
 * remaining admin: those are blocked server-side).
 */
export function AdminPanel({ onClose }: { onClose: () => void }) {
  const me = useAuthStore((s) => s.user);
  const adminListUsers = useAuthStore((s) => s.adminListUsers);
  const adminCreateUser = useAuthStore((s) => s.adminCreateUser);
  const adminDeleteUser = useAuthStore((s) => s.adminDeleteUser);
  const adminResetPassword = useAuthStore((s) => s.adminResetPassword);
  const adminRenameUser = useAuthStore((s) => s.adminRenameUser);
  const [tab, setTab] = useState<AdminTab>('users');

  const [users, setUsers] = useState<AdminUserRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // New-user form
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newIsAdmin, setNewIsAdmin] = useState(false);

  // Reset-password inline state per user id
  const [resettingId, setResettingId] = useState<number | null>(null);
  const [resetPwd, setResetPwd] = useState('');

  // Rename inline state per user id (mutually exclusive with reset-password)
  const [renamingId, setRenamingId] = useState<number | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const [pendingDelete, setPendingDelete] = useState<{ id: number; username: string } | null>(null);

  const refresh = async () => {
    try {
      const list = await adminListUsers();
      setUsers(list);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to load users');
    }
  };

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submitCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!newUsername.trim()) return setError('username is required');
    if (newPassword.length < 8) return setError('password must be at least 8 characters');
    setBusy(true);
    try {
      await adminCreateUser(newUsername.trim(), newPassword, newIsAdmin);
      setNewUsername('');
      setNewPassword('');
      setNewIsAdmin(false);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'create failed');
    } finally {
      setBusy(false);
    }
  };

  const submitReset = async (id: number) => {
    setError(null);
    if (resetPwd.length < 8) return setError('password must be at least 8 characters');
    setBusy(true);
    try {
      await adminResetPassword(id, resetPwd);
      setResettingId(null);
      setResetPwd('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'reset failed');
    } finally {
      setBusy(false);
    }
  };

  const submitRename = async (id: number) => {
    setError(null);
    const username = renameValue.trim();
    if (!username) return setError('username is required');
    setBusy(true);
    try {
      await adminRenameUser(id, username);
      setRenamingId(null);
      setRenameValue('');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'rename failed');
    } finally {
      setBusy(false);
    }
  };

  const submitDelete = async (id: number) => {
    setError(null);
    setBusy(true);
    try {
      await adminDeleteUser(id);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'delete failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
    {pendingDelete && (
      <ConfirmDialog
        title="Delete user"
        message={`Delete user "${pendingDelete.username}"? This cannot be undone.`}
        confirmLabel="Delete"
        destructive
        onCancel={() => setPendingDelete(null)}
        onConfirm={() => { const p = pendingDelete; setPendingDelete(null); void submitDelete(p.id); }}
      />
    )}
    <Dialog
      title="Admin Panel"
      icon={<Shield size={15} className="text-status-amber" />}
      onClose={onClose}
      size="lg"
      className="h-[min(calc(86*var(--vh)),820px)]"
      bodyClassName="p-0 flex flex-col"
    >
        <Tabs label="Admin sections" idPrefix="admin" items={ADMIN_TABS} value={tab} onChange={setTab} className="shrink-0 px-4 pt-1" />
        <div role="tabpanel" id={`admin-panel-${tab}`} aria-labelledby={`admin-tab-${tab}`} className="min-h-0 flex-1 overflow-y-auto p-4">
          {error && <Banner tone="red" className="mb-3">{error}</Banner>}

          {tab === 'cmdlog' && <CmdlogConfigSection />}
          {tab === 'backups' && <BackupConfigSection />}
          {tab === 'blur' && <BlurConfigSection />}
          {tab === 'retention' && <RetentionConfigSection />}

          {tab === 'users' && <>
          {/* Create-user form */}
          <form
            onSubmit={submitCreate}
            className="mb-4 rounded-md border border-border bg-muted/50 p-3"
          >
            <div className="mb-2 flex items-center gap-2 text-meta font-bold uppercase tracking-widest text-muted-foreground">
              <Plus size={12} /> Create user
            </div>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <Input
                type="text"
                placeholder="Username"
                autoComplete="off"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                className="px-2 py-1.5 text-xs"
              />
              <Input
                type="password"
                placeholder="Password (min 8)"
                autoComplete="new-password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="px-2 py-1.5 text-xs"
              />
            </div>
            <div className="mt-2 flex items-center justify-between">
              <Checkbox className="items-center text-muted-foreground" checked={newIsAdmin} onChange={(checked) => setNewIsAdmin(checked)} label="Grant admin privileges" />
              <Button variant="primary"
                type="submit"
                disabled={busy}
              >
                {busy ? 'Working…' : 'Create'}
              </Button>
            </div>
          </form>

          {/* User list */}
          <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full text-left text-xs">
              <thead className="bg-muted text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 font-medium">User</th>
                  <th className="px-3 py-2 font-medium">Role</th>
                  <th className="px-3 py-2 font-medium">Created</th>
                  <th className="px-3 py-2 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const isSelf = me?.id === u.id;
                  return (
                    <tr key={u.id} className="border-t border-border">
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <span
                            className="inline-block h-2 w-2 rounded-full"
                            style={{ backgroundColor: u.color }}
                            aria-hidden="true"
                          />
                          <span className="font-medium">{u.username}</span>
                          {isSelf && (
                            <Badge>you</Badge>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        {u.isAdmin ? (
                          <Badge tone="amber"><Shield size={10} /> admin</Badge>
                        ) : (
                          <span className="text-muted-foreground">user</span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">
                        {new Date(u.createdAt).toLocaleDateString()}
                      </td>
                      <td className="px-3 py-2">
                        {resettingId === u.id ? (
                          <div className="flex items-center justify-end gap-1">
                            <Input
                              type="password"
                              autoFocus
                              placeholder="New password"
                              value={resetPwd}
                              onChange={(e) => setResetPwd(e.target.value)}
                              className="w-32"
                            />
                            <Button variant="primary" size="sm"
                              onClick={() => void submitReset(u.id)}
                              disabled={busy}
                            >
                              Save
                            </Button>
                            <Button variant="ghost" size="sm"
                              onClick={() => { setResettingId(null); setResetPwd(''); }}
                              className="text-muted-foreground"
                            >
                              Cancel
                            </Button>
                          </div>
                        ) : renamingId === u.id ? (
                          <div className="flex items-center justify-end gap-1">
                            <Input
                              type="text"
                              autoFocus
                              placeholder="New username"
                              value={renameValue}
                              onChange={(e) => setRenameValue(e.target.value)}
                              className="w-32"
                            />
                            <Button variant="primary" size="sm"
                              onClick={() => void submitRename(u.id)}
                              disabled={busy}
                            >
                              Save
                            </Button>
                            <Button variant="ghost" size="sm"
                              onClick={() => { setRenamingId(null); setRenameValue(''); }}
                              className="text-muted-foreground"
                            >
                              Cancel
                            </Button>
                          </div>
                        ) : (
                          <div className="flex items-center justify-end gap-1">
                            <IconButton
                              onClick={() => { setRenamingId(u.id); setRenameValue(u.username); }}
                              label="Rename user"
                            >
                              <Pencil size={13} />
                            </IconButton>
                            <IconButton
                              onClick={() => { setResettingId(u.id); setResetPwd(''); }}
                              label="Reset password"
                            >
                              <KeyRound size={13} />
                            </IconButton>
                            <IconButton tone="danger"
                              onClick={() => setPendingDelete({ id: u.id, username: u.username })}
                              disabled={isSelf}
                              className="text-status-red"
                              label={isSelf ? 'Cannot delete your own account' : 'Delete user'}
                            >
                              <Trash2 size={13} />
                            </IconButton>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
                {users.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-3 py-4 text-center text-muted-foreground">
                      No users
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          </>}
        </div>
    </Dialog>
    </>
  );
}

/**
 * Admin config for the team command log: enable ingest (mints the shared
 * bearer token operators launch the capture agent with), edit the whitelist of
 * tools that get logged, pick the default target workspace, and copy a
 * ready-to-run agent install command.
 */
function CmdlogConfigSection() {
  const cmdlogGetConfig = useAuthStore((s) => s.cmdlogGetConfig);
  const cmdlogSaveConfig = useAuthStore((s) => s.cmdlogSaveConfig);
  const cmdlogRegenerateToken = useAuthStore((s) => s.cmdlogRegenerateToken);
  const workspaces = useAppStore((s) => s.workspaces);

  const [cfg, setCfg] = useState<CmdlogConfig | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [wlText, setWlText] = useState('');

  useEffect(() => {
    void cmdlogGetConfig().then((c) => { setCfg(c); setWlText(c.whitelist.join('\n')); }).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const origin = typeof window !== 'undefined' ? window.location.origin : '';
  const token = cfg?.token || '';
  const installCmd = `python3 -m btct_agent install --server ${origin} --token ${token || '<token>'} --operator <you>`;

  const save = async (patch: Parameters<typeof cmdlogSaveConfig>[0], note: string) => {
    setBusy(true); setErr(null); setMsg(null);
    try { const c = await cmdlogSaveConfig(patch); setCfg(c); setWlText(c.whitelist.join('\n')); setMsg(note); }
    catch (e) { setErr(e instanceof Error ? e.message : 'save failed'); }
    finally { setBusy(false); }
  };
  const saveWhitelist = () => {
    const tools = wlText.split(/[\n,]/).map((t) => t.trim().toLowerCase()).filter(Boolean);
    void save({ whitelist: tools }, `Whitelist saved (${tools.length} tools)`);
  };
  const regen = async () => {
    setBusy(true); setErr(null); setMsg(null);
    try {
      const { token: t } = await cmdlogRegenerateToken();
      setCfg((c) => (c ? { ...c, token: t, configured: true } : c));
      setRevealed(true); setMsg('Token regenerated');
    } catch (e) { setErr(e instanceof Error ? e.message : 'failed'); }
    finally { setBusy(false); }
  };
  const copy = (text: string) => {
    try { void navigator.clipboard.writeText(text); setMsg('Copied'); } catch { /* ignore */ }
  };

  return (
    <div className="mb-4 rounded-md border border-border bg-muted/50 p-3">
      <div className="mb-1 flex items-center gap-2 text-meta font-bold uppercase tracking-widest text-muted-foreground">
        <Terminal size={12} className="text-status-green" /> Command Log
      </div>
      <p className="mb-2 text-caption text-muted-foreground">
        Let operators' Kali boxes ship whitelisted shell commands into the Command Log tab. Each operator runs the capture agent with the token below.
      </p>

      <Checkbox className="items-center text-muted-foreground" checked={!!cfg?.enabled} onChange={(checked) => void save({ enabled: checked }, checked ? 'Ingest enabled' : 'Ingest disabled')} label="Enabled" />
      <div className="mt-1 text-meta">
        {cfg?.configured
          ? <span className="text-status-green">Ready ✓</span>
          : <span className="text-muted-foreground">Not configured: enable to generate a token</span>}
      </div>

      {cfg?.configured && (
        <div className="mt-3 space-y-3">
          <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">Ingest token (treat like a password)</label>
            <div className="flex items-center gap-1.5">
              <Input
                readOnly
                type={revealed ? 'text' : 'password'}
                value={token}
                mono className="flex-1 py-1.5"
              />
              <Button variant="outline" size="sm" onClick={() => setRevealed((r) => !r)}>{revealed ? 'Hide' : 'Reveal'}</Button>
              <IconButton onClick={() => copy(token)} label="Copy token" className="border border-border p-1.5"><Copy size={11} /></IconButton>
              <IconButton onClick={() => void regen()} disabled={busy} label="Regenerate" className="border border-border p-1.5"><RefreshCw size={11} /></IconButton>
            </div>
          </div>

          <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">Default workspace (where commands land)</label>
            <Select
              value={cfg.workspaceId ?? ''}
              onChange={(e) => void save({ workspaceId: e.target.value || null }, 'Default workspace set')}
              className="w-full py-1.5"
            >
              <option value="">none (uses first workspace)</option>
              {workspaces.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
            </Select>
          </div>

          <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">Whitelist (one tool per line)</label>
            <Textarea
              value={wlText}
              onChange={(e) => setWlText(e.target.value)}
              rows={5}
              spellCheck={false}
              mono className="py-1.5 text-meta"
            />
            <Button variant="outline" size="sm" onClick={saveWhitelist} disabled={busy} className="mt-1">Save whitelist</Button>
          </div>

          <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">Install on a Kali box</label>
            <div className="flex items-start gap-1.5">
              <code className="flex-1 overflow-x-auto whitespace-pre rounded-md border border-border bg-background px-2 py-1.5 font-mono text-caption text-foreground">{installCmd}</code>
              <IconButton onClick={() => copy(installCmd)} label="Copy command" className="border border-border p-1.5"><Copy size={11} /></IconButton>
            </div>
          </div>
        </div>
      )}

      {(msg || err) && (
        <div className={`mt-2 text-meta ${err ? 'text-status-red' : 'text-muted-foreground'}`}>{err || msg}</div>
      )}
    </div>
  );
}

// ── Backups ─────────────────────────────────────────────────────────────
//
// Consistent snapshots of the whole instance into the host folder mounted
// at BACKUP_DIR (server/backup.mjs), one self-contained .zip per run.
// Toggles save immediately (the cmdlog section's pattern); the interval and
// keep-last commit on blur/Enter. Every ZIP is a full copy, so keep-last
// defaults to 12 runs on the server; 0 keeps every run and the inventory
// below is then the retention tool.

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let x = n / 1024;
  let i = 0;
  while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
  return `${x.toFixed(1)} ${units[i]}`;
}

function fmtWhen(ms: number | null | undefined): string {
  if (!ms) return 'never';
  return new Date(ms).toLocaleString();
}

function fmtUntil(ms: number | null | undefined): string {
  if (!ms) return 'not scheduled';
  const mins = Math.round((ms - Date.now()) / 60000);
  if (mins <= 0) return 'now';
  if (mins < 60) return `in ${mins} min`;
  const h = Math.floor(mins / 60);
  return `in ${h} h ${mins - h * 60} min`;
}

const INCLUDE_LABELS: ReadonlyArray<{ key: keyof BackupConfig['includes']; label: string; hint: string }> = [
  { key: 'sqlite', label: 'Accounts & settings', hint: 'SQLite: users, prefs, settings, asset index, the full command log archive, page version list' },
  { key: 'yjsShared', label: 'Workspace metadata', hint: 'the shared doc: workspaces, pages list, nmap, change log, asset records, report source, live command log window' },
  { key: 'yjsPages', label: 'Page bodies', hint: 'one Yjs document per page' },
  { key: 'assets', label: 'Uploaded assets', hint: 'Screenshots used by notes' },
  { key: 'history', label: 'Version history', hint: 'per-page history twins behind version diffs' },
];

function BackupConfigSection() {
  const backupGetConfig = useAuthStore((s) => s.backupGetConfig);
  const backupSaveConfig = useAuthStore((s) => s.backupSaveConfig);
  const backupRegenerateToken = useAuthStore((s) => s.backupRegenerateToken);
  const backupStatus = useAuthStore((s) => s.backupStatus);
  const backupRun = useAuthStore((s) => s.backupRun);
  const backupList = useAuthStore((s) => s.backupList);
  const backupDelete = useAuthStore((s) => s.backupDelete);

  const [cfg, setCfg] = useState<BackupConfig | null>(null);
  const [status, setStatus] = useState<BackupStatus | null>(null);
  const [list, setList] = useState<BackupEntry[]>([]);
  const [intervalMin, setIntervalMin] = useState('60');
  const [keepLast, setKeepLast] = useState('0');
  const [pendingRemove, setPendingRemove] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [running, setRunning] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  // A backup ZIP being written to this computer (save dialog path only).
  const [saving, setSaving] = useState<{ name: string; written: number; total: number } | null>(null);

  const refresh = async () => {
    try {
      const [c, s, l] = await Promise.all([backupGetConfig(), backupStatus(), backupList()]);
      setCfg(c);
      setStatus(s);
      setList(l);
      setIntervalMin(String(c.fullIntervalMin));
      setKeepLast(String(c.keepLast ?? 0));
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'failed to load backup settings');
    }
  };
  useEffect(() => {
    void refresh();
    // Poll status while the panel is open and the tab is visible, so a
    // scheduled run shows up. The server caches run summaries, so this is cheap.
    let first = true;
    return pollWhileVisible(async () => {
      if (first) { first = false; return; } // refresh() above already loaded it
      try { setStatus(await backupStatus()); } catch { /* next tick */ }
    }, 15000);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const save = async (patch: BackupConfigInput, note: string) => {
    setBusy(true); setErr(null); setMsg(null);
    try {
      setCfg(await backupSaveConfig(patch));
      setMsg(note);
      setStatus(await backupStatus());
    } catch (e) { setErr(e instanceof Error ? e.message : 'save failed'); }
    finally { setBusy(false); }
  };
  const commitInterval = () => {
    const n = Number(intervalMin);
    if (!Number.isFinite(n) || n < 1) { setErr('interval must be at least 1 minute'); return; }
    if (cfg && Math.floor(n) !== cfg.fullIntervalMin) void save({ fullIntervalMin: Math.floor(n) }, `Backing up every ${Math.floor(n)} min`);
  };
  const commitKeepLast = () => {
    const n = keepLast.trim() === '' ? 0 : Number(keepLast);
    if (!Number.isFinite(n) || n < 0) { setErr('keep last must be 0 (keep all) or a number of runs'); return; }
    const k = Math.floor(n);
    if (cfg && k !== cfg.keepLast) void save({ keepLast: k }, k ? `Keeping the last ${k} backups` : 'Keeping every backup');
  };
  const runNow = async () => {
    setRunning(true); setErr(null); setMsg(null);
    try {
      const r = await backupRun();
      setMsg(r.ran
        ? `Wrote ${r.name} (${fmtBytes(r.bytes ?? 0)}, ${fmtBytes(r.newBytes ?? r.bytes ?? 0)} new, ${r.files ?? 0} files, ${Math.max(1, Math.round((r.durationMs ?? 0) / 1000))} s)`
        : 'A backup is already running');
    } catch (e) { setErr(e instanceof Error ? e.message : 'backup failed'); }
    finally { setRunning(false); await refresh(); }
  };
  // Save one ZIP run to this computer: the system save dialog where the
  // browser has one (streamed into the file), else a plain download.
  const saveRun = async (name: string, target?: BackupSaveOptions['target']) => {
    setErr(null); setMsg(null);
    try {
      const outcome = await saveBackupArchive(name, {
        target,
        onProgress: (written, total) => setSaving({ name, written, total }),
      });
      if (outcome === 'saved') setMsg(`Saved ${name} to this computer`);
      else if (outcome === 'downloaded') setMsg(`Downloading ${name} to your Downloads folder`);
    } catch (e) { setErr(e instanceof Error ? e.message : 'save failed'); }
    finally { setSaving(null); }
  };
  // Back up now and save: the dialog opens first, while the click still
  // counts as a user gesture, then the run, then the ZIP is written.
  const runAndSave = async () => {
    setErr(null); setMsg(null);
    const target = await pickSaveTarget(suggestedBackupName(), 'application/zip');
    if (target === 'cancelled') return;
    setRunning(true);
    let name: string | null = null;
    try {
      const r = await backupRun();
      if (r.ran && r.name) name = r.name;
      else setMsg('A backup is already running');
    } catch (e) { setErr(e instanceof Error ? e.message : 'backup failed'); }
    finally { setRunning(false); }
    if (!name) {
      if (target !== 'unavailable') await target.discard();
      await refresh();
      return;
    }
    await saveRun(name, target);
    await refresh();
  };
  const remove = async (name: string) => {
    setBusy(true); setErr(null); setMsg(null);
    try { await backupDelete(name); setMsg(`Deleted ${name}`); await refresh(); }
    catch (e) { setErr(e instanceof Error ? e.message : 'delete failed'); }
    finally { setBusy(false); }
  };
  const regen = async () => {
    setBusy(true); setErr(null); setMsg(null);
    try {
      const { token } = await backupRegenerateToken();
      setCfg((c) => (c ? { ...c, token, configured: true } : c));
      setRevealed(true); setMsg('Backup token regenerated');
    } catch (e) { setErr(e instanceof Error ? e.message : 'failed'); }
    finally { setBusy(false); }
  };
  const copy = (text: string) => {
    try { void navigator.clipboard.writeText(text); setMsg('Copied'); } catch { /* ignore */ }
  };

  const origin = typeof window !== 'undefined' ? window.location.origin : '';
  const token = cfg?.token || '';
  const runCmd = `curl -X POST -H "Authorization: Bearer ${token || '<token>'}" ${origin}/api/backup/run`;
  const isRunning = running || !!status?.running;
  // A scheduled backup that has not succeeded for two intervals needs a look.
  const stale = !!status?.enabled && !status.running
    && (!status.lastSuccessAt || Date.now() - status.lastSuccessAt > 2 * status.fullIntervalMin * 60_000)
    && !!status.lastRunAt;
  const failedRooms = status?.lastBackup?.failedRooms ?? [];

  return (
    <div className="mb-4 rounded-md border border-border bg-muted/50 p-3">
      <div className="mb-1 flex items-center gap-2 text-meta font-bold uppercase tracking-widest text-muted-foreground">
        <HardDrive size={12} className="text-primary" /> Backups
      </div>
      <p className="mb-2 text-caption text-muted-foreground">
        Consistent snapshots of the whole instance, written as one self-contained .zip per run into the host folder below.
        Each ZIP is a full copy (screenshots included), so it costs about as much disk as the whole instance.
        {cfg?.keepLast
          ? ` Only the newest ${cfg.keepLast} runs are kept.`
          : ' Nothing is deleted automatically; remove old runs from the list or set "keep last" when you want the space back.'}
      </p>

      <div className="mb-2 flex flex-wrap items-center gap-2 text-meta">
        <span className="text-muted-foreground">Folder</span>
        <code className="rounded bg-muted px-1.5 py-0.5 text-caption text-foreground">{cfg?.dir ?? status?.dir ?? '…'}</code>
        {(cfg?.hostDir ?? status?.hostDir) && <span className="text-muted-foreground">on the host: <code className="rounded bg-muted px-1.5 py-0.5 text-caption text-foreground">{cfg?.hostDir ?? status?.hostDir}</code></span>}
        {status && (
          <span className={`rounded px-1.5 py-0.5 text-caption ${status.dirWritable ? 'bg-status-green/15 text-status-green' : 'bg-status-red/15 text-status-red'}`}>
            {status.dirWritable ? 'writable' : 'not writable: check the ./backups bind mount'}
          </span>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <Checkbox className="items-center text-muted-foreground" checked={!!cfg?.enabled} disabled={!cfg || busy} onChange={(checked) => save({ enabled: checked }, checked ? 'Scheduled backups on' : 'Scheduled backups off')} label="Scheduled backups" />
        <label className="flex items-center gap-1.5 text-meta text-muted-foreground">
          every
          <Input
            type="number"
            min={1}
            value={intervalMin}
            disabled={!cfg || busy}
            onChange={(e) => setIntervalMin(e.target.value)}
            onBlur={commitInterval}
            onKeyDown={(e) => { if (e.key === 'Enter') commitInterval(); }}
            className="w-16 px-1.5 py-0.5 text-meta"
          />
          min
        </label>
        <label className="flex items-center gap-1.5 text-meta text-muted-foreground" title="Delete the oldest complete runs after each successful run (12 until you change it). 0 keeps every run.">
          keep last
          <Input
            type="number"
            min={0}
            value={keepLast}
            disabled={!cfg || busy}
            onChange={(e) => setKeepLast(e.target.value)}
            onBlur={commitKeepLast}
            onKeyDown={(e) => { if (e.key === 'Enter') commitKeepLast(); }}
            className="w-14 px-1.5 py-0.5 text-meta"
          />
          (0 = all)
        </label>
        <Button variant="primary" size="sm"
          onClick={runNow}
          disabled={!cfg || isRunning}
        >
          <Play size={11} /> {isRunning ? 'Backing up…' : 'Back up now'}
        </Button>
        <Button variant="outline" size="sm"
          onClick={() => void runAndSave()}
          disabled={!cfg || isRunning || !!saving}
          title="Run a backup, then save its ZIP to this computer"
        >
          <Download size={11} /> Back up now and save…
        </Button>
      </div>

      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
        {INCLUDE_LABELS.map((inc) => (
          <Checkbox key={inc.key} title={inc.hint} className="items-center text-muted-foreground" checked={cfg ? cfg.includes[inc.key] : true} disabled={!cfg || busy} onChange={(checked) => save({ includes: { [inc.key]: checked } }, `${inc.label}: ${checked ? 'included' : 'excluded'}`)} label={inc.label} />
        ))}
      </div>
      {cfg && (!cfg.includes.sqlite || !cfg.includes.yjsShared) && (
        <p className="mt-1 text-caption text-status-amber">
          A backup that leaves out a category can only be restored with --partial, on top of the existing data for that category.
        </p>
      )}

      {status && (
        <div className="mt-2 grid grid-cols-1 gap-x-4 gap-y-0.5 text-caption text-muted-foreground sm:grid-cols-2">
          <div>
            Last run: {fmtWhen(status.lastRunAt)}
            {status.lastError ? (
              <span className="text-status-red"> failed: {status.lastError}</span>
            ) : status.lastBackup ? (
              <span className="text-status-green"> ok, {fmtBytes(status.lastBackup.bytes)} in {Math.max(1, Math.round((status.lastBackup.durationMs ?? 0) / 1000))} s</span>
            ) : null}
          </div>
          <div>Next run: {status.running && status.runningSince ? `running since ${new Date(status.runningSince).toLocaleTimeString()}` : status.enabled ? fmtUntil(status.nextRunAt) : 'schedule off'}</div>
          <div>
            On disk: {status.usage.count} backup{status.usage.count === 1 ? '' : 's'}, {fmtBytes(status.usage.totalBytes)}
            {status.usage.newBytes != null && status.usage.newBytes < status.usage.totalBytes ? ` (about ${fmtBytes(status.usage.newBytes)}: older folder runs share screenshots through hard links)` : ''}
            {status.freeBytes != null ? `, ${fmtBytes(status.freeBytes)} free` : ''}
          </div>
          {status.lastBackup && <div>Last good: <code className="text-muted-foreground">{status.lastBackup.name}</code>, {fmtWhen(status.lastBackup.at)}</div>}
        </div>
      )}
      {stale && (
        <p className="mt-1 text-caption text-status-amber">
          No successful backup for more than two intervals. Check the error above and the free space on the backup disk.
        </p>
      )}
      {failedRooms.length > 0 && (
        <p className="mt-1 text-caption text-status-amber">
          The last good backup could not read {failedRooms.length} room{failedRooms.length === 1 ? '' : 's'} ({failedRooms.slice(0, 3).join(', ')}{failedRooms.length > 3 ? ', …' : ''}); restoring it leaves them out. See the server log.
        </p>
      )}

      {saving && (
        <p role="status" className="mt-2 text-caption text-muted-foreground">
          Saving {saving.name}: {fmtBytes(saving.written)}
          {saving.total ? ` of ${fmtBytes(saving.total)} (${Math.floor((saving.written / saving.total) * 100)}%)` : ''}
        </p>
      )}
      <div className="mt-2"><FirefoxSaveHint /></div>

      {list.length > 0 && (
        <div className="mt-2 max-h-40 overflow-y-auto rounded-md border border-border">
          <table className="w-full text-caption">
            <tbody>
              {list.map((b) => (
                <tr key={b.name} className="border-b border-border last:border-0">
                  <td className="px-2 py-1 font-mono text-foreground">
                    {b.name}
                    {b.format === 'folder' ? <span className="ml-1 text-muted-foreground" title="written by an older build as a folder; still restorable, but only .zip runs can be saved from here">(folder)</span> : null}
                    {b.partial ? <span className="ml-1 text-status-amber">(incomplete)</span> : null}
                    {b.failedRooms ? <span className="ml-1 text-status-amber" title="rooms the run could not read">({b.failedRooms} room{b.failedRooms === 1 ? '' : 's'} missing)</span> : null}
                  </td>
                  <td className="px-2 py-1 text-muted-foreground">{new Date(b.createdAt).toLocaleString()}</td>
                  <td className="px-2 py-1 text-right text-muted-foreground">{fmtBytes(b.bytes)}</td>
                  <td className="px-2 py-1 text-right text-muted-foreground">{b.files} files</td>
                  <td className="whitespace-nowrap px-1 py-1 text-right">
                    {b.format !== 'folder' && !b.partial && (
                      <IconButton
                        onClick={() => void saveRun(b.name)}
                        disabled={!!saving}
                        title="Save to this computer…"
                        label={`Save ${b.name} to this computer…`}
                      >
                        <Download size={11} />
                      </IconButton>
                    )}
                    <IconButton tone="danger"
                      onClick={() => setPendingRemove(b.name)}
                      disabled={busy}
                      label="Delete this backup"
                    >
                      <Trash2 size={11} />
                    </IconButton>
                    {pendingRemove === b.name && (
                      <ConfirmDialog
                        title="Delete backup"
                        message={`Delete ${b.name}? This cannot be undone.`}
                        confirmLabel="Delete"
                        destructive
                        onCancel={() => setPendingRemove(null)}
                        onConfirm={() => { setPendingRemove(null); void remove(b.name); }}
                      />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="mt-2 rounded-md border border-border bg-muted/50 p-2">
        <div className="mb-1 text-caption text-muted-foreground">
          Host scheduler (optional): a Task Scheduler job, cron entry or systemd timer can trigger a run with this token instead of an admin login.
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <code className="flex-1 truncate rounded bg-muted px-1.5 py-0.5 font-mono text-caption text-muted-foreground">
            {cfg?.configured ? (revealed ? token : '•'.repeat(24)) : 'no token yet (enable backups or regenerate)'}
          </code>
          {cfg?.configured && (
            <Button variant="ghost" size="sm" onClick={() => setRevealed((r) => !r)} className="px-1 py-0.5 text-caption text-muted-foreground hover:text-foreground">
              {revealed ? 'Hide' : 'Reveal'}
            </Button>
          )}
          {cfg?.configured && (
            <Button variant="ghost" size="sm" onClick={() => copy(runCmd)} title="Copy a curl command that runs a backup" className="px-1 py-0.5 text-caption text-muted-foreground hover:text-foreground">
              <Copy size={10} /> Copy curl
            </Button>
          )}
          <Button variant="ghost" size="sm" onClick={regen} disabled={busy} className="px-1 py-0.5 text-caption text-muted-foreground hover:text-foreground">
            <RefreshCw size={10} /> Regenerate
          </Button>
        </div>
        <div className="mt-1 text-caption text-muted-foreground">
          Restore: stop the container, then <code>docker compose run --rm btct bun restore.mjs /backups/&lt;name&gt;.zip --yes</code>, then start it.
          Check a copy without changing anything: <code>bun restore.mjs --verify /backups/&lt;name&gt;.zip</code>. Older folder runs restore the same way, without <code>.zip</code>.
          A restore makes every browser drop its cached copy, so edits made after the backup do not come back. See README "Backups".
        </div>
      </div>

      {(msg || err) && (
        <div className={`mt-2 text-caption ${err ? 'text-status-red' : 'text-status-green'}`}>{err || msg}</div>
      )}
    </div>
  );
}

/**
 * Workspace-wide default strength for new blur (redaction) regions, one
 * value per style. A user who sets their own default in Edit Profile keeps
 * it; every other account follows these.
 */
function BlurConfigSection() {
  const blur = useThemeStore((s) => s.blurDefaults);
  const updateBlurDefaults = useThemeStore((s) => s.updateBlurDefaults);
  const [gaussian, setGaussian] = useState(1);
  const [pixelate, setPixelate] = useState(1);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setGaussian(blur.gaussian);
    setPixelate(blur.pixelate);
  }, [blur]);

  const dirty = gaussian !== blur.gaussian || pixelate !== blur.pixelate;
  const save = async () => {
    setBusy(true); setErr(null); setMsg(null);
    try {
      await updateBlurDefaults({ gaussian, pixelate });
      setMsg('Blur defaults saved');
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'save failed');
    } finally {
      setBusy(false);
    }
  };

  const row = (label: string, hint: string, value: number, onChange: (n: number) => void) => (
    <div className="flex items-center gap-3">
      <span className="w-14 shrink-0 text-meta text-muted-foreground" title={hint}>{label}</span>
      <input
        type="range"
        min={0.25}
        max={3}
        step={0.05}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        aria-label={`${label} strength`}
        className="min-w-0 flex-1 accent-status-purple"
      />
      <span className="w-11 shrink-0 text-right font-mono text-meta text-muted-foreground">{Math.round(value * 100)}%</span>
    </div>
  );

  return (
    <div className="mb-4 rounded-md border border-border bg-muted/50 p-3">
      <div className="mb-1 flex items-center gap-2 text-meta font-bold uppercase tracking-widest text-muted-foreground">
        <EyeOff size={12} className="text-status-purple" /> Blur Defaults
      </div>
      <p className="mb-2 text-caption text-muted-foreground">
        Default strength for new redaction regions on report screenshots, per style.
        Users who set their own default in Edit Profile keep it; everyone else follows these.
      </p>
      <div className="space-y-2">
        {row('Blur', 'Smooth gaussian blur', gaussian, setGaussian)}
        {row('Pixels', 'Hard mosaic blocks', pixelate, setPixelate)}
      </div>
      <div className="mt-2 flex items-center justify-end gap-2">
        <Button variant="ghost" size="sm"
          onClick={() => { setGaussian(blur.gaussian); setPixelate(blur.pixelate); }}
          disabled={busy || !dirty}
          className="text-muted-foreground"
        >
          Reset
        </Button>
        <Button variant="primary"
          onClick={() => void save()}
          disabled={busy || !dirty}
        >
          Save defaults
        </Button>
      </div>
      {(msg || err) && (
        <div className={`mt-2 text-meta ${err ? 'text-status-red' : 'text-muted-foreground'}`}>{err || msg}</div>
      )}
    </div>
  );
}


/**
 * Data retention: auto-prune old page-version history and retired images after
 * a configurable number of days (OFF by default, so nothing is deleted until
 * an admin opts in), plus a one-off "delete edit history in a date range".
 */
function RetentionConfigSection() {
  const getCfg = useAuthStore((s) => s.retentionGetConfig);
  const saveCfg = useAuthStore((s) => s.retentionSaveConfig);
  const run = useAuthStore((s) => s.retentionRun);
  const pruneRange = useAuthStore((s) => s.retentionPruneHistoryRange);

  const [cfg, setCfg] = useState<RetentionStatus | null>(null);
  const [days, setDays] = useState('0');
  const [after, setAfter] = useState('');
  const [before, setBefore] = useState('');
  const [confirmRange, setConfirmRange] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const refresh = () => { void getCfg().then((c) => { setCfg(c); setDays(String(c.days)); }).catch(() => {}); };
  useEffect(() => { refresh(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

  const saveDays = async () => {
    const n = Number(days);
    if (!Number.isFinite(n) || n < 0) { setErr('Days must be 0 (off) or a positive number.'); return; }
    setBusy(true); setErr(null); setMsg(null);
    try { const c = await saveCfg({ days: Math.floor(n) }); setCfg(c); setMsg(n === 0 ? 'Retention off (data kept forever)' : `Auto-prune after ${Math.floor(n)} days`); }
    catch (e) { setErr(e instanceof Error ? e.message : 'save failed'); }
    finally { setBusy(false); }
  };
  const runNow = async () => {
    setBusy(true); setErr(null); setMsg(null);
    try { const res = await run(); setMsg(res.ran ? `Pruned ${res.versions} version(s) and ${res.assets} image(s)` : 'Retention is off'); refresh(); }
    catch (e) { setErr(e instanceof Error ? e.message : 'prune failed'); }
    finally { setBusy(false); }
  };
  const doRange = async () => {
    setBusy(true); setErr(null); setMsg(null);
    try {
      const a = after ? new Date(after).getTime() : 0;
      const b = before ? new Date(before).getTime() : Date.now();
      const res = await pruneRange(a, b);
      setMsg(`Deleted ${res.deleted} history version(s) in range`);
      refresh();
    } catch (e) { setErr(e instanceof Error ? e.message : 'delete failed'); }
    finally { setBusy(false); }
  };

  return (
    <div className="mb-4 rounded-md border border-border bg-muted/50 p-3">
      <div className="mb-1 flex items-center gap-2 text-meta font-bold uppercase tracking-widest text-muted-foreground">
        <Timer size={12} className="text-status-amber" /> Data Retention
      </div>
      <p className="mb-2 text-caption text-muted-foreground">
        Automatically delete page edit-history and images that were removed from notes after a set number of days.
        Off by default, so nothing is ever deleted until you set a number here. The timer survives restarts: an
        overdue prune runs right after the container comes back up.
      </p>

      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-1.5 text-meta text-muted-foreground">
          Delete after
          <Input
            type="number"
            min={0}
            value={days}
            onChange={(e) => setDays(e.target.value)}
            className="w-16 px-1.5 py-0.5 text-meta"
          />
          days {Number(days) === 0 && <span className="text-muted-foreground">(off)</span>}
        </label>
        <Button variant="primary" size="sm" onClick={() => void saveDays()} disabled={busy}>Save</Button>
        <Button variant="outline" size="sm" onClick={() => void runNow()} disabled={busy || !cfg || cfg.days === 0}>Prune now</Button>
      </div>

      {cfg && (
        <div className="mt-2 text-caption text-muted-foreground">
          {cfg.days > 0
            ? <>Auto-prune on. {cfg.dueVersionCount} history version{cfg.dueVersionCount === 1 ? '' : 's'} are past the window now.{cfg.lastPruned ? ` Last prune removed ${cfg.lastPruned.versions} version(s) and ${cfg.lastPruned.assets} image(s).` : ''}</>
            : 'Auto-prune off: history and images are kept forever.'}
        </div>
      )}

      <div className="mt-3 rounded-md border border-border bg-muted/50 p-2">
        <div className="mb-1 text-caption font-semibold uppercase tracking-wider text-muted-foreground">Delete edit history in a date range</div>
        <div className="flex flex-wrap items-center gap-2 text-meta text-muted-foreground">
          <label className="flex items-center gap-1">from <Input type="date" value={after} onChange={(e) => setAfter(e.target.value)} className="w-auto px-1.5 py-0.5 text-meta" /></label>
          <label className="flex items-center gap-1">to <Input type="date" value={before} onChange={(e) => setBefore(e.target.value)} className="w-auto px-1.5 py-0.5 text-meta" /></label>
          <Button variant="outline" size="sm" onClick={() => setConfirmRange(true)} disabled={busy} className="border-status-red/50 text-status-red hover:bg-status-red/10">
            <Trash2 size={11} /> Delete history
          </Button>
        </div>
        <p className="mt-1 text-micro text-muted-foreground">Empty "to" means up to now; empty "from" means from the beginning. This permanently deletes page versions created in the range.</p>
      </div>

      {confirmRange && (
        <ConfirmDialog
          title="Delete edit history"
          message={`Permanently delete all page history versions ${after ? `from ${after}` : 'from the beginning'} ${before ? `to ${before}` : 'up to now'}? This cannot be undone.`}
          confirmLabel="Delete history"
          destructive
          onCancel={() => setConfirmRange(false)}
          onConfirm={() => { setConfirmRange(false); void doRange(); }}
        />
      )}

      {(msg || err) && <div className={`mt-2 text-meta ${err ? 'text-status-red' : 'text-muted-foreground'}`}>{err || msg}</div>}
    </div>
  );
}
