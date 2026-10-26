import { useEffect, useState } from 'react';
import { useShallow } from 'zustand/react/shallow';
import { CloudOff, KeyRound, HardDrive } from 'lucide-react';
import { useAuthStore } from '@/auth/auth-store';
import { bannerFor, DISCONNECT_BANNER_MS, useConnectionStore, type LinkStatus } from '@/realtime/connection-status';
import { cn } from '@/lib/utils';
import { Banner } from '@/components/ui/Banner';
import { Button } from '@/components/ui/Button';

/**
 * A strip over the shell when edits are not reaching the server: the link has
 * been down for more than 10 s, the server rejected this session's token, or
 * the offline cache could not open. Renders nothing otherwise.
 */
export function ConnectionBanner() {
  const state = useConnectionStore(useShallow((s) => ({ ...s })));
  const logout = useAuthStore((s) => s.logout);
  // Re-evaluate once the disconnect threshold passes without a store change.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (state.downSince === null) return;
    const wait = Math.max(0, state.downSince + DISCONNECT_BANNER_MS - Date.now()) + 50;
    const t = window.setTimeout(() => setNow(Date.now()), wait);
    return () => window.clearTimeout(t);
  }, [state.downSince]);
  const kind = bannerFor(state, Math.max(now, Date.now()));
  if (!kind) return null;

  return (
    <Banner
      tone={kind === 'idb' ? 'amber' : 'red'}
      role="status"
      icon={kind === 'auth' ? <KeyRound size={13} /> : kind === 'offline' ? <CloudOff size={13} /> : <HardDrive size={13} />}
      className="shrink-0 rounded-[var(--pane-radius)]"
      actions={kind === 'auth' ? (
        <Button size="sm" variant="outline" className="border-current text-current" onClick={logout}>Log in again</Button>
      ) : undefined}
    >
      <span data-testid="connection-banner">
        {kind === 'auth' && 'The server no longer accepts this session. Edits stay in this browser until you log in again.'}
        {kind === 'offline' && 'Disconnected from the server. Edits are kept in this browser and sync when the connection returns.'}
        {kind === 'idb' && 'Offline cache unavailable (browser storage is blocked or full). Edits only reach the server while connected.'}
      </span>
    </Banner>
  );
}

const DOT: Record<LinkStatus, string> = {
  connected: 'bg-status-green',
  connecting: 'bg-status-amber',
  disconnected: 'bg-destructive',
};

/** A small dot for the sidebar: link state, with the last sync time on hover. */
export function ConnectionDot() {
  const status = useConnectionStore((s) => s.status);
  const lastSyncAt = useConnectionStore((s) => s.lastSyncAt);
  const authRejected = useConnectionStore((s) => s.authRejected);
  const label = authRejected
    ? 'Session rejected by the server'
    : status === 'connected'
      ? `Connected${lastSyncAt ? `, last sync ${new Date(lastSyncAt).toLocaleTimeString()}` : ''}`
      : status === 'connecting' ? 'Connecting to the server…' : 'Disconnected from the server';
  return (
    <span
      role="img"
      aria-label={label}
      title={label}
      data-testid="connection-dot"
      data-status={authRejected ? 'rejected' : status}
      className={cn('inline-block h-2 w-2 shrink-0 rounded-full', authRejected ? DOT.disconnected : DOT[status])}
    />
  );
}
