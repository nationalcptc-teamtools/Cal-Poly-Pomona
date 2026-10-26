/**
 * What the shared provider's connection looks like right now, for the status
 * dot in the sidebar and the banner over the shell.
 *
 * Three things used to fail in silence:
 * - the websocket dropped (server restart, network blip) and edits stayed in
 *   this browser with nothing on screen saying so;
 * - the token expired or was rejected: the server answers the upgrade with
 *   401, y-websocket reconnects forever and nothing ever tells the user;
 * - IndexedDB could not open (storage blocked, profile out of disk), which
 *   left the app on "Connecting..." for good.
 *
 * The store is plain state plus pure helpers; `bindConnectionStatus` wires
 * one provider to it and is called from `getSharedDoc`.
 */
import { create } from 'zustand';

export type LinkStatus = 'connecting' | 'connected' | 'disconnected';

export interface ConnectionState {
  status: LinkStatus;
  /** Last time the shared provider finished a sync with the server. */
  lastSyncAt: number | null;
  /** When the link last went from connected to anything else (null while connected). */
  downSince: number | null;
  /** The server rejected this session's token (401/403 on /api/me after failed connects). */
  authRejected: boolean;
  /** IndexedDB could not open: the app runs from memory and the server only. */
  idbUnavailable: boolean;
}

const INITIAL: ConnectionState = {
  status: 'connecting',
  lastSyncAt: null,
  downSince: null,
  authRejected: false,
  idbUnavailable: false,
};

export const useConnectionStore = create<ConnectionState>(() => ({ ...INITIAL }));

/** A disconnect shorter than this is a blip; the banner waits it out. */
export const DISCONNECT_BANNER_MS = 10_000;
/** Ask the server whether the token is still good at most this often. */
export const AUTH_PROBE_INTERVAL_MS = 15_000;
/** Consecutive failed connects before the token is suspected. */
export const AUTH_PROBE_AFTER_FAILURES = 2;

export type BannerKind = 'auth' | 'offline' | 'idb' | null;

/** Which banner (if any) the shell shows. Auth outranks offline, which outranks storage. */
export function bannerFor(s: ConnectionState, now: number): BannerKind {
  if (s.authRejected) return 'auth';
  if (s.status !== 'connected' && s.downSince !== null && now - s.downSince >= DISCONNECT_BANNER_MS) return 'offline';
  if (s.idbUnavailable) return 'idb';
  return null;
}

export function markIdbUnavailable(): void {
  useConnectionStore.setState({ idbUnavailable: true });
}

export function markAuthRejected(): void {
  useConnectionStore.setState({ authRejected: true });
}

export function resetConnectionStatus(): void {
  useConnectionStore.setState({ ...INITIAL, downSince: Date.now() });
}

interface ProviderLike {
  on(event: 'status', fn: (e: { status: LinkStatus }) => void): void;
  on(event: 'sync', fn: (synced: boolean) => void): void;
  on(event: 'connection-close' | 'connection-error', fn: () => void): void;
  off(event: string, fn: (...args: never[]) => void): void;
}

/**
 * Follow one provider. `probeAuth` is asked (rate-limited) whether the token
 * is still accepted once connects keep failing; it resolves 'rejected' only
 * for a 401/403, and the caller decides what to do then (`onRejected`).
 */
export function bindConnectionStatus(
  provider: ProviderLike,
  probeAuth: () => Promise<'ok' | 'rejected' | 'unreachable'>,
  onRejected: () => void,
  now: () => number = Date.now,
): () => void {
  let failures = 0;
  let lastProbe = Number.NEGATIVE_INFINITY;
  let probing = false;
  useConnectionStore.setState({ status: 'connecting', downSince: now() });

  const onStatus = (e: { status: LinkStatus }) => {
    const prev = useConnectionStore.getState();
    if (e.status === 'connected') {
      failures = 0;
      useConnectionStore.setState({ status: 'connected', downSince: null });
    } else {
      useConnectionStore.setState({ status: e.status, downSince: prev.downSince ?? now() });
    }
  };
  const onSync = (synced: boolean) => {
    if (synced) useConnectionStore.setState({ lastSyncAt: now() });
  };
  const onFailure = () => {
    if (useConnectionStore.getState().status === 'connected') return;
    failures++;
    if (failures < AUTH_PROBE_AFTER_FAILURES || probing) return;
    const t = now();
    if (t - lastProbe < AUTH_PROBE_INTERVAL_MS) return;
    lastProbe = t;
    probing = true;
    void probeAuth()
      .then((verdict) => {
        if (verdict !== 'rejected' || useConnectionStore.getState().authRejected) return;
        markAuthRejected();
        onRejected();
      })
      .catch(() => undefined)
      .finally(() => { probing = false; });
  };

  provider.on('status', onStatus);
  provider.on('sync', onSync);
  provider.on('connection-close', onFailure);
  provider.on('connection-error', onFailure);
  return () => {
    provider.off('status', onStatus as never);
    provider.off('sync', onSync as never);
    provider.off('connection-close', onFailure as never);
    provider.off('connection-error', onFailure as never);
  };
}
