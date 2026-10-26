import { beforeEach, describe, expect, it } from 'vitest';
import {
  AUTH_PROBE_INTERVAL_MS, DISCONNECT_BANNER_MS, bannerFor, bindConnectionStatus,
  resetConnectionStatus, useConnectionStore,
} from '@/realtime/connection-status';

// CLI-11 / C15: the shell must say when edits are local-only, and when the
// server stopped accepting this session's token.
class FakeProvider {
  private fns = new Map<string, Set<(...a: never[]) => void>>();
  on(ev: string, fn: (...a: never[]) => void) {
    if (!this.fns.has(ev)) this.fns.set(ev, new Set());
    this.fns.get(ev)!.add(fn);
  }
  off(ev: string, fn: (...a: never[]) => void) { this.fns.get(ev)?.delete(fn); }
  emit(ev: string, ...args: unknown[]) { for (const f of this.fns.get(ev) ?? []) (f as (...a: unknown[]) => void)(...args); }
}
const flush = () => new Promise((r) => setTimeout(r, 0));

beforeEach(() => resetConnectionStatus());

describe('bannerFor', () => {
  const base = { status: 'connected' as const, lastSyncAt: 1, downSince: null, authRejected: false, idbUnavailable: false };
  it('stays quiet while connected, and through a short blip', () => {
    expect(bannerFor(base, 100)).toBeNull();
    expect(bannerFor({ ...base, status: 'connecting', downSince: 0 }, DISCONNECT_BANNER_MS - 1)).toBeNull();
  });
  it('shows offline after the threshold, auth over offline, storage last', () => {
    const down = { ...base, status: 'disconnected' as const, downSince: 0 };
    expect(bannerFor(down, DISCONNECT_BANNER_MS)).toBe('offline');
    expect(bannerFor({ ...down, authRejected: true }, DISCONNECT_BANNER_MS)).toBe('auth');
    expect(bannerFor({ ...base, idbUnavailable: true }, 0)).toBe('idb');
  });
});

describe('bindConnectionStatus', () => {
  it('tracks status and sync time', () => {
    const p = new FakeProvider();
    let t = 1000;
    bindConnectionStatus(p, async () => 'ok', () => {}, () => t);
    p.emit('status', { status: 'connected' });
    expect(useConnectionStore.getState().status).toBe('connected');
    expect(useConnectionStore.getState().downSince).toBeNull();
    t = 2000;
    p.emit('sync', true);
    expect(useConnectionStore.getState().lastSyncAt).toBe(2000);
    t = 3000;
    p.emit('status', { status: 'disconnected' });
    expect(useConnectionStore.getState().downSince).toBe(3000);
  });

  it('probes the token after repeated failed connects and flags a 401, rate-limited', async () => {
    const p = new FakeProvider();
    let t = 0;
    let probes = 0;
    let rejected = 0;
    let verdict: 'ok' | 'rejected' | 'unreachable' = 'unreachable';
    bindConnectionStatus(p, async () => { probes++; return verdict; }, () => { rejected++; }, () => t);
    p.emit('connection-close');
    expect(probes).toBe(0);
    p.emit('connection-close');
    await flush();
    expect(probes).toBe(1);
    expect(useConnectionStore.getState().authRejected).toBe(false);
    verdict = 'rejected';
    p.emit('connection-close');
    await flush();
    expect(probes).toBe(1); // inside the interval
    t += AUTH_PROBE_INTERVAL_MS;
    p.emit('connection-error');
    await flush();
    expect(probes).toBe(2);
    expect(useConnectionStore.getState().authRejected).toBe(true);
    expect(rejected).toBe(1);
  });
});
