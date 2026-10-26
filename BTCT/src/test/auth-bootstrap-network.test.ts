import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@/realtime/shared-doc', () => ({ disposeSharedDoc: vi.fn() }));
vi.mock('@/realtime/yjs-providers', () => ({ disposeAllPageDocs: vi.fn() }));

// CLI-11 / C15: only a 401/403 from /api/me logs out. A network error or a
// 5xx (redeploy, proxy) keeps the stored session and retries.
const USER = { id: 1, username: 'qa', color: '#fff', isAdmin: true };

async function freshStore() {
  vi.resetModules();
  return (await import('@/auth/auth-store'));
}

beforeEach(() => {
  localStorage.setItem('btct.auth.token', 'tok');
  localStorage.setItem('btct.auth.user', JSON.stringify(USER));
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
  localStorage.clear();
});

describe('auth bootstrap', () => {
  it('keeps the session when the server is unreachable, then confirms it on retry', async () => {
    vi.useFakeTimers();
    let calls = 0;
    vi.stubGlobal('fetch', vi.fn(async () => {
      calls++;
      if (calls === 1) throw new TypeError('Failed to fetch');
      if (calls === 2) return new Response('bad gateway', { status: 502 });
      return new Response(JSON.stringify({ user: { ...USER, username: 'qa2' } }), { status: 200 });
    }));
    const { useAuthStore } = await freshStore();
    const run = useAuthStore.getState().bootstrap();
    await vi.advanceTimersByTimeAsync(0);
    expect(useAuthStore.getState().status).toBe('authenticated');
    expect(useAuthStore.getState().token).toBe('tok');
    await vi.advanceTimersByTimeAsync(5000);
    await run;
    expect(calls).toBe(3);
    expect(useAuthStore.getState().user?.username).toBe('qa2');
    expect(localStorage.getItem('btct.auth.token')).toBe('tok');
  });

  it('logs out on 401', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 401 })));
    const { useAuthStore } = await freshStore();
    await useAuthStore.getState().bootstrap();
    expect(useAuthStore.getState().status).toBe('unauthenticated');
    expect(localStorage.getItem('btct.auth.token')).toBeNull();
  });

  it('without a stored user, waits on the loading screen instead of logging out', async () => {
    localStorage.removeItem('btct.auth.user');
    vi.useFakeTimers();
    vi.stubGlobal('fetch', vi.fn(async () => new Response('oops', { status: 500 })));
    const { useAuthStore } = await freshStore();
    void useAuthStore.getState().bootstrap();
    await vi.advanceTimersByTimeAsync(0);
    expect(useAuthStore.getState().status).toBe('unknown');
    expect(useAuthStore.getState().error).toMatch(/unreachable/);
    expect(useAuthStore.getState().token).toBe('tok');
    useAuthStore.getState().logout();
    await vi.advanceTimersByTimeAsync(60_000);
  });

  it('checkMe classifies answers', async () => {
    const { checkMe } = await freshStore();
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 403 })));
    expect((await checkMe('t')).kind).toBe('rejected');
    vi.stubGlobal('fetch', vi.fn(async () => new Response('<html>', { status: 200 })));
    expect((await checkMe('t')).kind).toBe('unreachable');
  });
});
