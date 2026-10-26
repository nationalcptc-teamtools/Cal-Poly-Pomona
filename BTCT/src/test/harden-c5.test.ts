import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@/realtime/shared-doc', () => ({ disposeSharedDoc: vi.fn() }));
vi.mock('@/realtime/yjs-providers', () => ({ disposeAllPageDocs: vi.fn() }));

// C5: with site data blocked or the quota full, localStorage writes throw.
// The client runs memory-only in that case, so a session the server issued
// (or a profile change it saved) must still land in the store.
const USER = { id: 1, username: 'qa', color: '#fff', isAdmin: true };

async function freshStore() {
  vi.resetModules();
  return (await import('@/auth/auth-store'));
}

beforeEach(() => {
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new DOMException('blocked', 'SecurityError'); });
  vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => { throw new DOMException('blocked', 'SecurityError'); });
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  localStorage.clear();
});

describe('C5 auth with unwritable localStorage', () => {
  it('login still authenticates', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ token: 't', user: USER }), { status: 200 })));
    const { useAuthStore } = await freshStore();
    await useAuthStore.getState().login('qa', 'pw');
    expect(useAuthStore.getState().status).toBe('authenticated');
    expect(useAuthStore.getState().token).toBe('t');
  });

  it('updateProfile still updates the user', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ user: { ...USER, color: '#000' } }), { status: 200 })));
    const { useAuthStore } = await freshStore();
    useAuthStore.setState({ token: 't', user: USER, status: 'authenticated' });
    await useAuthStore.getState().updateProfile({ color: '#000' } as never);
    expect(useAuthStore.getState().user?.color).toBe('#000');
  });

  it('logout still clears the session', async () => {
    const { useAuthStore } = await freshStore();
    useAuthStore.setState({ token: 't', user: USER, status: 'authenticated' });
    try { useAuthStore.getState().logout(); } catch { /* asserted below */ }
    expect(useAuthStore.getState().status).toBe('unauthenticated');
    expect(useAuthStore.getState().token).toBeNull();
  });
});
