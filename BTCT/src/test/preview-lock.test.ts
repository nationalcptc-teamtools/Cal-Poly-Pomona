import { describe, it, expect, afterEach } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import {
  loadLockedWorkspaces, saveLockedWorkspaces, toggleLocked, previewLockKey, isPreviewLockKey, MAX_LOCKED_WORKSPACES,
} from '@/lib/preview-lock';
import { usePreviewLock } from '@/components/typst/use-preview-lock';
import { useAuthStore } from '@/auth/auth-store';

function memoryStorage(): Storage {
  const data = new Map<string, string>();
  return {
    get length() { return data.size; },
    clear: () => data.clear(),
    getItem: (k) => data.get(k) ?? null,
    key: (i) => [...data.keys()][i] ?? null,
    removeItem: (k) => { data.delete(k); },
    setItem: (k, v) => { data.set(k, String(v)); },
  };
}

describe('preview lock storage', () => {
  it('keeps each account apart', () => {
    const s = memoryStorage();
    saveLockedWorkspaces(1, new Set(['ws-a']), s);
    expect(loadLockedWorkspaces(1, s).has('ws-a')).toBe(true);
    expect(loadLockedWorkspaces(2, s).has('ws-a')).toBe(false);
    expect(previewLockKey(1)).not.toBe(previewLockKey(2));
  });

  it('writes nothing without an account and reads nothing back', () => {
    const s = memoryStorage();
    saveLockedWorkspaces(null, new Set(['ws-a']), s);
    expect(s.length).toBe(0);
    expect(loadLockedWorkspaces(null, s).size).toBe(0);
  });

  it('removes the key when nothing is locked', () => {
    const s = memoryStorage();
    saveLockedWorkspaces(1, new Set(['ws-a']), s);
    saveLockedWorkspaces(1, new Set(), s);
    expect(s.getItem(previewLockKey(1))).toBeNull();
  });

  it('reads junk as unlocked and survives a storage that throws', () => {
    const s = memoryStorage();
    s.setItem(previewLockKey(1), '{not json');
    expect(loadLockedWorkspaces(1, s).size).toBe(0);
    s.setItem(previewLockKey(1), JSON.stringify(['ok', 5, null, '']));
    expect([...loadLockedWorkspaces(1, s)]).toEqual(['ok']);
    const broken = { ...memoryStorage(), getItem: () => { throw new Error('denied'); }, setItem: () => { throw new Error('quota'); } } as Storage;
    expect(loadLockedWorkspaces(1, broken).size).toBe(0);
    expect(() => saveLockedWorkspaces(1, new Set(['x']), broken)).not.toThrow();
  });

  it('caps the stored list, dropping the oldest locks', () => {
    const s = memoryStorage();
    const many = new Set(Array.from({ length: MAX_LOCKED_WORKSPACES + 5 }, (_, i) => `ws-${i}`));
    saveLockedWorkspaces(1, many, s);
    const back = loadLockedWorkspaces(1, s);
    expect(back.size).toBe(MAX_LOCKED_WORKSPACES);
    expect(back.has('ws-0')).toBe(false);
    expect(back.has(`ws-${MAX_LOCKED_WORKSPACES + 4}`)).toBe(true);
  });

  it('toggles without touching the input and recognises its own storage events', () => {
    const start = new Set(['a']);
    expect([...toggleLocked(start, 'b')].sort()).toEqual(['a', 'b']);
    expect([...toggleLocked(start, 'a')]).toEqual([]);
    expect([...start]).toEqual(['a']);
    expect(isPreviewLockKey(previewLockKey(7), 7)).toBe(true);
    expect(isPreviewLockKey(previewLockKey(7), 8)).toBe(false);
    expect(isPreviewLockKey(null, 7)).toBe(false);
  });
});

describe('usePreviewLock', () => {
  const asUser = (id: number, username: string) =>
    useAuthStore.setState({ user: { id, username, color: '#888888' } as never });

  afterEach(() => {
    localStorage.clear();
    useAuthStore.setState({ user: null });
  });

  it('is per account on a shared browser and per workspace', () => {
    asUser(1, 'Roberto');
    const { result, rerender } = renderHook(({ ws }) => usePreviewLock(ws), { initialProps: { ws: 'w1' } });
    expect(result.current.locked).toBe(false);
    act(() => result.current.toggle());
    expect(result.current.locked).toBe(true);

    // Another workspace of the same account: not locked.
    rerender({ ws: 'w2' });
    expect(result.current.locked).toBe(false);
    rerender({ ws: 'w1' });
    expect(result.current.locked).toBe(true);

    // Warren logs in on the same browser: his preview is not locked.
    act(() => asUser(2, 'Warren'));
    expect(result.current.locked).toBe(false);

    // Back to Roberto: his lock is still there.
    act(() => asUser(1, 'Roberto'));
    expect(result.current.locked).toBe(true);
  });

  it('never writes the lock anywhere but this browser', () => {
    asUser(1, 'Roberto');
    const { result } = renderHook(() => usePreviewLock('w1'));
    act(() => result.current.toggle());
    expect(Object.keys(localStorage)).toEqual([previewLockKey(1)]);
  });
});
