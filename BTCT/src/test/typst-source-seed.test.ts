// The report source is the one Y.Text in the shared doc with no repo
// `create()` behind it: the tab that opens it is what seeds it. Seeding
// before the doc has synced writes a SECOND Y.Text into the `texts` slot,
// and Yjs resolves two concurrent map writes by client id, so half the time
// the starter template wins and the real report (which has no version
// history) is gone.
//
// `whenReady` alone is not enough, because it also resolves on its own 4 s
// cap: a client on a congested link or against a server still booting would
// seed anyway. These tests pin the seed to the websocket provider actually
// reporting synced, with the local doc's own copy adopted either way.
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import * as Y from 'yjs';
import { DEFAULT_TYPST_TEMPLATE } from '@/lib/typst-template';

const shared = vi.hoisted(() => ({ current: null as unknown }));

// A stand-in for the real shared doc: a bare Y.Doc plus a `whenReady` this
// test resolves by hand. `getOrInitYText` keeps the real module's semantics
// (return what is already in the slot, seed only when the slot is empty).
vi.mock('@/realtime/shared-doc', async () => {
  const Yjs = await import('yjs');
  interface FakeShared { doc: Y.Doc; texts: Y.Map<Y.Text>; whenReady: Promise<void> }
  const ctx = () => shared.current as unknown as FakeShared;
  return {
    getSharedDoc: () => ctx(),
    textKey: (entity: string, id: string, field: string) => `${entity}:${id}:${field}`,
    getOrInitYText: (key: string, initial: string) => {
      const c = ctx();
      const existing = c.texts.get(key);
      if (existing) return existing;
      let created: Y.Text | undefined;
      c.doc.transact(() => {
        created = c.texts.get(key);
        if (!created) {
          created = new Yjs.Text();
          if (initial) created.insert(0, initial);
          c.texts.set(key, created);
        }
      });
      return c.texts.get(key) ?? created!;
    },
  };
});

import { useTypstSource } from '@/components/typst/use-typst-source';

const KEY = 'typst:ws-1:source';

/** Just enough of y-websocket's provider: a `synced` flag and its event. */
class FakeProvider {
  synced = false;
  private handlers = new Set<(synced: boolean) => void>();
  on(event: string, cb: (synced: boolean) => void) { if (event === 'sync') this.handlers.add(cb); }
  off(event: string, cb: (synced: boolean) => void) { if (event === 'sync') this.handlers.delete(cb); }
  /** How many listeners are attached, so cleanup can be asserted. */
  get listeners() { return this.handlers.size; }
  emitSync() {
    this.synced = true;
    for (const cb of [...this.handlers]) cb(true);
  }
}

let doc: Y.Doc;
let texts: Y.Map<Y.Text>;
let provider: FakeProvider;
let ready: () => void;

beforeEach(() => {
  doc = new Y.Doc();
  texts = doc.getMap<Y.Text>('texts');
  provider = new FakeProvider();
  let resolve!: () => void;
  const whenReady = new Promise<void>((r) => { resolve = r; });
  ready = resolve;
  shared.current = { doc, texts, whenReady, provider };
});

describe('useTypstSource seeding', () => {
  it('writes nothing into the texts map until the shared doc is ready', async () => {
    const { result } = renderHook(() => useTypstSource('ws-1'));

    expect(texts.has(KEY)).toBe(false);
    expect(result.current).toBeNull();

    ready();
    provider.emitSync();
    await waitFor(() => expect(result.current).not.toBeNull());

    expect(texts.has(KEY)).toBe(true);
    expect(texts.get(KEY)!.toString()).toBe(DEFAULT_TYPST_TEMPLATE);
    expect(result.current).toBe(texts.get(KEY));
  });

  it('adopts a text that syncs in before readiness and never seeds over it', async () => {
    const { result } = renderHook(() => useTypstSource('ws-1'));

    // The websocket delivers the workspace's real report while the hook is
    // still waiting: the map observer adopts it.
    const remote = new Y.Text();
    remote.insert(0, '= The real report\n');
    doc.transact(() => texts.set(KEY, remote));

    await waitFor(() => expect(result.current).toBe(remote));

    ready();
    // The seed that runs after readiness finds the slot populated and hands
    // back the same Y.Text rather than replacing it with the template.
    await waitFor(() => expect(texts.get(KEY)).toBe(remote));
    expect(texts.get(KEY)!.toString()).toBe('= The real report\n');
    expect(result.current).toBe(remote);
  });

  it('drops the previous workspace text when the workspace changes', async () => {
    const { result, rerender } = renderHook((id: string) => useTypstSource(id), {
      initialProps: 'ws-1',
    });
    ready();
    provider.emitSync();
    await waitFor(() => expect(result.current).not.toBeNull());
    const first = result.current;

    rerender('ws-2');
    expect(result.current).toBeNull();
    expect(result.current).not.toBe(first);
  });
});

// `whenReady` resolves on a 4 s cap as well as on a real sync, so it cannot
// be the thing that authorizes a seed: a client that has simply not heard
// from the server yet would write the template and race the real text.
describe('useTypstSource waits for the websocket, not just for whenReady', () => {
  it('does not seed while the provider is unsynced, however long whenReady took', async () => {
    const { result } = renderHook(() => useTypstSource('ws-1'));

    ready();
    // Let every pending microtask run: the seed must still not have happened.
    await Promise.resolve();
    await Promise.resolve();

    expect(texts.has(KEY)).toBe(false);
    expect(result.current).toBeNull();
  });

  it('seeds as soon as the provider reports synced', async () => {
    const { result } = renderHook(() => useTypstSource('ws-1'));
    ready();
    await Promise.resolve();
    expect(texts.has(KEY)).toBe(false);

    provider.emitSync();

    await waitFor(() => expect(result.current).not.toBeNull());
    expect(texts.get(KEY)!.toString()).toBe(DEFAULT_TYPST_TEMPLATE);
  });

  it('uses a text the local doc already holds without waiting for the server', async () => {
    // Offline, but this workspace's report is in IndexedDB: it replayed into
    // the doc before `whenReady`, so it is the canonical text, not a seed.
    const cached = new Y.Text();
    cached.insert(0, '= Cached report\n');
    doc.transact(() => texts.set(KEY, cached));

    const { result } = renderHook(() => useTypstSource('ws-1'));
    ready();

    await waitFor(() => expect(result.current).toBe(cached));
    expect(provider.synced).toBe(false);
    expect(texts.get(KEY)!.toString()).toBe('= Cached report\n');
  });

  it('adopts a text that arrives before the sync event and never seeds over it', async () => {
    const { result } = renderHook(() => useTypstSource('ws-1'));
    ready();
    await Promise.resolve();

    const remote = new Y.Text();
    remote.insert(0, '= The real report\n');
    doc.transact(() => texts.set(KEY, remote));
    await waitFor(() => expect(result.current).toBe(remote));

    // The sync event still fires afterwards; the seed it authorizes finds the
    // slot populated and hands back the same text.
    provider.emitSync();
    await waitFor(() => expect(texts.get(KEY)).toBe(remote));
    expect(texts.get(KEY)!.toString()).toBe('= The real report\n');
    expect(result.current).toBe(remote);
  });

  it('removes its sync handler on unmount, so a later sync seeds nothing', async () => {
    const { unmount } = renderHook(() => useTypstSource('ws-1'));
    ready();
    await waitFor(() => expect(provider.listeners).toBe(1));

    unmount();
    expect(provider.listeners).toBe(0);

    provider.emitSync();
    await Promise.resolve();
    expect(texts.has(KEY)).toBe(false);
  });
});
