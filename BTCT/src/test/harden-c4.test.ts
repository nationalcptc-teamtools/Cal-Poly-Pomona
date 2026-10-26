import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// C4: the note image view must show the render of the asset's CURRENT
// framing (a stale render resolving late must not win), and must not leave a
// blob URL alive once the view is destroyed.
const h = vi.hoisted(() => {
  const listeners = new Set<(s: unknown, p: unknown) => void>();
  let state: { typstAssets: unknown[] } = { typstAssets: [] };
  const pending: Array<{ key: string; resolve: (b: Uint8Array) => void }> = [];
  return {
    listeners,
    pending,
    getState: () => state,
    setAssets: (a: unknown[]) => {
      const prev = state;
      state = { typstAssets: a };
      for (const l of listeners) l(state, prev);
    },
  };
});
vi.mock('@milkdown/utils', () => ({ $node: () => ({}), $view: (_s: unknown, f: () => unknown) => f() }));
vi.mock('@/stores', () => ({
  useAppStore: { getState: h.getState, subscribe: (l: never) => { h.listeners.add(l); return () => h.listeners.delete(l); } },
}));
vi.mock('@/lib/assets', () => ({
  resolveAssetBytes: (a: { blurs?: unknown[] }) =>
    new Promise<Uint8Array>((resolve) => h.pending.push({ key: (a.blurs?.length ?? 0) ? 'blurred' : 'plain', resolve })),
}));
import { assetImageView } from '@/lib/asset-image';

type View = { dom: HTMLElement; destroy: () => void };
const mount = assetImageView as unknown as (n: never) => View;
const fakeNode = { attrs: { assetId: 'X', alt: '', width: null }, type: {} } as never;
const flush = () => new Promise((r) => setTimeout(r, 0));

let n = 0;
let made: string[] = [];
let revoked: Set<string>;
const realCreate = URL.createObjectURL;
const realRevoke = URL.revokeObjectURL;
beforeEach(() => {
  made = [];
  revoked = new Set();
  h.pending.length = 0;
  URL.createObjectURL = () => { const u = `blob:c4-${++n}`; made.push(u); return u; };
  URL.revokeObjectURL = (u: string) => { revoked.add(u); };
});
afterEach(() => { URL.createObjectURL = realCreate; URL.revokeObjectURL = realRevoke; });

describe('C4 note image view render ordering and cleanup', () => {
  it('a render that resolves after destroy leaves no live blob URL', async () => {
    h.setAssets([{ id: 'X', filename: 'x.png', blurs: [] }]);
    const view = mount(fakeNode);
    view.destroy();
    h.pending.shift()!.resolve(new Uint8Array([1]));
    await flush();
    for (const u of made) expect(revoked.has(u)).toBe(true);
  });

  it('an older framing resolving last does not replace the current one', async () => {
    h.setAssets([{ id: 'X', filename: 'x.png', blurs: [{ x: 0, y: 0, w: 1, h: 1 }] }]);
    const view = mount(fakeNode);
    h.setAssets([{ id: 'X', filename: 'x.png', blurs: [] }]); // blur removed
    const [older, newer] = [h.pending[0]!, h.pending[1]!];
    expect([older.key, newer.key]).toEqual(['blurred', 'plain']);
    newer.resolve(new Uint8Array([2]));
    await flush();
    const img = view.dom.querySelector('img') as HTMLImageElement;
    const current = img.getAttribute('src');
    expect(current).toBeTruthy();
    older.resolve(new Uint8Array([3]));
    await flush();
    expect(img.getAttribute('src')).toBe(current);
    view.destroy();
  });
});
