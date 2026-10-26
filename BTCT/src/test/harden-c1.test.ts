import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Schema } from '@milkdown/prose/model';
import { EditorState } from '@milkdown/prose/state';

// C1: removing an image from one note must not retire an asset that is still
// in use elsewhere (another note, the report), because retention later
// deletes a retired asset's bytes for good ("retention never deletes the
// bytes of an image in use").
const store = vi.hoisted(() => ({
  retire: vi.fn(async (_id: string) => {}),
  unretire: vi.fn(async (_id: string) => {}),
}));
vi.mock('@/stores', () => {
  const state = {
    retireTypstAsset: store.retire,
    unretireTypstAsset: store.unretire,
    activeWorkspaceId: 'ws1',
    // Uploaded from the Assets tab (no note-paste origin), placed in the report.
    typstAssets: [{ id: 'X', workspaceId: 'ws1', filename: 'shot.png', kind: 'image', mime: 'image/png', size: 10, deletedAt: null }],
    // Note B still shows the same asset.
    pages: [
      { id: 'A', workspaceId: 'ws1', parentId: null, title: 'A', content: '' },
      { id: 'B', workspaceId: 'ws1', parentId: null, title: 'B', content: '![](asset:X)' },
    ],
  };
  return { useAppStore: { getState: () => state, subscribe: () => () => {} } };
});
import { RETIRE_DELAY_MS, trackAssetImageChanges } from '@/lib/note-image-paste';

const schema = new Schema({
  nodes: {
    doc: { content: 'block+' },
    paragraph: { group: 'block', content: 'text*', toDOM: () => ['p', 0] },
    asset_image: { group: 'block', atom: true, attrs: { assetId: { default: '' } }, toDOM: () => ['img'] },
    text: {},
  },
});

beforeEach(() => { vi.useFakeTimers(); store.retire.mockClear(); });
afterEach(() => { vi.useRealTimers(); });

describe('C1 shared asset retire', () => {
  it('does not retire an asset another note and the Assets tab still use', async () => {
    const a = EditorState.create({ doc: schema.node('doc', null, [schema.node('paragraph'), schema.node('asset_image', { assetId: 'X' })]) });
    const tr = a.tr.delete(2, 3);
    const next = a.apply(tr);
    trackAssetImageChanges([tr], a, next);
    await vi.advanceTimersByTimeAsync(RETIRE_DELAY_MS + 10);
    expect(store.retire).not.toHaveBeenCalled();
  });
});
