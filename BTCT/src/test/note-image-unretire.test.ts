import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Schema } from '@milkdown/prose/model';
import { EditorState, type Transaction } from '@milkdown/prose/state';

// CLI-4 / C6: a cut and paste (or a move between notes) must never leave the
// asset retired, and a re-inserted retired asset is un-retired.
const store = vi.hoisted(() => ({
  retire: vi.fn(async (_id: string) => {}),
  unretire: vi.fn(async (_id: string) => {}),
}));
vi.mock('@/stores', () => ({
  useAppStore: { getState: () => ({ retireTypstAsset: store.retire, unretireTypstAsset: store.unretire }) },
}));
import { RETIRE_DELAY_MS, collectAssetImageIds, retirePending, stepsTouchAssetImages, trackAssetImageChanges } from '@/lib/note-image-paste';

const schema = new Schema({
  nodes: {
    doc: { content: 'block+' },
    paragraph: { group: 'block', content: 'text*', toDOM: () => ['p', 0] },
    asset_image: { group: 'block', atom: true, attrs: { assetId: { default: '' } }, toDOM: () => ['img'] },
    text: {},
  },
});
const img = (id: string) => schema.node('asset_image', { assetId: id });
const para = (t: string) => schema.node('paragraph', null, t ? [schema.text(t)] : []);

function apply(state: EditorState, tr: Transaction): EditorState {
  const next = state.apply(tr);
  trackAssetImageChanges([tr], state, next);
  return next;
}

beforeEach(() => { vi.useFakeTimers(); store.retire.mockClear(); store.unretire.mockClear(); });
afterEach(() => { vi.useRealTimers(); });

describe('note image retire and un-retire', () => {
  it('cut then paste inside the delay never retires', async () => {
    let s = EditorState.create({ doc: schema.node('doc', null, [para('a'), img('A1'), para('b')]) });
    const imgPos = 3; // after the first paragraph (size 3)
    s = apply(s, s.tr.delete(imgPos, imgPos + 1));
    expect(retirePending('A1')).toBe(true);
    await vi.advanceTimersByTimeAsync(2000);
    s = apply(s, s.tr.insert(s.doc.content.size, img('A1')));
    expect(retirePending('A1')).toBe(false);
    await vi.advanceTimersByTimeAsync(RETIRE_DELAY_MS * 2);
    expect(store.retire).not.toHaveBeenCalled();
  });

  it('a removal that stays removed retires after the delay', async () => {
    let s = EditorState.create({ doc: schema.node('doc', null, [para('a'), img('B1')]) });
    s = apply(s, s.tr.delete(3, 4));
    await vi.advanceTimersByTimeAsync(RETIRE_DELAY_MS);
    expect(store.retire).toHaveBeenCalledWith('B1');
  });

  it('inserting an image un-retires its asset, remote or local', async () => {
    let s = EditorState.create({ doc: schema.node('doc', null, [para('a')]) });
    const tr = s.tr.insert(s.doc.content.size, img('C1'));
    tr.setMeta('y-sync$', { isChangeOrigin: true });
    s = apply(s, tr);
    await vi.advanceTimersByTimeAsync(0);
    expect(store.unretire).toHaveBeenCalledWith('C1');
  });

  it('typing next to an image does not walk the document', () => {
    const s = EditorState.create({ doc: schema.node('doc', null, [para('hello'), img('D1')]) });
    const tr = s.tr.insertText('x', 2);
    expect(stepsTouchAssetImages([tr])).toBe(false);
    const del = s.tr.delete(7, 8);
    expect(stepsTouchAssetImages([del])).toBe(true);
    expect([...collectAssetImageIds(s.doc)]).toEqual(['D1']);
  });
});
