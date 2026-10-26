import { afterEach, describe, expect, it, vi } from 'vitest';
import { Schema } from '@milkdown/prose/model';
import { EditorState } from '@milkdown/prose/state';
import { EditorView } from '@milkdown/prose/view';

// CLI-16 / C5: a failed upload keeps the File and offers Retry; an upload
// that finishes after its note closed says where the image went.
const store = vi.hoisted(() => ({ add: vi.fn() }));
vi.mock('@/stores', () => ({
  useAppStore: { getState: () => ({ addTypstAsset: store.add, retireTypstAsset: vi.fn(), unretireTypstAsset: vi.fn() }) },
}));
vi.mock('@/lib/active-editor', () => ({ getActiveMilkdownEditor: () => null }));
import { insertImages, MAX_NOTE_PASTE_CHARS, formatSize } from '@/lib/note-image-paste';
import { useEditorNotices } from '@/lib/editor-notices';

const schema = new Schema({
  nodes: {
    doc: { content: 'block+' },
    paragraph: { group: 'block', content: 'text*', toDOM: () => ['p', 0] },
    asset_image: { group: 'block', atom: true, attrs: { assetId: { default: '' }, alt: { default: '' } }, toDOM: () => ['img'] },
    text: {},
  },
});
function makeView() {
  const state = EditorState.create({ doc: schema.node('doc', null, [schema.node('paragraph', null, [schema.text('notes')])]) });
  return new EditorView(document.createElement('div'), { state });
}
const images = (v: EditorView) => { const ids: string[] = []; v.state.doc.descendants((n) => { if (n.type.name === 'asset_image') ids.push(n.attrs.assetId); }); return ids; };

afterEach(() => { useEditorNotices.setState({ notices: [] }); store.add.mockReset(); });

describe('note image paste failures', () => {
  it('a failed upload shows a notice whose Retry uploads the same file again', async () => {
    const view = makeView();
    const file = new File([new Uint8Array([1, 2, 3])], 'shot.png', { type: 'image/png' });
    store.add.mockRejectedValueOnce(new Error('request failed (502)'));
    await insertImages(view, [file]);
    const notices = useEditorNotices.getState().notices;
    expect(notices).toHaveLength(1);
    expect(notices[0]!.message).toMatch(/shot\.png.*502/);
    expect(images(view)).toEqual([]);

    store.add.mockResolvedValueOnce({ id: 'asset-1', filename: 'shot.png' });
    notices[0]!.actions.find((a) => a.label === 'Retry')!.run();
    await vi.waitFor(() => expect(images(view)).toEqual(['asset-1']));
    expect(store.add.mock.calls[1]![0]).toBe(file);
    view.destroy();
  });

  it('an upload that finishes after the note closed never dispatches to the dead view', async () => {
    const view = makeView();
    let resolve!: (v: unknown) => void;
    store.add.mockReturnValueOnce(new Promise((r) => { resolve = r; }));
    const file = new File([new Uint8Array([1])], 'late.png', { type: 'image/png' });
    const done = insertImages(view, [file]);
    view.destroy();
    resolve({ id: 'asset-late', filename: 'late.png' });
    await done;
    const n = useEditorNotices.getState().notices;
    expect(n).toHaveLength(1);
    expect(n[0]!.message).toMatch(/late\.png.*Assets tab/);
  });

  it('sizes a refused text paste', () => {
    expect(MAX_NOTE_PASTE_CHARS).toBe(1_000_000);
    expect(formatSize(3_200_000)).toBe('3.2 MB');
    expect(formatSize(250_000)).toBe('250 KB');
  });
});
