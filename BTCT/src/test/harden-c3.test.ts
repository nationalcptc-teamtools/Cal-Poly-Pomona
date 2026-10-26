import { describe, expect, it, vi } from 'vitest';
import { Schema } from '@milkdown/prose/model';
import { EditorState, type Plugin } from '@milkdown/prose/state';
import { EditorView } from '@milkdown/prose/view';

// C3: the corner handle accepts every IMAGE_TYPES node (CLAUDE.md: "the
// drag-resize handle works on asset_image too"), so the release must commit
// the width to that node, not only to commonmark's `image`.
vi.mock('@milkdown/utils', () => ({ $prose: (f: () => unknown) => f() }));
vi.mock('@milkdown/preset-commonmark', () => ({ imageAttr: { key: {} }, imageSchema: { extendSchema: () => ({}) } }));
vi.mock('@milkdown/components/image-block', () => ({ imageBlockSchema: { extendSchema: () => ({}) } }));
import { imageResizePlugin } from '@/lib/image-resize';

const schema = new Schema({
  nodes: {
    doc: { content: 'block+' },
    paragraph: { group: 'block', content: 'text*', toDOM: () => ['p', 0] },
    asset_image: { group: 'block', atom: true, attrs: { assetId: { default: '' }, width: { default: null } }, toDOM: () => ['div', ['img']] },
    image: { group: 'block', atom: true, attrs: { src: { default: '' }, width: { default: null } }, toDOM: () => ['div', ['img']] },
    'image-block': { group: 'block', atom: true, attrs: { src: { default: '' }, width: { default: null } }, toDOM: () => ['div', ['img']] },
    text: {},
  },
});

function dragWidth(node: ReturnType<typeof schema.node>): unknown {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const view = new EditorView(host, {
    state: EditorState.create({ schema, doc: schema.node('doc', null, [schema.node('paragraph'), node]), plugins: [imageResizePlugin as unknown as Plugin] }),
  });
  const img = view.dom.querySelector('.pm-image img') as HTMLElement;
  img.dispatchEvent(new MouseEvent('pointerdown', { bubbles: true, button: 0, clientX: 0, clientY: 0 }));
  window.dispatchEvent(new MouseEvent('pointerup', { clientX: 200, clientY: 0 }));
  const width = view.state.doc.child(1).attrs.width;
  view.destroy();
  host.remove();
  return width;
}

describe('C3 drag-resize commits on every resizable image type', () => {
  it('image keeps its dragged width (harness check)', () => {
    expect(dragWidth(schema.node('image', { src: 'x' }))).toBeGreaterThan(0);
  });
  it('asset_image keeps its dragged width', () => {
    expect(dragWidth(schema.node('asset_image', { assetId: 'X' }))).toBeGreaterThan(0);
  });
  it('image-block keeps its dragged width', () => {
    expect(dragWidth(schema.node('image-block', { src: 'x' }))).toBeGreaterThan(0);
  });
});
