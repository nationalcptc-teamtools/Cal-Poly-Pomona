import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import * as Y from 'yjs';
import { Schema, type Node as ProseNode, type Mark } from '@milkdown/prose/model';
import { EditorState, TextSelection, type Transaction } from '@milkdown/prose/state';
import { EditorView } from '@milkdown/prose/view';
import { ySyncPlugin, prosemirrorToYXmlFragment } from 'y-prosemirror';
import {
  buildRevealDecorations,
  buildRevealMarkers,
  naturalSlot,
  slotMarkersAt,
  slotStoredMarks,
  type RevealMarker,
} from '@/components/editor/live-preview/syntax-reveal';
import {
  createLivePreviewProsePlugin,
  livePreviewKey,
  placeCaretBeforeListMarker,
  slotFromClick,
  wrapSelection,
} from '@/components/editor/live-preview/live-preview-plugin';
import {
  DEFAULT_EDITOR_STYLE,
  __resetEditorStyleForTests,
  applyEditorStyle,
  getEditorStyle,
  isLivePreview,
  isSourceMode,
  otherEditorStyle,
  setSourceMode,
  resolveEditorStyle,
  subscribeEditorStyle,
} from '@/components/editor/live-preview/editor-style';
import { DEFAULT_EDITOR_PREFS, resolvePrefs } from '@/lib/editor-prefs';
import { createBlockSelectProsePlugin, __resetBlockSelectForTests } from '@/lib/block-select';

// A schema with Milkdown's node and mark names and the attributes the
// builder reads (heading.level, list_item.checked, ordered_list.order,
// code_block.language, strong/emphasis.marker, link.href/title).
const schema = new Schema({
  nodes: {
    doc: { content: 'block+' },
    paragraph: { group: 'block', content: 'inline*', toDOM: () => ['p', 0], parseDOM: [{ tag: 'p' }] },
    heading: {
      group: 'block',
      content: 'inline*',
      attrs: { level: { default: 1 } },
      toDOM: (n) => [`h${n.attrs.level}`, 0],
      parseDOM: [1, 2, 3, 4, 5, 6].map((l) => ({ tag: `h${l}`, attrs: { level: l } })),
    },
    blockquote: { group: 'block', content: 'block+', toDOM: () => ['blockquote', 0], parseDOM: [{ tag: 'blockquote' }] },
    code_block: {
      group: 'block',
      content: 'text*',
      marks: '',
      code: true,
      attrs: { language: { default: '' } },
      toDOM: () => ['pre', ['code', 0]],
      parseDOM: [{ tag: 'pre' }],
    },
    bullet_list: { group: 'block', content: 'list_item+', toDOM: () => ['ul', 0], parseDOM: [{ tag: 'ul' }] },
    ordered_list: {
      group: 'block',
      content: 'list_item+',
      attrs: { order: { default: 1 } },
      toDOM: () => ['ol', 0],
      parseDOM: [{ tag: 'ol' }],
    },
    list_item: {
      content: 'paragraph block*',
      attrs: { checked: { default: null } },
      toDOM: () => ['li', 0],
      parseDOM: [{ tag: 'li' }],
    },
    hr: { group: 'block', atom: true, selectable: true, toDOM: () => ['hr'], parseDOM: [{ tag: 'hr' }] },
    'image-block': {
      group: 'block',
      atom: true,
      selectable: true,
      attrs: { src: { default: '' }, caption: { default: '' }, ratio: { default: 1 } },
      toDOM: (n) => ['img', { src: n.attrs.src }],
    },
    image: {
      group: 'inline',
      inline: true,
      atom: true,
      attrs: { src: { default: '' }, alt: { default: '' }, title: { default: '' } },
      toDOM: (n) => ['img', { src: n.attrs.src }],
    },
    text: { group: 'inline' },
  },
  marks: {
    link: {
      attrs: { href: {}, title: { default: null } },
      inclusive: false,
      toDOM: (m) => ['a', { href: m.attrs.href }, 0],
      parseDOM: [{ tag: 'a[href]' }],
    },
    strong: { attrs: { marker: { default: '*' } }, toDOM: () => ['strong', 0], parseDOM: [{ tag: 'strong' }] },
    emphasis: { attrs: { marker: { default: '*' } }, toDOM: () => ['em', 0], parseDOM: [{ tag: 'em' }] },
    inlineCode: { inclusive: false, toDOM: () => ['code', 0], parseDOM: [{ tag: 'code' }] },
    strike_through: { toDOM: () => ['del', 0], parseDOM: [{ tag: 'del' }] },
    highlight: { attrs: { color: { default: 'yellow' } }, inclusive: false, toDOM: () => ['mark', 0], parseDOM: [{ tag: 'mark' }] },
  },
});

const t = (text: string, ...marks: Mark[]) => schema.text(text, marks);
const p = (...c: ProseNode[]) => schema.node('paragraph', null, c);
const h = (level: number, ...c: ProseNode[]) => schema.node('heading', { level }, c);
const doc = (...c: ProseNode[]) => schema.node('doc', null, c);
const strong = schema.marks.strong!.create();
const em = schema.marks.emphasis!.create();
const code = schema.marks.inlineCode!.create();
const strike = schema.marks.strike_through!.create();
const hl = schema.marks.highlight!.create();
const link = (href: string, title: string | null = null) => schema.marks.link!.create({ href, title });

/** Position of the first occurrence of `needle` in the doc's text (+ offset). */
function posOf(d: ProseNode, needle: string, offset = 0): number {
  let found = -1;
  d.descendants((node, pos) => {
    if (found >= 0) return false;
    if (node.isText) {
      const i = node.text!.indexOf(needle);
      if (i >= 0) found = pos + i + offset;
    }
    return true;
  });
  if (found < 0) throw new Error(`"${needle}" not in doc`);
  return found;
}

const caret = (d: ProseNode, needle: string, offset = 0) => {
  const pos = posOf(d, needle, offset);
  return { from: pos, to: pos };
};
const texts = (ms: RevealMarker[]) => ms.map((m) => m.text);

/** Render the markers into the text, the way the widgets read on screen. */
function render(d: ProseNode, ms: RevealMarker[], from: number, to: number): string {
  let out = '';
  for (let pos = from; pos <= to; pos++) {
    out += ms.filter((m) => m.pos === pos).map((m) => m.text).join('');
    if (pos < to) out += d.textBetween(pos, pos + 1, '\n', '□');
  }
  return out;
}

describe('buildRevealMarkers: block prefixes', () => {
  it('reveals the heading level at the start of the active heading only', () => {
    const d = doc(h(2, t('Recon')), p(t('body')), h(3, t('Ports')));
    const ms = buildRevealMarkers(d, caret(d, 'Recon', 2));
    expect(ms).toEqual([{ pos: 1, text: '## ', kind: 'heading', side: -1 }]);
    expect(buildRevealMarkers(d, caret(d, 'Ports'))[0]).toMatchObject({ text: '### ' });
    expect(buildRevealMarkers(d, caret(d, 'body'))).toEqual([]);
  });

  it('caps the heading marker at six hashes', () => {
    const d = doc(h(6, t('x')));
    expect(texts(buildRevealMarkers(d, caret(d, 'x')))).toEqual(['###### ']);
  });

  it('reveals `> ` for a quoted paragraph, once per nesting level', () => {
    const d = doc(
      schema.node('blockquote', null, [p(t('outer')), schema.node('blockquote', null, [p(t('inner'))])]),
    );
    expect(texts(buildRevealMarkers(d, caret(d, 'outer')))).toEqual(['> ']);
    // One marker per level, each its own caret slot.
    expect(texts(buildRevealMarkers(d, caret(d, 'inner')))).toEqual(['> ', '> ']);
  });

  it('reveals bullet, numbered and task markers on the first line of the item', () => {
    const li = (attrs: Record<string, unknown> | null, ...c: ProseNode[]) => schema.node('list_item', attrs, c);
    const d = doc(
      schema.node('bullet_list', null, [li(null, p(t('bullet')), p(t('continued')))]),
      schema.node('ordered_list', { order: 3 }, [li(null, p(t('third'))), li(null, p(t('fourth')))]),
      schema.node('bullet_list', null, [li({ checked: false }, p(t('todo'))), li({ checked: true }, p(t('done')))]),
    );
    const bullet = buildRevealMarkers(d, caret(d, 'bullet'));
    expect(bullet).toHaveLength(1);
    expect(bullet[0]).toMatchObject({ text: '- ', kind: 'list', listItemPos: 1 });
    // A second paragraph in the same item is a continuation: no marker.
    expect(buildRevealMarkers(d, caret(d, 'continued'))).toEqual([]);
    expect(buildRevealMarkers(d, caret(d, 'third'))[0]).toMatchObject({ text: '3. ', kind: 'ordered' });
    expect(texts(buildRevealMarkers(d, caret(d, 'fourth')))).toEqual(['4. ']);
    expect(buildRevealMarkers(d, caret(d, 'todo'))[0]).toMatchObject({ text: '- [ ] ', kind: 'task' });
    expect(buildRevealMarkers(d, caret(d, 'done'))[0]).toMatchObject({ text: '- [x] ', kind: 'task' });
  });

  it('reveals only the innermost item marker in a nested list', () => {
    const li = (...c: ProseNode[]) => schema.node('list_item', null, c);
    const d = doc(schema.node('bullet_list', null, [li(p(t('parent')), schema.node('bullet_list', null, [li(p(t('child')))]))]));
    expect(texts(buildRevealMarkers(d, caret(d, 'child')))).toEqual(['- ']);
    expect(texts(buildRevealMarkers(d, caret(d, 'parent')))).toEqual(['- ']);
  });

  it('reveals the fences around a code block that holds the selection', () => {
    const d = doc(p(t('before')), schema.node('code_block', { language: 'shell' }, [schema.text('nmap -sV 10.0.0.1')]), p(t('after')));
    const pos = posOf(d, 'nmap', 3);
    const ms = buildRevealMarkers(d, { from: pos, to: pos });
    const block = d.child(1);
    const blockPos = d.child(0).nodeSize;
    expect(ms).toEqual([
      { pos: blockPos, text: '```shell', kind: 'fence-open', side: -1 },
      { pos: blockPos + block.nodeSize, text: '```', kind: 'fence-close', side: 1 },
    ]);
    expect(buildRevealMarkers(d, caret(d, 'after'))).toEqual([]);
  });

  it('reveals the prefix of every block a selection spans', () => {
    const d = doc(h(1, t('Title')), p(t('middle')), h(2, t('Sub')));
    const ms = buildRevealMarkers(d, { from: posOf(d, 'Title', 1), to: posOf(d, 'Sub', 1) });
    expect(texts(ms)).toEqual(['# ', '## ']);
  });
});

describe('buildRevealMarkers: inline marks', () => {
  it('reveals the delimiters of each mark under the caret', () => {
    const cases: Array<[Mark, string, string]> = [
      [strong, '**', '**'],
      [em, '*', '*'],
      [strike, '~~', '~~'],
      [code, '`', '`'],
      [hl, '==', '=='],
    ];
    for (const [mark, open, close] of cases) {
      const d = doc(p(t('a '), t('word', mark), t(' b')));
      const ms = buildRevealMarkers(d, caret(d, 'word', 2));
      expect(render(d, ms, 1, d.child(0).nodeSize - 1)).toBe(`a ${open}word${close} b`);
    }
  });

  it('honours an underscore marker', () => {
    const d = doc(p(t('x', schema.marks.strong!.create({ marker: '_' }))));
    expect(texts(buildRevealMarkers(d, caret(d, 'x')))).toEqual(['__', '__']);
  });

  it('reveals only marks that contain or touch the caret', () => {
    const d = doc(p(t('bold', strong), t(' plain '), t('ital', em)));
    expect(texts(buildRevealMarkers(d, caret(d, 'plain', 2)))).toEqual([]);
    // Caret right after "bold" touches the strong range.
    expect(texts(buildRevealMarkers(d, caret(d, 'bold', 4)))).toEqual(['**', '**']);
    // Caret right before "ital" touches the emphasis range.
    expect(texts(buildRevealMarkers(d, caret(d, 'ital')))).toEqual(['*', '*']);
  });

  it('nests delimiters of nested marks in markdown order', () => {
    const d = doc(p(t('a '), t('b ', strong), t('c', strong, em), t(' d', strong), t(' e')));
    const ms = buildRevealMarkers(d, caret(d, 'c'));
    expect(render(d, ms, 1, d.child(0).nodeSize - 1)).toBe('a **b *c* d** e');
  });

  it('orders two marks over the same text as balanced pairs', () => {
    const d = doc(p(t('both', strong, em)));
    const ms = buildRevealMarkers(d, caret(d, 'both', 1));
    expect(render(d, ms, 1, 5)).toBe('***both***');
    const opens = ms.filter((m) => m.kind === 'mark-open').map((m) => m.mark);
    const closes = ms.filter((m) => m.kind === 'mark-close').map((m) => m.mark);
    expect(closes).toEqual([...opens].reverse());
  });

  it('puts a closer before an opener at a shared position', () => {
    const d = doc(p(t('one', strong), t('two', em)));
    const ms = buildRevealMarkers(d, { from: 1, to: 7 });
    expect(render(d, ms, 1, 7)).toBe('**one***two*');
  });

  it('reveals a link as [text](url), title included', () => {
    const d = doc(p(t('see '), t('the docs', link('https://example.com/a')), t(' now')));
    const ms = buildRevealMarkers(d, caret(d, 'docs'));
    expect(render(d, ms, 1, d.child(0).nodeSize - 1)).toBe('see [the docs](https://example.com/a) now');
    const d2 = doc(p(t('x', link('https://e.x', 'Title'))));
    expect(texts(buildRevealMarkers(d2, caret(d2, 'x')))).toEqual(['[', '](https://e.x "Title")']);
  });

  it('keeps a bold link nested correctly', () => {
    const d = doc(p(t('go', link('u'), strong)));
    const ms = buildRevealMarkers(d, caret(d, 'go', 1));
    const out = render(d, ms, 1, 3);
    expect(['[**go**](u)', '**[go](u)**']).toContain(out);
  });

  it('combines block prefixes and marks on one line', () => {
    const d = doc(h(2, t('Open '), t('ports', code)));
    const ms = buildRevealMarkers(d, caret(d, 'ports', 1));
    expect(render(d, ms, 1, d.child(0).nodeSize - 1)).toBe('## Open `ports`');
  });

  it('caret placement sides: openers after the caret, inclusive closers after, exclusive closers before', () => {
    const d = doc(p(t('b', strong), t(' '), t('c', code)));
    const ms = buildRevealMarkers(d, { from: 1, to: 5 });
    const s = (mark: string, kind: string) => ms.find((m) => m.mark === mark && m.kind === kind)!.side;
    expect(s('strong', 'mark-open')).toBeGreaterThan(0);
    expect(s('strong', 'mark-close')).toBeGreaterThan(0);
    expect(s('inlineCode', 'mark-close')).toBeLessThan(0);
  });
});

describe('buildRevealDecorations', () => {
  it('builds one widget per inline marker and keeps the checkbox while the caret is in the text', () => {
    const d = doc(schema.node('bullet_list', null, [schema.node('list_item', { checked: false }, [p(t('task', strong))])]));
    const set = buildRevealDecorations(d, caret(d, 'task', 1));
    const all = set.find();
    const widgets = all.filter((x) => (x.spec as { lpKind?: string }).lpKind);
    expect(widgets.map((x) => (x.spec as { lpKind: string }).lpKind).sort()).toEqual(['mark-close', 'mark-open']);
    // No node class: the checkbox stays rendered.
    expect(all.filter((x) => !(x.spec as { lpKind?: string }).lpKind)).toHaveLength(0);
  });

  it('swaps the checkbox for `- [ ]` in place when the caret is in front of the marker', () => {
    const d = doc(schema.node('bullet_list', null, [schema.node('list_item', { checked: false }, [p(t('task'))])]));
    const all = buildRevealDecorations(d, { from: 3, to: 3, slot: 0 }).find();
    expect(all).toHaveLength(1);
    expect(all[0]!.from).toBe(1);
    expect((all[0] as unknown as { type: { attrs: { class: string } } }).type.attrs.class).toBe('lp-li-raw lp-li-raw-todo lp-li-caret');
  });

  it('is empty when nothing is revealed', () => {
    const d = doc(p(t('plain')));
    expect(buildRevealDecorations(d, caret(d, 'plain')).find()).toHaveLength(0);
  });
});

// ── Plugin on a real EditorView (jsdom) ───────────────────────────────────

describe('live preview plugin', () => {
  beforeAll(() => {
    EditorView.prototype.coordsAtPos = () => ({ left: 0, right: 0, top: 0, bottom: 0 });
  });
  beforeEach(() => __resetEditorStyleForTests());
  afterEach(() => {
    __resetEditorStyleForTests();
    document.body.innerHTML = '';
  });

  function mount(d: ProseNode, extra: Parameters<typeof EditorState.create>[0]['plugins'] = [], focused = true) {
    const trs: Transaction[] = [];
    const state = EditorState.create({ doc: d, plugins: [...(extra ?? []), createLivePreviewProsePlugin({ initialFocused: focused })] });
    const el = document.createElement('div');
    document.body.appendChild(el);
    const view: EditorView = new EditorView(el, {
      state,
      dispatchTransaction(this: EditorView, tr) {
        trs.push(tr);
        this.updateState(this.state.apply(tr));
      },
    });
    return { view, trs };
  }
  const moveTo = (view: EditorView, pos: number, to = pos) =>
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, pos, to)));
  const markerText = (view: EditorView) => [...view.dom.querySelectorAll('.lp-marker')].map((e) => e.textContent).join('|');

  it('shows markers for the selection and never changes the document', () => {
    const d = doc(h(2, t('Recon')), p(t('see '), t('bold', strong), t(' and '), t('link', link('https://x.y'))));
    const { view, trs } = mount(d);
    const before = view.state.doc;
    expect(view.dom.classList.contains('lp-live')).toBe(true);

    moveTo(view, posOf(view.state.doc, 'Recon', 1));
    expect(markerText(view)).toBe('## ');
    moveTo(view, posOf(view.state.doc, 'bold', 2));
    expect(markerText(view)).toBe('**|**');
    moveTo(view, posOf(view.state.doc, 'link', 2));
    expect(markerText(view)).toBe('[|](https://x.y)');
    moveTo(view, 1, view.state.doc.content.size - 1);
    expect(markerText(view)).toContain('## ');

    expect(trs.every((tr) => !tr.docChanged)).toBe(true);
    expect(view.state.doc.eq(before)).toBe(true);
    // Markers are widgets: the document text never contains them.
    expect(view.state.doc.textContent).toBe('Reconsee bold and link');
    view.destroy();
  });

  it('switching style is live, meta-only, and Blocks shows nothing', async () => {
    const d = doc(h(1, t('Title')));
    const { view, trs } = mount(d);
    moveTo(view, 2);
    expect(markerText(view)).toBe('# ');

    applyEditorStyle('blocks');
    expect(livePreviewKey.getState(view.state)!.style).toBe('blocks');
    expect(markerText(view)).toBe('');
    expect(view.dom.classList.contains('lp-live')).toBe(false);

    applyEditorStyle('live');
    expect(markerText(view)).toBe('# ');
    expect(trs.every((tr) => !tr.docChanged)).toBe(true);
    const metas = trs.filter((tr) => tr.getMeta(livePreviewKey));
    expect(metas.length).toBeGreaterThanOrEqual(2);
    expect(metas.every((tr) => tr.getMeta('addToHistory') === false)).toBe(true);
    view.destroy();
  });

  it('shows nothing before the first focus, then keeps the cursor line revealed after a blur', () => {
    const d = doc(h(1, t('Title')));
    const { view } = mount(d, [], false);
    moveTo(view, 2);
    expect(markerText(view)).toBe('');
    view.dom.dispatchEvent(new FocusEvent('focusin', { bubbles: true }));
    expect(markerText(view)).toBe('# ');
    view.dom.dispatchEvent(new FocusEvent('focusout', { bubbles: true, relatedTarget: null }));
    expect(livePreviewKey.getState(view.state)!.focused).toBe(false);
    expect(markerText(view)).toBe('# ');
    view.destroy();
  });

  it('keeps (maps) its decorations during an IME composition', () => {
    const d = doc(h(1, t('Title')));
    const { view } = mount(d);
    moveTo(view, 2);
    const before = livePreviewKey.getState(view.state)!.decorations;
    view.dom.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true }));
    moveTo(view, 4);
    // Not rebuilt during the composition: the same widget, mapped.
    expect(livePreviewKey.getState(view.state)!.decorations.find().map((x) => x.from)).toEqual(before.find().map((x) => x.from));
    view.dom.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true }));
    view.destroy();
  });

  it('holds the markers still during a mouse drag and rebuilds on release', async () => {
    const d = doc(h(1, t('Title')), p(t('some '), t('bold', strong)));
    const { view } = mount(d);
    moveTo(view, 2);
    expect(markerText(view)).toBe('# ');
    // jsdom has no layout: keep ProseMirror's own mousedown handler out of it.
    (view as unknown as { posAtCoords: () => null }).posAtCoords = () => null;
    view.dom.querySelector('p')!.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, button: 0 }));
    moveTo(view, 2, posOf(view.state.doc, 'bold', 2));
    // Mid-drag: still only the heading marker, mapped.
    expect(markerText(view)).toBe('# ');
    window.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 5));
    expect(markerText(view)).toBe('# |**|**');
    view.destroy();
  });


  it('collaboration: moving the cursor and switching styles writes nothing to Yjs', async () => {
    const ydoc = new Y.Doc();
    const frag = ydoc.getXmlFragment('prosemirror');
    const d = doc(h(2, t('Scope')), p(t('a '), t('bold', strong), t(' '), t('ref', link('https://x.y'))), schema.node('code_block', { language: 'shell' }, [schema.text('id')]));
    prosemirrorToYXmlFragment(d, frag);
    const peer = new Y.Doc();
    Y.applyUpdate(peer, Y.encodeStateAsUpdate(ydoc));

    const { view } = mount(schema.node('doc', null, [p()]), [ySyncPlugin(frag)]);
    await new Promise((r) => setTimeout(r, 10));
    expect(view.state.doc.textContent).toBe('Scopea bold refid');

    const sv = Y.encodeStateVector(ydoc);
    let updates = 0;
    ydoc.on('update', () => { updates++; });

    for (const needle of ['Scope', 'bold', 'ref', 'id']) {
      moveTo(view, posOf(view.state.doc, needle, 1));
    }
    moveTo(view, 1, view.state.doc.content.size - 1);
    applyEditorStyle('blocks');
    applyEditorStyle('live');
    view.dom.dispatchEvent(new FocusEvent('focusout', { bubbles: true }));
    view.dom.dispatchEvent(new FocusEvent('focusin', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 10));

    expect(updates).toBe(0);
    expect(Buffer.from(Y.encodeStateVector(ydoc)).equals(Buffer.from(sv))).toBe(true);
    // A peer's edit still lands in the decorated view.
    const peerFrag = peer.getXmlFragment('prosemirror');
    peer.on('update', (u: Uint8Array) => Y.applyUpdate(ydoc, u));
    const heading = peerFrag.get(0) as Y.XmlElement;
    (heading.get(0) as Y.XmlText).insert(5, ' and rules');
    await new Promise((r) => setTimeout(r, 10));
    expect(view.state.doc.child(0).textContent).toBe('Scope and rules');
    view.destroy();
  });
});

// ── Obsidian parity: list markers, caret slots, atoms ─────────────────────

const li = (attrs: Record<string, unknown> | null, ...c: ProseNode[]) => schema.node('list_item', attrs, c);
const ul = (...items: ProseNode[]) => schema.node('bullet_list', null, items);
const ol = (...items: ProseNode[]) => schema.node('ordered_list', null, items);
const quote = (...c: ProseNode[]) => schema.node('blockquote', null, c);

/** Render with the caret drawn as `|` where the slot puts it. */
function renderCaret(d: ProseNode, ms: RevealMarker[], from: number, to: number, caretPos: number): string {
  let out = '';
  for (let pos = from; pos <= to; pos++) {
    const here = ms.filter((m) => m.pos === pos && !m.hidden);
    if (pos === caretPos) {
      out += here.filter((m) => m.side < 0).map((m) => m.text).join('') + '|' + here.filter((m) => m.side > 0).map((m) => m.text).join('');
    } else {
      out += here.map((m) => m.text).join('');
    }
    if (pos < to) out += d.textBetween(pos, pos + 1, '\n', '□');
  }
  return out;
}

describe('Obsidian parity: list markers', () => {
  it('keeps the bullet while the caret is anywhere in the item text, even at its start', () => {
    const d = doc(ul(li(null, p(t('item')))));
    for (const off of [0, 2, 4]) {
      const [m] = buildRevealMarkers(d, caret(d, 'item', off));
      expect(m).toMatchObject({ kind: 'list', text: '- ', hidden: true });
    }
  });

  it('shows the raw marker with the caret in front of it (slot 0)', () => {
    const d = doc(ul(li(null, p(t('item')))));
    const [m] = buildRevealMarkers(d, { from: 3, to: 3, slot: 0 });
    expect(m).toMatchObject({ kind: 'list', hidden: false, caret: true });
  });

  it('shows the raw marker of every item a selection runs across, not the one it starts in', () => {
    const d = doc(ul(li(null, p(t('one'))), li(null, p(t('two'))), li(null, p(t('three')))));
    const ms = buildRevealMarkers(d, { from: posOf(d, 'one', 1), to: posOf(d, 'three', 2) });
    expect(ms.filter((m) => m.kind === 'list').map((m) => m.hidden)).toEqual([true, false, false]);
  });

  it('treats an ordered item as text in both states', () => {
    const d = doc(ol(li(null, p(t('first')))));
    const [m] = buildRevealMarkers(d, { from: 3, to: 3, slot: 0 });
    expect(m).toMatchObject({ kind: 'ordered', text: '1. ', caret: true });
    const classes = buildRevealDecorations(d, { from: 3, to: 3, slot: 0 }).find()[0] as unknown as { type: { attrs: { class: string } } };
    expect(classes.type.attrs.class).toBe('lp-li-raw lp-li-raw-ordered lp-li-caret');
  });

  it('a nested item reveals only its own marker', () => {
    const d = doc(ul(li(null, p(t('parent')), ul(li(null, p(t('child')))))));
    const ms = buildRevealMarkers(d, { from: posOf(d, 'child'), to: posOf(d, 'child'), slot: 0 });
    expect(ms.filter((m) => !m.hidden).map((m) => m.listItemPos)).toEqual([posOf(d, 'child') - 2]);
  });
});

describe('Obsidian parity: caret slots', () => {
  it('the natural slot follows ProseMirror: inside an inclusive closer, outside an exclusive one', () => {
    const d = doc(p(t('bold', strong), t(' '), t('code', code)));
    const end = posOf(d, 'bold', 4);
    expect(renderCaret(d, buildRevealMarkers(d, caret(d, 'bold', 4)), 1, 6, end)).toBe('**bold|** ');
    const cEnd = posOf(d, 'code', 4);
    expect(renderCaret(d, buildRevealMarkers(d, { from: cEnd, to: cEnd }), 6, cEnd, cEnd)).toBe('`code`|');
  });

  it('a slot moves the caret across the markers at one position', () => {
    const d = doc(p(t('a '), t('bold', strong), t(' z')));
    const end = posOf(d, 'bold', 4);
    const at = slotMarkersAt(buildRevealMarkers(d, { from: end, to: end }), end);
    expect(at.map((m) => m.text)).toEqual(['**']);
    expect(naturalSlot(at)).toBe(0);
    const ms = buildRevealMarkers(d, { from: end, to: end, slot: 1 });
    expect(renderCaret(d, ms, 1, d.child(0).nodeSize - 1, end)).toBe('a **bold**| z');
  });

  it('line prefixes are slots too: in front of `## ` and after it', () => {
    const d = doc(quote(h(2, t('Title'))));
    const start = posOf(d, 'Title');
    const at = slotMarkersAt(buildRevealMarkers(d, { from: start, to: start }), start);
    expect(at.map((m) => m.text)).toEqual(['> ', '## ']);
    expect(naturalSlot(at)).toBe(2);
    expect(renderCaret(d, buildRevealMarkers(d, { from: start, to: start, slot: 0 }), start, start + 5, start)).toBe('|> ## Title');
    expect(renderCaret(d, buildRevealMarkers(d, { from: start, to: start, slot: 1 }), start, start + 5, start)).toBe('> |## Title');
  });

  it('slotStoredMarks: what typing picks up in each slot', () => {
    const d = doc(p(t('x '), t('bold', strong), t(' y')));
    const end = posOf(d, 'bold', 4);
    const ms = buildRevealMarkers(d, { from: end, to: end });
    expect(slotStoredMarks(d, ms, end, 0).map((m) => m.type.name)).toEqual(['strong']);
    expect(slotStoredMarks(d, ms, end, 1)).toEqual([]);
    const start = posOf(d, 'bold');
    const ms2 = buildRevealMarkers(d, { from: start, to: start });
    expect(slotStoredMarks(d, ms2, start, 0)).toEqual([]);
    expect(slotStoredMarks(d, ms2, start, 1).map((m) => m.type.name)).toEqual(['strong']);
  });

  it('a slot out of range is clamped', () => {
    const d = doc(h(1, t('T')));
    const ms = buildRevealMarkers(d, { from: 1, to: 1, slot: 99 });
    expect(ms[0]!.side).toBeLessThan(0);
  });
});

describe('Obsidian parity: rules and images', () => {
  it('a selected rule shows `---` in place of its line', () => {
    const d = doc(p(t('a')), schema.node('hr'), p(t('b')));
    const hrPos = 3;
    const ms = buildRevealMarkers(d, { from: hrPos, to: hrPos + 1 });
    expect(ms).toEqual([{ pos: hrPos, text: '---', kind: 'hr', side: -1, nodePos: hrPos }]);
    const decos = buildRevealDecorations(d, { from: hrPos, to: hrPos + 1 }).find();
    expect(decos.some((x) => (x as unknown as { type: { attrs?: { class?: string } } }).type.attrs?.class === 'lp-hr-raw')).toBe(true);
    expect(buildRevealMarkers(d, caret(d, 'a'))).toEqual([]);
  });

  it('a selected image block shows its markdown above it', () => {
    const d = doc(schema.node('image-block', { src: 'https://x/y.png', caption: 'cap', ratio: 1 }));
    expect(texts(buildRevealMarkers(d, { from: 0, to: 1 }))).toEqual(['![1.00](https://x/y.png "cap")']);
  });

  it('an inline image shows its markdown while the caret is on its line', () => {
    const d = doc(p(t('see '), schema.node('image', { src: 'a.png', alt: 'shot' }), t(' here')));
    expect(texts(buildRevealMarkers(d, caret(d, 'here')))).toEqual(['![shot](a.png)']);
  });
});

describe('Obsidian parity: editing the revealed syntax', () => {
  beforeAll(() => {
    EditorView.prototype.coordsAtPos = () => ({ left: 0, right: 0, top: 0, bottom: 0 });
  });
  beforeEach(() => __resetEditorStyleForTests());
  afterEach(() => {
    __resetEditorStyleForTests();
    document.body.innerHTML = '';
  });

  function mount(d: ProseNode, extra: Parameters<typeof EditorState.create>[0]['plugins'] = []) {
    const state = EditorState.create({ doc: d, plugins: [...(extra ?? []), createLivePreviewProsePlugin({ initialFocused: true })] });
    const el = document.createElement('div');
    document.body.appendChild(el);
    return new EditorView(el, { state });
  }
  const at = (view: EditorView, pos: number) =>
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, pos)));
  const key = (view: EditorView, k: string, o: KeyboardEventInit = {}) => {
    const ev = new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true, ...o });
    view.dom.dispatchEvent(ev);
    return ev.defaultPrevented;
  };
  const slot = (view: EditorView) => livePreviewKey.getState(view.state)!.slot;
  const liClass = (view: EditorView) => view.dom.querySelector('li')?.className ?? '';
  const markerText = (view: EditorView) => [...view.dom.querySelectorAll('.lp-marker')].map((e) => e.textContent).join('|');

  it('ArrowLeft at the start of a bullet item steps in front of the marker; ArrowRight steps back', () => {
    const view = mount(doc(ul(li(null, p(t('item'))))));
    at(view, 3);
    expect(view.dom.querySelector('.lp-li-raw')).toBeNull();
    expect(key(view, 'ArrowLeft')).toBe(true);
    expect(slot(view)).toBe(0);
    expect(view.dom.querySelector('.lp-li-raw-bullet.lp-li-caret')).not.toBeNull();
    expect(key(view, 'ArrowRight')).toBe(true);
    expect(view.dom.querySelector('.lp-li-raw')).toBeNull();
    // Out of slots: the browser moves the caret.
    expect(key(view, 'ArrowRight')).toBe(false);
    expect(view.state.selection.from).toBe(3);
    void liClass;
    view.destroy();
  });

  it('Home at the start of a heading puts the caret in front of `## `', () => {
    const view = mount(doc(h(2, t('Title'))));
    at(view, 1);
    expect(key(view, 'Home')).toBe(true);
    const w = view.dom.querySelector('.lp-marker') as HTMLElement;
    expect(w.textContent).toBe('## ');
    expect(slot(view)).toBe(0);
    view.destroy();
  });

  it('clicking a bullet (placeCaretBeforeListMarker) reveals its `-` with the caret in front', () => {
    const view = mount(doc(p(t('x')), ul(li(null, p(t('item'))))));
    at(view, 1);
    expect(placeCaretBeforeListMarker(view, 4)).toBe(true);
    expect(view.state.selection.from).toBe(6);
    expect(view.dom.querySelector('.lp-li-raw-bullet.lp-li-caret')).not.toBeNull();
    view.destroy();
  });

  it('Backspace after a revealed `## ` lowers the heading, then makes it text', () => {
    const view = mount(doc(h(2, t('Title'))));
    at(view, 1);
    expect(key(view, 'Backspace')).toBe(true);
    expect(view.state.doc.child(0).attrs.level).toBe(1);
    expect(key(view, 'Backspace')).toBe(true);
    expect(view.state.doc.child(0).type.name).toBe('paragraph');
    expect(view.state.doc.textContent).toBe('Title');
    view.destroy();
  });

  it('`#` typed in front of `## ` raises the level and keeps the caret in front', () => {
    const view = mount(doc(h(2, t('Title'))));
    at(view, 1);
    key(view, 'Home');
    expect(key(view, '#', { shiftKey: true })).toBe(true);
    expect(view.state.doc.child(0).attrs.level).toBe(3);
    expect(slot(view)).toBe(0);
    view.destroy();
  });

  it('Delete in front of `## ` removes one `#`; Delete after it deletes the first letter', () => {
    const view = mount(doc(h(2, t('Title'))));
    at(view, 1);
    key(view, 'Home');
    expect(key(view, 'Delete')).toBe(true);
    expect(view.state.doc.child(0).attrs.level).toBe(1);
    at(view, 1);
    expect(key(view, 'Delete')).toBe(true);
    expect(view.state.doc.child(0).attrs.level).toBe(1);
    expect(view.state.doc.textContent).toBe('itle');
    view.destroy();
  });

  it('Backspace right after a revealed `**` unbolds the whole run', () => {
    const view = mount(doc(p(t('a '), t('bold', strong), t(' z'))));
    const end = posOf(view.state.doc, 'bold', 4);
    at(view, end);
    expect(key(view, 'ArrowRight')).toBe(true); // past the closer
    expect(key(view, 'Backspace')).toBe(true);
    expect(view.state.doc.rangeHasMark(1, view.state.doc.content.size, schema.marks.strong!)).toBe(false);
    expect(view.state.doc.textContent).toBe('a bold z');
    view.destroy();
  });

  it('Backspace after a revealed inline-code closer removes the code mark; Delete before `**` unbolds', () => {
    const view = mount(doc(p(t('x '), t('c', code), t(' '), t('b', strong))));
    const cEnd = posOf(view.state.doc, 'c', 1);
    at(view, cEnd);
    expect(key(view, 'Backspace')).toBe(true);
    expect(view.state.doc.rangeHasMark(1, view.state.doc.content.size, schema.marks.inlineCode!)).toBe(false);
    const bStart = posOf(view.state.doc, 'b');
    at(view, bStart);
    expect(key(view, 'Delete')).toBe(true);
    expect(view.state.doc.rangeHasMark(1, view.state.doc.content.size, schema.marks.strong!)).toBe(false);
    view.destroy();
  });

  it('Backspace at the start of a task drops the box, then the bullet', () => {
    const view = mount(doc(ul(li({ checked: false }, p(t('todo'))))));
    at(view, 3);
    expect(key(view, 'Backspace')).toBe(true);
    expect(view.state.doc.child(0).child(0).attrs.checked).toBe(null);
    expect(key(view, 'Backspace')).toBe(true);
    expect(view.state.doc.child(0).type.name).toBe('paragraph');
    expect(view.state.doc.textContent).toBe('todo');
    view.destroy();
  });

  it('Backspace at the start of a later item makes it a continuation of the item above', () => {
    const view = mount(doc(ul(li(null, p(t('one'))), li(null, p(t('two'))))));
    at(view, posOf(view.state.doc, 'two'));
    expect(key(view, 'Backspace')).toBe(true);
    const list = view.state.doc.child(0);
    expect(list.childCount).toBe(1);
    expect(list.child(0).childCount).toBe(2);
    expect(list.child(0).child(1).textContent).toBe('two');
    view.destroy();
  });

  it('Backspace on an empty line after a nested list deletes the line and goes to the end of the line above', () => {
    const view = mount(doc(ul(li(null, p(t('two')), ul(li(null, p(t('kid')))), p()))));
    const empty = view.state.doc.content.size - 3;
    at(view, empty);
    expect(view.state.selection.$from.parent.content.size).toBe(0);
    expect(key(view, 'Backspace')).toBe(true);
    const item = view.state.doc.child(0).child(0);
    expect(item.childCount).toBe(2);
    expect(view.state.selection.$from.parent.textContent).toBe('kid');
    expect(view.state.selection.$from.parentOffset).toBe(3);
    view.destroy();
  });

  it('Backspace at the start of a quoted line takes it out of the quote', () => {
    const view = mount(doc(quote(p(t('one')), p(t('two')))));
    at(view, posOf(view.state.doc, 'two'));
    expect(key(view, 'Backspace')).toBe(true);
    expect(view.state.doc.child(0).type.name).toBe('blockquote');
    expect(view.state.doc.child(1).type.name).toBe('paragraph');
    expect(view.state.doc.child(1).textContent).toBe('two');
    view.destroy();
  });

  it('typing at the start of a line in front of `**bold**` is plain, as the caret is drawn', () => {
    const view = mount(doc(p(t('bold', strong))));
    at(view, 1);
    expect((view.state.storedMarks ?? []).length).toBe(0);
    view.dispatch(view.state.tr.insertText('x'));
    expect(view.state.doc.child(0).child(0).text).toBe('x');
    expect(view.state.doc.child(0).child(0).marks).toEqual([]);
    view.destroy();
  });

  it('marks an input rule chose stay chosen, and the caret is drawn in the slot that types them', () => {
    const view = mount(doc(p(t('x'))));
    at(view, 2);
    // What the `**bold**` input rule leaves behind: a bold run, the caret
    // at its end, stored marks set to "no bold".
    const tr = view.state.tr.insertText('bold', 2).addMark(2, 6, strong).setStoredMarks([]);
    view.dispatch(tr);
    expect(view.state.storedMarks).toEqual([]);
    expect(slot(view)).toBe(1);
    expect(markerText(view)).toBe('**|**');
    view.dispatch(view.state.tr.insertText('!'));
    expect(view.state.doc.child(0).lastChild!.text).toBe('!');
    expect(view.state.doc.child(0).lastChild!.marks).toEqual([]);
    view.destroy();
  });

  it('typing in the slot after a closer is outside the mark', () => {
    const view = mount(doc(p(t('bold', strong), t(' z'))));
    at(view, 5);
    key(view, 'ArrowRight');
    view.dispatch(view.state.tr.insertText('!'));
    expect(view.state.doc.child(0).textContent).toBe('bold! z');
    const bang = view.state.doc.child(0).child(1);
    expect(bang.text).toBe('! z');
    expect(bang.marks).toEqual([]);
    view.destroy();
  });

  it('caret slots and their stored marks never touch Yjs', async () => {
    const ydoc = new Y.Doc();
    const frag = ydoc.getXmlFragment('prosemirror');
    prosemirrorToYXmlFragment(doc(h(2, t('T')), p(t('a '), t('bold', strong), t(' z')), ul(li(null, p(t('item'))))), frag);
    const view = mount(schema.node('doc', null, [p()]), [ySyncPlugin(frag)]);
    await new Promise((r) => setTimeout(r, 10));
    let updates = 0;
    ydoc.on('update', () => {
      updates++;
    });
    at(view, posOf(view.state.doc, 'T'));
    key(view, 'Home');
    key(view, 'ArrowRight');
    at(view, posOf(view.state.doc, 'bold', 4));
    key(view, 'ArrowRight');
    key(view, 'ArrowLeft');
    at(view, posOf(view.state.doc, 'item'));
    key(view, 'ArrowLeft');
    placeCaretBeforeListMarker(view, posOf(view.state.doc, 'item') - 2);
    view.dom.dispatchEvent(new FocusEvent('focusout', { bubbles: true }));
    await new Promise((r) => setTimeout(r, 10));
    expect(updates).toBe(0);
    view.destroy();
  });

  it('Blocks style: the keys do nothing special', () => {
    const view = mount(doc(h(2, t('Title'))));
    applyEditorStyle('blocks');
    at(view, 1);
    expect(key(view, 'Home')).toBe(false);
    expect(key(view, 'ArrowLeft')).toBe(false);
    view.destroy();
  });
});

describe('==highlight== paste in Live preview', () => {
  beforeEach(() => __resetEditorStyleForTests());
  afterEach(() => {
    __resetEditorStyleForTests();
    document.body.innerHTML = '';
  });

  it('a paste in Live preview converts what it inserted', () => {
    EditorView.prototype.coordsAtPos = () => ({ left: 0, right: 0, top: 0, bottom: 0 });
    const el = document.createElement('div');
    document.body.appendChild(el);
    const view = new EditorView(el, { state: EditorState.create({ doc: doc(p(t('x'))), plugins: [createLivePreviewProsePlugin({ initialFocused: true })] }) });
    view.dom.dispatchEvent(new Event('paste', { bubbles: true, cancelable: true }));
    view.dispatch(view.state.tr.insertText(' ==pasted==', 2));
    expect(view.state.doc.textContent).toBe('x pasted');
    // A later typed `==a==` is not a paste.
    view.dispatch(view.state.tr.insertText(' ==typed==', view.state.doc.content.size - 1));
    expect(view.state.doc.textContent).toBe('x pasted ==typed==');
    view.destroy();
  });
});

describe('Source mode', () => {
  beforeAll(() => {
    EditorView.prototype.coordsAtPos = () => ({ left: 0, right: 0, top: 0, bottom: 0 });
  });
  beforeEach(() => __resetEditorStyleForTests());
  afterEach(() => {
    __resetEditorStyleForTests();
    document.body.innerHTML = '';
  });

  it('builds every line\'s markers, list markers included, with the caret slot still applied', () => {
    const d = doc(h(1, t('Title')), p(t('a '), t('b', strong)), ul(li(null, p(t('item')))), schema.node('hr'));
    const ms = buildRevealMarkers(d, { from: 3, to: 3, all: true });
    expect(texts(ms.filter((m) => !m.hidden))).toEqual(['# ', '**', '**', '- ', '---']);
    // Caret in front of `# ` via its slot.
    const withSlot = buildRevealMarkers(d, { from: 1, to: 1, slot: 0, all: true });
    expect(withSlot.find((m) => m.kind === 'heading')!.side).toBeGreaterThan(0);
  });

  it('turns on and off live in every editor, without touching the document', () => {
    const d = doc(h(2, t('One')), p(t('two '), t('b', strong)), ul(li({ checked: true }, p(t('done')))));
    const el = document.createElement('div');
    document.body.appendChild(el);
    const trs: Transaction[] = [];
    const view: EditorView = new EditorView(el, {
      state: EditorState.create({ doc: d, plugins: [createLivePreviewProsePlugin({ initialFocused: false })] }),
      dispatchTransaction(this: EditorView, tr) {
        trs.push(tr);
        this.updateState(this.state.apply(tr));
      },
    });
    const shown = () => [...view.dom.querySelectorAll('.lp-marker')].map((e) => e.textContent).join('|');
    expect(shown()).toBe('');
    setSourceMode(true);
    expect(isSourceMode()).toBe(true);
    expect(view.dom.classList.contains('lp-source')).toBe(true);
    expect(shown()).toBe('## |**|**');
    expect(view.dom.querySelector('.lp-li-raw-done')).not.toBeNull();
    setSourceMode(false);
    expect(shown()).toBe('');
    expect(view.dom.classList.contains('lp-source')).toBe(false);
    expect(trs.every((tr) => !tr.docChanged)).toBe(true);
    view.destroy();
  });

  it('Blocks style shows nothing even with Source mode on', () => {
    const d = doc(h(2, t('One')));
    const el = document.createElement('div');
    document.body.appendChild(el);
    const view = new EditorView(el, { state: EditorState.create({ doc: d, plugins: [createLivePreviewProsePlugin({ initialFocused: true })] }) });
    setSourceMode(true);
    applyEditorStyle('blocks');
    expect(view.dom.querySelectorAll('.lp-marker')).toHaveLength(0);
    view.destroy();
  });
});

describe('wrapping a selection (Obsidian auto pair)', () => {
  beforeAll(() => {
    EditorView.prototype.coordsAtPos = () => ({ left: 0, right: 0, top: 0, bottom: 0 });
  });
  beforeEach(() => __resetEditorStyleForTests());
  afterEach(() => {
    __resetEditorStyleForTests();
    document.body.innerHTML = '';
  });
  function mountSel(d: ProseNode, from: number, to: number) {
    const el = document.createElement('div');
    document.body.appendChild(el);
    const view = new EditorView(el, {
      state: EditorState.create({ doc: d, plugins: [createLivePreviewProsePlugin({ initialFocused: true })] }),
    });
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, from, to)));
    return view;
  }
  const marksOf = (view: EditorView) => view.state.doc.child(0).child(1).marks.map((m) => m.type.name).sort();
  const press = (view: EditorView, k: string) => {
    const ev = new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true, shiftKey: k !== '=' });
    view.dom.dispatchEvent(ev);
    return ev.defaultPrevented;
  };

  it('`*` makes italic, again bold, again bold and italic; the selection stays', () => {
    const view = mountSel(doc(p(t('a word b'))), 3, 7);
    expect(press(view, '*')).toBe(true);
    expect(marksOf(view)).toEqual(['emphasis']);
    press(view, '*');
    expect(marksOf(view)).toEqual(['strong']);
    press(view, '*');
    expect(marksOf(view)).toEqual(['emphasis', 'strong']);
    expect(view.state.doc.textContent).toBe('a word b');
    expect([view.state.selection.from, view.state.selection.to]).toEqual([3, 7]);
    view.destroy();
  });

  it('`~` strikes, `=` highlights, `_` uses the underscore marker', () => {
    let view = mountSel(doc(p(t('a word b'))), 3, 7);
    press(view, '~');
    expect(marksOf(view)).toEqual(['strike_through']);
    view.destroy();
    view = mountSel(doc(p(t('a word b'))), 3, 7);
    press(view, '=');
    expect(marksOf(view)).toEqual(['highlight']);
    view.destroy();
    view = mountSel(doc(p(t('a word b'))), 3, 7);
    expect(wrapSelection(view, '_')).toBe(true);
    expect(view.state.doc.child(0).child(1).marks[0]!.attrs.marker).toBe('_');
    view.destroy();
  });

  it('does nothing across lines, in code, or in Blocks style', () => {
    let view = mountSel(doc(p(t('one')), p(t('two'))), 2, 7);
    expect(press(view, '*')).toBe(false);
    view.destroy();
    view = mountSel(doc(schema.node('code_block', null, [schema.text('x = 1')])), 1, 2);
    expect(press(view, '*')).toBe(false);
    view.destroy();
    view = mountSel(doc(p(t('a word b'))), 3, 7);
    applyEditorStyle('blocks');
    expect(press(view, '*')).toBe(false);
    view.destroy();
  });
});

describe('slotFromClick', () => {
  const d = doc(p(t('a '), t('bold', strong), t(' z')), ul(li(null, p(t('x', strong)))), h(2, t('H')));
  const end = posOf(d, 'bold', 4);
  const atEnd = slotMarkersAt(buildRevealMarkers(d, { from: end, to: end }), end);

  it('a click right of a closer\'s middle lands after it, left of it before it', () => {
    expect(slotFromClick(atEnd, [{ left: 100, right: 110 }], 107)).toBe(1);
    expect(slotFromClick(atEnd, [{ left: 100, right: 110 }], 103)).toBe(0);
  });

  it('never picks the slot in front of a list marker from a click in the text', () => {
    const start = posOf(d, 'x');
    const at = slotMarkersAt(buildRevealMarkers(d, { from: start, to: start }), start);
    expect(at.map((m) => m.kind)).toEqual(['list', 'mark-open']);
    expect(slotFromClick(at, [{ left: 50, right: 60 }], 10)).toBe(1);
    expect(slotFromClick(at, [{ left: 50, right: 60 }], 59)).toBe(2);
  });

  it('a click left of `## ` lands in front of it; mismatched boxes give null', () => {
    const at = slotMarkersAt(buildRevealMarkers(d, { from: posOf(d, 'H'), to: posOf(d, 'H') }), posOf(d, 'H'));
    expect(slotFromClick(at, [{ left: 20, right: 40 }], 22)).toBe(0);
    expect(slotFromClick(at, [], 22)).toBeNull();
  });
});

describe('editor style pref', () => {
  afterEach(() => __resetEditorStyleForTests());

  it('defaults to Live preview', () => {
    expect(DEFAULT_EDITOR_STYLE).toBe('live');
    expect(DEFAULT_EDITOR_PREFS.editorStyle).toBe('live');
    expect(resolvePrefs(null).editorStyle).toBe('live');
    expect(resolvePrefs({ prefs: {} }).editorStyle).toBe('live');
    expect(getEditorStyle()).toBe('live');
    expect(isLivePreview()).toBe(true);
  });

  it('keeps a saved choice and drops junk', () => {
    expect(resolvePrefs({ prefs: { editorStyle: 'blocks' } }).editorStyle).toBe('blocks');
    expect(resolvePrefs({ prefs: { editorStyle: 'live' } }).editorStyle).toBe('live');
    expect(resolveEditorStyle('notion')).toBe('live');
    expect(resolveEditorStyle(42)).toBe('live');
  });

  it('toggles live, stamps <html> and notifies subscribers', () => {
    const seen: string[] = [];
    const off = subscribeEditorStyle((s) => seen.push(s));
    applyEditorStyle(otherEditorStyle(getEditorStyle()));
    expect(getEditorStyle()).toBe('blocks');
    expect(document.documentElement.getAttribute('data-editor-style')).toBe('blocks');
    applyEditorStyle('blocks'); // no-op
    applyEditorStyle(otherEditorStyle('blocks'));
    expect(document.documentElement.getAttribute('data-editor-style')).toBe('live');
    expect(seen).toEqual(['blocks', 'live']);
    off();
  });

  it('Live preview has no Notion block selection: Esc and Ctrl+A stay text editing', () => {
    __resetBlockSelectForTests();
    const plain = new Schema({
      nodes: { doc: { content: 'block+' }, paragraph: { group: 'block', content: 'text*', toDOM: () => ['p', 0] }, text: {} },
    });
    const d = plain.node('doc', null, [plain.node('paragraph', null, [plain.text('one')]), plain.node('paragraph', null, [plain.text('two')])]);
    const el = document.createElement('div');
    document.body.appendChild(el);
    const view = new EditorView(el, { state: EditorState.create({ doc: d, plugins: [createBlockSelectProsePlugin()] }) });
    const key = (k: string, o: KeyboardEventInit = {}) => view.dom.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true, ...o }));
    key('Escape');
    expect(view.dom.classList.contains('block-select-mode')).toBe(false);
    key('a', { ctrlKey: true });
    expect(view.dom.classList.contains('block-select-mode')).toBe(false);
    applyEditorStyle('blocks');
    key('Escape');
    expect(view.dom.classList.contains('block-select-mode')).toBe(true);
    view.destroy();
  });
});
