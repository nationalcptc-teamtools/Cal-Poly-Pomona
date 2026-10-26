import { describe, it, expect } from 'vitest';
import * as Y from 'yjs';
import { Editor, editorViewCtx, rootCtx, schemaCtx } from '@milkdown/core';
import { commonmark } from '@milkdown/preset-commonmark';
import { gfm } from '@milkdown/preset-gfm';
import { collab, collabServiceCtx } from '@milkdown/plugin-collab';
import { listItemBlockComponent, defaultListItemBlockConfig } from '@milkdown/components/list-item-block';
import { TextSelection } from '@milkdown/prose/state';
import type { EditorView } from '@milkdown/prose/view';
import { yXmlFragmentToProseMirrorRootNode } from 'y-prosemirror';

import { createListItemView, listItemView, listLabelKind } from '@/lib/list-item-view';
import { notionTypingRules } from '@/lib/notion-typing';

// A real Milkdown editor with Crepe's list item component registered first
// (as Crepe does in its constructor) and ours after it, bound to a Y.Doc the
// way the page editor is. Typing goes through handleTextInput / handleKeyDown
// so the input rules and the list keymap run as they do for real keys.
async function withEditor<T>(fn: (view: EditorView, ydoc: Y.Doc, editor: Editor) => T | Promise<T>): Promise<T> {
  const root = document.createElement('div');
  document.body.appendChild(root);
  const ydoc = new Y.Doc();
  const editor = Editor.make()
    .config((ctx) => ctx.set(rootCtx, root))
    .use(commonmark)
    .use(gfm)
    .use(listItemBlockComponent)
    .use(notionTypingRules)
    .use(listItemView)
    .use(collab);
  await editor.create();
  editor.action((ctx) => { ctx.get(collabServiceCtx).bindDoc(ydoc).connect(); });
  try {
    return await fn(editor.action((ctx) => ctx.get(editorViewCtx)), ydoc, editor);
  } finally {
    await editor.destroy();
    root.remove();
  }
}

function type(view: EditorView, text: string) {
  for (const ch of text) {
    const { from, to } = view.state.selection;
    const handled = view.someProp('handleTextInput', (f) => f(view, from, to, ch, () => view.state.tr.insertText(ch, from, to)));
    if (!handled) view.dispatch(view.state.tr.insertText(ch, from, to));
  }
}

function enter(view: EditorView) {
  const ev = new KeyboardEvent('keydown', { key: 'Enter', keyCode: 13, bubbles: true });
  expect(view.someProp('handleKeyDown', (f) => f(view, ev))).toBe(true);
}

const outline = (node: { type: { name: string }; isTextblock: boolean; textContent: string; forEach: (f: (c: never) => void) => void }): string => {
  if (node.isTextblock) return `${node.type.name}(${node.textContent})`;
  const kids: string[] = [];
  node.forEach((c) => { kids.push(outline(c)); });
  return `${node.type.name}[${kids.join(',')}]`;
};

const frame = () => new Promise((r) => setTimeout(r, 30));

describe('list item node view', () => {
  it('is the view the editor uses, not the Vue one registered before it', async () => {
    await withEditor((view) => {
      type(view, '- alpha');
      const block = view.dom.querySelector('.milkdown-list-item-block') as HTMLElement & { __vue_app__?: unknown };
      expect(block).not.toBeNull();
      expect(block.__vue_app__).toBeUndefined();
      expect(block.querySelector(':scope > li.list-item > .label-wrapper > .label.bullet')).not.toBeNull();
      expect(block.querySelector(':scope > li.list-item > .children > .content-dom > p')?.textContent).toBe('alpha');
    });
  });

  it('never moves the content element when the label changes, so the caret stays put', async () => {
    await withEditor(async (view) => {
      type(view, '- alpha');
      enter(view);
      enter(view);
      const children = () => [...view.dom.querySelectorAll('.milkdown-list-item-block .children')];
      const observer = new MutationObserver(() => {});
      const watch = () => children().forEach((c) => observer.observe(c, { childList: true }));
      type(view, '1. ');
      watch();
      // Put the DOM caret inside the new item, then change its attrs (turn it
      // into a to-do): any attrs change re-rendered Crepe's Vue view.
      const item = view.dom.querySelectorAll('.milkdown-list-item-block')[1]!;
      const para = item.querySelector('p')!;
      const range = document.createRange();
      range.setStart(para, 0);
      range.collapse(true);
      getSelection()!.removeAllRanges();
      getSelection()!.addRange(range);
      const itemPos = view.state.selection.$from.before(view.state.selection.$from.depth - 1);
      view.dispatch(view.state.tr.setNodeAttribute(itemPos, 'checked', false));
      await frame();
      expect(observer.takeRecords()).toEqual([]);
      expect(item.querySelector('.label')!.classList.contains('unchecked')).toBe(true);
      expect(para.contains(getSelection()!.anchorNode)).toBe(true);
      observer.disconnect();
    });
  });

  it('typing `1. one` right after leaving a list makes a new numbered item, in the editor and in Yjs', async () => {
    for (const before of ['- alpha', '1. alpha', '[] alpha']) {
      await withEditor(async (view, ydoc, editor) => {
        type(view, before);
        enter(view);
        enter(view);
        type(view, '1. ');
        await frame();
        type(view, 'one');
        await frame();
        const pm = outline(view.state.doc as never);
        expect(pm).toMatch(/ordered_list\[list_item\[paragraph\(one\)\]\]/);
        expect(pm).not.toMatch(/alphaone/);
        const schema = editor.action((ctx) => ctx.get(schemaCtx));
        const fromY = yXmlFragmentToProseMirrorRootNode(ydoc.getXmlFragment('prosemirror'), schema);
        expect(outline(fromY as never)).toBe(pm);
      });
    }
  });

  it('ticks a task box on pointerdown and ignores bullets', async () => {
    await withEditor((view) => {
      type(view, '[] task');
      const label = view.dom.querySelector('.label-wrapper') as HTMLElement;
      expect(view.dom.querySelector('.label.unchecked')).not.toBeNull();
      label.dispatchEvent(new Event('pointerdown', { bubbles: true, cancelable: true }));
      const item = view.state.doc.firstChild!.firstChild!;
      expect(item.attrs.checked).toBe(true);
      expect(view.dom.querySelector('.label.checked')).not.toBeNull();
      // The caret is still in the text, not on the label.
      expect(view.state.selection).toBeInstanceOf(TextSelection);
    });
  });

  it('writes an ordered label as text, never as HTML', () => {
    const fakeView = { editable: true } as unknown as EditorView;
    const node = {
      type: { name: 'list_item' },
      attrs: { label: '<img src=x onerror=alert(1)>', listType: 'ordered', checked: null },
    } as never;
    const nv = createListItemView(node, fakeView, () => 0, defaultListItemBlockConfig);
    const label = (nv.dom as HTMLElement).querySelector('.label')!;
    expect(label.querySelector('img')).toBeNull();
    expect(label.textContent).toBe('<img src=x onerror=alert(1)>');
    expect(label.classList.contains('ordered')).toBe(true);
  });

  it('picks the marker kind from the attrs', () => {
    expect(listLabelKind({ listType: 'bullet', checked: null })).toBe('bullet');
    expect(listLabelKind({ listType: 'ordered', checked: null })).toBe('ordered');
    expect(listLabelKind({ listType: 'bullet', checked: true })).toBe('checked');
    expect(listLabelKind({ listType: 'ordered', checked: false })).toBe('unchecked');
  });
});
