import { describe, it, expect } from 'vitest';
import { Editor, editorViewCtx, rootCtx } from '@milkdown/core';
import { commonmark } from '@milkdown/preset-commonmark';
import { gfm } from '@milkdown/preset-gfm';
import type { EditorView } from '@milkdown/prose/view';

import { notionTypingRules } from '@/lib/notion-typing';

// Builds a bare Milkdown editor (no Crepe) with the same preset pair the
// page editor uses (commonmark + gfm, so list items carry the `checked`
// attr), plus the Notion typing rules under test. Characters are fed through
// ProseMirror's `handleTextInput` prop, which is how input rules see real
// typing; unhandled characters are inserted manually the way the DOM would.
async function withEditor<T>(fn: (view: EditorView) => T): Promise<T> {
  const root = document.createElement('div');
  document.body.appendChild(root);
  const editor = Editor.make()
    .config((ctx) => ctx.set(rootCtx, root))
    .use(commonmark)
    .use(gfm)
    .use(notionTypingRules);
  await editor.create();
  try {
    return editor.action((ctx) => fn(ctx.get(editorViewCtx)));
  } finally {
    await editor.destroy();
    root.remove();
  }
}

function type(view: EditorView, text: string) {
  for (const ch of text) {
    const { from, to } = view.state.selection;
    const handled = view.someProp('handleTextInput', (f) =>
      f(view, from, to, ch, () => view.state.tr.insertText(ch, from, to)),
    );
    if (!handled) view.dispatch(view.state.tr.insertText(ch, from, to));
  }
}

describe('notion typing conversions', () => {
  it('[] at the start of a line becomes an unchecked to-do immediately', async () => {
    await withEditor((view) => {
      type(view, '[]');
      const list = view.state.doc.firstChild!;
      expect(list.type.name).toBe('bullet_list');
      const item = list.firstChild!;
      expect(item.type.name).toBe('list_item');
      expect(item.attrs.checked).toBe(false);
    });
  });

  it('[x] + space becomes a checked to-do', async () => {
    await withEditor((view) => {
      type(view, '[x] ');
      const item = view.state.doc.firstChild!.firstChild!;
      expect(item.type.name).toBe('list_item');
      expect(item.attrs.checked).toBe(true);
    });
  });

  it('[] mid-line stays plain text', async () => {
    await withEditor((view) => {
      type(view, 'run nmap[]');
      const first = view.state.doc.firstChild!;
      expect(first.type.name).toBe('paragraph');
      expect(first.textContent).toBe('run nmap[]');
    });
  });

  it('" + space becomes a quote block', async () => {
    await withEditor((view) => {
      type(view, '" ');
      expect(view.state.doc.firstChild!.type.name).toBe('blockquote');
    });
  });
});
