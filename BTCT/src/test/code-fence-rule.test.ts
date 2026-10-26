import { describe, it, expect } from 'vitest';
import { Editor, editorViewCtx, rootCtx } from '@milkdown/core';
import { commonmark, createCodeBlockInputRule } from '@milkdown/preset-commonmark';

import { DEFAULT_CODE_LANGUAGE } from '@/lib/code-theme';
import { codeBlockShellDefault, codeFenceInputRule } from '@/lib/editor-keybinds';

// Builds a bare Milkdown editor (no Crepe, no CodeMirror) wired the way
// PageEditor wires the fence rule, types `text` at the caret, then presses
// Enter through the same ProseMirror prop Milkdown's input-rule plugin hooks
// for Enter. Returns what the first block became.
async function typeThenEnter(text: string, swapFenceRule: boolean) {
  const root = document.createElement('div');
  document.body.appendChild(root);
  const editor = Editor.make()
    .config((ctx) => ctx.set(rootCtx, root))
    .use(commonmark);
  if (swapFenceRule) {
    void editor.remove(createCodeBlockInputRule);
    editor.use(codeBlockShellDefault).use(codeFenceInputRule);
  }
  await editor.create();
  try {
    return editor.action((ctx) => {
      const view = ctx.get(editorViewCtx);
      view.dispatch(view.state.tr.insertText(text));
      const handled = view.someProp('handleKeyDown', (f) =>
        f(view, new KeyboardEvent('keydown', { key: 'Enter' })),
      );
      const node = view.state.doc.firstChild;
      return {
        handled: Boolean(handled),
        type: node?.type.name,
        language: node?.attrs.language as unknown,
      };
    });
  } finally {
    await editor.destroy();
    root.remove();
  }
}

describe('``` + Enter (codeFenceInputRule)', () => {
  it('opens a code block in the default (shell) language from a bare fence', async () => {
    const r = await typeThenEnter('```', true);
    expect(r.handled).toBe(true);
    expect(r.type).toBe('code_block');
    expect(r.language).toBe(DEFAULT_CODE_LANGUAGE);
  });

  it('keeps a language typed after the fence', async () => {
    const r = await typeThenEnter('```python', true);
    expect(r.type).toBe('code_block');
    expect(r.language).toBe('python');
  });

  // Pins the upstream behavior the swap exists for: commonmark's own rule
  // stores the captured language verbatim, so a bare fence lands as "" no
  // matter what the schema default says. If this ever starts passing with
  // the default language, the remove()/use() dance in PageEditor can go.
  it('without the swap, the preset rule stores an empty language', async () => {
    const r = await typeThenEnter('```', false);
    expect(r.type).toBe('code_block');
    expect(r.language).toBe('');
  });
});
