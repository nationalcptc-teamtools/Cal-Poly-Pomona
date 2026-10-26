// ─────────────────────────────────────────────────────────────────────────
// Notion-style typing conversions the presets don't cover.
//
//   • `[]` at the start of a line → to-do checkbox, immediately on the `]`
//     (Notion: "there's no space in between"). `[ ]`/`[x]` + space work too.
//     GFM's own rule only fires *inside* an existing list item; these also
//     convert a plain paragraph, wrapping it in a task list in one step.
//   • `"` + space at the start of a line → quote block (Notion's quote
//     trigger; `>` stays a quote here because BTCT is markdown-first and has
//     no toggle blocks for `>` to make).
//
// Both are ordinary Milkdown `$inputRule`s: `.use()`d after the presets they
// extend, so the preset rules keep first shot and these only see what the
// presets declined (a first-match-wins chain, same story as the code fence
// rule in editor-keybinds.ts).
// ─────────────────────────────────────────────────────────────────────────

import { InputRule, wrappingInputRule } from '@milkdown/prose/inputrules';
import { findWrapping } from '@milkdown/prose/transform';
import { blockquoteSchema, listItemSchema } from '@milkdown/preset-commonmark';
import { $inputRule } from '@milkdown/utils';
import type { Ctx } from '@milkdown/ctx';
import type { EditorState } from '@milkdown/prose/state';
import type { Transaction } from '@milkdown/prose/state';

function toTodo(
  ctx: Ctx,
  state: EditorState,
  start: number,
  end: number,
  checked: boolean,
): Transaction | null {
  const listItemType = listItemSchema.type(ctx);
  const $start = state.doc.resolve(start);

  // Already inside a list item: convert it in place (mirrors GFM's rule,
  // which handles the spaced variants there already).
  for (let d = $start.depth; d > 0; d--) {
    const node = $start.node(d);
    if (node.type === listItemType) {
      if (node.attrs.checked != null) return null; // already a to-do
      return state.tr
        .delete(start, end)
        .setNodeMarkup($start.before(d), undefined, { ...node.attrs, checked });
    }
  }

  // Plain textblock: strip the trigger text, then wrap the block in a task
  // list item (findWrapping supplies the enclosing bullet list).
  const tr = state.tr.delete(start, end);
  const range = tr.doc.resolve(start).blockRange();
  if (!range) return null;
  const wrapping = findWrapping(range, listItemType, { checked });
  if (!wrapping) return null;
  return tr.wrap(range, wrapping);
}

/** `[]` → unchecked to-do, firing the moment the `]` is typed. */
export const todoBracketInputRule = $inputRule((ctx) =>
  new InputRule(/^\[\]$/, (state, _match, start, end) =>
    toTodo(ctx, state, start, end, false),
  ),
);

/** `[ ]` / `[x]` + space → to-do with that checked state (paragraphs too). */
export const todoSpacedInputRule = $inputRule((ctx) =>
  new InputRule(/^\[(?<check>[x ])\]\s$/, (state, match, start, end) =>
    toTodo(ctx, state, start, end, match.groups?.check === 'x'),
  ),
);

/** `"` + space at the start of a line → quote block. */
export const quoteInputRule = $inputRule((ctx) =>
  wrappingInputRule(/^"\s$/, blockquoteSchema.type(ctx)),
);

export const notionTypingRules = [
  todoBracketInputRule,
  todoSpacedInputRule,
  quoteInputRule,
].flat();
