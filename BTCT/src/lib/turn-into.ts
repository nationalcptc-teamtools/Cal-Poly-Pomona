// ─────────────────────────────────────────────────────────────────────────
// "Turn into" block conversions (Notion-style).
//
// One shared implementation behind two entry points:
//
//   • the floating format toolbar's "Turn into" dropdown, and
//   • the Ctrl/⌘+Shift+0..8 shortcuts (Notion's create-a-block digit family;
//     7 = toggle list and 9 = page don't exist in BTCT and are skipped).
//
// Conversions first lift the block out of any list / quote nesting so
// "turn this bullet into a heading" produces a top-level heading rather than
// a heading trapped inside a list item, which is what Notion does.
// ─────────────────────────────────────────────────────────────────────────

import { commandsCtx } from '@milkdown/core';
import type { Ctx } from '@milkdown/ctx';
import { editorViewCtx } from '@milkdown/core';
import { lift } from '@milkdown/prose/commands';
import { listItemSchema, paragraphSchema } from '@milkdown/preset-commonmark';

import { DEFAULT_CODE_LANGUAGE } from '@/lib/code-theme';

export type TurnIntoTarget =
  | 'text'
  | 'h1'
  | 'h2'
  | 'h3'
  | 'todo'
  | 'bullet'
  | 'ordered'
  | 'quote'
  | 'code';

/** Display order + labels for the "Turn into" dropdown (Notion's naming). */
export const TURN_INTO_ITEMS: ReadonlyArray<{ target: TurnIntoTarget; label: string }> = [
  { target: 'text', label: 'Text' },
  { target: 'h1', label: 'Heading 1' },
  { target: 'h2', label: 'Heading 2' },
  { target: 'h3', label: 'Heading 3' },
  { target: 'todo', label: 'To-do list' },
  { target: 'bullet', label: 'Bulleted list' },
  { target: 'ordered', label: 'Numbered list' },
  { target: 'quote', label: 'Quote' },
  { target: 'code', label: 'Code' },
];

/**
 * Notion's digit map (Windows: Ctrl+Shift+digit): 0 text, 1..3 headings,
 * 4 to-do, 5 bulleted, 6 numbered, 8 code. 7 (toggle) and 9 (page) have no
 * BTCT equivalent and return null.
 */
export function digitToTarget(digit: number): TurnIntoTarget | null {
  switch (digit) {
    case 0: return 'text';
    case 1: return 'h1';
    case 2: return 'h2';
    case 3: return 'h3';
    case 4: return 'todo';
    case 5: return 'bullet';
    case 6: return 'ordered';
    case 8: return 'code';
    default: return null;
  }
}

/** Lift the selection out of lists / quotes until nothing lifts any more. */
function liftAll(ctx: Ctx): void {
  const view = ctx.get(editorViewCtx);
  // Bounded: real documents never nest deeper than a handful of levels.
  for (let i = 0; i < 8; i++) {
    if (!lift(view.state, view.dispatch)) break;
  }
}

/** Apply one turn-into conversion to the current selection. */
export function turnIntoBlock(ctx: Ctx, target: TurnIntoTarget): void {
  const commands = ctx.get(commandsCtx);
  switch (target) {
    case 'text':
      liftAll(ctx);
      commands.call('SetBlockType', { nodeType: paragraphSchema.type(ctx) });
      break;
    case 'h1':
    case 'h2':
    case 'h3': {
      liftAll(ctx);
      commands.call('WrapInHeading', Number(target.slice(1)));
      break;
    }
    case 'todo':
      liftAll(ctx);
      commands.call('WrapInBlockType', {
        nodeType: listItemSchema.type(ctx),
        attrs: { checked: false },
      });
      break;
    case 'bullet':
      liftAll(ctx);
      commands.call('WrapInBulletList');
      break;
    case 'ordered':
      liftAll(ctx);
      commands.call('WrapInOrderedList');
      break;
    case 'quote':
      liftAll(ctx);
      commands.call('WrapInBlockquote');
      break;
    case 'code':
      liftAll(ctx);
      commands.call('CreateCodeBlock', DEFAULT_CODE_LANGUAGE);
      break;
  }
}
