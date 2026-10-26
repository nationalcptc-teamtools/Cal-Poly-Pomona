// ─────────────────────────────────────────────────────────────────────────
// Table header styling + the two table variants.
//
// GFM has no such thing as a table without a header: the delimiter row is
// part of the syntax, so every markdown table has a header row whether or not
// you want one. A "plain" table is therefore a table whose header row is
// *blank*, and this plugin marks those so CSS can render them flat instead
// of shaded.
//
// That's also why the check can't live in CSS alone: ProseMirror wraps every
// cell's content in a `<p>`, so `th:empty` never matches even when the cell
// has no text. The emptiness has to be read off the rendered table.
//
// The upshot for the two slash-menu entries (see PageEditor.tsx):
//   • "Table" seeds the header cells with column names → renders shaded.
//   • "Plain table" leaves them blank → the row collapses away entirely.
// Typing into a blank header turns it back into a real header, which is the
// behaviour you'd want: the row *is* a header the moment it says something.
// ─────────────────────────────────────────────────────────────────────────

import { Plugin, PluginKey } from '@milkdown/prose/state';

import type { Node as ProseNode } from '@milkdown/prose/model';
import { $prose } from '@milkdown/utils';
import { commandsCtx, editorViewCtx } from '@milkdown/core';
import type { Ctx } from '@milkdown/ctx';
import {
  addBlockTypeCommand,
  clearTextInCurrentBlockCommand,
  selectTextNearPosCommand,
} from '@milkdown/preset-commonmark';
import { createTable } from '@milkdown/preset-gfm';

/**
 * Mark every rendered table whose header cells are all blank.
 *
 * This works on the **DOM**, not the document, deliberately. Crepe renders
 * tables through `tableBlock`, a custom NodeView from
 * `@milkdown/kit/component/table-block`, and a custom NodeView doesn't apply
 * node-decoration attributes to its own DOM unless it explicitly handles
 * them, so the obvious `Decoration.node(...)` approach silently does
 * nothing here. Reading the rendered table directly sidesteps the NodeView
 * entirely.
 *
 * prosemirror-tables emits `<table><tbody><tr><th>…`, with no `<thead>`, so
 * the header cells are the `th` elements of the first row.
 */
function syncTableHeaderState(root: HTMLElement): void {
  root.querySelectorAll('table').forEach((table) => {
    const firstRow = table.querySelector('tr');
    if (!firstRow) return;
    const headers = Array.from(firstRow.children).filter((c) => c.tagName === 'TH');
    // A first row of ordinary cells isn't a header row at all: leave it be.
    const blank =
      headers.length > 0 && headers.every((h) => (h.textContent ?? '').trim() === '');
    if (blank) table.setAttribute('data-blank-header', 'true');
    else table.removeAttribute('data-blank-header');
  });
}

const tableHeaderStateKey = new PluginKey('table-header-state');

/**
 * Keeps `data-blank-header` in sync so index.css can collapse the header row
 * of a "plain" table.
 *
 * Updates are coalesced to one pass per animation frame: the plugin sees an
 * update per keystroke, and re-scanning every table on each one would be
 * wasteful on a long page.
 */
export const tableHeaderStatePlugin = $prose(
  () =>
    new Plugin({
      key: tableHeaderStateKey,
      view: (editorView) => {
        let frame = 0;
        const schedule = () => {
          if (frame) return;
          frame = requestAnimationFrame(() => {
            frame = 0;
            syncTableHeaderState(editorView.dom as HTMLElement);
          });
        };
        schedule();
        return {
          update: schedule,
          destroy: () => { if (frame) cancelAnimationFrame(frame); },
        };
      },
    }),
);

/** Column names seeded into a header table, so the two variants differ. */
export const DEFAULT_HEADER_LABELS = ['Column 1', 'Column 2', 'Column 3'];

/**
 * Rebuild `table` with its header cells filled from `labels`.
 *
 * Works off a table that `createTable` already produced rather than
 * constructing one from scratch, so cell attributes (alignment, colspan
 * defaults) stay exactly as the GFM preset intends.
 */
function withHeaderLabels(table: ProseNode, labels: readonly string[]): ProseNode {
  const firstRow = table.firstChild;
  if (!firstRow) return table;

  const schema = table.type.schema;
  const paragraph = schema.nodes.paragraph;
  if (!paragraph) return table;

  const cells: ProseNode[] = [];
  firstRow.forEach((cell, _offset, index) => {
    const label = labels[index];
    if (!label) { cells.push(cell); return; }
    cells.push(cell.type.create(cell.attrs, paragraph.create(null, schema.text(label))));
  });

  const rows: ProseNode[] = [firstRow.type.create(firstRow.attrs, cells)];
  table.forEach((row, _offset, index) => { if (index > 0) rows.push(row); });
  return table.type.create(table.attrs, rows);
}

/**
 * Slash-menu icon. Crepe keeps its own table icon module-private, so this is
 * a matching Material-style glyph rather than an import.
 */
export const TABLE_ICON = `<svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
  <path d="M4 3h16a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Zm0 2v3h16V5H4Zm0 5v3h7v-3H4Zm9 0v3h7v-3h-7Zm-9 5v4h7v-4H4Zm9 0v4h7v-4h-7Z"/>
</svg>`;

/**
 * Insert a 3×3 table at the cursor.
 *
 * `labels` seeds the header row (shaded variant); `null` leaves it blank
 * (plain variant). Mirrors Crepe's own table command: clear the current
 * block, insert, then drop the caret back where it was, so the two entries
 * behave identically apart from the header content.
 */
export function insertTable(ctx: Ctx, labels: readonly string[] | null): void {
  const commands = ctx.get(commandsCtx);
  const view = ctx.get(editorViewCtx);
  const table = createTable(ctx, 3, 3);

  commands.call(clearTextInCurrentBlockCommand.key);
  const { from } = view.state.selection;
  commands.call(addBlockTypeCommand.key, {
    nodeType: labels ? withHeaderLabels(table, labels) : table,
  });
  commands.call(selectTextNearPosCommand.key, { pos: from });
}
