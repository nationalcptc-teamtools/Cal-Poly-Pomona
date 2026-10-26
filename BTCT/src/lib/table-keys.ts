// ─────────────────────────────────────────────────────────────────────────
// Table keyboard behavior beyond prosemirror-tables' own defaults.
//
// Backspace/Delete over a CellSelection that covers a whole column, a whole
// row, or the entire table deletes that structure (cellSelectionDeleteTarget
// is the pure classifier); a partial rectangle falls through to
// prosemirror-tables' own clear-contents default (deleteCellSelection, bound
// by tableEditing()). Shift+Enter with the caret in a cell (not a
// CellSelection) inserts a row below and moves the caret into it, same
// column.
//
// The plugin is prepended to prosePluginsCtx by hand instead of using
// $prose (which appends): the GFM preset's tableEditing() is already in the
// array by the time this plugin registers, and ProseMirror gives the
// earliest-registered plugin's handleKeyDown the key first, so appending
// would mean tableEditing()'s own Backspace/Delete handler always wins.
// ─────────────────────────────────────────────────────────────────────────

import { SchemaReady, prosePluginsCtx } from '@milkdown/core';
import type { Ctx } from '@milkdown/ctx';
import { Plugin, PluginKey, TextSelection, type EditorState, type Transaction } from '@milkdown/prose/state';
import type { EditorView } from '@milkdown/prose/view';
import {
  CellSelection,
  TableMap,
  addRow,
  deleteColumn,
  deleteRow,
  deleteTable,
  isInTable,
  selectedRect,
} from '@milkdown/prose/tables';

export type CellSelectionDeleteTarget = 'table' | 'row' | 'column' | null;

/** Pure: classify what a CellSelection covers, if anything deletable as a whole. */
export function cellSelectionDeleteTarget(selection: CellSelection): CellSelectionDeleteTarget {
  const isCol = selection.isColSelection();
  const isRow = selection.isRowSelection();
  if (isCol && isRow) return 'table';
  if (isCol) return 'column';
  if (isRow) return 'row';
  return null;
}

/**
 * Insert a row below the caret's row and move the caret into it (same
 * column). Ignored for a CellSelection: multi-cell selections don't have a
 * single "current row" to insert relative to.
 */
export function insertRowBelowCaret(state: EditorState, dispatch?: (tr: Transaction) => void): boolean {
  if (state.selection instanceof CellSelection) return false;
  if (!isInTable(state)) return false;
  const rect = selectedRect(state);
  const col = rect.left;
  const newRow = rect.bottom;
  if (dispatch) {
    const tr = addRow(state.tr, rect, newRow);
    const table = tr.doc.resolve(rect.tableStart).node();
    const map = TableMap.get(table);
    const cellStart = map.positionAt(newRow, col, table);
    dispatch(tr.setSelection(TextSelection.near(tr.doc.resolve(rect.tableStart + cellStart + 1))));
  }
  return true;
}

/**
 * The actual keydown logic, factored out of the Milkdown plugin wrapper so
 * it can be driven directly against a real EditorView in tests.
 */
export function handleTableKeyDown(view: EditorView, event: KeyboardEvent): boolean {
  if (event.key === 'Enter' && event.shiftKey) {
    if (insertRowBelowCaret(view.state, view.dispatch)) {
      event.preventDefault();
      return true;
    }
    return false;
  }
  if (event.key !== 'Backspace' && event.key !== 'Delete') return false;
  const { selection } = view.state;
  if (!(selection instanceof CellSelection)) return false;
  const target = cellSelectionDeleteTarget(selection);
  if (!target) return false; // partial rectangle: fall through to tableEditing()'s clear-contents default
  event.preventDefault();
  const command = target === 'table' ? deleteTable : target === 'row' ? deleteRow : deleteColumn;
  command(view.state, view.dispatch);
  return true;
}

const tableKeysPluginKey = new PluginKey('table-keys');

export const tableKeysPlugin = (ctx: Ctx) => async () => {
  await ctx.wait(SchemaReady);
  const plugin = new Plugin({
    key: tableKeysPluginKey,
    props: { handleKeyDown: handleTableKeyDown },
  });
  ctx.update(prosePluginsCtx, (plugins) => [plugin, ...plugins]);
  return () => {
    ctx.update(prosePluginsCtx, (plugins) => plugins.filter((p) => p !== plugin));
  };
};
