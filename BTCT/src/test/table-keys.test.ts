import { describe, it, expect, beforeAll } from 'vitest';
import { EditorState, TextSelection } from '@milkdown/prose/state';
import { EditorView } from '@milkdown/prose/view';
import { Schema } from '@milkdown/prose/model';
import { CellSelection, tableEditing, tableNodes } from '@milkdown/prose/tables';
import { cellSelectionDeleteTarget, handleTableKeyDown, insertRowBelowCaret } from '@/lib/table-keys';

// ── Minimal schema: paragraph/text + prosemirror-tables' own node specs ────

const schema = new Schema({
  nodes: {
    doc: { content: 'block+' },
    paragraph: { group: 'block', content: 'text*', toDOM: () => ['p', 0], parseDOM: [{ tag: 'p' }] },
    text: {},
    ...tableNodes({ tableGroup: 'block', cellContent: 'paragraph+', cellAttributes: {} }),
  },
});

/** A `rows` x `cols` table of single-paragraph cells, plus a trailing paragraph. */
function makeDoc(rows: number, cols: number) {
  const cell = () => schema.nodes.table_cell!.createAndFill()!;
  const row = () => schema.nodes.table_row!.create(null, Array.from({ length: cols }, cell));
  const table = schema.nodes.table!.create(null, Array.from({ length: rows }, row));
  return schema.node('doc', null, [table, schema.node('paragraph', null, [schema.text('after')])]);
}

/** Position right before the cell at (row, col), 0-indexed: `nodeAfter` is the cell itself. */
function cellPos(doc: ReturnType<typeof makeDoc>, row: number, col: number): number {
  const table = doc.firstChild!;
  let pos = 1; // inside the table, before its first row
  for (let r = 0; r < row; r++) pos += table.child(r).nodeSize;
  pos += 1; // inside the row, before its first cell
  for (let c = 0; c < col; c++) pos += table.child(row).child(c).nodeSize;
  return pos;
}

/** Position inside the cell's paragraph content, at (row, col), 0-indexed. */
function cellContentPos(doc: ReturnType<typeof makeDoc>, row: number, col: number): number {
  return cellPos(doc, row, col) + 2; // past the cell's own tag, then the paragraph's
}

function makeView(rows: number, cols: number): EditorView {
  const doc = makeDoc(rows, cols);
  const state = EditorState.create({ doc, plugins: [tableEditing()] });
  const mount = document.createElement('div');
  document.body.appendChild(mount);
  return new EditorView(mount, { state });
}

function selectCells(view: EditorView, anchor: [number, number], head: [number, number]) {
  const $anchor = view.state.doc.resolve(cellPos(view.state.doc, ...anchor));
  const $head = view.state.doc.resolve(cellPos(view.state.doc, ...head));
  view.dispatch(view.state.tr.setSelection(new CellSelection($anchor, $head)));
}

function key(view: EditorView, k: string, opts: KeyboardEventInit = {}) {
  return handleTableKeyDown(view, new KeyboardEvent('keydown', { key: k, cancelable: true, ...opts }));
}

// ── cellSelectionDeleteTarget (pure) ────────────────────────────────────────

describe('cellSelectionDeleteTarget', () => {
  it('classifies a selection spanning every row and column as the whole table', () => {
    const view = makeView(3, 3);
    selectCells(view, [0, 0], [2, 2]);
    expect(cellSelectionDeleteTarget(view.state.selection as CellSelection)).toBe('table');
  });

  it('classifies a selection spanning every row within one column as a column', () => {
    const view = makeView(3, 3);
    selectCells(view, [0, 1], [2, 1]);
    expect(cellSelectionDeleteTarget(view.state.selection as CellSelection)).toBe('column');
  });

  it('classifies a selection spanning every column within one row as a row', () => {
    const view = makeView(3, 3);
    selectCells(view, [1, 0], [1, 2]);
    expect(cellSelectionDeleteTarget(view.state.selection as CellSelection)).toBe('row');
  });

  it('classifies a rectangle that touches neither every row nor every column as partial (null)', () => {
    const view = makeView(3, 3);
    selectCells(view, [0, 0], [1, 1]);
    expect(cellSelectionDeleteTarget(view.state.selection as CellSelection)).toBeNull();
  });
});

// ── Integration: Backspace/Delete over a CellSelection, driven for real ─────

describe('table Backspace/Delete over a CellSelection (integration)', () => {
  beforeAll(() => {
    // jsdom has no layout engine; irrelevant to what these tests assert.
    EditorView.prototype.coordsAtPos = () => ({ left: 0, right: 0, top: 0, bottom: 0 });
  });

  it('deletes the whole table when every row and column is selected', () => {
    const view = makeView(3, 3);
    selectCells(view, [0, 0], [2, 2]);
    expect(key(view, 'Backspace')).toBe(true);
    expect(view.state.doc.childCount).toBe(1); // only the trailing paragraph remains
    expect(view.state.doc.firstChild!.type.name).toBe('paragraph');
  });

  it('deletes just the selected column via Delete, keeping the other columns', () => {
    const view = makeView(2, 3);
    selectCells(view, [0, 1], [1, 1]);
    expect(key(view, 'Delete')).toBe(true);
    const table = view.state.doc.firstChild!;
    expect(table.child(0).childCount).toBe(2); // 3 columns -> 2
    expect(table.child(1).childCount).toBe(2);
  });

  it('deletes just the selected row via Backspace, keeping the other rows', () => {
    const view = makeView(3, 2);
    selectCells(view, [1, 0], [1, 1]);
    expect(key(view, 'Backspace')).toBe(true);
    expect(view.state.doc.firstChild!.childCount).toBe(2); // 3 rows -> 2
  });

  it('leaves a partial rectangle alone (returns false, no structural delete)', () => {
    const view = makeView(3, 3);
    selectCells(view, [0, 0], [1, 1]);
    expect(key(view, 'Backspace')).toBe(false);
    expect(view.state.doc.firstChild!.childCount).toBe(3); // unchanged
  });

  it('does nothing for a plain (non-table) key with a CellSelection', () => {
    const view = makeView(3, 3);
    selectCells(view, [0, 0], [2, 2]);
    expect(key(view, 'a')).toBe(false);
  });
});

// ── insertRowBelowCaret / Shift+Enter ────────────────────────────────────────

describe('insertRowBelowCaret', () => {
  it('inserts a new row below the caret and moves the caret into it, same column', () => {
    const view = makeView(2, 2);
    const $pos = view.state.doc.resolve(cellContentPos(view.state.doc, 0, 1));
    view.dispatch(view.state.tr.setSelection(TextSelection.near($pos)));

    expect(key(view, 'Enter', { shiftKey: true })).toBe(true);

    const table = view.state.doc.firstChild!;
    expect(table.childCount).toBe(3); // 2 rows -> 3

    const newRowCellStart = cellContentPos(view.state.doc, 1, 1);
    const newRowCell = table.child(1).child(1);
    expect(view.state.selection.from).toBeGreaterThanOrEqual(newRowCellStart);
    expect(view.state.selection.from).toBeLessThan(newRowCellStart + newRowCell.nodeSize);
  });

  it('is a no-op for a CellSelection (handled key returns false)', () => {
    const view = makeView(2, 2);
    selectCells(view, [0, 0], [0, 1]);
    expect(insertRowBelowCaret(view.state)).toBe(false);
    expect(key(view, 'Enter', { shiftKey: true })).toBe(false);
  });
});
