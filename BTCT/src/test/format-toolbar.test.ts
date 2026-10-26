import { describe, it, expect } from 'vitest';
import { EditorState, NodeSelection, TextSelection } from '@milkdown/prose/state';
import { Schema } from '@milkdown/prose/model';
import { CellSelection, tableNodes } from '@milkdown/prose/tables';
import { selectionWantsFormatToolbar } from '@/lib/format-toolbar';

const schema = new Schema({
  nodes: {
    doc: { content: 'block+' },
    paragraph: { group: 'block', content: 'text*', toDOM: () => ['p', 0] },
    text: {},
    ...tableNodes({ tableGroup: 'block', cellContent: 'paragraph+', cellAttributes: {} }),
  },
});

// <table><tr><td><p>10.10.10.21</p></td><td><p>nginx</p></td></tr></table><p>Found an upload</p>
const cell = (t: string) => schema.nodes.table_cell!.create(null, schema.node('paragraph', null, [schema.text(t)]));
const doc = schema.node('doc', null, [
  schema.nodes.table!.create(null, schema.nodes.table_row!.create(null, [cell('10.10.10.21'), cell('nginx')])),
  schema.node('paragraph', null, [schema.text('Found an upload')]),
]);
const state = EditorState.create({ doc });
const tableEnd = doc.firstChild!.nodeSize;
// First cell starts at 2 (table 0, row 1); its paragraph at 3, text at 4.
const firstCellPara = 3;

describe('selectionWantsFormatToolbar', () => {
  it('shows for a non-empty text selection, in a paragraph or inside a cell', () => {
    expect(selectionWantsFormatToolbar(TextSelection.create(state.doc, tableEnd + 1, tableEnd + 6))).toBe(true);
    expect(selectionWantsFormatToolbar(TextSelection.create(state.doc, firstCellPara + 1, firstCellPara + 6))).toBe(true);
  });

  it('hides for a caret', () => {
    expect(selectionWantsFormatToolbar(TextSelection.create(state.doc, tableEnd + 3))).toBe(false);
  });

  it("hides for the NodeSelection of a cell's paragraph that a click into a table cell makes", () => {
    const sel = NodeSelection.create(state.doc, firstCellPara);
    expect(sel.node.type.name).toBe('paragraph');
    expect(selectionWantsFormatToolbar(sel)).toBe(false);
  });

  it('hides for a cell selection', () => {
    expect(selectionWantsFormatToolbar(CellSelection.create(state.doc, 2, 2 + doc.firstChild!.firstChild!.firstChild!.nodeSize))).toBe(false);
  });
});
