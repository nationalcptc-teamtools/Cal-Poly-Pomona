import { NodeSelection, type Selection } from '@milkdown/prose/state';
import { CellSelection } from '@milkdown/prose/tables';

/**
 * Whether the floating format toolbar should follow this editor selection.
 * It is for a range of text, so an empty selection, a node selection and a
 * cell selection get none. Crepe's table view turns the first click into a
 * cell into a NodeSelection of the cell's paragraph, which the browser paints
 * as selected text; without this check that click opened the toolbar.
 */
export function selectionWantsFormatToolbar(selection: Selection): boolean {
  if (selection.empty) return false;
  if (selection instanceof NodeSelection) return false;
  if (selection instanceof CellSelection) return false;
  return true;
}
