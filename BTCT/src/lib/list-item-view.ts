// ─────────────────────────────────────────────────────────────────────────
// List item node view, plain DOM.
//
// Replaces Crepe's Vue list item view (@milkdown/components/list-item-block)
// with the same markup, so its CSS, the live-preview reveal and the block
// handle keep working, minus one bug.
//
// The bug: Crepe's view appends its content element (the item's paragraph)
// from a Vue function ref, and Vue calls a function ref again on every
// re-render. `appendChild` on a node that is already the last child still
// removes and re-inserts it, so whenever the item re-rendered (its label or
// type changing, as when `1. ` turns a paragraph into a numbered item), the
// paragraph holding the caret left the document for a moment. Firefox then
// put the caret at the nearest editable spot, the end of the line above;
// ProseMirror read that back as a selection change, and Crepe's own fix-up
// (a requestAnimationFrame that restores the selection) is skipped as soon
// as the document changed. So with quick typing, `1. one` right after a list
// left an empty `1.` item and appended `one` to the line above.
//
// Here the content element is placed once, in the constructor, and the
// label is repainted in place, so nothing ever moves the caret's node.
// ─────────────────────────────────────────────────────────────────────────

import DOMPurify from 'dompurify';
import { listItemSchema } from '@milkdown/preset-commonmark';
import { listItemBlockConfig, type ListItemBlockConfig } from '@milkdown/components/list-item-block';
import { $view } from '@milkdown/utils';
import type { Node } from '@milkdown/prose/model';
import type { EditorView, NodeView, NodeViewConstructor } from '@milkdown/prose/view';
import { isLivePreview } from '@/components/editor/live-preview/editor-style';
import { placeCaretBeforeListMarker } from '@/components/editor/live-preview/live-preview-plugin';

export type ListLabelKind = 'bullet' | 'ordered' | 'checked' | 'unchecked';

/** Which marker an item shows: a task box wins over the list type. */
export function listLabelKind(attrs: { listType?: unknown; checked?: unknown }): ListLabelKind {
  if (attrs.checked == null) return attrs.listType === 'bullet' ? 'bullet' : 'ordered';
  return attrs.checked ? 'checked' : 'unchecked';
}

/**
 * Build the node view for one list item. Exported for tests; the editor
 * uses `listItemView` below.
 */
export function createListItemView(
  initialNode: Node,
  view: EditorView,
  getPos: () => number | undefined,
  config: ListItemBlockConfig,
): NodeView {
  const dom = document.createElement('div');
  dom.className = 'milkdown-list-item-block';
  const li = document.createElement('li');
  li.className = 'list-item';
  const labelWrapper = document.createElement('div');
  labelWrapper.className = 'label-wrapper';
  labelWrapper.setAttribute('contenteditable', 'false');
  const label = document.createElement('span');
  labelWrapper.appendChild(label);
  const children = document.createElement('div');
  children.className = 'children';
  const contentDOM = document.createElement('div');
  contentDOM.className = 'content-dom';
  contentDOM.setAttribute('data-content-dom', 'true');
  children.appendChild(contentDOM);
  li.append(labelWrapper, children);
  dom.appendChild(li);

  let node = initialNode;
  let painted = '';
  const paint = () => {
    const readonly = !view.editable;
    const kind = listLabelKind(node.attrs);
    const text = String(node.attrs.label ?? '');
    const key = `${kind}|${text}|${readonly}`;
    if (key === painted) return;
    painted = key;
    label.className = ['milkdown-icon', 'label', readonly ? 'readonly' : '', kind].filter(Boolean).join(' ');
    // index.css dims a ticked to-do's text.
    dom.dataset.checked = String(kind === 'checked');
    if (kind === 'ordered') {
      // The number comes from the shared document, so it is text, never HTML.
      label.textContent = text;
      return;
    }
    const icon = config.renderLabel({
      label: text,
      listType: String(node.attrs.listType ?? ''),
      checked: node.attrs.checked ?? undefined,
      readonly,
    });
    label.innerHTML = DOMPurify.sanitize(String(icon ?? '').trim());
  };
  paint();

  // Ticking a task box. pointerdown, like Crepe, so the click never moves
  // the caret into the label first. In the Live preview style a click on a
  // bullet or number puts the caret in front of the item's marker, which
  // then shows as raw markdown in the same spot (Obsidian's "select the
  // bullet to see the `-`").
  labelWrapper.addEventListener('pointerdown', (e) => {
    e.stopPropagation();
    e.preventDefault();
    if (!view.editable) return;
    const pos = getPos();
    if (pos == null) return;
    if (node.attrs.checked == null) {
      if (isLivePreview() && e.button === 0) placeCaretBeforeListMarker(view, pos);
      return;
    }
    if (!view.hasFocus()) view.focus();
    view.dispatch(view.state.tr.setNodeAttribute(pos, 'checked', !node.attrs.checked));
  });

  return {
    dom,
    contentDOM,
    update: (updated) => {
      if (updated.type !== node.type) return false;
      node = updated;
      paint();
      return true;
    },
    ignoreMutation: (mutation) => {
      if ((mutation.type as string) === 'selection') return false;
      if (mutation.target === contentDOM && mutation.type === 'attributes') return true;
      return !contentDOM.contains(mutation.target);
    },
    selectNode: () => {
      dom.classList.add('selected');
      li.classList.add('ProseMirror-selectednode');
    },
    deselectNode: () => {
      dom.classList.remove('selected');
      li.classList.remove('ProseMirror-selectednode');
    },
  };
}

/**
 * `.use()` after Crepe is constructed: Milkdown builds `nodeViews` with
 * `Object.fromEntries`, so the view registered last for `list_item` wins.
 * Crepe's ListItem feature stays on for its stylesheet and its label icons
 * (read from `listItemBlockConfig`).
 */
export const listItemView = $view(listItemSchema.node, (ctx): NodeViewConstructor =>
  (node, view, getPos) => createListItemView(node, view, getPos, ctx.get(listItemBlockConfig.key)),
);
