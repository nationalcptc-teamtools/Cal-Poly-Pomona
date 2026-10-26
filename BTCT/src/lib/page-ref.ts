// ─────────────────────────────────────────────────────────────────────────
// Page-reference chips in the note editor.
//
// A `page_ref` node is an inline atom that points at another page by id
// (see `insertPageRef` below, wired to the `/page` slash-menu item in
// PageEditor.tsx). It renders as a small pill showing the target page's
// live title (subscribed to the store, so a rename anywhere updates every
// chip pointing at it) and navigates there on click.
//
// Markdown round-trips through the same mdast "image" leaf-node type
// asset_image already uses (a `page:<id>` URL instead of `asset:<id>`),
// rather than the built-in "link" mark: links wrap arbitrary inline content
// as a mark, not a single self-contained node, so reusing that machinery
// for an atom whose visible text is a live lookup (not authored content)
// would fight the built-in link mark's own parser for the same mdast type.
// ─────────────────────────────────────────────────────────────────────────

import { $node, $view } from '@milkdown/utils';
import { commandsCtx, editorViewCtx } from '@milkdown/core';
import { clearTextInCurrentBlockCommand } from '@milkdown/preset-commonmark';
import type { Ctx } from '@milkdown/ctx';
import type { Node as ProseNode } from '@milkdown/prose/model';
import { v4 as uuidv4 } from 'uuid';
import { useAppStore } from '@/stores';

const PAGE_URL_PREFIX = 'page:';

export const pageRefSchema = $node('page_ref', () => ({
  group: 'inline',
  inline: true,
  atom: true,
  selectable: true,
  marks: '',
  attrs: {
    pageId: { default: '' },
  },
  parseDOM: [
    {
      tag: 'a[data-page-ref-id]',
      getAttrs: (dom) => {
        if (!(dom instanceof HTMLElement)) return false;
        return { pageId: dom.getAttribute('data-page-ref-id') || '' };
      },
    },
  ],
  toDOM: (node) => {
    const { pageId } = node.attrs as { pageId: string };
    return ['a', { 'data-page-ref-id': pageId, href: '#', class: 'page-ref-chip' }, 0];
  },
  parseMarkdown: {
    match: (node) => node.type === 'image' && typeof node.url === 'string' && node.url.startsWith(PAGE_URL_PREFIX),
    runner: (state, node, type) => {
      state.addNode(type, { pageId: String(node.url).slice(PAGE_URL_PREFIX.length) });
    },
  },
  toMarkdown: {
    match: (node) => node.type.name === 'page_ref',
    runner: (state, node) => {
      const pageId = node.attrs.pageId as string;
      const page = useAppStore.getState().pages.find((p) => p.id === pageId);
      state.addNode('image', undefined, undefined, {
        url: `${PAGE_URL_PREFIX}${pageId}`,
        alt: page?.title || 'Untitled',
        title: '',
      });
    },
  },
}));

export const pageRefView = $view(pageRefSchema, () => {
  return (initialNode: ProseNode) => {
    const dom = document.createElement('a');
    dom.className = 'page-ref-chip';
    dom.href = '#';
    dom.contentEditable = 'false';

    let node = initialNode;

    const render = () => {
      const pageId = node.attrs.pageId as string;
      dom.dataset.pageRefId = pageId;
      const page = useAppStore.getState().pages.find((p) => p.id === pageId);
      const label = page ? (page.title || 'Untitled') : 'Deleted page';
      if (dom.textContent !== label) dom.textContent = label;
      dom.classList.toggle('page-ref-chip--missing', !page);
    };

    const handleClick = (e: MouseEvent) => {
      e.preventDefault();
      const pageId = node.attrs.pageId as string;
      const page = useAppStore.getState().pages.find((p) => p.id === pageId);
      if (!page) return;
      useAppStore.getState().openTab({ id: uuidv4(), kind: 'page', entityId: page.id, title: page.title });
    };
    dom.addEventListener('click', handleClick);

    render();
    // Re-render on any store change so a rename elsewhere updates this chip live.
    const unsubscribe = useAppStore.subscribe((s, prev) => {
      if (s.pages === prev.pages) return;
      render();
    });

    return {
      dom,
      update: (updated: ProseNode) => {
        if (updated.type !== initialNode.type) return false;
        node = updated;
        render();
        return true;
      },
      selectNode: () => dom.classList.add('ProseMirror-selectednode'),
      deselectNode: () => dom.classList.remove('ProseMirror-selectednode'),
      stopEvent: () => false,
      ignoreMutation: () => true,
      destroy: () => {
        dom.removeEventListener('click', handleClick);
        unsubscribe();
      },
    };
  };
});

/**
 * Create a subnote under `parentPageId` and insert a `page_ref` chip at the
 * cursor pointing at it, then open the new subnote as its own tab so the
 * cursor lands ready to type. Mirrors `insertTable`'s pattern (clear the
 * slash-command's own text, then insert), except the page has to exist
 * first since the chip needs its id.
 */
export async function insertPageRef(ctx: Ctx, parentPageId: string): Promise<void> {
  const store = useAppStore.getState();
  const newPage = await store.createPage(parentPageId, 'Untitled');

  const commands = ctx.get(commandsCtx);
  const view = ctx.get(editorViewCtx);
  commands.call(clearTextInCurrentBlockCommand.key);
  const nodeType = view.state.schema.nodes.page_ref;
  if (nodeType) {
    view.dispatch(view.state.tr.replaceSelectionWith(nodeType.create({ pageId: newPage.id })));
  }

  store.openTab({ id: uuidv4(), kind: 'page', entityId: newPage.id, title: newPage.title });
}

/** Slash-menu icon: a simple page/document glyph. */
export const PAGE_REF_ICON = `<svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
  <path d="M6 2h9l5 5v13a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2Zm8 1.5V8h4.5L14 3.5ZM7 12h10v1.5H7V12Zm0 4h10v1.5H7V16Zm0-8h5v1.5H7V8Z"/>
</svg>`;
