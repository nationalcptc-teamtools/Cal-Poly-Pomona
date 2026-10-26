import type { Node as DocumentNode } from '@milkdown/prose/model';
const decorationCache = new WeakMap<DocumentNode, DecorationSet>();
// ─────────────────────────────────────────────────────────────────────────
// Drag-to-resize for images in the note editor.
//
// Two pieces, both `.use()`d in PageEditor:
//
//   • `imageResizableSchema` extends commonmark's `image` node with a `width`
//     attribute (pixels). It lives in the ProseMirror doc, so it syncs through
//     Yjs and survives a reload like any other note content, and it is written
//     into the img's HTML/`data-width` on copy so a paste back in keeps the
//     size. Markdown has no width syntax, so a markdown export drops it (the
//     image is unchanged, just full-width again).
//
//   • `imageResizePlugin` draws a handle on the selected image and turns a drag
//     from its bottom-right corner into a `width` change. The width is written
//     straight to the DOM during the drag (one style mutation per move) and
//     committed to the node once, on release, so a live collaborator's cursor
//     and the Crepe image node view are never rebuilt mid-drag.
//
// Crepe renders images with its own (Vue) node view over the SAME `image`
// node, so we never replace that view: the width reaches the rendered <img>
// through a node decoration (style on the node view's element), and the CSS in
// index.css makes the inner <img> fill it.
// ─────────────────────────────────────────────────────────────────────────

import { imageAttr, imageSchema } from '@milkdown/preset-commonmark';
import { imageBlockSchema } from '@milkdown/components/image-block';
import { $prose } from '@milkdown/utils';
import { NodeSelection, Plugin, PluginKey } from '@milkdown/prose/state';
import { Decoration, DecorationSet, type EditorView } from '@milkdown/prose/view';
import { toLayoutPx } from './ui-zoom';

/** The image node types we make resizable: inline images and Crepe's image block. */
const IMAGE_TYPES = new Set(['image', 'image-block', 'asset_image']);

/** Smallest and how-close-to-the-corner a grab counts, in CSS pixels. */
export const MIN_IMAGE_WIDTH = 48;
const HANDLE_HIT = 20;

/**
 * New width for an image dragged by `dx` pixels from its start width, clamped
 * between the minimum and the available column width. Pure, so the drag math
 * is unit-tested without a DOM.
 */
export function clampImageWidth(startWidth: number, dx: number, maxWidth: number): number {
  const upper = Math.max(MIN_IMAGE_WIDTH, maxWidth);
  return Math.round(Math.min(Math.max(startWidth + dx, MIN_IMAGE_WIDTH), upper));
}

// ── Schema: add a `width` attr to the image node ──────────────────────────

export const imageResizableSchema = imageSchema.extendSchema((prev) => (ctx) => {
  const base = prev(ctx);
  return {
    ...base,
    attrs: {
      ...base.attrs,
      // Pixel width, or null for the natural / full width.
      width: { default: null },
    },
    parseDOM: [
      {
        tag: 'img[src]',
        getAttrs: (dom: HTMLElement | string) => {
          if (!(dom instanceof HTMLElement)) return false;
          const raw = dom.getAttribute('data-width') || dom.style.width || dom.getAttribute('width') || '';
          const w = Number.parseInt(raw, 10);
          return {
            src: dom.getAttribute('src') || '',
            alt: dom.getAttribute('alt') || '',
            title: dom.getAttribute('title') || dom.getAttribute('alt') || '',
            width: Number.isFinite(w) && w > 0 ? w : null,
          };
        },
      },
    ],
    toDOM: (node) => {
      const attrs = node.attrs as { width: number | null; [k: string]: unknown };
      const width = attrs.width;
      const out: Record<string, unknown> = {
        ...ctx.get(imageAttr.key)(node),
        src: attrs.src,
        alt: attrs.alt,
        title: attrs.title,
      };
      if (typeof width === 'number' && width > 0) {
        // The HTML width attribute travels to plain-HTML paste targets; the
        // data-width mirror is what our parseDOM reads back on a paste in.
        out.width = String(width);
        out['data-width'] = String(width);
        out.style = `width:${width}px;max-width:100%;height:auto;`;
      }
      return ['img', out];
    },
  };
});

// Crepe renders pasted / dropped images as a block node (`image-block`, a Vue
// component). Add ONLY a `width` attr so the corner handle can size it; the
// node's own `parseDOM` / `toDOM` / markdown runners and its Vue node view are
// left exactly as Crepe defined them (overriding them broke the component's
// rendering). The width lives in the page Y.Doc and is painted onto the node
// view element by the decoration below; index.css overrides the component's
// fixed inline height so the picture scales with the width.
export const imageBlockResizableSchema = imageBlockSchema.extendSchema((prev) => (ctx) => {
  const base = prev(ctx);
  return {
    ...base,
    attrs: {
      ...base.attrs,
      width: { default: null },
    },
  };
});

// ── Plugin: the resize handle + drag ──────────────────────────────────────

const KEY = new PluginKey('image-resize');

interface Drag {
  pos: number;
  startX: number;
  startWidth: number;
  maxWidth: number;
  dom: HTMLElement;
}

/** The rendered <img> inside an image node's element (or the element itself). */
function innerImg(el: HTMLElement): HTMLImageElement | null {
  if (el instanceof HTMLImageElement) return el;
  return el.querySelector('img');
}

/**
 * The doc position of the image node whose node view element is `host`.
 * Matched by DOM identity, so it works for both the inline image and Crepe's
 * Vue-rendered image block without depending on the selection.
 */
function findImagePos(view: EditorView, host: HTMLElement): number {
  let found = -1;
  view.state.doc.descendants((node, pos) => {
    if (found !== -1) return false;
    if (IMAGE_TYPES.has(node.type.name) && view.nodeDOM(pos) === host) {
      found = pos;
      return false;
    }
    return true;
  });
  return found;
}

function createImageResizeProsePlugin(): Plugin {
  return new Plugin({
    key: KEY,
    props: {
      // Tag every image node so the CSS can find it, and paint the stored
      // width onto the node view's element (works whichever node view renders
      // the image, including Crepe's own).
      decorations(state) {
        const hit = decorationCache.get(state.doc);
        if (hit !== undefined) return hit;
        const decos: Decoration[] = [];
        state.doc.descendants((node, pos) => {
          if (!IMAGE_TYPES.has(node.type.name)) return;
          const width = (node.attrs as { width?: number | null }).width;
          const cls = width ? 'pm-image pm-img-sized' : 'pm-image';
          const attrs: Record<string, string> = { class: cls };
          if (width) attrs.style = `width:${width}px`;
          decos.push(Decoration.node(pos, pos + node.nodeSize, attrs));
        });
        const result = decos.length ? DecorationSet.create(state.doc, decos) : DecorationSet.empty;
          decorationCache.set(state.doc, result);
          return result;
      },
    },

    view(view) {
      let drag: Drag | null = null;

      const onPointerDown = (event: PointerEvent) => {
        if (event.button !== 0 || drag) return;
        // The image node view element under the pointer (tagged `pm-image` by
        // the decoration above). Works for the inline image and the block
        // image alike, selected or not.
        const host = (event.target as HTMLElement)?.closest?.('.pm-image') as HTMLElement | null;
        const img = host && innerImg(host);
        if (!host || !img) return;

        // Only a grab that starts near the bottom-right corner resizes; a
        // click elsewhere on the image keeps selecting / editing it.
        const rect = img.getBoundingClientRect();
        const nearCorner =
          event.clientX >= rect.right - HANDLE_HIT && event.clientX <= rect.right + 6 &&
          event.clientY >= rect.bottom - HANDLE_HIT && event.clientY <= rect.bottom + 6;
        if (!nearCorner) return;

        const pos = findImagePos(view, host);
        if (pos < 0) return;

        const column = (host.parentElement?.clientWidth ?? view.dom.clientWidth) || toLayoutPx(rect.width);
        drag = {
          pos,
          startX: event.clientX,
          // CSS px, which is what style.width takes (rect is screen px under interface zoom).
          startWidth: toLayoutPx(rect.width),
          maxWidth: column,
          dom: host,
        };
        // Select the node so the handle stays visible during the drag.
        try {
          view.dispatch(view.state.tr.setSelection(NodeSelection.create(view.state.doc, pos)));
        } catch { /* some node views manage their own selection */ }
        event.preventDefault();
        event.stopPropagation();
        try { (event.target as Element).setPointerCapture?.(event.pointerId); } catch { /* ignore */ }
        document.body.style.cursor = 'nwse-resize';
        document.body.style.userSelect = 'none';
        window.addEventListener('pointermove', onPointerMove);
        window.addEventListener('pointerup', onPointerUp, { once: true });
      };

      const onPointerMove = (event: PointerEvent) => {
        if (!drag) return;
        const next = clampImageWidth(drag.startWidth, toLayoutPx(event.clientX - drag.startX), drag.maxWidth);
        // Live: style the node view element directly (CSS makes the img fill
        // it). No transaction, so nothing re-renders mid-drag.
        drag.dom.style.width = `${next}px`;
        drag.dom.classList.add('pm-img-sized');
      };

      const onPointerUp = (event: PointerEvent) => {
        window.removeEventListener('pointermove', onPointerMove);
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
        if (!drag) return;
        const next = clampImageWidth(drag.startWidth, toLayoutPx(event.clientX - drag.startX), drag.maxWidth);
        const active = drag;
        drag = null;
        const node = view.state.doc.nodeAt(active.pos);
        if (!node || !IMAGE_TYPES.has(node.type.name)) return;
        view.dispatch(
          view.state.tr.setNodeMarkup(active.pos, undefined, { ...node.attrs, width: next }),
        );
      };

      view.dom.addEventListener('pointerdown', onPointerDown, true);
      return {
        destroy() {
          view.dom.removeEventListener('pointerdown', onPointerDown, true);
          window.removeEventListener('pointermove', onPointerMove);
          document.body.style.cursor = '';
          document.body.style.userSelect = '';
        },
      };
    },
  });
}

export const imageResizePlugin = $prose(() => createImageResizeProsePlugin());

/**
 * Size the image whose node view element is `host` to `fraction` of its
 * column, or back to its natural width with `null`. The height follows the
 * width in CSS, so the picture keeps its aspect ratio. Returns false when the
 * node is no longer in the document.
 */
export function setImageWidthFraction(view: EditorView, host: HTMLElement, fraction: number | null): boolean {
  const pos = findImagePos(view, host);
  const node = pos < 0 ? null : view.state.doc.nodeAt(pos);
  if (!node || !IMAGE_TYPES.has(node.type.name)) return false;
  const column = host.parentElement?.clientWidth || view.dom.clientWidth;
  const width = fraction === null || !(column > 0)
    ? null
    : clampImageWidth(0, column * fraction, column);
  view.dispatch(view.state.tr.setNodeMarkup(pos, undefined, { ...node.attrs, width }));
  return true;
}
