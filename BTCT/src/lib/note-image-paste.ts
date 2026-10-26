// ─────────────────────────────────────────────────────────────────────────
// Paste / drop an image into a note → upload it as a shared asset and insert
// an `asset_image` node (see asset-image.ts). The image then appears in the
// Assets Manager and can be blurred non-destructively.
//
// Also: the right-click menu over a note image and the "blur the selected
// image" action, both of which open the crop/blur editor on the asset.
// ─────────────────────────────────────────────────────────────────────────

import { Plugin, PluginKey, NodeSelection } from '@milkdown/prose/state';
import type { EditorState, Transaction } from '@milkdown/prose/state';
import { Decoration, DecorationSet } from '@milkdown/prose/view';
import type { EditorView } from '@milkdown/prose/view';
import type { Node as ProseNode } from '@milkdown/prose/model';
import { editorViewCtx } from '@milkdown/core';
import { $prose } from '@milkdown/utils';
import { ySyncPluginKey } from 'y-prosemirror';
import { useAppStore } from '@/stores';
import { getSharedDoc, textKey } from '@/realtime/shared-doc';
import { ASSET_DIR } from '@/lib/assets';
import { getActiveMilkdownEditor } from '@/lib/active-editor';
import { pushNotice } from '@/lib/editor-notices';
import { parseAssetLinkList } from '@/lib/asset-link';
import { setImageWidthFraction } from '@/lib/image-resize';

const IMAGE_RE = /^image\//;

function imageFilesFrom(dt: DataTransfer | null | undefined): File[] {
  if (!dt) return [];
  return Array.from(dt.files ?? []).filter((f) => IMAGE_RE.test(f.type) || /\.(png|jpe?g|gif|webp|svg)$/i.test(f.name));
}

/**
 * A picture copied as HTML only (`copyImage` over plain http, or a page that
 * copies an inline image): the `data:` image of an HTML clipboard holding
 * exactly one `<img>` and no other text, as a File to upload. Null otherwise,
 * so ordinary rich text keeps its normal paste.
 */
export function dataImageFileFrom(html: string): File | null {
  if (!html || html.length > 40 * 1024 * 1024) return null;
  const imgs = html.match(/<img\b[^>]*>/gi);
  if (!imgs || imgs.length !== 1) return null;
  const rest = html.replace(imgs[0], '').replace(/<[^>]*>/g, '').replace(/&nbsp;/g, ' ').trim();
  if (rest) return null;
  const m = /\ssrc\s*=\s*"(data:(image\/(?:png|jpeg|gif|webp));base64,([A-Za-z0-9+/=\s]+))"/i.exec(imgs[0]);
  if (!m) return null;
  try {
    const bin = atob(m[3]!.replace(/\s+/g, ''));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const ext = m[2]!.split('/')[1]!.replace('jpeg', 'jpg');
    return new File([bytes], `pasted-image.${ext}`, { type: m[2]!.toLowerCase() });
  } catch {
    return null;
  }
}

/**
 * A text paste over this many characters is refused with an offer to save it
 * as a file. The whole body goes over the page's websocket as one update: the
 * relay drops a message over 16 MB (the socket closes and the client
 * reconnects in a loop with the edit never stored), and a few MB already
 * costs hundreds of MB of server heap and slows every editor on the page.
 */
export const MAX_NOTE_PASTE_CHARS = 1_000_000;

export function formatSize(chars: number): string {
  return chars >= 1_000_000 ? `${(chars / 1_000_000).toFixed(1)} MB` : `${Math.round(chars / 1000)} KB`;
}

/**
 * Hand `text` to the browser as `name` inside `paste_<date>_txt.zip` (every
 * download is a ZIP, src/lib/download-zip.ts, loaded only when used).
 */
function downloadText(text: string, name: string): void {
  void import('./download-zip')
    .then(({ downloadAsZip }) => downloadAsZip('paste', [{ name, data: text }]))
    .catch((e: unknown) => pushNotice({ tone: 'error', message: `Could not save the paste: ${e instanceof Error ? e.message : String(e)}` }));
}

// ── Upload placeholders ──────────────────────────────────────────────────
// A paste or drop marks its spot with a widget decoration that is mapped
// through every later transaction, so an image lands where it was pasted
// even if the user kept typing during the upload (the old code inserted at
// whatever the caret was by then).

interface PlaceholderSpec { uploadId: object }
const uploadKey = new PluginKey<DecorationSet>('note-image-upload');
type UploadMeta = { add: { id: object; pos: number; name: string } } | { remove: { id: object } };

function placeholderWidget(name: string): HTMLElement {
  const el = document.createElement('div');
  el.className = 'note-image-uploading';
  el.contentEditable = 'false';
  el.textContent = `Uploading ${name}…`;
  el.setAttribute('style', 'font-size:12px;opacity:.7;padding:4px 0;');
  return el;
}

function findPlaceholder(state: EditorState, id: object): number | null {
  const set = uploadKey.getState(state);
  const found = set?.find(undefined, undefined, (spec) => (spec as PlaceholderSpec).uploadId === id);
  return found && found.length > 0 ? found[0]!.from : null;
}

/** The ProseMirror view of the active page editor, if any. */
function activeView(): EditorView | null {
  const editor = getActiveMilkdownEditor();
  if (!editor) return null;
  let view: EditorView | null = null;
  try { editor.action((ctx) => { view = ctx.get(editorViewCtx); }); } catch { return null; }
  const v = view as EditorView | null;
  return v && !v.isDestroyed ? v : null;
}

function errorText(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  return msg.length > 160 ? `${msg.slice(0, 160)}…` : msg;
}

/** Insert an asset_image at `pos` (fitted to a valid block position), or at the selection. */
function placeImage(view: EditorView, node: ProseNode, pos: number | null, id?: object): void {
  let tr: Transaction = view.state.tr;
  if (typeof pos === 'number') {
    const clamped = Math.max(0, Math.min(pos, tr.doc.content.size));
    tr = tr.replaceRangeWith(clamped, clamped, node);
  } else {
    // replaceSelectionWith inserts the block and leaves the selection
    // after it, so several pasted images stack in order.
    tr = tr.replaceSelectionWith(node);
  }
  if (id) tr.setMeta(uploadKey, { remove: { id } } satisfies UploadMeta);
  view.dispatch(tr.scrollIntoView());
}

/**
 * Upload each image and insert an `asset_image` node at its placeholder.
 * A failed upload keeps the File and offers Retry; an upload that finishes
 * after its note closed says where the image went (the Assets tab) and
 * offers to place it in the note being edited now.
 */
export async function insertImages(view: EditorView, files: File[], pos?: number): Promise<void> {
  if (view.isDestroyed || !view.state.schema.nodes.asset_image) return;
  const at = typeof pos === 'number' ? Math.max(0, Math.min(pos, view.state.doc.content.size)) : view.state.selection.from;
  const jobs = files.map((file) => ({ file, id: {} as object }));
  // The plugin reads one meta per transaction, so each placeholder gets its own.
  for (const job of jobs) {
    view.dispatch(view.state.tr.setMeta(uploadKey, { add: { id: job.id, pos: at, name: job.file.name } } satisfies UploadMeta));
  }

  for (const { file, id } of jobs) {
    try {
      const asset = await useAppStore.getState().addTypstAsset(file, 'image', null);
      const target = view.isDestroyed ? null : view;
      if (!target) {
        pushNotice({
          tone: 'info',
          message: `"${asset.filename}" finished uploading after its note closed. It is in the Assets tab.`,
          actions: [{
            label: 'Insert in current note',
            run: () => {
              const v = activeView();
              const type = v?.state.schema.nodes.asset_image;
              if (v && type) placeImage(v, type.create({ assetId: asset.id, alt: file.name }), null);
            },
          }],
        });
        continue;
      }
      const type = target.state.schema.nodes.asset_image!;
      const node = type.create({ assetId: asset.id, alt: file.name });
      placeImage(target, node, findPlaceholder(target.state, id), id);
    } catch (err) {
      if (!view.isDestroyed) view.dispatch(view.state.tr.setMeta(uploadKey, { remove: { id } } satisfies UploadMeta));
      pushNotice({
        tone: 'error',
        message: `Could not upload "${file.name}": ${errorText(err)}`,
        actions: [{
          label: 'Retry',
          run: () => {
            const v = view.isDestroyed ? activeView() : view;
            if (v) void insertImages(v, [file]);
            else pushNotice({ tone: 'error', message: 'Open a note to retry the upload.', actions: [{ label: 'Retry', run: () => { const w = activeView(); if (w) void insertImages(w, [file]); } }] });
          },
        }],
      });
    }
  }
}

/**
 * Paste / drop of an image → upload + insert. Uses capture-phase listeners on
 * the editor DOM rather than ProseMirror's `handlePaste`/`handleDrop` props,
 * because Milkdown's clipboard plugin also registers those and, running first,
 * consumes the event before ours would see it. A text paste over
 * `MAX_NOTE_PASTE_CHARS` is refused here too, with an offer to save it.
 */
export const noteImagePastePlugin = $prose(() =>
  new Plugin<DecorationSet>({
    key: uploadKey,
    state: {
      init: () => DecorationSet.empty,
      apply(tr, set) {
        let next = set.map(tr.mapping, tr.doc);
        const meta = tr.getMeta(uploadKey) as UploadMeta | undefined;
        if (meta && 'add' in meta) {
          const name = meta.add.name;
          const deco = Decoration.widget(meta.add.pos, () => placeholderWidget(name), { uploadId: meta.add.id, side: 1 } as PlaceholderSpec & { side: number });
          next = next.add(tr.doc, [deco]);
        } else if (meta && 'remove' in meta) {
          next = next.remove(next.find(undefined, undefined, (spec) => (spec as PlaceholderSpec).uploadId === meta.remove.id));
        }
        return next;
      },
    },
    props: {
      decorations(state) { return uploadKey.getState(state); },
    },
    view(view) {
      const onPaste = (event: ClipboardEvent) => {
        const files = imageFilesFrom(event.clipboardData);
        if (files.length === 0) {
          const pasted = dataImageFileFrom(event.clipboardData?.getData('text/html') ?? '');
          if (pasted) files.push(pasted);
        }
        if (files.length === 0) {
          const text = event.clipboardData?.getData('text/plain') ?? '';
          // A copied asset link (Copy link on the Assets tab) becomes that
          // image, the same node a pasted screenshot turns into.
          const ids = text.length < 4096 ? parseAssetLinkList(text) : null;
          const type = view.state.schema.nodes.asset_image;
          if (ids && type) {
            const assets = useAppStore.getState().typstAssets;
            const found = ids
              .map((id) => assets.find((a) => a.id === id && a.kind === 'image'))
              .filter((a): a is NonNullable<typeof a> => !!a);
            if (found.length > 0) {
              event.preventDefault();
              event.stopImmediatePropagation();
              for (const a of found) {
                placeImage(view, type.create({ assetId: a.id, alt: a.filename }), null);
              }
              return;
            }
          }
          const size = Math.max(text.length, event.clipboardData?.getData('text/html')?.length ?? 0);
          if (size <= MAX_NOTE_PASTE_CHARS) return;
          event.preventDefault();
          event.stopImmediatePropagation();
          pushNotice({
            tone: 'info',
            message: `That paste is ${formatSize(size)} of text, too large for a note: it would not sync to the team. Save it as a .txt file (downloaded in a .zip) instead and attach it to the report separately.`,
            actions: [{ label: 'Save as .txt', run: () => downloadText(text, `paste-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`) }],
          });
          return;
        }
        event.preventDefault();
        event.stopImmediatePropagation();
        void insertImages(view, files);
      };
      const onDrop = (event: DragEvent) => {
        const files = imageFilesFrom(event.dataTransfer);
        if (files.length === 0) return;
        event.preventDefault();
        event.stopImmediatePropagation();
        const pos = view.posAtCoords({ left: event.clientX, top: event.clientY })?.pos;
        void insertImages(view, files, pos);
      };
      view.dom.addEventListener('paste', onPaste, true);
      view.dom.addEventListener('drop', onDrop, true);
      return {
        destroy() {
          view.dom.removeEventListener('paste', onPaste, true);
          view.dom.removeEventListener('drop', onDrop, true);
        },
      };
    },
  }),
);

/**
 * Right-click over an `asset_image` opens a small menu (rendered app-side from
 * the `imageMenu` store flag) offering "Blur / edit image". Left to bubble for
 * any other target so the browser's own menu still works elsewhere.
 */
/** The note image the open right-click menu is for, so its Size row can resize it. */
let menuTarget: { view: EditorView; host: HTMLElement } | null = null;

/** Size the menu's image to `fraction` of its column (null: natural width), keeping its aspect ratio. */
export function resizeMenuImage(fraction: number | null): void {
  const target = menuTarget;
  useAppStore.getState().setImageMenu(null);
  if (target && target.host.isConnected) setImageWidthFraction(target.view, target.host, fraction);
}

export const noteImageContextPlugin = $prose(() =>
  new Plugin({
    props: {
      handleDOMEvents: {
        contextmenu(view, event) {
          const el = (event.target as HTMLElement | null)?.closest?.('.asset-image');
          const assetId = el?.querySelector('img')?.getAttribute('data-asset-id')
            ?? (el instanceof HTMLElement ? el.getAttribute('data-asset-id') : null);
          const idFromImg = (event.target as HTMLElement | null)?.closest?.('img')?.getAttribute('data-asset-id');
          const id = assetId || idFromImg;
          if (!id) return false;
          event.preventDefault();
          const host = (event.target as HTMLElement | null)?.closest?.('.pm-image');
          menuTarget = host instanceof HTMLElement ? { view, host } : null;
          useAppStore.getState().setImageMenu({ x: event.clientX, y: event.clientY, assetId: id });
          return true;
        },
      },
    },
  }),
);

/** All asset ids referenced by `asset_image` nodes in a document (cached per immutable doc). */
const idsCache = new WeakMap<ProseNode, Set<string>>();
export function collectAssetImageIds(doc: ProseNode): Set<string> {
  const hit = idsCache.get(doc);
  if (hit) return hit;
  const ids = new Set<string>();
  doc.descendants((n) => {
    if (n.type.name === 'asset_image' && n.attrs.assetId) ids.add(n.attrs.assetId as string);
    // An asset_image is a block atom; nothing inside inline content can hold one.
    return !n.isTextblock;
  });
  idsCache.set(doc, ids);
  return ids;
}

function rangeHasAssetImage(doc: ProseNode, from: number, to: number): boolean {
  let found = false;
  const lo = Math.max(0, Math.min(from, doc.content.size));
  const hi = Math.max(lo, Math.min(to, doc.content.size));
  if (lo === hi) return false;
  doc.nodesBetween(lo, hi, (n) => {
    if (found) return false;
    if (n.type.name === 'asset_image') { found = true; return false; }
    return !n.isTextblock;
  });
  return found;
}

/**
 * True when some step of these transactions replaced a range that held, or
 * now holds, an asset_image. Typing a character touches only its own range,
 * so the two whole-document walks below run only when an image could have
 * come or gone (and for y-prosemirror's whole-document remote replaces).
 */
export function stepsTouchAssetImages(trs: readonly Transaction[]): boolean {
  for (const tr of trs) {
    for (let i = 0; i < tr.steps.length; i++) {
      const before = tr.docs[i]!;
      const after = i + 1 < tr.docs.length ? tr.docs[i + 1]! : tr.doc;
      let hit = false;
      tr.steps[i]!.getMap().forEach((oldStart, oldEnd, newStart, newEnd) => {
        if (hit) return;
        hit = rangeHasAssetImage(before, oldStart, oldEnd) || rangeHasAssetImage(after, newStart, newEnd);
      });
      if (hit) return true;
    }
  }
  return false;
}

/**
 * A removed image is retired only after this long, and only if no insert of
 * the same asset came in meanwhile: a cut and paste, or a drag into a note
 * in the other pane, is a removal followed by an insert, and must never
 * flip the asset to retired.
 */
export const RETIRE_DELAY_MS = 10_000;
const pendingRetire = new Map<string, ReturnType<typeof setTimeout>>();

/**
 * Checked when the timer fires: an asset can sit in several notes and in the
 * report (Copy link, invariant 35), so leaving one doc is not enough to retire it.
 */
function assetStillReferenced(id: string): boolean {
  const st = useAppStore.getState();
  const wsId = st.activeWorkspaceId;
  for (const p of st.pages ?? []) {
    if (p.workspaceId === wsId && typeof p.content === 'string' && p.content.includes(`asset:${id}`)) return true;
  }
  const asset = st.typstAssets?.find((a) => a.id === id);
  if (!asset || !wsId) return false;
  const report = getSharedDoc().texts.get(textKey('typst', wsId, 'source'));
  return !!report && report.toString().includes(`${ASSET_DIR}/${asset.filename}`);
}

function scheduleRetire(id: string): void {
  if (pendingRetire.has(id)) return;
  pendingRetire.set(id, setTimeout(() => {
    pendingRetire.delete(id);
    if (assetStillReferenced(id)) return;
    void useAppStore.getState().retireTypstAsset(id).catch(() => undefined);
  }, RETIRE_DELAY_MS));
}

function cancelRetire(id: string): void {
  const t = pendingRetire.get(id);
  if (t === undefined) return;
  clearTimeout(t);
  pendingRetire.delete(id);
}

/** Test hook: is a retire queued for this asset? */
export function retirePending(id: string): boolean {
  return pendingRetire.has(id);
}

/**
 * A remote transaction from y-prosemirror (another client's edit) carries
 * `isChangeOrigin`; an undo or redo carries it too but is this user's own
 * action, so it counts as local.
 */
function isLocal(tr: Transaction): boolean {
  const meta = tr.getMeta(ySyncPluginKey) as { isChangeOrigin?: boolean; isUndoRedoOperation?: boolean } | undefined;
  return !meta?.isChangeOrigin || !!meta.isUndoRedoOperation;
}

/**
 * When an `asset_image` node is removed from a note (and no other image in the
 * same note still references that asset), RETIRE the underlying asset: it is
 * hidden from the Assets Manager but its bytes are kept, so any page-history
 * version still shows it. The retention job (server/retention.mjs) permanently
 * deletes retired assets once they are past the admin's retention window.
 *
 * The retire waits `RETIRE_DELAY_MS` and is cancelled by a re-insert, and it
 * runs only on the client that removed the image (one writer, not one per
 * open editor). An inserted image whose asset is retired, local or remote (a
 * paste after the delay, a version restore, a teammate's undo), is
 * un-retired, so retention never deletes the bytes of an image in use.
 */
export function trackAssetImageChanges(trs: readonly Transaction[], oldState: EditorState, newState: EditorState): void {
  if (!trs.some((t) => t.docChanged)) return;
  if (!stepsTouchAssetImages(trs)) return;
  const before = collectAssetImageIds(oldState.doc);
  const after = collectAssetImageIds(newState.doc);
  const local = trs.some(isLocal);
  for (const id of before) {
    if (!after.has(id) && local) scheduleRetire(id);
  }
  for (const id of after) {
    if (before.has(id)) continue;
    cancelRetire(id);
    queueMicrotask(() => { void useAppStore.getState().unretireTypstAsset(id).catch(() => undefined); });
  }
}

export const noteImageCleanupPlugin = $prose(() =>
  new Plugin({
    appendTransaction(trs, oldState, newState) {
      trackAssetImageChanges(trs, oldState, newState);
      return null;
    },
  }),
);

/** Open the crop/blur editor for a note image's asset. */
export function openAssetImageEditor(assetId: string): void {
  useAppStore.getState().setImageMenu(null);
  useAppStore.getState().setEditingAssetId(assetId);
}

/**
 * If the active note editor has an `asset_image` selected, open its blur/crop
 * editor. Returns true when it acted (so a keybind can preventDefault).
 */
export function blurSelectedImage(): boolean {
  const editor = getActiveMilkdownEditor();
  if (!editor) return false;
  let assetId: string | null = null;
  try {
    editor.action((ctx) => {
      const view = ctx.get(editorViewCtx);
      const sel = view.state.selection;
      if (sel instanceof NodeSelection && sel.node.type.name === 'asset_image') {
        assetId = sel.node.attrs.assetId as string;
      }
    });
  } catch {
    return false;
  }
  if (!assetId) return false;
  openAssetImageEditor(assetId);
  return true;
}
