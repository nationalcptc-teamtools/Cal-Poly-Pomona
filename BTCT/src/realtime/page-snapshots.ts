/**
 * Restoring a page body to an earlier version.
 *
 * Versions themselves are recorded on the server (server/history.mjs) from a
 * GC-off twin of each page room; the client fetches a version's full state
 * through src/realtime/page-history-api.ts and hands the bytes here.
 *
 * Two paths, best first:
 *   1. The page is open in a tab: the restored document is built with the
 *      live editor's schema and applied as ONE ProseMirror transaction. The
 *      y-prosemirror binding diffs it against the fragment and emits a
 *      minimal Yjs delta, so unchanged blocks stay untouched and remote
 *      cursors survive (invariant #3b).
 *   2. No editor for that page is mounted: the snapshot is decoded into a
 *      throwaway Y.Doc and its `prosemirror` fragment children are cloned
 *      into the live fragment inside one Y transaction, which still merges
 *      deterministically for every peer.
 *
 * Either way the caller records a `restore` version afterwards so the
 * rollback is part of the timeline and later versions are kept.
 */
import * as Y from 'yjs';
import { yXmlFragmentToProseMirrorRootNode } from 'y-prosemirror';
import { editorViewCtx } from '@milkdown/core';
import { getPageEditor } from '@/lib/active-editor';
import { getPageYContext, whenServerSynced } from './yjs-providers';

const FRAGMENT = 'prosemirror';

/**
 * Wait for the page's provider to really sync, then restore. Never acts on a
 * doc that has only passed the 3 s fallback of `whenFullySynced`: there the
 * fragment can still be empty, the replacement would land beside the stored
 * body when it arrives, and the page would hold both.
 */
export async function restorePageVersion(pageId: string, bytes: Uint8Array, timeoutMs?: number): Promise<'editor' | 'yjs'> {
  await whenServerSynced(getPageYContext(pageId), timeoutMs);
  return restoreFromState(pageId, bytes);
}

export function restoreFromState(pageId: string, bytes: Uint8Array): 'editor' | 'yjs' {
  if (!getPageYContext(pageId).provider.synced) {
    throw new Error('the page has not synced with the server yet');
  }
  const editor = getPageEditor(pageId);
  if (editor) {
    try {
      let applied = false;
      editor.action((ctx) => {
        const view = ctx.get(editorViewCtx);
        const tmp = new Y.Doc();
        Y.applyUpdate(tmp, bytes);
        const node = yXmlFragmentToProseMirrorRootNode(tmp.getXmlFragment(FRAGMENT), view.state.schema);
        tmp.destroy();
        view.dispatch(view.state.tr.replaceWith(0, view.state.doc.content.size, node.content));
        applied = true;
      });
      if (applied) return 'editor';
    } catch (err) {
      if (import.meta.env.DEV) console.warn('[history] editor restore failed, using the Yjs path:', err);
    }
  }
  replaceFragment(pageId, bytes);
  return 'yjs';
}

function replaceFragment(pageId: string, bytes: Uint8Array): void {
  const liveDoc = getPageYContext(pageId).doc;
  const liveFragment = liveDoc.getXmlFragment(FRAGMENT);

  const tmpDoc = new Y.Doc();
  Y.applyUpdate(tmpDoc, bytes);
  // Y.XmlElement / Y.XmlText expose .clone(); a type cannot be shared across
  // docs, so clone unconditionally before touching the live fragment.
  const replacement = tmpDoc
    .getXmlFragment(FRAGMENT)
    .toArray()
    .map((child) => (child as Y.XmlElement | Y.XmlText).clone());

  liveDoc.transact(() => {
    if (liveFragment.length > 0) liveFragment.delete(0, liveFragment.length);
    if (replacement.length > 0) liveFragment.insert(0, replacement);
  });
  tmpDoc.destroy();
}

