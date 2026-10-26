/**
 * Seeding an empty page body from its record's markdown, in a way two
 * clients can do at the same moment without doubling the page.
 *
 * Milkdown's `applyTemplate` writes the template through a fresh Y.Doc with
 * a random client id. When two operators open a page whose room is empty
 * (an imported page nobody has opened yet) within one round trip, both see
 * an empty fragment after a real sync, both seed, and Yjs keeps both copies.
 *
 * Here the template is written by a client id derived from the page id and
 * the markdown itself. Two clients seeding the same text produce the same
 * Yjs items with the same ids, so the second copy is recognised as already
 * integrated and dropped: the body appears once. Two clients seeding
 * different text get different ids and behave as before (no worse), and a
 * doc that already carries the derived id (the page was seeded, then
 * emptied) falls back to a random id so the seed is not silently ignored.
 */
import * as Y from 'yjs';
import { prosemirrorToYXmlFragment } from 'y-prosemirror';
import type { Node as ProseNode } from '@milkdown/prose/model';

export const PAGE_FRAGMENT = 'prosemirror';

/** FNV-1a over the page id and the markdown, folded into a non-zero uint32. */
export function seedClientId(pageId: string, markdown: string): number {
  let h = 0x811c9dc5;
  const input = `btct-seed\u0000${pageId}\u0000${markdown}`;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h === 0 ? 1 : h;
}

/** The Yjs update that writes `node` into an empty fragment as `clientId`. */
export function buildSeedUpdate(node: ProseNode, clientId: number): Uint8Array {
  const tmp = new Y.Doc();
  tmp.clientID = clientId;
  prosemirrorToYXmlFragment(node, tmp.getXmlFragment(PAGE_FRAGMENT));
  const update = Y.encodeStateAsUpdate(tmp);
  tmp.destroy();
  return update;
}

/**
 * Seed `doc`'s page fragment with `node` (parsed from `markdown`) if, and
 * only if, the fragment is empty. Returns true when it wrote.
 */
export function seedPageFragment(doc: Y.Doc, node: ProseNode, pageId: string, markdown: string): boolean {
  const fragment = doc.getXmlFragment(PAGE_FRAGMENT);
  if (fragment.length > 0) return false;
  let clientId = seedClientId(pageId, markdown);
  if (doc.store.clients.has(clientId)) {
    // Seeded once already and since emptied: the derived ids are taken, so
    // the same update would be ignored. Use a fresh id instead.
    clientId = ((Math.random() * 0xffffffff) >>> 0) || 1;
  }
  Y.applyUpdate(doc, buildSeedUpdate(node, clientId));
  return true;
}
