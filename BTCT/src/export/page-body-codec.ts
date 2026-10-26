import * as Y from 'yjs';

// ─────────────────────────────────────────────────────────────────────────
// Pure helpers over a page body's Yjs update (the `prosemirror` fragment the
// note editor binds to). No network, no IndexedDB: unit-tested in
// src/test/page-body-codec.test.ts.
// ─────────────────────────────────────────────────────────────────────────

/** The fragment name y-prosemirror (Milkdown's collab plugin) writes a page body into. */
export const BODY_FRAGMENT = 'prosemirror';

function docFrom(update: Uint8Array): Y.Doc {
  const doc = new Y.Doc({ gc: false });
  Y.applyUpdate(doc, update);
  return doc;
}

/** True when the update holds no body at all (no block in the fragment). */
export function bodyIsEmpty(update: Uint8Array): boolean {
  if (update.byteLength <= 2) return true;
  const doc = docFrom(update);
  try { return doc.getXmlFragment(BODY_FRAGMENT).length === 0; }
  finally { doc.destroy(); }
}

function* assetImages(doc: Y.Doc): Generator<Y.XmlElement> {
  const walker = doc.getXmlFragment(BODY_FRAGMENT).createTreeWalker(
    (n) => n instanceof Y.XmlElement && n.nodeName === 'asset_image',
  );
  for (const node of walker) yield node as Y.XmlElement;
}

/** Asset ids of every `asset_image` node in the body, in document order, deduplicated. */
export function assetIdsInUpdate(update: Uint8Array): string[] {
  if (update.byteLength <= 2) return [];
  const doc = docFrom(update);
  try {
    const seen = new Set<string>();
    for (const el of assetImages(doc)) {
      const id = el.getAttribute('assetId');
      if (typeof id === 'string' && id) seen.add(id.toLowerCase());
    }
    return [...seen];
  } finally {
    doc.destroy();
  }
}

/**
 * Point every `asset_image` whose id is in `map` at its new id. Returns the
 * input unchanged when nothing maps to a different id. Applies the update to
 * a scratch doc and re-encodes it, so the result is a superset of the input
 * (the same items plus the attribute changes) and merges cleanly into a room
 * that already has the original.
 */
export function remapAssetIdsInUpdate(update: Uint8Array, map: ReadonlyMap<string, string>): Uint8Array {
  if (!map.size || update.byteLength <= 2) return update;
  if (![...map].some(([from, to]) => from !== to)) return update;
  const doc = docFrom(update);
  try {
    let changed = false;
    doc.transact(() => {
      for (const el of assetImages(doc)) {
        const id = el.getAttribute('assetId');
        if (typeof id !== 'string') continue;
        const next = map.get(id) ?? map.get(id.toLowerCase());
        if (next && next !== id) { el.setAttribute('assetId', next); changed = true; }
      }
    });
    return changed ? Y.encodeStateAsUpdate(doc) : update;
  } finally {
    doc.destroy();
  }
}

/** True when every client clock in `want` is at or below the one in `have`. */
export function stateVectorCovers(have: Uint8Array, want: Uint8Array): boolean {
  const h = Y.decodeStateVector(have);
  for (const [client, clock] of Y.decodeStateVector(want)) {
    if ((h.get(client) ?? 0) < clock) return false;
  }
  return true;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.byteLength; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
