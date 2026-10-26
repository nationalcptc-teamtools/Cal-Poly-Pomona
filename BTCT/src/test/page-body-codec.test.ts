import { describe, expect, it } from 'vitest';
import * as Y from 'yjs';
import {
  assetIdsInUpdate, base64ToBytes, bodyIsEmpty, bytesToBase64, remapAssetIdsInUpdate, stateVectorCovers,
} from '@/export/page-body-codec';

function body(build: (frag: Y.XmlFragment) => void): Uint8Array {
  const doc = new Y.Doc();
  build(doc.getXmlFragment('prosemirror'));
  return Y.encodeStateAsUpdate(doc);
}

function image(id: string): Y.XmlElement {
  const el = new Y.XmlElement('asset_image');
  el.setAttribute('assetId', id);
  return el;
}

function idsIn(update: Uint8Array): string[] {
  const doc = new Y.Doc();
  Y.applyUpdate(doc, update);
  const out: string[] = [];
  for (const n of doc.getXmlFragment('prosemirror').createTreeWalker((x) => x instanceof Y.XmlElement && x.nodeName === 'asset_image')) {
    out.push((n as Y.XmlElement).getAttribute('assetId') as string);
  }
  return out;
}

describe('page body codec', () => {
  it('tells an empty body from one with blocks', () => {
    expect(bodyIsEmpty(Y.encodeStateAsUpdate(new Y.Doc()))).toBe(true);
    expect(bodyIsEmpty(body((f) => { const p = new Y.XmlElement('paragraph'); p.insert(0, [new Y.XmlText('hi')]); f.insert(0, [p]); }))).toBe(false);
  });

  it('finds asset_image ids nested in lists and quotes', () => {
    const u = body((f) => {
      const list = new Y.XmlElement('bullet_list');
      const item = new Y.XmlElement('list_item');
      item.insert(0, [image('a')]);
      list.insert(0, [item]);
      f.insert(0, [image('b'), list, image('b')]);
    });
    expect(assetIdsInUpdate(u)).toEqual(['b', 'a']);
  });

  it('remaps mapped ids, leaves the rest, and the result merges into the original room', () => {
    const original = body((f) => f.insert(0, [image('old-1'), image('keep'), image('old-2')]));
    const out = remapAssetIdsInUpdate(original, new Map([['old-1', 'new-1'], ['old-2', 'new-2']]));
    expect(idsIn(out)).toEqual(['new-1', 'keep', 'new-2']);
    const room = new Y.Doc();
    Y.applyUpdate(room, original);
    Y.applyUpdate(room, out);
    expect(room.getXmlFragment('prosemirror').length).toBe(3);
  });

  it('returns the same bytes for an identity map or no match', () => {
    const u = body((f) => f.insert(0, [image('x')]));
    expect(remapAssetIdsInUpdate(u, new Map([['x', 'x']]))).toBe(u);
    expect(remapAssetIdsInUpdate(u, new Map([['y', 'z']]))).toBe(u);
  });

  it('compares state vectors', () => {
    const doc = new Y.Doc();
    doc.getText('t').insert(0, 'abc');
    const want = Y.encodeStateVectorFromUpdate(Y.encodeStateAsUpdate(doc));
    expect(stateVectorCovers(Y.encodeStateVector(new Y.Doc()), want)).toBe(false);
    const server = new Y.Doc();
    Y.applyUpdate(server, Y.encodeStateAsUpdate(doc));
    expect(stateVectorCovers(Y.encodeStateVector(server), want)).toBe(true);
  });

  it('round-trips base64', () => {
    const bytes = new Uint8Array(40_000).map((_, i) => i % 251);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });
});
