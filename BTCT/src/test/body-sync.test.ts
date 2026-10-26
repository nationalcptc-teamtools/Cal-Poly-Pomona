import { describe, expect, it } from 'vitest';
import * as Y from 'yjs';
import { readPageBodies, writePageBodies, type PageBodyIO } from '@/export/body-sync';
import { base64ToBytes, bodyIsEmpty } from '@/export/page-body-codec';

function full(text: string): Uint8Array {
  const doc = new Y.Doc();
  const p = new Y.XmlElement('paragraph');
  p.insert(0, [new Y.XmlText(text)]);
  doc.getXmlFragment('prosemirror').insert(0, [p]);
  return Y.encodeStateAsUpdate(doc);
}
const EMPTY = Y.encodeStateAsUpdate(new Y.Doc());

function io(over: Partial<PageBodyIO>): PageBodyIO {
  return {
    readFromServer: async () => EMPTY,
    readLocal: async () => null,
    write: async () => true,
    ...over,
  };
}

describe('readPageBodies', () => {
  it('re-reads an empty body whose markdown is not empty, and takes the second answer', async () => {
    const calls: string[] = [];
    let n = 0;
    const result = await readPageBodies([{ id: 'p1', content: 'hello' }], io({
      readFromServer: async (id) => { calls.push(id); return ++n === 1 ? EMPTY : full('hello'); },
    }), { retryDelayMs: 0 });
    expect(calls).toEqual(['p1', 'p1']);
    expect(result.incomplete).toEqual([]);
    expect(bodyIsEmpty(base64ToBytes(result.updates.p1!))).toBe(false);
  });

  it('lists a body that stays empty as possibly incomplete, and an empty page as fine', async () => {
    const result = await readPageBodies(
      [{ id: 'has-text', content: 'notes' }, { id: 'blank', content: '' }],
      io({}),
      { retryDelayMs: 0 },
    );
    expect(result.incomplete.map((i) => i.pageId)).toEqual(['has-text']);
    expect(Object.keys(result.updates).sort()).toEqual(['blank', 'has-text']);
  });

  it('falls back to the offline copy when the server does not answer, and says so', async () => {
    const result = await readPageBodies(
      [{ id: 'a', content: 'x' }, { id: 'b', content: 'y' }],
      io({ readFromServer: async () => null, readLocal: async (id) => (id === 'a' ? full('cached') : null) }),
      { retryDelayMs: 0 },
    );
    expect(Object.keys(result.updates)).toEqual(['a']);
    expect(result.incomplete.map((i) => i.pageId).sort()).toEqual(['a', 'b']);
    expect(result.incomplete.find((i) => i.pageId === 'b')!.reason).toMatch(/only the markdown/);
  });

  it('never runs more than four reads at once', async () => {
    let live = 0;
    let peak = 0;
    await readPageBodies(Array.from({ length: 20 }, (_, i) => ({ id: `p${i}`, content: '' })), io({
      readFromServer: async () => { live++; peak = Math.max(peak, live); await new Promise((r) => setTimeout(r, 2)); live--; return EMPTY; },
    }));
    expect(peak).toBe(4);
  });
});

describe('writePageBodies', () => {
  it('reports bodies the server did not confirm and ones that threw', async () => {
    const out = await writePageBodies(
      [{ pageId: 'ok', update: full('a') }, { pageId: 'slow', update: full('b') }, { pageId: 'bad', update: full('c') }],
      io({ write: async (id) => { if (id === 'bad') throw new Error('boom'); return id === 'ok'; } }),
    );
    expect(out.unconfirmed).toEqual(['slow']);
    expect(out.failed).toEqual([{ pageId: 'bad', error: 'boom' }]);
  });
});
