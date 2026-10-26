import { describe, expect, it } from 'vitest';
import * as Y from 'yjs';
import { Schema } from '@milkdown/prose/model';
import { PAGE_FRAGMENT, seedClientId, seedPageFragment } from '@/lib/page-seed';

// CLI-3: two clients that both find an empty room after a real sync (an
// imported page opened by two operators at once) must not double the body.
const schema = new Schema({
  nodes: {
    doc: { content: 'block+' },
    paragraph: { group: 'block', content: 'text*', toDOM: () => ['p', 0] },
    text: {},
  },
});
const body = (...paras: string[]) =>
  schema.node('doc', null, paras.map((t) => schema.node('paragraph', null, t ? [schema.text(t)] : [])));

function exchange(a: Y.Doc, b: Y.Doc) {
  const ua = Y.encodeStateAsUpdate(a, Y.encodeStateVector(b));
  const ub = Y.encodeStateAsUpdate(b, Y.encodeStateVector(a));
  Y.applyUpdate(b, ua);
  Y.applyUpdate(a, ub);
}
const paragraphs = (d: Y.Doc) => d.getXmlFragment(PAGE_FRAGMENT).length;

describe('seedPageFragment', () => {
  it('two clients seeding the same record text concurrently converge on one copy', () => {
    const md = 'one\n\ntwo\n\nthree';
    const a = new Y.Doc();
    const b = new Y.Doc();
    expect(seedPageFragment(a, body('one', 'two', 'three'), 'page-1', md)).toBe(true);
    expect(seedPageFragment(b, body('one', 'two', 'three'), 'page-1', md)).toBe(true);
    exchange(a, b);
    expect(paragraphs(a)).toBe(3);
    expect(paragraphs(b)).toBe(3);
    expect(a.getXmlFragment(PAGE_FRAGMENT).toString()).toBe(b.getXmlFragment(PAGE_FRAGMENT).toString());
  });

  it('applyTemplate-style random ids would have doubled it (control)', () => {
    const a = new Y.Doc();
    const b = new Y.Doc();
    // Same node, different client ids: what Milkdown's applyTemplate does.
    for (const d of [a, b]) {
      const tmp = new Y.Doc();
      const frag = tmp.getXmlFragment(PAGE_FRAGMENT);
      tmp.transact(() => {
        for (const t of ['one', 'two', 'three']) {
          const p = new Y.XmlElement('paragraph');
          p.insert(0, [new Y.XmlText(t)]);
          frag.push([p]);
        }
      });
      Y.applyUpdate(d, Y.encodeStateAsUpdate(tmp));
    }
    exchange(a, b);
    expect(paragraphs(a)).toBe(6);
  });

  it('never seeds a fragment that already has content', () => {
    const d = new Y.Doc();
    seedPageFragment(d, body('kept'), 'p', 'kept');
    expect(seedPageFragment(d, body('other'), 'p', 'other')).toBe(false);
    expect(paragraphs(d)).toBe(1);
  });

  it('different text gets a different id, and a re-seed after emptying still writes', () => {
    expect(seedClientId('p', 'a')).not.toBe(seedClientId('p', 'b'));
    expect(seedClientId('p', 'a')).not.toBe(seedClientId('q', 'a'));
    const d = new Y.Doc();
    seedPageFragment(d, body('x'), 'p', 'x');
    const frag = d.getXmlFragment(PAGE_FRAGMENT);
    frag.delete(0, frag.length);
    expect(seedPageFragment(d, body('x'), 'p', 'x')).toBe(true);
    expect(paragraphs(d)).toBe(1);
  });
});
