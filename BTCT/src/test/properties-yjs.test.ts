// Property tests for the Y.Text rewrite helpers (invariant 3b): whatever the
// current and target strings, the final text is the target.
import { describe, it, expect, vi } from 'vitest';
import * as Y from 'yjs';
import fc from 'fast-check';

vi.mock('@/realtime/shared-doc', () => ({
  getSharedDoc: () => null,
  sharedTransact: (fn: () => void) => fn(),
}));

import { replaceYTextContent, updateYTextContent } from '@/realtime/use-y-text';

const RUNS = { numRuns: 200 };
// BMP text only; the astral case is its own test below.
const text = fc.oneof(fc.string({ maxLength: 40 }), fc.string({ unit: 'grapheme', maxLength: 20 }).map((s) => s.replace(/[\ud800-\udfff]/g, '')));
const astral = fc.string({ unit: 'binary', maxLength: 20 });

function make(s: string): Y.Text {
  const doc = new Y.Doc();
  const t = doc.getText('t');
  if (s) t.insert(0, s);
  return t;
}

describe('replaceYTextContent', () => {
  it('leaves exactly the target text', () => {
    fc.assert(
      fc.property(text, text, (from, to) => {
        const t = make(from);
        replaceYTextContent(t, to);
        expect(t.toString()).toBe(to);
      }),
      RUNS,
    );
  });

  // Regression: diff() used to trim by UTF-16 unit, so two astral chars sharing a high
  // surrogate ("\u{1F600}" -> "\u{1F601}", U+10FC00 -> U+10FC01) split the pair into U+FFFD.
  it('leaves exactly the target text for astral characters (surrogate pairs stay whole)', () => {
    fc.assert(
      fc.property(astral, astral, (from, to) => {
        const t = make(from);
        replaceYTextContent(t, to);
        expect(t.toString()).toBe(to);
      }),
      RUNS,
    );
  });

  it('never deletes more than the changed middle span', () => {
    fc.assert(
      fc.property(text, text, text, (pre, mid, suf) => {
        const doc = new Y.Doc();
        const t = doc.getText('t');
        t.insert(0, pre + 'A' + suf);
        let deleted = 0;
        t.observe((ev) => {
          for (const op of ev.delta) if (typeof op.delete === 'number') deleted += op.delete;
        });
        replaceYTextContent(t, pre + mid + suf);
        expect(t.toString()).toBe(pre + mid + suf);
        expect(deleted).toBeLessThanOrEqual(1);
      }),
      RUNS,
    );
  });

  it('converges a peer that only receives the update', () => {
    fc.assert(
      fc.property(text, text, (from, to) => {
        const t = make(from);
        const peer = new Y.Doc();
        Y.applyUpdate(peer, Y.encodeStateAsUpdate(t.doc!));
        t.doc!.on('update', (u: Uint8Array) => Y.applyUpdate(peer, u));
        replaceYTextContent(t, to);
        expect(peer.getText('t').toString()).toBe(to);
      }),
      RUNS,
    );
  });
});

describe('updateYTextContent', () => {
  it('feeds compute the live text and ends on its result', () => {
    fc.assert(
      fc.property(text, text, (from, add) => {
        const t = make(from);
        let seen: string | null = null;
        updateYTextContent(t, (cur) => {
          seen = cur;
          return cur + add;
        });
        expect(seen).toBe(from);
        expect(t.toString()).toBe(from + add);
      }),
      RUNS,
    );
  });
});
