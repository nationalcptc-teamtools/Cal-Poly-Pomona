// Property tests: pane-layout tree ops keep every leaf and tab consistent, and
// finding fields survive an encode/decode round trip.
import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import type { PaneNode, DropPosition } from '@/types';
import {
  allLeaves,
  collapse,
  createLeaf,
  findLeaf,
  findLeafContainingTab,
  moveTab,
  removeTab,
  splitLeaf,
  updateRatio,
  moveWithin,
} from '@/lib/pane-layout';
import {
  blankFinding,
  contentIsBalanced,
  decodeField,
  encodeField,
  findFindings,
  readFindingFields,
  serializeFinding,
  STATUSES,
  SEVERITIES,
  type ScopeRow,
} from '@/lib/typst-findings';
import { emptyValue } from '@/lib/typst-finding-schema';

const RUNS = { numRuns: 120 };

// ── pane layout ─────────────────────────────────────────────────────────

/** Build a tree by splitting random leaves; every tab id is unique. */
const layoutOps = fc.array(
  fc.record({
    target: fc.nat(),
    dir: fc.constantFrom('horizontal', 'vertical'),
    pos: fc.constantFrom('before', 'after'),
  }),
  { maxLength: 6 },
);

function build(ops: { target: number; dir: 'horizontal' | 'vertical'; pos: 'before' | 'after' }[]): { root: PaneNode; tabs: string[] } {
  let n = 0;
  const first = `t${n++}`;
  let root: PaneNode = createLeaf([first], first);
  const tabs = [first];
  for (const op of ops) {
    const leaves = allLeaves(root);
    const tab = `t${n++}`;
    tabs.push(tab);
    root = splitLeaf(root, leaves[op.target % leaves.length]!.id, op.dir, tab, op.pos);
  }
  return { root, tabs };
}

/** Every leaf's active tab is null (empty leaf) or one of its own tabs. */
function activeIsLive(root: PaneNode): boolean {
  return allLeaves(root).every((l) => (l.activeTabId === null ? true : l.tabIds.includes(l.activeTabId)));
}

const positions = fc.constantFrom<DropPosition>('center', 'left', 'right', 'top', 'bottom');

describe('pane-layout', () => {
  it('moveTab keeps each tab in exactly one leaf and every active tab live', () => {
    fc.assert(
      fc.property(layoutOps, fc.nat(), fc.nat(), positions, (ops, a, b, pos) => {
        const { root, tabs } = build(ops);
        const tab = tabs[a % tabs.length]!;
        const target = allLeaves(root)[b % allLeaves(root).length]!;
        const out = moveTab(root, tab, target.id, pos);
        const seen = allLeaves(out).flatMap((l) => l.tabIds);
        expect([...seen].sort()).toEqual([...tabs].sort());
        expect(activeIsLive(out)).toBe(true);
        expect(findLeafContainingTab(out, tab)).not.toBeNull();
        // No empty leaf survives a split tree.
        if (allLeaves(out).length > 1) expect(allLeaves(out).every((l) => l.tabIds.length > 0)).toBe(true);
      }),
      RUNS,
    );
  });

  it('removeTab then collapse keeps the remaining tabs and a live active tab', () => {
    fc.assert(
      fc.property(layoutOps, fc.nat(), (ops, a) => {
        const { root, tabs } = build(ops);
        const tab = tabs[a % tabs.length]!;
        const out = collapse(removeTab(root, tab));
        const seen = allLeaves(out).flatMap((l) => l.tabIds);
        expect([...seen].sort()).toEqual(tabs.filter((t) => t !== tab).sort());
        expect(activeIsLive(out)).toBe(true);
        expect(allLeaves(out).length).toBeGreaterThanOrEqual(1);
      }),
      RUNS,
    );
  });

  it('moveTab onto an unknown pane is a no-op', () => {
    fc.assert(
      fc.property(layoutOps, fc.nat(), positions, (ops, a, pos) => {
        const { root, tabs } = build(ops);
        expect(moveTab(root, tabs[a % tabs.length]!, 'no-such-pane', pos)).toBe(root);
        expect(findLeaf(root, 'no-such-pane')).toBeNull();
      }),
      RUNS,
    );
  });

  it('updateRatio keeps every split ratio in 0.15..0.85', () => {
    fc.assert(
      fc.property(layoutOps, fc.double({ min: -5, max: 5, noNaN: true }), (ops, r) => {
        let { root } = build(ops);
        const ids: string[] = [];
        (function walk(n: PaneNode) {
          if (n.type === 'split') { ids.push(n.id); walk(n.children[0]); walk(n.children[1]); }
        })(root);
        for (const id of ids) root = updateRatio(root, id, r);
        (function walk(n: PaneNode) {
          if (n.type === 'split') {
            expect(n.ratio).toBeGreaterThanOrEqual(0.15);
            expect(n.ratio).toBeLessThanOrEqual(0.85);
            walk(n.children[0]); walk(n.children[1]);
          }
        })(root);
      }),
      RUNS,
    );
  });

  it('moveWithin is a permutation of the list', () => {
    fc.assert(
      fc.property(fc.uniqueArray(fc.string({ minLength: 1, maxLength: 3 }), { maxLength: 10 }), fc.nat(), fc.nat(), fc.constantFrom('before', 'after'), (list, i, j, place) => {
        if (list.length === 0) return;
        const out = moveWithin(list, list[i % list.length]!, list[j % list.length]!, place, (x) => x);
        expect([...out].sort()).toEqual([...list].sort());
      }),
      RUNS,
    );
  });
});

// ── finding serialize / parse ──────────────────────────────────────────

const str = fc.string({ maxLength: 30 });
// Content is a Typst [..] block: brackets must balance, edges are trimmed on read.
const content = fc.string({ maxLength: 40 }).filter(contentIsBalanced).map((s) => s.replace(/\r/g, ''));
const scopeRows = fc.array(fc.tuple(str, str, str) as fc.Arbitrary<ScopeRow>, { maxLength: 3 });
const severity = fc.constantFrom(...SEVERITIES, null);

describe('finding fields', () => {
  it('string fields round-trip through encode/decode', () => {
    fc.assert(
      fc.property(str, (s) => {
        expect(decodeField(encodeField(s, 'string'), 'string').value).toBe(s);
      }),
      RUNS,
    );
  });

  it('string lists and scope tables round-trip', () => {
    fc.assert(
      fc.property(fc.array(str, { maxLength: 4 }), scopeRows, (items, rows) => {
        expect(decodeField(encodeField(items, 'strings'), 'strings').value).toEqual(items);
        expect(decodeField(encodeField(rows, 'scope'), 'scope').value).toEqual(rows);
      }),
      RUNS,
    );
  });

  it('content round-trips up to surrounding whitespace', () => {
    fc.assert(
      fc.property(content, (s) => {
        const back = decodeField(encodeField(s, 'content'), 'content').value as string;
        expect(back.replace(/\s+/g, ' ').trim()).toBe(s.replace(/\s+/g, ' ').trim());
      }),
      RUNS,
    );
  });

  it('a serialized block is found again with its id, status, severity and title', () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[a-z0-9]{4,8}$/),
        fc.constantFrom(...STATUSES),
        severity,
        str.filter((s) => s.trim() === s),
        scopeRows,
        content,
        fc.array(str, { maxLength: 3 }),
        (id, status, sev, title, scope, description, tactics) => {
          const src = serializeFinding({ severity: sev, title, scope, description, tactics }, { id, status });
          const found = findFindings(src);
          expect(found).toHaveLength(1);
          const f = found[0]!;
          expect(f.id).toBe(id);
          expect(f.tag).toBe(status);
          expect(f.severity).toBe(sev);
          expect(f.title).toBe(title);
          const fields = readFindingFields(src, f);
          expect(fields.title!.value).toBe(title);
          expect(fields.scope!.value).toEqual(scope);
          expect(fields.tactics!.value).toEqual(tactics);
          expect((fields.description!.value as string).replace(/\s+/g, ' ').trim()).toBe(description.replace(/\s+/g, ' ').trim());
        },
      ),
      RUNS,
    );
  });

  it('blank blocks concatenate into exactly as many findings, in order', () => {
    fc.assert(
      fc.property(fc.array(severity, { minLength: 1, maxLength: 5 }), (sevs) => {
        const src = sevs.map((s, i) => blankFinding(s, { id: `id${i}` })).join('\n\n');
        const found = findFindings(src);
        expect(found.map((f) => f.id)).toEqual(sevs.map((_, i) => `id${i}`));
        expect(found.map((f) => f.severity)).toEqual(sevs);
      }),
      RUNS,
    );
  });

  it('emptyValue encodes and decodes back to itself for every kind', () => {
    for (const kind of ['string', 'content', 'strings', 'contents', 'scope', 'bool'] as const) {
      const v = emptyValue(kind) as never;
      expect(decodeField(encodeField(v, kind), kind).value).toEqual(v);
    }
  });
});
