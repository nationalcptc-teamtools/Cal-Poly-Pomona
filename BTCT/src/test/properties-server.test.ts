// Property-based tests for the server's pure helpers, read through their
// .d.mts declarations. numRuns stays small so the file runs in well under 3 s.
import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import * as Y from 'yjs';
import {
  backupName,
  backupNameTime,
  isBackupName,
  normalizeKeepLast,
  KEEP_LAST_MAX,
  parseBackupEntryName,
} from '../../server/backup-format.mjs';
import { mergeUpdatesBounded } from '../../server/relay-persistence.mjs';

const RUNS = { numRuns: 150 };

const baseName = fc
  .tuple(
    fc.date({ min: new Date('2000-01-01T00:00:00Z'), max: new Date('2099-12-31T23:59:59Z'), noInvalidDate: true }),
    fc.option(fc.stringMatching(/^[a-z0-9]{1,6}$/), { nil: null }),
  )
  .map(([d, sfx]) => backupName(d) + (sfx ? `-${sfx}` : ''));

describe('parseBackupEntryName', () => {
  it('round-trips every composed entry name', () => {
    fc.assert(
      fc.property(baseName, fc.constantFrom('dir', 'zip'), fc.boolean(), (base, kind, partial) => {
        const name = base + (kind === 'zip' ? '.zip' : '') + (partial ? '.tmp' : '');
        expect(parseBackupEntryName(name)).toEqual({ base, kind, partial });
      }),
      RUNS,
    );
  });

  it('never throws and only accepts names whose base is a plain backup name', () => {
    fc.assert(
      fc.property(fc.oneof(fc.string(), fc.anything()), (raw) => {
        const p = parseBackupEntryName(raw);
        if (p) {
          expect(isBackupName(p.base)).toBe(true);
          expect(p.base).not.toMatch(/[/\\]/);
        }
      }),
      RUNS,
    );
  });

  it('rejects path-ish suffixes and prefixes added to a valid name', () => {
    fc.assert(
      fc.property(baseName, fc.constantFrom('/', '\\', '../', '.', ' ', '\n'), fc.boolean(), (base, junk, front) => {
        const name = front ? junk + base : base + junk;
        expect(parseBackupEntryName(name)).toBeNull();
      }),
      RUNS,
    );
  });
});

describe('backup name time', () => {
  it('backupNameTime recovers the second a name was made for', () => {
    fc.assert(
      fc.property(fc.date({ min: new Date('2000-01-01'), max: new Date('2099-12-31'), noInvalidDate: true }), (d) => {
        expect(backupNameTime(backupName(d))).toBe(Math.floor(d.getTime() / 1000) * 1000);
      }),
      RUNS,
    );
  });
});

describe('normalizeKeepLast (clamp)', () => {
  it('always yields an integer in 0..KEEP_LAST_MAX', () => {
    fc.assert(
      fc.property(fc.oneof(fc.double({ noNaN: false }), fc.string(), fc.constant(null), fc.constant(undefined)), (v) => {
        const n = normalizeKeepLast(v);
        expect(Number.isInteger(n)).toBe(true);
        expect(n).toBeGreaterThanOrEqual(0);
        expect(n).toBeLessThanOrEqual(KEEP_LAST_MAX);
      }),
      RUNS,
    );
  });

  it('is the identity on integers already in range', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: KEEP_LAST_MAX }), (n) => {
        expect(normalizeKeepLast(n)).toBe(n);
      }),
      RUNS,
    );
  });
});

describe('mergeUpdatesBounded', () => {
  /** A list of updates produced by random edits on one doc. */
  const edits = fc.array(
    fc.record({ at: fc.nat(40), del: fc.nat(5), ins: fc.string({ maxLength: 8 }) }),
    { minLength: 0, maxLength: 40 },
  );

  it('applies to the same document as Y.mergeUpdates, for any group size', () => {
    fc.assert(
      fc.property(edits, fc.integer({ min: 2, max: 8 }), (ops, group) => {
        const doc = new Y.Doc();
        const updates: Uint8Array[] = [];
        doc.on('update', (u: Uint8Array) => updates.push(u));
        const t = doc.getText('t');
        for (const op of ops) {
          const at = Math.min(op.at, t.length);
          doc.transact(() => {
            if (op.del) t.delete(at, Math.min(op.del, t.length - at));
            if (op.ins) t.insert(at, op.ins);
          });
        }
        const bounded = mergeUpdatesBounded(Y, updates, group);
        if (updates.length === 0) {
          expect(bounded).toBeNull();
          return;
        }
        const a = new Y.Doc();
        const b = new Y.Doc();
        Y.applyUpdate(a, bounded!);
        Y.applyUpdate(b, Y.mergeUpdates(updates));
        expect(a.getText('t').toString()).toBe(t.toString());
        expect(a.getText('t').toString()).toBe(b.getText('t').toString());
        expect(Y.encodeStateVector(a)).toEqual(Y.encodeStateVector(b));
      }),
      RUNS,
    );
  });

  it('merges updates delivered in a shuffled order to the same text', () => {
    fc.assert(
      fc.property(edits, fc.integer({ min: 2, max: 6 }), fc.infiniteStream(fc.nat()), (ops, group, rnd) => {
        const doc = new Y.Doc();
        const updates: Uint8Array[] = [];
        doc.on('update', (u: Uint8Array) => updates.push(u));
        const t = doc.getText('t');
        for (const op of ops) t.insert(Math.min(op.at, t.length), op.ins || 'x');
        const it = rnd[Symbol.iterator]();
        const shuffled = updates
          .map((u) => ({ u, k: it.next().value as number }))
          .sort((x, y) => x.k - y.k)
          .map((x) => x.u);
        if (shuffled.length === 0) return;
        const a = new Y.Doc();
        Y.applyUpdate(a, mergeUpdatesBounded(Y, shuffled, group)!);
        expect(a.getText('t').toString()).toBe(t.toString());
      }),
      RUNS,
    );
  });
});
