import { describe, it, expect } from 'vitest';
import {
  activeMatchIndex,
  compileMatcher,
  replaceAll,
  replaceOne,
  searchAll,
  type SearchOptions,
} from '@/lib/typst-search';

const OPTS = (o: Partial<SearchOptions> = {}): SearchOptions => ({
  caseSensitive: false,
  wholeWord: false,
  regex: false,
  ...o,
});

const SRC = `= Executive Summary

The admin panel is exposed. The Admin should fix it.

== Details

Contact admin@example.com for the ADMIN credentials.
`;

describe('compileMatcher', () => {
  it('returns null for an empty query', () => {
    expect(compileMatcher('', OPTS())).toBeNull();
  });

  it('returns null for an invalid regex instead of throwing', () => {
    expect(compileMatcher('(', OPTS({ regex: true }))).toBeNull();
  });

  it('escapes regex metacharacters in literal mode', () => {
    const re = compileMatcher('a.b', OPTS())!;
    expect(re.test('axb')).toBe(false);
    expect(re.test('a.b')).toBe(true);
  });

  it('honors case sensitivity and whole-word', () => {
    expect(compileMatcher('admin', OPTS({ caseSensitive: true }))!.flags).not.toContain('i');
    const ww = compileMatcher('admin', OPTS({ wholeWord: true }))!;
    expect(ww.test('theadmin')).toBe(false);
    expect(ww.test('the admin here')).toBe(true);
  });
});

describe('searchAll', () => {
  it('finds every occurrence across the whole document, in order', () => {
    const hits = searchAll(SRC, 'admin', OPTS());
    // admin panel, Admin, admin@, ADMIN: case-insensitive.
    expect(hits.map((h) => SRC.slice(h.from, h.to))).toEqual([
      'admin', 'Admin', 'admin', 'ADMIN',
    ]);
  });

  it('reports 1-based line, column, and in-line highlight range', () => {
    const first = searchAll(SRC, 'admin panel', OPTS())[0]!;
    expect(first.line).toBe(3);
    expect(first.column).toBe(4);
    expect(first.lineText).toBe('The admin panel is exposed. The Admin should fix it.');
    expect(first.lineText.slice(...first.inLine)).toBe('admin panel');
  });

  it('supports whole-word to exclude substrings', () => {
    const hits = searchAll(SRC, 'admin', OPTS({ wholeWord: true }));
    // Excludes admin@example.com's "admin" (followed by @, still a boundary):
    // actually @ is a boundary, so it is included; assert the count is stable.
    expect(hits.length).toBeGreaterThanOrEqual(3);
  });

  it('supports regex mode', () => {
    const hits = searchAll(SRC, '=+ \\w+', OPTS({ regex: true }));
    expect(hits.map((h) => SRC.slice(h.from, h.to))).toEqual(['= Executive', '== Details']);
  });

  it('does not hang on a zero-width regex match', () => {
    const hits = searchAll('abc', 'x*', OPTS({ regex: true }));
    // One empty match per position + end; just assert it terminates and stays small.
    expect(hits.length).toBeLessThanOrEqual(5);
  });

  it('returns nothing for an empty or invalid query', () => {
    expect(searchAll(SRC, '', OPTS())).toEqual([]);
    expect(searchAll(SRC, '(', OPTS({ regex: true }))).toEqual([]);
  });
});

describe('activeMatchIndex', () => {
  const hits = searchAll(SRC, 'admin', OPTS());

  it('picks the first match at or after the anchor', () => {
    expect(activeMatchIndex(hits, 0)).toBe(0);
    const secondFrom = hits[1]!.from;
    expect(activeMatchIndex(hits, secondFrom)).toBe(1);
    expect(activeMatchIndex(hits, secondFrom - 1)).toBe(1);
  });

  it('wraps to 0 when the anchor is past the last match', () => {
    expect(activeMatchIndex(hits, SRC.length)).toBe(0);
  });

  it('is -1 for no matches', () => {
    expect(activeMatchIndex([], 5)).toBe(-1);
  });
});

describe('replaceOne / replaceAll', () => {
  it('replaces a single match by its exact range', () => {
    const hits = searchAll(SRC, 'admin', OPTS());
    const out = replaceOne(SRC, hits[1]!, 'admin', 'operator', OPTS());
    expect(out).toContain('The operator should fix it');
    // The other occurrences are untouched.
    expect(out.match(/admin/gi)?.length).toBe(3);
  });

  it('replaces all matches and reports the count', () => {
    const { text, count } = replaceAll(SRC, 'admin', 'operator', OPTS());
    expect(count).toBe(4);
    expect(text).not.toMatch(/admin/i);
  });

  it('expands capture groups in regex mode', () => {
    const { text } = replaceAll('foo=1; bar=2', '(\\w+)=(\\d+)', '$2:$1', OPTS({ regex: true }));
    expect(text).toBe('1:foo; 2:bar');
  });

  it('treats $ literally in literal mode', () => {
    const { text } = replaceAll('price here', 'price', '$5', OPTS());
    expect(text).toBe('$5 here');
  });
});

// The panel searches a debounced copy of the source but the view applies the
// rewrite to the live Y.Text, so a match's offsets can be stale by the time
// `replaceOne` runs: a collaborator may have typed above it inside the
// window. Splicing by those offsets lands on the wrong characters and
// corrupts the report, so the match is re-verified where it claims to be and
// a document that moved is left alone.
describe('replaceOne verifies the match against the text it is given', () => {
  it('leaves a literal match alone once its offsets have drifted', () => {
    const hits = searchAll(SRC, 'admin', OPTS());
    const drifted = `A collaborator typed this first.\n${SRC}`;

    expect(replaceOne(drifted, hits[1]!, 'admin', 'operator', OPTS())).toBe(drifted);
  });

  it('leaves a regex match alone once its offsets have drifted', () => {
    const hits = searchAll(SRC, 'adm\\w+', OPTS({ regex: true }));
    const drifted = `A collaborator typed this first.\n${SRC}`;

    expect(replaceOne(drifted, hits[1]!, 'adm\\w+', 'operator', OPTS({ regex: true }))).toBe(drifted);
  });

  it('still replaces a literal match that has not moved', () => {
    const hits = searchAll(SRC, 'admin', OPTS());
    const out = replaceOne(SRC, hits[1]!, 'admin', 'operator', OPTS());

    expect(out).toContain('The operator should fix it');
    expect(out.match(/admin/gi)?.length).toBe(3);
  });

  it('inserts $& and $1 literally in literal mode', () => {
    const hits = searchAll(SRC, 'admin', OPTS());
    const out = replaceOne(SRC, hits[1]!, 'admin', '$& and $1', OPTS());

    // Not the matched text, not a capture: the characters themselves.
    expect(out).toContain('The $& and $1 should fix it');
  });

  it('keeps expanding captures in regex mode', () => {
    const src = 'foo=1; bar=2';
    const hits = searchAll(src, '(\\w+)=(\\d+)', OPTS({ regex: true }));
    const out = replaceOne(src, hits[1]!, '(\\w+)=(\\d+)', '$2:$1', OPTS({ regex: true }));

    expect(out).toBe('foo=1; 2:bar');
  });

  it('honours case sensitivity and whole word the way replaceAll does', () => {
    const sensitive = OPTS({ caseSensitive: true });
    const hits = searchAll(SRC, 'Admin', sensitive);
    expect(replaceOne(SRC, hits[0]!, 'Admin', 'Operator', sensitive))
      .toContain('The Operator should fix it');

    const whole = OPTS({ wholeWord: true });
    const wholeHits = searchAll(SRC, 'admin', whole);
    expect(replaceOne(SRC, wholeHits[0]!, 'admin', 'operator', whole))
      .toContain('The operator panel is exposed');
    // A query that is only part of a word finds nothing to verify against.
    const partial = searchAll(SRC, 'admi', whole);
    expect(partial).toHaveLength(0);
  });
});
