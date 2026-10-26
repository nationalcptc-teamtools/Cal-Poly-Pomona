import { describe, it, expect } from 'vitest';
import {
  joinRuns, compileFindQuery, findInPages, stepMatch, firstMatchFrom, matchLabel, toPageBox, textRange, glyphSpan,
} from '@/lib/preview-find';

const ci = { caseSensitive: false };
const cs = { caseSensitive: true };

describe('joinRuns', () => {
  it('puts one space at a seam that has none and none where a side already has one', () => {
    expect(joinRuns(['Executive', 'Summary']).text).toBe('Executive Summary');
    expect(joinRuns(['the ', 'report']).text).toBe('the report');
    expect(joinRuns(['bold', ' tail']).text).toBe('bold tail');
    expect(joinRuns(['a', '', 'b']).text).toBe('a b');
  });

  it('records where each run starts', () => {
    expect(joinRuns(['ab', 'cd', ' e']).starts).toEqual([0, 3, 5]);
  });
});

describe('compileFindQuery', () => {
  it('is null for an empty or blank query', () => {
    expect(compileFindQuery('', ci)).toBeNull();
    expect(compileFindQuery('   ', ci)).toBeNull();
  });

  it('treats the query literally', () => {
    const re = compileFindQuery('a.b (c)', ci)!;
    expect(re.test('xa.b (c)y')).toBe(true);
    re.lastIndex = 0;
    expect(re.test('aXb (c)')).toBe(false);
  });

  it('lets any whitespace in the query match any whitespace on the page', () => {
    const re = compileFindQuery('remote  code', ci)!;
    expect('remote code'.match(re)?.[0]).toBe('remote code');
  });
});

describe('findInPages', () => {
  const pages = [['Alpha beta', ' gamma'], ['BETA'], ['no match here'], ['beta', 'beta']];

  it('finds every match, page by page, in reading order', () => {
    const found = findInPages(pages, 'beta', ci);
    expect(found.map((m) => m.page)).toEqual([0, 1, 3, 3]);
    expect(found[0]!.pieces).toEqual([{ run: 0, start: 6, end: 10 }]);
    expect(found[3]!.pieces).toEqual([{ run: 1, start: 0, end: 4 }]);
  });

  it('honours case sensitivity', () => {
    expect(findInPages(pages, 'beta', cs)).toHaveLength(3);
    expect(findInPages(pages, 'BETA', cs).map((m) => m.page)).toEqual([1]);
  });

  it('matches a phrase across a style change or a line break, one piece per run', () => {
    const found = findInPages([['the remote', 'code execution']], 'remote code', ci);
    expect(found).toHaveLength(1);
    expect(found[0]!.pieces).toEqual([{ run: 0, start: 4, end: 10 }, { run: 1, start: 0, end: 4 }]);
  });

  it('never matches across two pages', () => {
    expect(findInPages([['end of'], ['page']], 'of page', ci)).toHaveLength(0);
  });

  it('stops at the cap', () => {
    expect(findInPages([['a a a a a']], 'a', ci, 3)).toHaveLength(3);
  });

  it('finds nothing for a blank query', () => {
    expect(findInPages(pages, '  ', ci)).toEqual([]);
  });
});

describe('stepping', () => {
  it('wraps in both directions and starts at the ends from nowhere', () => {
    expect(stepMatch(0, 3, 1)).toBe(1);
    expect(stepMatch(2, 3, 1)).toBe(0);
    expect(stepMatch(0, 3, -1)).toBe(2);
    expect(stepMatch(-1, 3, 1)).toBe(0);
    expect(stepMatch(-1, 3, -1)).toBe(2);
    expect(stepMatch(0, 0, 1)).toBe(-1);
  });

  it('starts a new search at the page in view, wrapping to the top', () => {
    const matches = [{ page: 0, pieces: [] }, { page: 2, pieces: [] }, { page: 5, pieces: [] }];
    expect(firstMatchFrom(matches, 1)).toBe(1);
    expect(firstMatchFrom(matches, 5)).toBe(2);
    expect(firstMatchFrom(matches, 6)).toBe(0);
    expect(firstMatchFrom([], 0)).toBe(-1);
  });

  it('labels the count', () => {
    expect(matchLabel(-1, 0, '', false)).toBe('');
    expect(matchLabel(-1, 0, 'x', false)).toBe('No matches');
    expect(matchLabel(2, 12, 'x', false)).toBe('3 of 12');
    expect(matchLabel(0, 2000, 'x', true)).toBe('1 of 2000+');
  });
});

describe('toPageBox', () => {
  const rect = (left: number, top: number, right: number, bottom: number) => ({ left, top, right, bottom, width: right - left });

  it('converts screen rectangles to page units by the card ratio, at any zoom', () => {
    // A 200-unit page drawn 400 px wide (2x), its card at (100, 50).
    const card = rect(100, 50, 500, 450);
    const run = rect(120, 70, 400, 90);
    expect(toPageBox([rect(140, 72, 180, 88)], card, 200, run)).toEqual({ x: 20, y: 10, w: 20, h: 10 });
  });

  it('clips to the run box and merges a piece into one box', () => {
    const card = rect(0, 0, 200, 200);
    const run = rect(10, 10, 50, 20);
    expect(toPageBox([rect(5, 12, 20, 18), rect(20, 12, 60, 18)], card, 200, run)).toEqual({ x: 10, y: 10, w: 40, h: 10 });
  });

  it('gives nothing for empty rectangles or a page of no size', () => {
    expect(toPageBox([rect(0, 0, 0, 0)], rect(0, 0, 10, 10), 10, null)).toBeNull();
    expect(toPageBox([rect(1, 1, 2, 2)], rect(0, 0, 0, 0), 10, null)).toBeNull();
  });
});

describe('textRange', () => {
  it('spans nested text nodes the way textContent counts them', () => {
    const div = document.createElement('div');
    div.innerHTML = 'ab<span>cd</span>ef';
    const range = textRange(div, 1, 5)!;
    expect(range.toString()).toBe('bcde');
    expect(textRange(div, 4, 9)).toBeNull();
    expect(textRange(div, 2, 2)).toBeNull();
  });
});

describe('glyphSpan', () => {
  // "ab cd": glyphs a(0) b(10) space(20) c(25) d(35), run ends at 45.
  const g = (x: number, blank = false) => ({ x, blank });
  const glyphs = [g(0), g(10), g(20, true), g(25), g(35)];

  it('puts a whole word exactly on its glyphs', () => {
    expect(glyphSpan('ab cd', 3, 5, glyphs, 45)).toEqual([25, 45]);
    expect(glyphSpan('ab cd', 0, 2, glyphs, 45)).toEqual([0, 20]);
  });

  it('places a position inside a word by its characters', () => {
    expect(glyphSpan('ab cd', 1, 2, glyphs, 45)).toEqual([10, 20]);
  });

  it('copes with a ligature (fewer glyphs than letters)', () => {
    // "fin" drawn as "fi" + "n".
    expect(glyphSpan('fin', 0, 3, [g(0), g(12)], 20)).toEqual([0, 20]);
  });

  it('steps off whitespace at either end of a phrase', () => {
    expect(glyphSpan('ab cd', 2, 5, glyphs, 45)).toEqual([25, 45]);
    expect(glyphSpan('ab cd', 0, 3, glyphs, 45)).toEqual([0, 20]);
  });

  it('gives up when words and glyph groups disagree', () => {
    expect(glyphSpan('ab cd', 0, 2, [g(0), g(10)], 20)).toBeNull();
    expect(glyphSpan('ab', 0, 0, glyphs, 45)).toBeNull();
  });
});
