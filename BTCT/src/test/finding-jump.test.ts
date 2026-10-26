import { describe, it, expect } from 'vitest';
import {
  blockRegion, findingSelectEffects, findingTarget, locateAll, locateFindingBlock, titleKey, BLOCK_LABEL,
} from '@/lib/finding-jump';

/** One rendered finding block's runs, as typst.ts emits them (number, title, pill, labels). */
function block(num: string, title: string | string[], sev = 'CRITICAL'): string[] {
  return [num, ...(Array.isArray(title) ? title : [title]), sev, 'CVSS SCORE', 'CVSS VECTOR', 'LIKELIHOOD', 'IMPACT', '9.8', 'AV:N', 'High', 'High', 'AFFECTED SCOPE'];
}

describe('findingTarget', () => {
  it('counts duplicate titles before and in total, ignoring case and spacing', () => {
    const titles = ['SQL injection', 'Weak TLS', 'sql  INJECTION', 'SQL injection'];
    expect(findingTarget(titles, 2)).toEqual({ ordinal: 2, count: 4, title: 'sql  INJECTION', titleOrdinal: 1, titleCount: 3, nextTitle: 'SQL injection' });
    expect(findingTarget(titles, 3).nextTitle).toBe('');
    expect(titleKey('  A \n b ')).toBe('a b');
  });
});

describe('locateAll', () => {
  it('reports matches with document-wide offsets across pages', () => {
    const hits = locateAll([['alpha beta'], ['beta']], 'beta', false);
    expect(hits.map((h) => [h.page, h.at])).toEqual([[0, 6], [1, 11]]);
  });
});

describe('locateFindingBlock', () => {
  const contents = ['TABLE OF CONTENTS', '6.1.1 SQL injection', '6.1.2 Weak TLS', 'Report card', 'SQL injection', 'Critical'];

  it('maps the n-th finding to the n-th block label, past the contents and the report card', () => {
    const pages = [contents, block('6.1.1', 'SQL injection'), [...block('6.2.1', 'Weak TLS', 'HIGH'), 'END OF FINDING BLOCK']];
    const t = findingTarget(['SQL injection', 'Weak TLS'], 0);
    const hit = locateFindingBlock(pages, t)!;
    expect(hit.via).toBe('label');
    expect(hit.page).toBe(1);
    expect(hit.pieces).toEqual([{ run: 1, start: 0, end: 13 }]);
    expect(hit.next).toBeNull();
    expect(locateFindingBlock(pages, findingTarget(['SQL injection', 'Weak TLS'], 1))!.page).toBe(2);
  });

  it('tells duplicate titles apart by order', () => {
    const pages = [[...block('6.1.1', 'Default creds'), ...block('6.1.2', 'Default creds')]];
    const titles = ['Default creds', 'Default creds'];
    const first = locateFindingBlock(pages, findingTarget(titles, 0))!;
    const second = locateFindingBlock(pages, findingTarget(titles, 1))!;
    expect(first.pieces[0]!.run).toBe(1);
    expect(second.pieces[0]!.run).toBe(13);
    // The first block's outline stops at the second block's head on the same page.
    expect(first.next).toEqual([{ run: 13, start: 0, end: 13 }]);
  });

  it('finds a title that wraps across two runs', () => {
    const pages = [block('6.1.1', ['Unauthenticated remote code', 'execution in the admin panel'])];
    const hit = locateFindingBlock(pages, findingTarget(['Unauthenticated remote code execution in the admin panel'], 0))!;
    expect(hit.pieces.map((p) => p.run)).toEqual([1, 2]);
  });

  it('lands on the label for a block with an empty title', () => {
    const pages = [[...block('6.1.1', 'Weak TLS'), ...block('6.1.2', '')]];
    const hit = locateFindingBlock(pages, findingTarget(['Weak TLS', ''], 1))!;
    expect(hit.via).toBe('label');
    // The head reaches back over the title bar's number and pill to the label.
    expect(hit.pieces.map((p) => pages[0]![p.run])).toEqual(['6.1.2', '', 'CRITICAL', BLOCK_LABEL].filter(Boolean));
    // Without a bar run before it, the label alone.
    const bare = [['Some prose', 'CVSS SCORE']];
    const h2 = locateFindingBlock(bare, findingTarget([''], 0))!;
    expect(h2.pieces.map((p) => bare[0]![p.run])).toEqual([BLOCK_LABEL]);
  });

  it('finds a block on a later page among many', () => {
    const pages = [contents, ['intro'], ['more'], block('6.1.1', 'A'), ['narrative'], block('6.2.1', 'B'), block('6.3.1', 'C')];
    const hit = locateFindingBlock(pages, findingTarget(['A', 'B', 'C'], 2))!;
    expect(hit.page).toBe(6);
  });

  it('falls back to the title when the label count does not match, preferring block heads', () => {
    // A custom template with no CVSS label: only titles to go on, contents first.
    const pages = [['Contents', 'SQL injection', 'Weak TLS'], ['SQL injection', 'Some text'], ['Weak TLS', 'Text']];
    const hit = locateFindingBlock(pages, findingTarget(['SQL injection', 'Weak TLS'], 0))!;
    expect(hit.via).toBe('title');
    // Two matches for one finding: the extra (contents) one is earlier, so count from the end.
    expect(hit.page).toBe(1);
    // A label after a title marks it as a block head.
    const labelled = [['SQL injection', 'summary'], ['SQL injection', 'CVSS SCORE'], ['Weak TLS']];
    const h2 = locateFindingBlock(labelled, findingTarget(['SQL injection', 'Weak TLS', 'x'], 0))!;
    expect(h2.page).toBe(1);
  });

  it('is null when there is nothing to go on', () => {
    expect(locateFindingBlock([['no blocks here']], findingTarget([''], 0))).toBeNull();
    expect(locateFindingBlock([['nothing']], findingTarget(['Missing'], 0))).toBeNull();
  });

  it('does not count a capitalised "CVSS score" in prose as a block', () => {
    const pages = [['The CVSS score of each finding is shown'], block('6.1.1', 'A')];
    expect(locateFindingBlock(pages, findingTarget(['A'], 0))!.via).toBe('label');
  });
});

describe('blockRegion', () => {
  const card = { left: 100, top: 1000, right: 712, bottom: 1792 }; // 612 x 792 page at scale 1
  const r = (l: number, t: number, w: number, h: number) => ({ left: card.left + l, top: card.top + t, right: card.left + l + w, bottom: card.top + t + h });

  it('spans from above the head to above the next head, across the text column', () => {
    const box = blockRegion([r(80, 200, 200, 14)], [r(80, 500, 100, 14)], [r(54, 100, 400, 10), r(80, 200, 200, 14), r(300, 300, 258, 10)], card, 612, 792)!;
    expect(box.y).toBe(192);
    expect(box.y + box.h).toBe(492);
    expect(box.x).toBe(46);
    expect(box.x + box.w).toBeCloseTo(566);
  });

  it('runs to the last line on the page, ignoring the footer band, when the next block is elsewhere', () => {
    const all = [r(60, 200, 300, 14), r(60, 600, 300, 10), r(60, 760, 50, 8)];
    const box = blockRegion([r(60, 200, 300, 14)], null, all, card, 612, 792)!;
    expect(box.y + box.h).toBe(618);
  });

  it('holds at any zoom (a ratio of rectangles)', () => {
    const big = { left: 0, top: 0, right: 1224, bottom: 1584 };
    const box = blockRegion([{ left: 160, top: 400, right: 560, bottom: 428 }], null, [{ left: 108, top: 400, right: 1116, bottom: 428 }], big, 612, 792)!;
    expect(box.y).toBe(192);
  });

  it('is null without a head or a measurable card', () => {
    expect(blockRegion([], null, [], card, 612, 792)).toBeNull();
    expect(blockRegion([r(0, 0, 1, 1)], null, [], { left: 0, top: 0, right: 0, bottom: 0 }, 612, 792)).toBeNull();
  });
});

describe('findingSelectEffects (the preview lock gate)', () => {
  it('unlocked: spotlight the code and jump the preview', () => {
    expect(findingSelectEffects(false)).toEqual({ spotlightCode: true, jumpPreview: true });
  });
  it('locked: only the preview jumps; the code is left alone', () => {
    expect(findingSelectEffects(true)).toEqual({ spotlightCode: false, jumpPreview: true });
  });
});
