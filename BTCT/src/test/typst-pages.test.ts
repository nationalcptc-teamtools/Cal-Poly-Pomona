import { describe, it, expect } from 'vitest';
import { splitTypstPages, extractTextRuns } from '@/lib/typst-pages';

// ── splitTypstPages ──────────────────────────────────────────────────────


// Shape of a real typst.ts 0.7 document: style + glyph/clip defs before the
// pages, nested groups inside each page, and a trailing <script>.
const PRELUDE =
  '<style type="text/css">.tsel{position:fixed}</style>' +
  '<defs class="glyph"><path id="gA" d="M0 0"/></defs>' +
  '<defs class="clip-path"><clipPath id="cA"><rect/></clipPath></defs>';
const PAGE_1 =
  '<g class="typst-page" transform="translate(0, 0)" data-tid="p1" data-page-width="200" data-page-height="120">' +
  '<g class="typst-group"><g><use href="#gA"/></g></g>' +
  '<foreignObject x="1" y="2" width="10" height="5"><div class="tsel">Alpha</div></foreignObject>' +
  '</g>';
const PAGE_2 =
  '<g class="typst-page" transform="translate(0, 120)" data-tid="p2" data-page-width="200" data-page-height="80">' +
  '<g class="typst-group"><g><use href="#gA"/></g></g>' +
  '<foreignObject x="1" y="2" width="10" height="5"><div class="tsel">Alpha</div></foreignObject>' +
  '<foreignObject x="1" y="9" width="10" height="5"><div class="tsel">Beta &amp; <span>Gamma</span></div></foreignObject>' +
  '</g>';
const REAL_SHAPE_SVG =
  '<svg style="overflow: visible;" class="typst-doc" viewBox="0 0 200.000 200.000" width="200.000" height="200.000" ' +
  'xmlns="http://www.w3.org/2000/svg" xmlns:h5="http://www.w3.org/1999/xhtml">' +
  PRELUDE + PAGE_1 + PAGE_2 +
  '<script>console.log("</g>")</script>' +
  '</svg>';

describe('splitTypstPages', () => {
  it('returns one fragment per page with its size and content id', () => {
    const split = splitTypstPages(REAL_SHAPE_SVG)!;
    expect(split).not.toBeNull();
    expect(split.pages).toHaveLength(2);
    expect(split.pages[0]).toMatchObject({ tid: 'p1', width: 200, height: 120 });
    expect(split.pages[1]).toMatchObject({ tid: 'p2', width: 200, height: 80 });
  });

  it('keeps the prelude (style + defs) once, outside every page', () => {
    const split = splitTypstPages(REAL_SHAPE_SVG)!;
    expect(split.shared).toBe(PRELUDE);
    for (const p of split.pages) {
      expect(p.body).not.toContain('<defs');
      expect(p.body).not.toContain('<style');
    }
  });

  it('resets each page to the origin and keeps its nested groups intact', () => {
    const split = splitTypstPages(REAL_SHAPE_SVG)!;
    expect(split.pages[1]!.body.startsWith(
      '<g class="typst-page" transform="translate(0, 0)" data-tid="p2" data-page-width="200" data-page-height="80">',
    )).toBe(true);
    expect(split.pages[1]!.body.endsWith('</g>')).toBe(true);
    expect(split.pages[1]!.body).toContain('<g class="typst-group"><g><use href="#gA"/></g></g>');
    expect(split.pages[1]!.body).toContain('Gamma');
    // Page 1 stops where page 2 begins: nothing from the second page leaks in.
    expect(split.pages[0]!.body).not.toContain('data-tid="p2"');
    expect(split.pages[0]!.body).not.toContain('Beta');
  });

  it('drops the trailing script (it is never executed by innerHTML anyway)', () => {
    const split = splitTypstPages(REAL_SHAPE_SVG)!;
    expect(split.shared).not.toContain('<script');
    for (const p of split.pages) expect(p.body).not.toContain('<script');
  });

  it('is stable: identical page markup yields identical fragment strings', () => {
    // The preview reuses a page's DOM when its fragment string is unchanged,
    // so two compiles of the same page must split to the same string.
    const a = splitTypstPages(REAL_SHAPE_SVG)!;
    const b = splitTypstPages(REAL_SHAPE_SVG)!;
    expect(a.pages[0]!.body).toBe(b.pages[0]!.body);
    expect(a.shared).toBe(b.shared);
  });

  it('returns null for SVG that is not a typst.ts document', () => {
    expect(splitTypstPages('<svg viewBox="0 0 10 10"><g class="other"></g></svg>')).toBeNull();
    expect(splitTypstPages('')).toBeNull();
  });

  it('returns null when a page group never closes (malformed input)', () => {
    const broken = '<svg><g class="typst-page" transform="translate(0, 0)" data-tid="p1" data-page-width="1" data-page-height="1"><g></svg>';
    expect(splitTypstPages(broken)).toBeNull();
  });
});

describe('extractTextRuns', () => {
  it('lists the text of every selection run in a page fragment, in document order', () => {
    const split = splitTypstPages(REAL_SHAPE_SVG)!;
    expect(extractTextRuns(split.pages[0]!.body)).toEqual(['Alpha']);
    // Entities are decoded and nested spans are flattened, exactly as the
    // live DOM's textContent would report them.
    expect(extractTextRuns(split.pages[1]!.body)).toEqual(['Alpha', 'Beta & Gamma']);
  });

  it('returns an empty list for a page with no text', () => {
    expect(extractTextRuns('<g class="typst-page"><path d="M0 0"/></g>')).toEqual([]);
  });
});
