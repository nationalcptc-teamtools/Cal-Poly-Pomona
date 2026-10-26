// ─────────────────────────────────────────────────────────────────────────
// Per-page handling of a rendered Typst document.
//
// typst.ts renders a multi-page document into ONE <svg> with each page as a
// `<g class="typst-page" transform="translate(x,y)" data-page-width=W
// data-page-height=H>` stacked vertically with ZERO gap and NO page background
// (pages are transparent). The preview shows them typst.app-style instead:
// each page on its own white card, separated by a gap, and mounted only
// while it is near the viewport (see `splitTypstPages`).
// ─────────────────────────────────────────────────────────────────────────

/** Gap between pages in the preview, in CSS px at 100% zoom. */
export const DEFAULT_PAGE_GAP = 24;

// Matches a top-level page group's opening tag as emitted by typst.ts 0.7.
// Attribute order is stable: class, transform, data-tid, data-page-width,
// data-page-height. If the format ever changes this simply matches nothing and
// the caller falls back to mounting the whole document.
const PAGE_TAG_RE =
  /<g class="typst-page" transform="translate\(\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)\s*\)" data-tid="([^"]*)" data-page-width="([\d.]+)" data-page-height="([\d.]+)">/g;

// ─────────────────────────────────────────────────────────────────────────
// Splitting a rendered document into per-page fragments.
//
// The preview mounts pages individually (see components/typst/TypstPreview):
// only the pages near the viewport are in the DOM, and a page whose markup
// did not change between two compiles keeps the DOM it already has. Both
// depend on carving the single <svg> typst.ts emits into a shared prelude and
// one self-contained fragment per page.
//
// Why it matters: a long report renders to tens of thousands of SVG nodes
// (one <use> per glyph, one position:fixed <div> per text run). Committing
// that whole tree after every keystroke pause costs seconds of main-thread
// time in style/layout/paint, while the compile itself takes tens of ms.
// ─────────────────────────────────────────────────────────────────────────

/** One page of a split document. */
export interface TypstPageFragment {
  /** typst.ts's content id for the page; stable while the page is unchanged. */
  tid: string;
  /** Page size in SVG user units (pt). */
  width: number;
  height: number;
  /**
   * The page's `<g class="typst-page">…</g>`, with its translate reset to the
   * origin so it can be mounted in its own `<svg viewBox="0 0 w h">`.
   */
  body: string;
}

export interface SplitTypstSvg {
  /**
   * Everything the pages share: the stylesheet and the glyph/clip-path
   * <defs>. Mounted once, in a hidden <svg>; the pages' <use href="#…"> and
   * clip-path="url(#…)" references resolve document-wide.
   */
  shared: string;
  pages: TypstPageFragment[];
}

// Opening tags of every <g> (depth +1 unless self-closing) and every </g>.
const GROUP_TOKEN_RE = /<g\b[^>]*>|<\/g>/g;

/**
 * Offset just past the `</g>` that closes the group opening at `openStart`,
 * or -1 if it never closes.
 */
function findGroupEnd(svg: string, openStart: number): number {
  GROUP_TOKEN_RE.lastIndex = openStart;
  let depth = 0;
  let m: RegExpExecArray | null;
  while ((m = GROUP_TOKEN_RE.exec(svg)) !== null) {
    const tok = m[0];
    if (tok === '</g>') {
      depth--;
      if (depth === 0) return m.index + tok.length;
    } else if (!tok.endsWith('/>')) {
      depth++;
    }
  }
  return -1;
}

/**
 * Split a typst.ts document SVG into its shared prelude and per-page
 * fragments. Returns null when the input is not recognized (empty, not an
 * <svg>, no page groups, or a page group that never closes), in which case
 * the caller should fall back to mounting the whole string.
 *
 * Pure and deterministic: the same page markup always yields the same
 * fragment string, which is what lets the preview skip re-mounting it.
 */
export function splitTypstPages(svg: string): SplitTypstSvg | null {
  if (!svg.startsWith('<svg')) return null;
  const rootTagEnd = svg.indexOf('>');
  if (rootTagEnd === -1) return null;

  const pages: TypstPageFragment[] = [];
  let shared: string | null = null;
  const tagRe = new RegExp(PAGE_TAG_RE.source, 'g');
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(svg)) !== null) {
    const [tag, , , tid, w, h] = m;
    if (shared === null) shared = svg.slice(rootTagEnd + 1, m.index).trim();
    const end = findGroupEnd(svg, m.index);
    if (end === -1) return null;
    const inner = svg.slice(m.index + tag.length, end);
    pages.push({
      tid: tid!,
      width: parseFloat(w!),
      height: parseFloat(h!),
      body:
        `<g class="typst-page" transform="translate(0, 0)" data-tid="${tid}" ` +
        `data-page-width="${w}" data-page-height="${h}">` + inner,
    });
    tagRe.lastIndex = end;
  }
  if (shared === null || pages.length === 0) return null;
  return { shared, pages };
}

// ─────────────────────────────────────────────────────────────────────────
// The shared prelude, mounted without invalidating the document's styles.
//
// Measured on a 23-page report with two pages mounted: any full-document
// style recalculation costs 1.0 to 1.5 s (thousands of <use> glyph
// instances and position:fixed selection runs), and inserting or replacing a
// <style> element, even with identical text, forces exactly that. Replacing
// the glyph <defs> wholesale costs about 90 ms because every <use> is
// re-instantiated. So the stylesheet is split out and rendered once, and the
// defs are reconciled child by child, keyed by id.
// ─────────────────────────────────────────────────────────────────────────

const STYLE_RE = /<style\b[^>]*>([\s\S]*?)<\/style>/g;

/** The CSS of every <style> block in the prelude, and the prelude without them. */
export function splitSharedStyle(shared: string): { css: string; defs: string } {
  const css: string[] = [];
  const defs = shared.replace(STYLE_RE, (_m, body: string) => { if (body.trim()) css.push(body); return ''; });
  return { css: css.join('\n'), defs: defs.trim() };
}

const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * Same tag, attributes and content. Compared attribute by attribute rather
 * than through outerHTML: an element parsed as XML and one living in the
 * HTML document serialize differently even when they are the same.
 */
function sameElement(a: Element, b: Element): boolean {
  if (a.tagName !== b.tagName || a.attributes.length !== b.attributes.length) return false;
  for (const attr of Array.from(a.attributes)) if (b.getAttribute(attr.name) !== attr.value) return false;
  return a.childNodes.length === b.childNodes.length && a.textContent === b.textContent;
}

/**
 * Make `host`'s children match `markup` (a sequence of `<defs class="…">`
 * blocks) with the fewest DOM changes: a block's children are diffed by id,
 * so a glyph that is still in use keeps its element and the <use> instances
 * pointing at it are left alone. A block whose children carry no ids is
 * replaced as a whole.
 */
export function reconcileDefs(host: Element, markup: string): void {
  const parsed = new DOMParser().parseFromString(`<svg xmlns="${SVG_NS}">${markup}</svg>`, 'image/svg+xml');
  const next = parsed.documentElement;
  if (parsed.querySelector('parsererror')) { host.innerHTML = markup; return; }
  const keyOf = (el: Element) => `${el.tagName}|${el.getAttribute('class') ?? ''}`;
  const current = new Map<string, Element>();
  for (const el of Array.from(host.children)) current.set(keyOf(el), el);
  const seen = new Set<string>();
  for (const block of Array.from(next.children)) {
    const key = keyOf(block);
    seen.add(key);
    const existing = current.get(key);
    if (!existing) { host.appendChild(host.ownerDocument.importNode(block, true)); continue; }
    const wanted = Array.from(block.children);
    const have = Array.from(existing.children);
    if (wanted.some((c) => !c.id) || have.some((c) => !c.id)) {
      if (existing.innerHTML !== block.innerHTML) existing.innerHTML = block.innerHTML;
      continue;
    }
    const wantIds = new Map(wanted.map((c) => [c.id, c] as const));
    const haveIds = new Map(have.map((c) => [c.id, c] as const));
    for (const c of have) if (!wantIds.has(c.id)) c.remove();
    for (const c of wanted) {
      const h = haveIds.get(c.id);
      if (!h) existing.appendChild(host.ownerDocument.importNode(c, true));
      else if (!sameElement(h, c)) h.replaceWith(host.ownerDocument.importNode(c, true));
    }
  }
  for (const [key, el] of current) if (!seen.has(key)) el.remove();
}

/**
 * The text of every selection run (`<foreignObject>` → `.tsel`) in a page
 * fragment, in document order, as the live DOM's `textContent` would report
 * it (entities decoded, nested spans flattened).
 *
 * Used for pages that are not mounted: click-to-source needs the runs of
 * every page *before* the clicked one to count which occurrence of a string
 * was clicked, and an off-screen page has no DOM to read them from. Parsing
 * with the HTML parser (not XML) matches how innerHTML parses the same
 * markup, so the two agree on things like `&nbsp;`.
 */
export function extractTextRuns(fragment: string): string[] {
  const doc = new DOMParser().parseFromString(`<svg xmlns="http://www.w3.org/2000/svg">${fragment}</svg>`, 'text/html');
  return Array.from(doc.querySelectorAll('foreignObject')).map((o) => o.textContent ?? '');
}
