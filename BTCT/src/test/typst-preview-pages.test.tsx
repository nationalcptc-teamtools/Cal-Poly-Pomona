import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act, fireEvent } from '@testing-library/react';

// The compiler is wasm + fonts: far outside jsdom. Stub it to hand back
// canned documents so the test can drive the preview's DOM behaviour alone.
const compileTypstSvg = vi.fn();
vi.mock('@/lib/typst-compiler', () => ({
  compileTypstSvg: (...args: unknown[]) => compileTypstSvg(...args),
  typstErrorMessage: (e: unknown) => String(e),
}));

import { TypstPreview } from '@/components/typst/TypstPreview';
import { clearRenderCache, renderCache } from '@/lib/typst-render-cache';

type IoCallback = (entries: Array<{ isIntersecting: boolean; target: Element }>, observer: unknown) => void;

/** Minimal IntersectionObserver stub: records observers so tests can fire them. */
class FakeIntersectionObserver {
  static instances: FakeIntersectionObserver[] = [];
  targets = new Set<Element>();
  constructor(public cb: IoCallback, public opts?: IntersectionObserverInit) {
    FakeIntersectionObserver.instances.push(this);
  }
  observe(el: Element) { this.targets.add(el); }
  unobserve(el: Element) { this.targets.delete(el); }
  disconnect() { this.targets.clear(); }
  takeRecords() { return []; }
}

const page = (n: number, height: number, text: string) =>
  `<g class="typst-page" transform="translate(0, ${(n - 1) * 100})" data-tid="p${n}" data-page-width="200" data-page-height="${height}">` +
  '<g><use href="#gA"/></g>' +
  `<foreignObject x="1" y="2" width="10" height="5"><div class="tsel">${text}</div></foreignObject>` +
  '</g>';

const doc = (pages: string[]) =>
  '<svg style="overflow: visible;" class="typst-doc" viewBox="0 0 200.000 400.000" width="200.000" height="400.000" xmlns="http://www.w3.org/2000/svg">' +
  '<style type="text/css">.tsel{position:fixed}</style><defs class="glyph"><path id="gA" d="M0 0"/></defs>' +
  pages.join('') +
  '<script>1</script></svg>';

const FOUR_PAGES = doc([page(1, 100, 'one'), page(2, 100, 'two'), page(3, 100, 'three'), page(4, 100, 'four')]);

async function settle() {
  // Past the 350 ms debounce, then let the (mocked) compile resolve and commit.
  await act(async () => { await vi.advanceTimersByTimeAsync(400); });
}

/** The pages render inside the preview host's shadow root. */
const shadow = (root: HTMLElement): ShadowRoot | null => root.querySelector('[data-testid="preview-shadow-host"]')?.shadowRoot ?? null;
const cards = (root: HTMLElement) => Array.from(shadow(root)?.querySelectorAll<HTMLElement>('[data-page-index]') ?? []);
const mountedSvg = (card: HTMLElement) => card.querySelector('svg');

describe('TypstPreview document switching', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    FakeIntersectionObserver.instances = [];
    vi.stubGlobal('IntersectionObserver', FakeIntersectionObserver);
    compileTypstSvg.mockReset();
    clearRenderCache();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('does not compile until ready, then compiles a new document at once and debounces edits', async () => {
    compileTypstSvg.mockResolvedValue({ svg: FOUR_PAGES, diagnostics: [] });
    const { rerender } = render(<TypstPreview source="a" docKey="w1:main.typ" ready={false} />);
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(compileTypstSvg).not.toHaveBeenCalled();

    rerender(<TypstPreview source="a" docKey="w1:main.typ" ready />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(compileTypstSvg).toHaveBeenCalledTimes(1); // no 350 ms wait for a switch

    rerender(<TypstPreview source="ab" docKey="w1:main.typ" ready />);
    await act(async () => { await vi.advanceTimersByTimeAsync(100); });
    expect(compileTypstSvg).toHaveBeenCalledTimes(1); // typing still debounces
    await act(async () => { await vi.advanceTimersByTimeAsync(300); });
    expect(compileTypstSvg).toHaveBeenCalledTimes(2);
  });

  it('shows a cached render for a revisited document immediately and restores its scroll offset', async () => {
    compileTypstSvg.mockResolvedValue({ svg: FOUR_PAGES, diagnostics: [] });
    const { container, rerender } = render(<TypstPreview source="a" docKey="w1:main.typ" ready />);
    await settle();
    expect(cards(container)).toHaveLength(4);
    const area = container.querySelector<HTMLElement>('[data-testid="preview-pages"]')!;
    // The user scrolls down, then switches to a document never rendered before.
    fireEvent.scroll(area, { target: { scrollTop: 240 } });
    compileTypstSvg.mockResolvedValue({ svg: doc([page(1, 100, 'other')]), diagnostics: [] });
    rerender(<TypstPreview source="z" docKey="w2:main.typ" ready />);
    // No stale pages from w1 while w2 renders for the first time.
    expect(cards(container)).toHaveLength(0);
    expect(container.textContent).toContain('Rendering');
    expect(renderCache.get('w1:main.typ')).toMatchObject({ scrollTop: 240 });
    await settle();
    expect(cards(container)).toHaveLength(1);

    // Back to w1: its four pages are on screen before any compile runs.
    compileTypstSvg.mockClear();
    rerender(<TypstPreview source="a" docKey="w1:main.typ" ready />);
    expect(cards(container)).toHaveLength(4);
    expect(compileTypstSvg).not.toHaveBeenCalled();
    expect(area.scrollTop).toBe(240);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(compileTypstSvg).toHaveBeenCalledTimes(1);
  });

  // How the cache is actually filled in BTCT: a mounted preview's docKey is
  // its workspace id and never changes, so closing the Report tab (unmount)
  // is the only moment a real session leaves a document behind.
  it('keeps its render when the tab closes and repaints it on reopen without compiling', async () => {
    compileTypstSvg.mockResolvedValue({ svg: FOUR_PAGES, diagnostics: [] });
    const first = render(<TypstPreview source="a" docKey="w1:main.typ" ready />);
    await settle();
    expect(cards(first.container)).toHaveLength(4);
    fireEvent.scroll(first.container.querySelector<HTMLElement>('[data-testid="preview-pages"]')!, {
      target: { scrollTop: 180 },
    });

    first.unmount();
    expect(renderCache.get('w1:main.typ')).toMatchObject({ svg: FOUR_PAGES, scrollTop: 180 });

    // Reopening the tab: the pages are back before any compile is dispatched.
    compileTypstSvg.mockClear();
    const again = render(<TypstPreview source="a" docKey="w1:main.typ" ready />);
    expect(cards(again.container)).toHaveLength(4);
    expect(compileTypstSvg).not.toHaveBeenCalled();
    expect(again.container.querySelector<HTMLElement>('[data-testid="preview-pages"]')!.scrollTop).toBe(180);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(compileTypstSvg).toHaveBeenCalledTimes(1);
  });

  // StrictMode mounts, tears down and remounts. The throwaway first mount has
  // rendered nothing, and its cleanup must not leave a blank entry behind.
  it('does not cache an empty render from a mount that never compiled', async () => {
    compileTypstSvg.mockResolvedValue({ svg: FOUR_PAGES, diagnostics: [] });
    render(<TypstPreview source="a" docKey="w9:main.typ" ready={false} />).unmount();
    expect(renderCache.get('w9:main.typ')).toBeUndefined();

    // The mount that does render still caches on the way out.
    const real = render(<TypstPreview source="a" docKey="w9:main.typ" ready />);
    await settle();
    real.unmount();
    expect(renderCache.get('w9:main.typ')?.svg).toBe(FOUR_PAGES);
  });
});

describe('TypstPreview page virtualization', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    FakeIntersectionObserver.instances = [];
    vi.stubGlobal('IntersectionObserver', FakeIntersectionObserver);
    compileTypstSvg.mockReset();
    // The unmount write means every test in this block now leaves an entry
    // behind; without this the next one would start from a stale render.
    clearRenderCache();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('renders one sized card per page and mounts only the first pages eagerly', async () => {
    compileTypstSvg.mockResolvedValue({ svg: FOUR_PAGES, diagnostics: [] });
    const { container } = render(<TypstPreview source="a" />);
    await settle();

    const all = cards(container);
    expect(all).toHaveLength(4);
    expect(all[0]!.style.width).toBe('200px');
    expect(all[0]!.style.height).toBe('100px');
    // The preview opens at the top: the first pages are mounted without
    // waiting for the observer, the rest stay empty cards.
    expect(mountedSvg(all[0]!)).not.toBeNull();
    expect(mountedSvg(all[1]!)).not.toBeNull();
    expect(mountedSvg(all[2]!)).toBeNull();
    expect(mountedSvg(all[3]!)).toBeNull();
  });

  it('mounts the shared defs and stylesheet exactly once', async () => {
    compileTypstSvg.mockResolvedValue({ svg: FOUR_PAGES, diagnostics: [] });
    const { container } = render(<TypstPreview source="a" />);
    await settle();
    const root = shadow(container)!;
    expect(root.querySelectorAll('defs.glyph')).toHaveLength(1);
    expect(Array.from(root.querySelectorAll('style')).filter((s) => s.textContent?.includes('.tsel'))).toHaveLength(1);
    expect(container.querySelectorAll('defs.glyph')).toHaveLength(0); // nothing leaks into the document
  });

  it('mounts a page when it scrolls near the viewport and unmounts it when it leaves', async () => {
    compileTypstSvg.mockResolvedValue({ svg: FOUR_PAGES, diagnostics: [] });
    const { container } = render(<TypstPreview source="a" />);
    await settle();

    const third = cards(container)[2]!;
    const io = FakeIntersectionObserver.instances.find((i) => i.targets.has(third))!;
    expect(io).toBeDefined();

    act(() => io.cb([{ isIntersecting: true, target: third }], io));
    expect(mountedSvg(third)).not.toBeNull();
    expect(mountedSvg(third)!.innerHTML).toContain('three');

    act(() => io.cb([{ isIntersecting: false, target: third }], io));
    expect(mountedSvg(third)).toBeNull();
  });

  it('keeps the DOM of pages whose markup did not change between compiles', async () => {
    compileTypstSvg.mockResolvedValueOnce({ svg: FOUR_PAGES, diagnostics: [] });
    const { container, rerender } = render(<TypstPreview source="a" />);
    await settle();
    const firstCardBefore = cards(container)[0]!;
    const firstBefore = mountedSvg(firstCardBefore)!;

    // Second compile: only page 2 changed.
    compileTypstSvg.mockResolvedValueOnce({
      svg: doc([page(1, 100, 'one'), page(2, 100, 'two, edited'), page(3, 100, 'three'), page(4, 100, 'four')]),
      diagnostics: [],
    });
    rerender(<TypstPreview source="b" />);
    await settle();

    const firstCardAfter = cards(container)[0]!;
    const firstAfter = mountedSvg(firstCardAfter)!;
    const secondAfter = mountedSvg(cards(container)[1]!)!;
    expect(firstCardAfter).toBe(firstCardBefore); // untouched page: the card itself is the same node too
    expect(firstAfter).toBe(firstBefore); // untouched page: the very same node
    expect(secondAfter.innerHTML).toContain('two, edited');
  });

  it('falls back to mounting the whole SVG when it is not a paged typst.ts document', async () => {
    compileTypstSvg.mockResolvedValue({ svg: '<svg viewBox="0 0 10 10"><rect id="lone"/></svg>', diagnostics: [] });
    const { container } = render(<TypstPreview source="a" />);
    await settle();
    expect(cards(container)).toHaveLength(0);
    expect(shadow(container)!.querySelector('#lone')).not.toBeNull();
  });

  it('counts click-to-source occurrences across earlier pages, mounted or not', async () => {
    // "dup" appears on pages 1, 2 and 3; clicking the run on page 3 must report
    // occurrence 2 even though page 2 is not mounted at the time.
    compileTypstSvg.mockResolvedValue({
      svg: doc([page(1, 100, 'dup'), page(2, 100, 'dup'), page(3, 100, 'dup'), page(4, 100, 'other')]),
      diagnostics: [],
    });
    const onRevealSource = vi.fn();
    const { container } = render(<TypstPreview source="a" onRevealSource={onRevealSource} />);
    await settle();

    const all = cards(container);
    const second = all[1]!;
    const third = all[2]!;
    // Scroll page 2 out and page 3 in.
    const io2 = FakeIntersectionObserver.instances.find((i) => i.targets.has(second))!;
    const io3 = FakeIntersectionObserver.instances.find((i) => i.targets.has(third))!;
    act(() => io2.cb([{ isIntersecting: false, target: second }], io2));
    act(() => io3.cb([{ isIntersecting: true, target: third }], io3));
    expect(mountedSvg(second)).toBeNull();
    expect(mountedSvg(third)).not.toBeNull();

    // jsdom has no layout: give the run on page 3 a real box so the hit-test finds it.
    const run = third.querySelector('foreignObject')!;
    const box = { left: 0, top: 0, right: 50, bottom: 20, width: 50, height: 20, x: 0, y: 0, toJSON() { return {}; } };
    vi.spyOn(run, 'getBoundingClientRect').mockReturnValue(box as DOMRect);

    fireEvent.click(run, { clientX: 10, clientY: 10 });
    expect(onRevealSource).toHaveBeenCalledTimes(1);
    const candidates = onRevealSource.mock.calls[0]![0] as Array<{ text: string; occurrence: number }>;
    expect(candidates[0]).toEqual({ text: 'dup', occurrence: 2 });
  });
});
