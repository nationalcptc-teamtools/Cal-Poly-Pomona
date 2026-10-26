import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act, fireEvent } from '@testing-library/react';

const compileTypstSvg = vi.fn();
vi.mock('@/lib/typst-compiler', () => ({
  compileTypstSvg: (...args: unknown[]) => compileTypstSvg(...args),
  typstErrorMessage: (e: unknown) => String(e),
}));

import { TypstPreview } from '@/components/typst/TypstPreview';
import { clearRenderCache } from '@/lib/typst-render-cache';

const page = (n: number, runs: string[]) =>
  `<g class="typst-page" transform="translate(0, ${(n - 1) * 100})" data-tid="p${n}-${runs.join('|')}" data-page-width="200" data-page-height="100">` +
  '<g><use href="#gA"/></g>' +
  runs.map((t, i) => `<foreignObject x="1" y="${2 + i * 10}" width="100" height="8"><div class="tsel">${t}</div></foreignObject>`).join('') +
  '</g>';

const doc = (pages: string[]) =>
  '<svg class="typst-doc" viewBox="0 0 200 400" width="200" height="400" xmlns="http://www.w3.org/2000/svg">' +
  '<style type="text/css">.tsel{position:fixed}</style><defs class="glyph"><path id="gA" d="M0 0"/></defs>' +
  pages.join('') + '</svg>';

const REPORT = doc([page(1, ['Alpha beta', 'gamma']), page(2, ['BETA']), page(3, ['no match']), page(4, ['beta'])]);

async function settle(ms = 400) {
  await act(async () => { await vi.advanceTimersByTimeAsync(ms); });
}

const pagesArea = (c: HTMLElement) => c.querySelector<HTMLElement>('[data-testid="preview-pages"]')!;
const shadow = (c: HTMLElement) => c.querySelector('[data-testid="preview-shadow-host"]')!.shadowRoot!;
const findBar = (c: HTMLElement) => c.querySelector('[data-testid="preview-find-bar"]');
const count = (c: HTMLElement) => c.querySelector('[data-testid="preview-find-count"]')?.textContent;
const findInput = (c: HTMLElement) => c.querySelector<HTMLInputElement>('input[aria-label="Find in the preview"]')!;

const RECT = { left: 0, top: 0, right: 200, bottom: 100, width: 200, height: 100, x: 0, y: 0, toJSON: () => ({}) } as DOMRect;

describe('TypstPreview lock and find', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.stubGlobal('IntersectionObserver', undefined);
    compileTypstSvg.mockReset();
    compileTypstSvg.mockResolvedValue({ svg: REPORT, diagnostics: [] });
    clearRenderCache();
    // jsdom has no layout: give every element a box so hit-testing and
    // highlight measuring have something to work with.
    vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue(RECT);
    (Range.prototype as unknown as { getClientRects: () => DOMRect[] }).getClientRects = () => [{ ...RECT, left: 10, right: 30, width: 20 } as DOMRect];
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    vi.useRealTimers();
    delete (Range.prototype as unknown as { getClientRects?: unknown }).getClientRects;
  });

  it('jumps to the source when unlocked and ignores clicks when locked', async () => {
    const onRevealSource = vi.fn();
    const { container, rerender } = render(<TypstPreview source="a" onRevealSource={onRevealSource} onToggleLock={() => {}} />);
    await settle();
    fireEvent.click(shadow(container).querySelector('.tsel')!);
    expect(onRevealSource).toHaveBeenCalledTimes(1);

    rerender(<TypstPreview source="a" onRevealSource={onRevealSource} locked onToggleLock={() => {}} />);
    fireEvent.click(shadow(container).querySelector('.tsel')!);
    expect(onRevealSource).toHaveBeenCalledTimes(1);
    expect(container.querySelector('[data-testid="preview-locked-badge"]')?.textContent).toContain('Locked');
    expect(shadow(container).querySelector('.stack.locked')).not.toBeNull();
    expect(pagesArea(container).className).toContain('cursor-text');
  });

  it('toggles the lock from the toolbar and with L while the preview has focus', async () => {
    const onToggleLock = vi.fn();
    const { container, getByRole } = render(<TypstPreview source="a" onToggleLock={onToggleLock} />);
    await settle();
    fireEvent.click(getByRole('button', { name: 'Lock the preview' }));
    expect(onToggleLock).toHaveBeenCalledTimes(1);

    pagesArea(container).focus();
    fireEvent.keyDown(pagesArea(container), { key: 'l', code: 'KeyL' });
    expect(onToggleLock).toHaveBeenCalledTimes(2);

    // Typing an "l" in a text field elsewhere is just typing.
    const outside = document.createElement('input');
    document.body.appendChild(outside);
    outside.focus();
    fireEvent.pointerOver(pagesArea(container));
    fireEvent.keyDown(outside, { key: 'l', code: 'KeyL' });
    expect(onToggleLock).toHaveBeenCalledTimes(2);
    outside.remove();
  });

  it('finds across pages, steps through matches, and closes with Escape', async () => {
    const { container } = render(<TypstPreview source="a" />);
    await settle();
    pagesArea(container).focus();
    const notDefault = fireEvent.keyDown(pagesArea(container), { key: 'f', code: 'KeyF', ctrlKey: true });
    expect(notDefault).toBe(false); // the browser's find never opens
    expect(findBar(container)).not.toBeNull();
    expect(document.activeElement).toBe(findInput(container));

    fireEvent.change(findInput(container), { target: { value: 'beta' } });
    await settle(200);
    expect(count(container)).toBe('1 of 3');
    // Pages 1 and 2 are mounted (no observer here, so all are): every match is drawn.
    expect(shadow(container).querySelectorAll('.find-hit')).toHaveLength(3);
    expect(shadow(container).querySelectorAll('.find-hit.current')).toHaveLength(1);

    fireEvent.keyDown(findInput(container), { key: 'Enter' });
    expect(count(container)).toBe('2 of 3');
    fireEvent.keyDown(findInput(container), { key: 'Enter', shiftKey: true });
    fireEvent.keyDown(findInput(container), { key: 'Enter', shiftKey: true });
    expect(count(container)).toBe('3 of 3');

    fireEvent.click(container.querySelector('button[aria-label="Match case"]')!);
    await settle(200);
    expect(count(container)).toBe('1 of 2');

    fireEvent.keyDown(findInput(container), { key: 'Escape' });
    expect(findBar(container)).toBeNull();
    expect(shadow(container).querySelectorAll('.find-hit')).toHaveLength(0);
  });

  it('searches again when the pages re-render', async () => {
    const { container, rerender } = render(<TypstPreview source="a" />);
    await settle();
    fireEvent.click(container.querySelector('button[aria-label="Find in the preview"]')!);
    fireEvent.change(findInput(container), { target: { value: 'beta' } });
    await settle(200);
    expect(count(container)).toBe('1 of 3');

    compileTypstSvg.mockResolvedValue({ svg: doc([page(1, ['beta beta beta']), page(2, ['Beta'])]), diagnostics: [] });
    rerender(<TypstPreview source="b" />);
    await settle(); // the compile's debounce and result
    await settle(); // then the search's own debounce
    expect(count(container)).toBe('1 of 4');
    expect(shadow(container).querySelectorAll('.find-hit')).toHaveLength(4);
  });

  it('opens with the pointer over the preview, but leaves Ctrl+F to the code editor when it has focus', async () => {
    const { container } = render(<TypstPreview source="a" />);
    await settle();
    const editor = document.createElement('div');
    editor.setAttribute('contenteditable', 'true');
    editor.tabIndex = 0; // jsdom does not make contenteditable focusable on its own
    document.body.appendChild(editor);
    editor.focus();
    fireEvent.pointerOver(pagesArea(container));
    expect(fireEvent.keyDown(editor, { key: 'f', code: 'KeyF', ctrlKey: true })).toBe(true);
    expect(findBar(container)).toBeNull();

    editor.blur();
    editor.remove();
    expect(fireEvent.keyDown(document.body, { key: 'f', code: 'KeyF', metaKey: true })).toBe(false);
    expect(findBar(container)).not.toBeNull();
  });
});
