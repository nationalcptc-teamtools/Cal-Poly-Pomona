// Invariant #3c, enforced for the crop window's two gestures.
//
// A pointer device fires several hundred events a second; a display shows 60.
// Both drags here therefore write to the DOM (or coalesce) per animation frame
// and touch React state only at the end. These assertions count work, not
// milliseconds, so they hold on any machine.
//
// The blur drag used to call setState on every pointermove and resize a
// `backdrop-filter` element with it, which made the compositor re-blur two
// full-size images per sample. It cost 3.2 ms per event with a dozen regions
// already drawn, in jsdom, which does no layout or paint at all.
import { describe, it, expect, beforeEach } from 'vitest';
import { render, cleanup } from '@testing-library/react';
import { Profiler, act } from 'react';
import { FigureViewport } from '@/components/assets/FigureViewport';
import type { BlurRegion, CropRect } from '@/types';

const CROP: CropRect = { x: 0.1, y: 0.1, w: 0.6, h: 0.6 };

function regions(n: number): BlurRegion[] {
  return Array.from({ length: n }, (_, i) => ({
    x: 0.05 + (i % 5) * 0.17, y: 0.05 + Math.floor(i / 5) * 0.17, w: 0.14, h: 0.09,
  }));
}

function fire(el: Element, type: string, x: number, y: number) {
  const ev = new MouseEvent(type, { clientX: x, clientY: y, bubbles: true, cancelable: true });
  Object.defineProperty(ev, 'pointerId', { value: 1 });
  el.dispatchEvent(ev);
}

/**
 * container > host > surface. The pointer handlers live on the surface.
 *
 * jsdom reports a zero-sized rect for everything, and the component converts
 * a pointer position to frame coordinates through that rect, so every event
 * would land at (0, 0) and no drag would ever have a size. Give the surface a
 * real box.
 */
function surfaceOf(container: HTMLElement): Element {
  const el = container.firstElementChild?.firstElementChild;
  if (!el) throw new Error('viewport surface not rendered');
  el.getBoundingClientRect = () => ({
    x: 0, y: 0, left: 0, top: 0, right: 400, bottom: 300, width: 400, height: 300,
    toJSON: () => ({}),
  }) as DOMRect;
  return el;
}

beforeEach(cleanup);

describe('drawing a blur region', () => {
  it('does not re-render while the pointer moves', () => {
    let commits = 0;
    const added: BlurRegion[] = [];
    const { container } = render(
      <Profiler id="v" onRender={() => { commits++; }}>
        <FigureViewport
          imageUrl="data:," crop={CROP} boxAspect={1.5} onCropChange={() => {}}
          blurMode blurs={regions(12)} onAddBlur={(r) => added.push(r)}
        />
      </Profiler>,
    );
    const surface = surfaceOf(container);

    act(() => { fire(surface, 'pointerdown', 60, 40); });
    commits = 0;
    for (let i = 0; i < 200; i++) act(() => { fire(surface, 'pointermove', 60 + i, 40 + i); });

    expect(commits, 'a blur drag must not re-render per pointermove').toBe(0);
  });

  it('still commits the region it drew', () => {
    const added: BlurRegion[] = [];
    const { container } = render(
      <FigureViewport
        imageUrl="data:," crop={CROP} boxAspect={1.5} onCropChange={() => {}}
        blurMode blurs={[]} onAddBlur={(r) => added.push(r)}
      />,
    );
    const surface = surfaceOf(container);

    act(() => { fire(surface, 'pointerdown', 2, 2); });
    act(() => { fire(surface, 'pointermove', 30, 20); });
    act(() => { fire(surface, 'pointerup', 30, 20); });

    expect(added).toHaveLength(1);
    expect(added[0]!.w).toBeGreaterThan(0);
    expect(added[0]!.h).toBeGreaterThan(0);
  });

  it('draws the draft rectangle without a backdrop filter', () => {
    // A backdrop-filter that resizes every frame is the specific thing that
    // made this stutter: it forces a full backdrop re-blur per sample.
    const { container } = render(
      <FigureViewport
        imageUrl="data:," crop={CROP} boxAspect={1.5} onCropChange={() => {}}
        blurMode blurs={[]} onAddBlur={() => {}}
      />,
    );
    const surface = surfaceOf(container);
    act(() => { fire(surface, 'pointerdown', 5, 5); });
    act(() => { fire(surface, 'pointermove', 40, 30); });

    for (const el of Array.from(container.querySelectorAll<HTMLElement>('*'))) {
      expect(el.style.backdropFilter || '').toBe('');
    }
  });
});

describe('panning the image', () => {
  it('coalesces a burst of moves into far fewer crop updates', () => {
    let calls = 0;
    const { container } = render(
      <FigureViewport
        imageUrl="data:," crop={CROP} boxAspect={1.5} onCropChange={() => { calls++; }}
      />,
    );
    const surface = surfaceOf(container);

    act(() => { fire(surface, 'pointerdown', 100, 100); });
    calls = 0;
    for (let i = 0; i < 200; i++) act(() => { fire(surface, 'pointermove', 100 + i, 100 + i); });

    expect(calls, 'a pan must not push a crop update per pointermove').toBeLessThan(200);
  });

  it('lands the final position on pointer-up rather than a frame later', () => {
    const seen: CropRect[] = [];
    const { container } = render(
      <FigureViewport
        imageUrl="data:," crop={CROP} boxAspect={1.5} onCropChange={(c) => seen.push(c)}
      />,
    );
    const surface = surfaceOf(container);

    act(() => { fire(surface, 'pointerdown', 100, 100); });
    act(() => { fire(surface, 'pointermove', 140, 130); });
    act(() => { fire(surface, 'pointerup', 140, 130); });

    expect(seen.length).toBeGreaterThan(0);
    expect(seen[seen.length - 1]!.x).not.toBe(CROP.x);
  });
});
