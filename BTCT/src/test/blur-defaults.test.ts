import { describe, it, expect } from 'vitest';
import { resolveBlurStrengthPolicy, resolvePrefs } from '@/lib/editor-prefs';
import {
  DEFAULT_BLUR_STRENGTH,
  DEFAULT_BLUR_STYLE,
  effectiveStrength,
  effectiveStyle,
  MAX_STRENGTH,
  MIN_STRENGTH,
} from '@/lib/blur-math';

describe('resolveBlurStrengthPolicy', () => {
  it('falls back builtin → admin → user, per style', () => {
    expect(resolveBlurStrengthPolicy(null, { gaussian: null, pixelate: null }))
      .toEqual({ gaussian: DEFAULT_BLUR_STRENGTH, pixelate: DEFAULT_BLUR_STRENGTH });
    expect(resolveBlurStrengthPolicy({ gaussian: 2, pixelate: 0.5 }, { gaussian: null, pixelate: null }))
      .toEqual({ gaussian: 2, pixelate: 0.5 });
    expect(resolveBlurStrengthPolicy({ gaussian: 2, pixelate: 0.5 }, { gaussian: 1.5, pixelate: null }))
      .toEqual({ gaussian: 1.5, pixelate: 0.5 });
  });

  it('clamps out-of-range and drops malformed values', () => {
    expect(resolveBlurStrengthPolicy({ gaussian: 99, pixelate: 0 }, { gaussian: null, pixelate: null }))
      .toEqual({ gaussian: 3, pixelate: 0.25 });
    expect(resolveBlurStrengthPolicy(
      { gaussian: Number.NaN } as { gaussian: number },
      { gaussian: null, pixelate: null },
    ).gaussian).toBe(DEFAULT_BLUR_STRENGTH);
  });
});

describe('resolvePrefs blurDefaults', () => {
  it('defaults to inherit and keeps valid stored values', () => {
    expect(resolvePrefs(null).blurDefaults).toEqual({ gaussian: null, pixelate: null });
    expect(resolvePrefs({ prefs: { blurDefaults: { gaussian: 2.5, pixelate: null } } }).blurDefaults)
      .toEqual({ gaussian: 2.5, pixelate: null });
  });

  it('drops malformed values back to inherit', () => {
    const prefs = { blurDefaults: { gaussian: 'strong', pixelate: 7 } } as never;
    expect(resolvePrefs({ prefs }).blurDefaults).toEqual({ gaussian: null, pixelate: 3 });
  });
});

describe('what a newly drawn region starts as', () => {
  it('is pixelate at 40 percent', () => {
    expect(DEFAULT_BLUR_STYLE).toBe('pixelate');
    expect(DEFAULT_BLUR_STRENGTH).toBe(0.4);
    // The dialog prints the strength as a percentage.
    expect(Math.round(DEFAULT_BLUR_STRENGTH * 100)).toBe(40);
  });

  it('sits inside the supported range', () => {
    expect(DEFAULT_BLUR_STRENGTH).toBeGreaterThanOrEqual(MIN_STRENGTH);
    expect(DEFAULT_BLUR_STRENGTH).toBeLessThanOrEqual(MAX_STRENGTH);
  });

  it('does not change how already-saved regions render', () => {
    // Records written before these fields existed must keep looking the same:
    // the new default applies to new regions only.
    expect(effectiveStyle({ x: 0, y: 0, w: 0.1, h: 0.1 })).toBe('gaussian');
    expect(effectiveStrength({ x: 0, y: 0, w: 0.1, h: 0.1 })).toBe(1);
  });
});
