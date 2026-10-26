import { describe, it, expect } from 'vitest';
import { contrastRatio, parseHex, readableTextOn, relativeLuminance, ON_DARK, ON_LIGHT } from '@/lib/contrast';
import { accentForegroundTriplet, applyThemeColor, type StyleTarget } from '@/lib/theme';

describe('contrast helper', () => {
  it('parses short and long hex, rejects the rest', () => {
    expect(parseHex('#fff')).toEqual([255, 255, 255]);
    expect(parseHex('#ff6c52')).toEqual([255, 108, 82]);
    expect(parseHex('red')).toBeNull();
    expect(parseHex('#12345')).toBeNull();
  });

  it('computes WCAG luminance and ratios', () => {
    expect(relativeLuminance('#000000')).toBe(0);
    expect(relativeLuminance('#ffffff')).toBe(1);
    expect(contrastRatio('#000000', '#ffffff')).toBeCloseTo(21, 5);
    expect(contrastRatio('#777777', '#777777')).toBeCloseTo(1, 5);
    // Known pair: #767676 on white is the classic 4.54.
    expect(contrastRatio('#767676', '#ffffff')).toBeCloseTo(4.54, 2);
  });

  it('picks dark text on pale fills and white on deep ones', () => {
    for (const pale of ['#eab308', '#84cc16', '#22d3ee', '#ff6c52', '#ffffff', '#f59e0b']) {
      expect(readableTextOn(pale), pale).toBe(ON_LIGHT);
    }
    for (const deep of ['#000000', '#1e3a8a', '#7c3aed', '#b91c1c', '#3b3b3b']) {
      expect(readableTextOn(deep), deep).toBe(ON_DARK);
    }
  });

  it('picks the better of the two for every server presence colour', () => {
    // A mid-tone (violet #8b5cf6) cannot reach 4.5:1 with either; the helper
    // must still take the better side, and never fall under 3:1 (AA for the
    // 10px bold cursor flag counts as non-text UI here).
    for (const c of ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6', '#ec4899', '#14b8a6', '#f97316']) {
      const ratio = contrastRatio(readableTextOn(c), c)!;
      const best = Math.max(contrastRatio(ON_LIGHT, c)!, contrastRatio(ON_DARK, c)!);
      expect(ratio, c).toBe(best);
      expect(ratio, c).toBeGreaterThanOrEqual(3);
    }
  });

  it('falls back to white for an unparseable fill', () => {
    expect(readableTextOn('hsl(0 0% 50%)')).toBe(ON_DARK);
  });
});

function fakeStyle(): StyleTarget & { props: Map<string, string> } {
  const props = new Map<string, string>();
  return {
    props,
    setProperty: (k, v) => void props.set(k, v),
    removeProperty: (k) => { props.delete(k); return ''; },
  };
}

describe('admin accent', () => {
  it('writes primary, ring and a contrast-picked foreground', () => {
    const s = fakeStyle();
    applyThemeColor('#eab308', s);
    expect(s.props.get('--primary')).toBe(s.props.get('--ring'));
    expect(s.props.get('--primary-foreground')).toBe('0 0% 7%');
    applyThemeColor('#1e3a8a', s);
    expect(s.props.get('--primary-foreground')).toBe('0 0% 100%');
  });

  it('clears the override when no accent is chosen, so the theme primary shows', () => {
    const s = fakeStyle();
    applyThemeColor('#3b82f6', s);
    applyThemeColor('', s);
    expect([...s.props.keys()]).toEqual([]);
    applyThemeColor('#3b82f6', s);
    applyThemeColor('not-a-colour', s);
    expect(s.props.size).toBe(0);
  });

  it('accentForegroundTriplet matches readableTextOn', () => {
    expect(accentForegroundTriplet('#ffffff')).toBe('0 0% 7%');
    expect(accentForegroundTriplet('#000000')).toBe('0 0% 100%');
  });
});
