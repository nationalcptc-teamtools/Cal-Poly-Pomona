import { describe, it, expect } from 'vitest';
import {
  DEFAULT_THEME_PREFS,
  HEADING_LEVELS,
  resolvePrefs,
  resolveThemePrefs,
  isThemeCustomized,
} from '@/lib/editor-prefs';
import { applyHeadingColors, resolveEffectiveHeadings } from '@/lib/theme';

describe('resolveThemePrefs', () => {
  it('returns the defaults for anything that is not an object', () => {
    expect(resolveThemePrefs(undefined)).toEqual(DEFAULT_THEME_PREFS);
    expect(resolveThemePrefs(null)).toEqual(DEFAULT_THEME_PREFS);
    expect(resolveThemePrefs('#ff0000')).toEqual(DEFAULT_THEME_PREFS);
    expect(resolveThemePrefs([])).toEqual(DEFAULT_THEME_PREFS);
  });

  it('keeps a valid heading colour and per-level overrides', () => {
    const t = resolveThemePrefs({ headingColor: '#ABCDEF', headings: { h1: '#112233', h6: '#445566' } });
    expect(t.headingColor).toBe('#ABCDEF');
    expect(t.headings).toEqual({ h1: '#112233', h6: '#445566' });
  });

  it('drops malformed colours and unknown levels instead of failing', () => {
    const t = resolveThemePrefs({
      headingColor: 'red',
      headings: { h1: '#12345', h2: 42, h7: '#112233', h3: '#abcdef' },
    });
    expect(t.headingColor).toBeNull();
    expect(t.headings).toEqual({ h3: '#abcdef' });
  });

  it('never returns a shared mutable default', () => {
    const a = resolveThemePrefs(undefined);
    a.headings.h1 = '#000000';
    expect(resolveThemePrefs(undefined).headings).toEqual({});
    expect(DEFAULT_THEME_PREFS.headings).toEqual({});
  });

  it('lists the six heading levels in order', () => {
    expect(HEADING_LEVELS).toEqual(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']);
  });
});

describe('resolvePrefs.theme', () => {
  it('defaults to inherit when the account has no theme prefs', () => {
    expect(resolvePrefs({ prefs: { codeAccent: '#ff7b72' } }).theme).toEqual(DEFAULT_THEME_PREFS);
    expect(resolvePrefs(null).theme).toEqual(DEFAULT_THEME_PREFS);
  });

  it('round-trips a stored theme', () => {
    const r = resolvePrefs({ prefs: { theme: { headingColor: '#ff8800', headings: { h2: '#00ff88' } } } });
    expect(r.theme).toEqual({ headingColor: '#ff8800', headings: { h2: '#00ff88' } });
  });
});

describe('isThemeCustomized', () => {
  it('is false for the defaults and true once any colour is set', () => {
    expect(isThemeCustomized(DEFAULT_THEME_PREFS)).toBe(false);
    expect(isThemeCustomized({ headingColor: '#ffffff', headings: {} })).toBe(true);
    expect(isThemeCustomized({ headingColor: null, headings: { h4: '#ffffff' } })).toBe(true);
  });
});

describe('resolveEffectiveHeadings', () => {
  const admin = { headingColor: '#aaaaaa', headings: { h1: '#a1a1a1' } };
  const user = { headingColor: '#bbbbbb', headings: { h2: '#b2b2b2' } };

  it('uses the admin colours when the lock is on, whatever the user chose', () => {
    const r = resolveEffectiveHeadings({ headings: admin, lock: true }, user);
    expect(r.locked).toBe(true);
    expect(r.headings).toEqual(admin);
  });

  it('lets a customised user theme replace the admin defaults when unlocked', () => {
    const r = resolveEffectiveHeadings({ headings: admin, lock: false }, user);
    expect(r.locked).toBe(false);
    expect(r.headings).toEqual(user);
  });

  it('falls back to the admin defaults for a user who never customised', () => {
    const r = resolveEffectiveHeadings({ headings: admin, lock: false }, DEFAULT_THEME_PREFS);
    expect(r.headings).toEqual(admin);
  });

  it('falls back to inherit when there is no policy at all', () => {
    const r = resolveEffectiveHeadings(null, DEFAULT_THEME_PREFS);
    expect(r).toEqual({ headings: DEFAULT_THEME_PREFS, locked: false });
  });
});

describe('applyHeadingColors', () => {
  function fakeStyle() {
    const vars = new Map<string, string>();
    return {
      vars,
      setProperty: (k: string, v: string) => { vars.set(k, v); },
      removeProperty: (k: string) => { vars.delete(k); },
    };
  }

  it('writes one variable per configured colour and clears the rest', () => {
    const s = fakeStyle();
    applyHeadingColors({ headingColor: '#123456', headings: { h3: '#654321' } }, s);
    expect(s.vars.get('--heading-color')).toBe('#123456');
    expect(s.vars.get('--heading-3')).toBe('#654321');
    expect(s.vars.has('--heading-1')).toBe(false);

    applyHeadingColors(DEFAULT_THEME_PREFS, s);
    expect(s.vars.size).toBe(0);
  });

  it('removes a level that was set before and is now absent', () => {
    const s = fakeStyle();
    applyHeadingColors({ headingColor: null, headings: { h1: '#111111', h2: '#222222' } }, s);
    applyHeadingColors({ headingColor: null, headings: { h2: '#222222' } }, s);
    expect([...s.vars.keys()]).toEqual(['--heading-2']);
  });
});
