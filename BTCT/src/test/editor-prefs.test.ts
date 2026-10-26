import { describe, it, expect } from 'vitest';
import {
  DEFAULT_CODE_ACCENT,
  DEFAULT_KEYBINDS,
  DEFAULT_NOTE_WIDTH,
  resolvePrefs,
  resolveNoteWidth,
  parseShortcut,
  matchShortcut,
  shortcutFromEvent,
  formatShortcut,
} from '@/lib/editor-prefs';

// Minimal stand-in for the fields matchShortcut / shortcutFromEvent read.
function kev(
  key: string,
  mods: { ctrl?: boolean; meta?: boolean; shift?: boolean; alt?: boolean } = {},
) {
  return {
    key,
    ctrlKey: !!mods.ctrl,
    metaKey: !!mods.meta,
    shiftKey: !!mods.shift,
    altKey: !!mods.alt,
  };
}

describe('resolvePrefs', () => {
  it('falls back to defaults for a user with no prefs', () => {
    const prefs = resolvePrefs(null);
    expect(prefs.codeAccent).toBe(DEFAULT_CODE_ACCENT);
    expect(prefs.keybinds).toEqual(DEFAULT_KEYBINDS);
  });

  it('merges stored keybinds over the defaults', () => {
    const prefs = resolvePrefs({ prefs: { keybinds: { bold: 'Mod-Alt-b' } as never } });
    expect(prefs.keybinds.bold).toBe('Mod-Alt-b');
    expect(prefs.keybinds.italic).toBe(DEFAULT_KEYBINDS.italic); // untouched
  });

  it('drops a malformed code accent', () => {
    const prefs = resolvePrefs({ prefs: { codeAccent: 'not-a-hex' } });
    expect(prefs.codeAccent).toBe(DEFAULT_CODE_ACCENT);
  });

  it('keeps a valid code accent', () => {
    const prefs = resolvePrefs({ prefs: { codeAccent: '#00ff88' } });
    expect(prefs.codeAccent).toBe('#00ff88');
  });

  it('falls back to the default note width for a user with no prefs', () => {
    expect(resolvePrefs(null).noteWidth).toBe(DEFAULT_NOTE_WIDTH);
  });

  it('keeps a valid stored note width', () => {
    expect(resolvePrefs({ prefs: { noteWidth: 'wide' } }).noteWidth).toBe('wide');
  });

  it('drops a malformed note width', () => {
    expect(resolvePrefs({ prefs: { noteWidth: 'huge' as never } }).noteWidth).toBe(DEFAULT_NOTE_WIDTH);
  });

  it('includes the openFollowPanel keybind by default', () => {
    expect(resolvePrefs(null).keybinds.openFollowPanel).toBe(DEFAULT_KEYBINDS.openFollowPanel);
  });

  it('defaults the language picker off the intercepted Ctrl+Shift+letter space', () => {
    expect(DEFAULT_KEYBINDS.focusLanguage).toBe('Mod-/');
    expect(resolvePrefs(null).keybinds.focusLanguage).toBe('Mod-/');
  });

  it('migrates a profile that pinned either retired language shortcut', () => {
    // A profile saved before a change persists the whole map, so it still
    // carries the old key; resolvePrefs re-points both retired keys at the new
    // default (Mod-Shift-l and the short-lived Mod-Shift-y).
    for (const old of ['Mod-Shift-l', 'Mod-Shift-y']) {
      const prefs = resolvePrefs({ prefs: { keybinds: { focusLanguage: old } as never } });
      expect(prefs.keybinds.focusLanguage).toBe(DEFAULT_KEYBINDS.focusLanguage);
    }
  });

  it('keeps a language shortcut the user deliberately rebound to something else', () => {
    const prefs = resolvePrefs({ prefs: { keybinds: { focusLanguage: 'Mod-Alt-l' } as never } });
    expect(prefs.keybinds.focusLanguage).toBe('Mod-Alt-l');
  });

  it('defaults follow prefs to precise / no overrides / unset placement', () => {
    const follow = resolvePrefs(null).follow;
    expect(follow.defaultPrecision).toBe('precise');
    expect(follow.precisionByUserId).toEqual({});
    expect(follow.panePlacement).toBeNull();
  });

  it('merges valid follow prefs and drops malformed ones', () => {
    const follow = resolvePrefs({
      prefs: {
        follow: {
          defaultPrecision: 'view',
          panePlacement: 'takeover',
          precisionByUserId: { '7': 'precise', '9': 'bogus' },
        },
      } as never,
    }).follow;
    expect(follow.defaultPrecision).toBe('view');
    expect(follow.panePlacement).toBe('takeover');
    expect(follow.precisionByUserId['7']).toBe('precise');
    expect(follow.precisionByUserId['9']).toBeUndefined(); // malformed dropped
  });

  it('ignores an invalid panePlacement value', () => {
    const follow = resolvePrefs({
      prefs: { follow: { panePlacement: 'sideways' } } as never,
    }).follow;
    expect(follow.panePlacement).toBeNull();
  });
});

describe('resolveNoteWidth', () => {
  it('accepts each valid preset', () => {
    expect(resolveNoteWidth('narrow')).toBe('narrow');
    expect(resolveNoteWidth('default')).toBe('default');
    expect(resolveNoteWidth('wide')).toBe('wide');
    expect(resolveNoteWidth('full')).toBe('full');
  });

  it('falls back to the default for anything else', () => {
    expect(resolveNoteWidth('huge')).toBe(DEFAULT_NOTE_WIDTH);
    expect(resolveNoteWidth(null)).toBe(DEFAULT_NOTE_WIDTH);
    expect(resolveNoteWidth(undefined)).toBe(DEFAULT_NOTE_WIDTH);
    expect(resolveNoteWidth(42)).toBe(DEFAULT_NOTE_WIDTH);
  });
});

describe('parseShortcut', () => {
  it('parses modifiers and key', () => {
    expect(parseShortcut('Mod-Shift-l')).toEqual({ mod: true, shift: true, alt: false, key: 'l' });
  });
  it('treats Ctrl/Cmd/Meta as Mod', () => {
    expect(parseShortcut('Ctrl-b')?.mod).toBe(true);
    expect(parseShortcut('Cmd-b')?.mod).toBe(true);
  });
  it('rejects unknown modifier tokens', () => {
    expect(parseShortcut('Hyper-x')).toBeNull();
  });
});

describe('matchShortcut', () => {
  it('matches an exact modifier combination', () => {
    expect(matchShortcut(kev('b', { ctrl: true }), 'Mod-b')).toBe(true);
    expect(matchShortcut(kev('B', { meta: true }), 'Mod-b')).toBe(true); // case-insensitive key
  });
  it('does not match when an extra modifier is held', () => {
    expect(matchShortcut(kev('b', { ctrl: true, shift: true }), 'Mod-b')).toBe(false);
  });
  it('never matches a bare modifier key', () => {
    expect(matchShortcut(kev('Shift', { shift: true }), 'Mod-Shift-l')).toBe(false);
  });
});

describe('shortcutFromEvent', () => {
  it('builds a canonical string from a keydown', () => {
    expect(shortcutFromEvent(kev('L', { ctrl: true, shift: true }))).toBe('Mod-Shift-l');
  });
  it('returns null while only a modifier is held', () => {
    expect(shortcutFromEvent(kev('Control', { ctrl: true }))).toBeNull();
  });
});

describe('formatShortcut', () => {
  it('pretty-prints a shortcut', () => {
    expect(formatShortcut('Mod-Shift-l')).toBe('Ctrl/⌘ + Shift + L');
  });
});
