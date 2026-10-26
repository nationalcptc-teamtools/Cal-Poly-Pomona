// ─────────────────────────────────────────────────────────────────────────
// Per-account editor preferences.
//
// Customizable on a per-account basis:
//   1. `codeAccent`: the base color that tints code-block syntax highlighting
//      (see src/lib/code-theme.ts `applyCodeAccent`).
//   2. `keybinds`: shortcuts for the floating-format-panel actions plus the
//      "focus the code-block language picker" action (see editor-keybinds.ts).
//   3. `follow`: live-follow precision and pane placement.
//   4. `theme`: note heading colours (see src/lib/theme.ts
//      `applyHeadingColors`; an admin can override or hard-lock these).
//
// Prefs are persisted server-side on the user row (JSON blob) and arrive on the
// `AuthUser.prefs` field. The defaults below are merged under whatever the
// account has saved so a brand-new / never-customized account still works.
// ─────────────────────────────────────────────────────────────────────────

import { DEFAULT_BLUR_STRENGTH, MAX_STRENGTH, MIN_STRENGTH } from './blur-math';
import { DEFAULT_EDITOR_STYLE, resolveEditorStyle, type EditorStyle } from '@/components/editor/live-preview/editor-style';

export type KeybindAction =
  | 'bold'
  | 'italic'
  | 'strikethrough'
  | 'inlineCode'
  | 'link'
  | 'highlight'
  | 'focusLanguage'
  // Global (non-editor) shortcut: open the "active users / follow" window.
  | 'openFollowPanel'
  // Editor shortcut: blur/crop the selected note image.
  | 'blurImage';

/** How precisely to mirror a teammate when following them. */
export type FollowPrecision = 'precise' | 'view';

/**
 * How a followed view is laid out when you already have split panes:
 *   • 'split'   : drop the followed view into your active pane, keeping panes.
 *   • 'takeover': collapse to a single pane showing the followed view.
 *   • null      : not yet chosen; prompt the first time you follow while split.
 */
export type FollowPanePlacement = 'split' | 'takeover' | null;

export interface FollowPrefs {
  /** Default precision for teammates with no explicit override. */
  defaultPrecision: FollowPrecision;
  /** Per-teammate precision overrides, keyed by user id (as a string). */
  precisionByUserId: Record<string, FollowPrecision>;
  /** Remembered pane-placement choice (see FollowPanePlacement). */
  panePlacement: FollowPanePlacement;
}

export type HeadingLevel = 'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6';
export const HEADING_LEVELS: readonly HeadingLevel[] = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'];

/**
 * Note heading colours. `headingColor` applies to every level; `headings`
 * holds per-level overrides that win over it. `null` / absent means "inherit
 * the body text colour", which is what a fresh account gets.
 */
export interface ThemePrefs {
  headingColor: string | null;
  headings: Partial<Record<HeadingLevel, string>>;
}

/**
 * Per-account default strength for new blur (redaction) regions, one value
 * per style. `null` means "follow the workspace default" (the admin policy,
 * falling back to 1). Existing regions are never re-interpreted: the default
 * is stamped onto a region when it is drawn.
 */
export interface BlurDefaults {
  gaussian: number | null;
  pixelate: number | null;
}

/** How wide the note content column renders. 'default' matches the original fixed width. */
export type NoteWidth = 'narrow' | 'default' | 'wide' | 'full';
export const NOTE_WIDTHS: readonly NoteWidth[] = ['narrow', 'default', 'wide', 'full'];

/** CSS `max-width` value per preset; 'full' has no cap (the page's own padding still applies). */
export const NOTE_WIDTH_CSS: Record<NoteWidth, string> = {
  narrow: '40rem',
  default: 'var(--editor-width)', // 768px, the theme's editor width (tokens.css)
  wide: '64rem',
  full: 'none',
};

export interface EditorPrefs {
  /** #RRGGBB base color for code-block syntax highlighting. */
  codeAccent: string;
  /** Action → canonical shortcut string (e.g. "Mod-Shift-l"). */
  keybinds: Record<KeybindAction, string>;
  /** Live-follow preferences (presence / spectate feature). */
  follow: FollowPrefs;
  /** Note heading colours. */
  theme: ThemePrefs;
  /** Default strength for new blur regions (null = workspace default). */
  blurDefaults: BlurDefaults;
  /** How wide the note content column renders. */
  noteWidth: NoteWidth;
  /** Editor style: 'live' (Obsidian live preview, the default) or 'blocks' (Notion). */
  editorStyle: EditorStyle;
}

// GitHub Dark's keyword color. The rest of the code palette is fixed GitHub
// Dark (see index.css); the accent retints keywords, so this default makes a
// fresh account render as pure GitHub Dark until it's changed.
export const DEFAULT_CODE_ACCENT = '#ff7b72';

export const DEFAULT_KEYBINDS: Record<KeybindAction, string> = {
  bold: 'Mod-b',
  italic: 'Mod-i',
  strikethrough: 'Mod-Shift-x',
  inlineCode: 'Mod-e',
  link: 'Mod-Shift-k',
  highlight: 'Mod-Shift-h',
  // Not a Ctrl/Cmd+Shift+letter combo: that space is crowded by browser,
  // extension and password-manager shortcuts (Bitwarden/LastPass auto-fill on
  // Ctrl+Shift+L, and Ctrl+Shift+Y was intercepted too), which swallow the
  // keydown before the page sees it, so the picker looked dead even with the
  // caret inside a code block. Mod-/ sits outside all of that. See
  // RETIRED_KEYBINDS below.
  focusLanguage: 'Mod-/',
  openFollowPanel: 'Mod-Shift-u',
  blurImage: 'Mod-Shift-b',
};

// Defaults we have moved away from. `resolvePrefs` treats a stored binding that
// still equals one of these as "never customised" and re-points it at the
// current default, so a profile saved under an old default follows the change.
// focusLanguage went Mod-Shift-l -> Mod-Shift-y -> Mod-/ (both earlier keys were
// eaten by browser / password-manager shortcuts before the page saw them).
export const RETIRED_KEYBINDS: Partial<Record<KeybindAction, string[]>> = {
  focusLanguage: ['Mod-Shift-l', 'Mod-Shift-y'],
};

export const DEFAULT_FOLLOW_PREFS: FollowPrefs = {
  defaultPrecision: 'precise',
  precisionByUserId: {},
  panePlacement: null,
};

export const DEFAULT_THEME_PREFS: ThemePrefs = Object.freeze({
  headingColor: null,
  headings: Object.freeze({}),
}) as ThemePrefs;

export const DEFAULT_BLUR_DEFAULTS: BlurDefaults = Object.freeze({
  gaussian: null,
  pixelate: null,
}) as BlurDefaults;

export const DEFAULT_NOTE_WIDTH: NoteWidth = 'default';

export const DEFAULT_EDITOR_PREFS: EditorPrefs = {
  codeAccent: DEFAULT_CODE_ACCENT,
  keybinds: { ...DEFAULT_KEYBINDS },
  follow: { ...DEFAULT_FOLLOW_PREFS, precisionByUserId: {} },
  theme: { headingColor: null, headings: {} },
  blurDefaults: { gaussian: null, pixelate: null },
  noteWidth: DEFAULT_NOTE_WIDTH,
  editorStyle: DEFAULT_EDITOR_STYLE,
};

// Human-readable labels + display order for the keybinds dialog.
export const KEYBIND_ACTIONS: ReadonlyArray<{ id: KeybindAction; label: string }> = [
  { id: 'bold', label: 'Bold' },
  { id: 'italic', label: 'Italic' },
  { id: 'strikethrough', label: 'Strikethrough' },
  { id: 'inlineCode', label: 'Inline code' },
  { id: 'link', label: 'Link' },
  { id: 'highlight', label: 'Highlight (last color)' },
  { id: 'focusLanguage', label: 'Focus code language' },
  { id: 'openFollowPanel', label: 'Active users / follow' },
  { id: 'blurImage', label: 'Blur / edit selected image' },
];

const HEX_RE = /^#[0-9a-fA-F]{6}$/;

/**
 * Validate a theme blob from anywhere (account prefs, the admin settings
 * row, an imported file). Malformed colours and unknown levels are dropped
 * rather than rejected so one bad key never blanks the whole theme. Always
 * returns a fresh object.
 */
export function resolveThemePrefs(raw: unknown): ThemePrefs {
  const out: ThemePrefs = { headingColor: null, headings: {} };
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return out;
  const r = raw as Record<string, unknown>;
  if (typeof r.headingColor === 'string' && HEX_RE.test(r.headingColor)) {
    out.headingColor = r.headingColor;
  }
  const levels = r.headings;
  if (levels && typeof levels === 'object' && !Array.isArray(levels)) {
    for (const level of HEADING_LEVELS) {
      const v = (levels as Record<string, unknown>)[level];
      if (typeof v === 'string' && HEX_RE.test(v)) out.headings[level] = v;
    }
  }
  return out;
}

/** True once the user has set any heading colour (so their theme should replace the admin default). */
export function isThemeCustomized(theme: ThemePrefs): boolean {
  return theme.headingColor !== null || Object.keys(theme.headings).length > 0;
}

interface MaybeUser {
  prefs?: Partial<EditorPrefs> | null;
}

/**
 * Merge an account's stored prefs over the defaults, dropping anything
 * malformed. Always returns a complete, valid `EditorPrefs`.
 */
export function resolvePrefs(user: MaybeUser | null | undefined): EditorPrefs {
  const stored = user?.prefs ?? {};
  const codeAccent =
    typeof stored.codeAccent === 'string' && HEX_RE.test(stored.codeAccent)
      ? stored.codeAccent
      : DEFAULT_CODE_ACCENT;

  const keybinds: Record<KeybindAction, string> = { ...DEFAULT_KEYBINDS };
  const storedKb = stored.keybinds;
  if (storedKb && typeof storedKb === 'object') {
    for (const { id } of KEYBIND_ACTIONS) {
      const v = (storedKb as Record<string, unknown>)[id];
      if (typeof v === 'string' && v.trim()) keybinds[id] = v;
    }
  }
  // Migrate retired defaults. The keybinds dialog and profile editor both save
  // the whole map, so a profile saved before a default changed still pins the
  // old value; move those onto the current default. focusLanguage left
  // Mod-Shift-l because password managers (Bitwarden/LastPass) auto-fill on it.
  for (const [id, retired] of Object.entries(RETIRED_KEYBINDS) as [KeybindAction, string[]][]) {
    if (retired.includes(keybinds[id])) keybinds[id] = DEFAULT_KEYBINDS[id];
  }

  const follow: FollowPrefs = {
    defaultPrecision: DEFAULT_FOLLOW_PREFS.defaultPrecision,
    precisionByUserId: {},
    panePlacement: DEFAULT_FOLLOW_PREFS.panePlacement,
  };
  const storedFollow = stored.follow;
  if (storedFollow && typeof storedFollow === 'object' && !Array.isArray(storedFollow)) {
    const sf = storedFollow as unknown as Record<string, unknown>;
    if (sf.defaultPrecision === 'precise' || sf.defaultPrecision === 'view') {
      follow.defaultPrecision = sf.defaultPrecision;
    }
    if (sf.panePlacement === 'split' || sf.panePlacement === 'takeover') {
      follow.panePlacement = sf.panePlacement;
    }
    if (sf.precisionByUserId && typeof sf.precisionByUserId === 'object' && !Array.isArray(sf.precisionByUserId)) {
      for (const [uid, v] of Object.entries(sf.precisionByUserId as Record<string, unknown>)) {
        if (v === 'precise' || v === 'view') follow.precisionByUserId[uid] = v;
      }
    }
  }

  const theme = resolveThemePrefs(stored.theme);
  const blurDefaults = resolveBlurDefaults(stored.blurDefaults);
  const noteWidth = resolveNoteWidth(stored.noteWidth);
  const editorStyle = resolveEditorStyle(stored.editorStyle);
  return { codeAccent, keybinds, follow, theme, blurDefaults, noteWidth, editorStyle };
}

/** Validate a stored noteWidth value: anything not one of the presets falls back to the default. */
export function resolveNoteWidth(raw: unknown): NoteWidth {
  return (NOTE_WIDTHS as readonly unknown[]).includes(raw) ? (raw as NoteWidth) : DEFAULT_NOTE_WIDTH;
}

/** Change the note content column's width without touching any open editor. */
export function applyNoteWidth(width: NoteWidth): void {
  if (typeof document === 'undefined') return;
  document.documentElement.style.setProperty('--note-width', NOTE_WIDTH_CSS[width]);
}

/** Validate a stored blurDefaults blob: numbers clamp to range, junk inherits. */
export function resolveBlurDefaults(raw: unknown): BlurDefaults {
  const out: BlurDefaults = { gaussian: null, pixelate: null };
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return out;
  for (const key of ['gaussian', 'pixelate'] as const) {
    const v = (raw as Record<string, unknown>)[key];
    if (typeof v === 'number' && Number.isFinite(v)) {
      out[key] = Math.min(Math.max(v, MIN_STRENGTH), MAX_STRENGTH);
    }
  }
  return out;
}

/**
 * The strengths a new blur region starts with: the user's own default per
 * style, else the admin's workspace default, else 1. Everything clamps to
 * the supported range and malformed values fall through to the next tier.
 */
export function resolveBlurStrengthPolicy(
  admin: { gaussian?: number; pixelate?: number } | null | undefined,
  user: BlurDefaults,
): { gaussian: number; pixelate: number } {
  const pick = (v: unknown, fallback: number): number =>
    typeof v === 'number' && Number.isFinite(v)
      ? Math.min(Math.max(v, MIN_STRENGTH), MAX_STRENGTH)
      : fallback;
  return {
    gaussian: pick(user.gaussian, pick(admin?.gaussian, DEFAULT_BLUR_STRENGTH)),
    pixelate: pick(user.pixelate, pick(admin?.pixelate, DEFAULT_BLUR_STRENGTH)),
  };
}

// ── Shortcut parsing / matching ──────────────────────────────────────────
//
// Canonical form: hyphen-joined modifiers followed by a key, e.g.
// "Mod-Shift-l". "Mod" means ⌘ on macOS / Ctrl elsewhere. Matching mirrors
// the Ctrl+K handling in src/App.tsx (metaKey || ctrlKey).

export interface ParsedShortcut {
  mod: boolean;
  shift: boolean;
  alt: boolean;
  key: string; // lowercased
}

export function parseShortcut(shortcut: string): ParsedShortcut | null {
  const parts = shortcut.split('-').map((p) => p.trim()).filter(Boolean);
  if (parts.length === 0) return null;
  const key = parts.pop()!.toLowerCase();
  let mod = false;
  let shift = false;
  let alt = false;
  for (const p of parts) {
    switch (p.toLowerCase()) {
      case 'mod':
      case 'ctrl':
      case 'cmd':
      case 'meta':
        mod = true;
        break;
      case 'shift':
        shift = true;
        break;
      case 'alt':
      case 'option':
        alt = true;
        break;
      default:
        return null; // unknown modifier token
    }
  }
  return { mod, shift, alt, key };
}

const MODIFIER_KEYS = new Set(['control', 'shift', 'alt', 'meta', 'os']);

/** True when a keyboard event exactly matches a canonical shortcut string. */
export function matchShortcut(
  event: Pick<KeyboardEvent, 'key' | 'ctrlKey' | 'metaKey' | 'shiftKey' | 'altKey'>,
  shortcut: string,
): boolean {
  const parsed = parseShortcut(shortcut);
  if (!parsed) return false;
  const eventKey = event.key.toLowerCase();
  if (MODIFIER_KEYS.has(eventKey)) return false; // a modifier by itself never matches
  return (
    parsed.mod === (event.ctrlKey || event.metaKey) &&
    parsed.shift === event.shiftKey &&
    parsed.alt === event.altKey &&
    parsed.key === eventKey
  );
}

/**
 * Build a canonical shortcut string from a captured keydown, or null when the
 * event is only a modifier (so the capture UI keeps waiting for a real key).
 */
export function shortcutFromEvent(
  event: Pick<KeyboardEvent, 'key' | 'ctrlKey' | 'metaKey' | 'shiftKey' | 'altKey'>,
): string | null {
  const key = event.key.toLowerCase();
  if (MODIFIER_KEYS.has(key)) return null;
  const parts: string[] = [];
  if (event.ctrlKey || event.metaKey) parts.push('Mod');
  if (event.shiftKey) parts.push('Shift');
  if (event.altKey) parts.push('Alt');
  parts.push(key.length === 1 ? key : key);
  return parts.join('-');
}

/** Pretty-print a shortcut for display (e.g. "Mod-Shift-l" → "Ctrl/⌘ + Shift + L"). */
export function formatShortcut(shortcut: string): string {
  const parsed = parseShortcut(shortcut);
  if (!parsed) return shortcut;
  const parts: string[] = [];
  if (parsed.mod) parts.push('Ctrl/⌘');
  if (parsed.shift) parts.push('Shift');
  if (parsed.alt) parts.push('Alt');
  parts.push(parsed.key.length === 1 ? parsed.key.toUpperCase() : parsed.key);
  return parts.join(' + ');
}
