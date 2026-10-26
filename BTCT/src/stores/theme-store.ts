/**
 * Global theme store. The accent colour and the admin heading-colour policy
 * (default heading colours for everyone, plus the hard-lock) live in the
 * server's SQLite settings table so every LAN client sees the same theme.
 * The store seeds from `GET /api/settings` on app start, then follows the
 * server-written `settingsPublic.theme` mirror in the shared doc (wired in
 * shared-bindings.ts) so an admin change re-themes every connected client
 * without a reload. `updatedAt` is the server's stamp for the last change:
 * a payload older than what we already hold (a stale mirror copy replayed
 * from IndexedDB) is ignored.
 *
 * Side-effect: every accepted payload paints the accent onto :root via
 * applyThemeColor ('' = no accent chosen, the theme primary shows). Heading colours are painted by App.tsx, which combines
 * this policy with the user's own prefs through resolveEffectiveHeadings.
 */
import { create } from 'zustand';
import { useAuthStore } from '@/auth/auth-store';
import { applyThemeColor, DEFAULT_THEME_COLOR } from '@/lib/theme';
import { resolveThemePrefs, type ThemePrefs } from '@/lib/editor-prefs';
import { DEFAULT_BLUR_STRENGTH } from '@/lib/blur-math';
import { DEFAULT_FEATURES, resolveFeatures, type Features } from '@/lib/features';

function apiUrl(): string {
  if (typeof window === 'undefined') return 'http://127.0.0.1:1234';
  const fromEnv = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, '');
  return fromEnv || window.location.origin;
}

/** Shape of GET /api/settings and of the `settingsPublic.theme` mirror. */
export interface PublicThemeSettings {
  themeColor?: string;
  themeHeadings?: unknown;
  themeLock?: boolean;
  themeUpdatedAt?: number;
}

/** Shape of the blur half of GET /api/settings and of `settingsPublic.blur`. */
export interface PublicBlurSettings {
  blurDefaults?: { gaussian?: number; pixelate?: number };
  blurUpdatedAt?: number;
}

/** Admin-only patch for POST /api/settings/theme; every field is optional. */
export interface ThemeUpdate {
  /** '#RRGGBB', or '' to clear the accent back to the theme's primary. */
  color?: string;
  headings?: ThemePrefs;
  lock?: boolean;
}

interface ThemeState {
  color: string;
  /** Admin heading colours: the default for everyone, forced when `lock` is on. */
  headings: ThemePrefs;
  lock: boolean;
  /** Server stamp of the last theme change; older payloads are ignored. */
  updatedAt: number;
  loaded: boolean;
  /**
   * True only after `loadTheme`'s `GET /api/settings` fetch has resolved and
   * set `features`. Kept separate from `loaded`, which also flips true from
   * the live `settingsPublic` mirror (an IndexedDB replay or websocket sync,
   * independent of that fetch and carrying no `features` data at all); a
   * feature-gated render must wait on this flag, not `loaded`, or it can
   * read the still-default `features` as final.
   */
  featuresLoaded: boolean;
  loadTheme: () => Promise<void>;
  /** Accept a server payload (REST seed or live mirror); stale ones are dropped. */
  applyServerTheme: (data: PublicThemeSettings | null | undefined) => void;
  // Admin-only: fails with 403 otherwise. Optimistically paints a new
  // accent so the picker feels instant; reverts on server error.
  updateTheme: (patch: ThemeUpdate) => Promise<void>;
  /** Workspace default strength for new blur regions, per style. */
  blurDefaults: { gaussian: number; pixelate: number };
  /** Server stamp of the last blur-defaults change; older payloads are ignored. */
  blurUpdatedAt: number;
  applyServerBlur: (data: PublicBlurSettings | null | undefined) => void;
  /** Admin-only: set the workspace blur defaults. */
  updateBlurDefaults: (patch: { gaussian?: number; pixelate?: number }) => Promise<void>;
  /** Server-decided feature switches (env-driven); seeded by GET /api/settings. */
  features: Features;
}

const HEX_RE = /^#[0-9a-fA-F]{6}$/;

/**
 * Backoff for the `GET /api/settings` seed, in milliseconds.
 *
 * That fetch is the only thing that ever sets `features`, and nothing
 * re-checks it live, so losing it to one hiccup used to leave every
 * feature-gated view stuck on its loading state for the rest of the session.
 * Four further attempts over ~22 s, then give up: a server that is still
 * unreachable after that is not coming back inside a page load.
 */
const SETTINGS_RETRY_DELAYS_MS = [1500, 3000, 6000, 12000];

/** One retry timer at a time; `loadTheme` replaces a pending one. */
let settingsRetryTimer: ReturnType<typeof setTimeout> | null = null;

/** One attempt at the settings seed, scheduling the next one on failure. */
async function fetchSettings(attempt: number): Promise<void> {
  const store = useThemeStore;
  try {
    const res = await fetch(`${apiUrl()}/api/settings`);
    if (!res.ok) throw new Error(String(res.status));
    const data = (await res.json()) as PublicThemeSettings & PublicBlurSettings;
    store.getState().applyServerTheme(data);
    store.getState().applyServerBlur(data);
    store.setState({ features: resolveFeatures(data), featuresLoaded: true });
  } catch {
    // Network/server hiccup: fall back to the default so the UI never ends up
    // uncolored, but only on the first attempt and only while nothing has
    // painted a real accent yet. A retry must not repaint the default over a
    // colour the live `settingsPublic` mirror already applied, and `loaded`
    // stays false either way so a later success still overwrites it.
    if (attempt === 0 && !store.getState().loaded) {
      applyThemeColor(DEFAULT_THEME_COLOR);
      store.setState({ color: DEFAULT_THEME_COLOR });
    }
    const delay = SETTINGS_RETRY_DELAYS_MS[attempt];
    if (delay === undefined) return; // attempts exhausted
    settingsRetryTimer = setTimeout(() => {
      settingsRetryTimer = null;
      void fetchSettings(attempt + 1);
    }, delay);
  }
}

export const useThemeStore = create<ThemeState>((set, get) => ({
  color: DEFAULT_THEME_COLOR,
  headings: { headingColor: null, headings: {} },
  lock: false,
  updatedAt: 0,
  loaded: false,
  featuresLoaded: false,
  blurDefaults: { gaussian: DEFAULT_BLUR_STRENGTH, pixelate: DEFAULT_BLUR_STRENGTH },
  blurUpdatedAt: 0,
  features: DEFAULT_FEATURES,

  applyServerTheme: (data) => {
    if (!data || typeof data !== 'object') return;
    const raw = Number(data.themeUpdatedAt ?? 0);
    const stamp = Number.isFinite(raw) ? raw : 0;
    if (stamp < get().updatedAt) return; // stale copy of the mirror
    const color =
      typeof data.themeColor === 'string' && (data.themeColor === '' || HEX_RE.test(data.themeColor))
        ? data.themeColor
        : get().color;
    applyThemeColor(color);
    set({
      color,
      headings: resolveThemePrefs(data.themeHeadings),
      lock: data.themeLock === true,
      updatedAt: stamp,
      loaded: true,
    });
  },

  applyServerBlur: (data) => {
    if (!data || typeof data !== 'object') return;
    const raw = Number(data.blurUpdatedAt ?? 0);
    const stamp = Number.isFinite(raw) ? raw : 0;
    if (stamp < get().blurUpdatedAt) return; // stale copy of the mirror
    const clampS = (n: unknown, fallback: number) =>
      typeof n === 'number' && Number.isFinite(n) ? Math.min(Math.max(n, 0.25), 3) : fallback;
    const prev = get().blurDefaults;
    set({
      blurDefaults: {
        gaussian: clampS(data.blurDefaults?.gaussian, prev.gaussian),
        pixelate: clampS(data.blurDefaults?.pixelate, prev.pixelate),
      },
      blurUpdatedAt: stamp,
    });
  },

  updateBlurDefaults: async (patch) => {
    const token = useAuthStore.getState().token;
    const res = await fetch(`${apiUrl()}/api/settings/blur`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(patch),
    });
    const data = (await res.json().catch(() => ({}))) as { error?: string } & PublicBlurSettings;
    if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
    get().applyServerBlur(data);
  },

  loadTheme: async () => {
    if (settingsRetryTimer !== null) {
      clearTimeout(settingsRetryTimer);
      settingsRetryTimer = null;
    }
    await fetchSettings(0);
  },

  updateTheme: async (patch) => {
    const prev = get().color;
    if (patch.color !== undefined) {
      applyThemeColor(patch.color);
      set({ color: patch.color });
    }
    try {
      const token = useAuthStore.getState().token;
      const res = await fetch(`${apiUrl()}/api/settings/theme`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(patch),
      });
      const data = (await res.json().catch(() => ({}))) as { error?: string } & PublicThemeSettings;
      if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
      get().applyServerTheme(data);
    } catch (err) {
      applyThemeColor(prev);
      set({ color: prev });
      throw err;
    }
  },
}));
