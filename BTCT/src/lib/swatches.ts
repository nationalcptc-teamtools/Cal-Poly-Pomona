/**
 * The one list of preset colours offered by every colour picker (admin
 * accent, user colour, code accent, note headings). These are data a person
 * picks and saves, not interface colours, so they stay hex; the interface
 * itself only reads tokens. The server's presence palette
 * (`server/db.mjs`, assigned to new accounts) is the first eight entries.
 */
export const SWATCHES = [
  '#ef4444', // red
  '#f59e0b', // amber
  '#10b981', // emerald
  '#3b82f6', // blue
  '#8b5cf6', // violet
  '#ec4899', // pink
  '#14b8a6', // teal
  '#f97316', // orange
  '#06b6d4', // cyan
  '#a855f7', // purple
  '#84cc16', // lime
  '#eab308', // yellow
] as const;

/** Neutral picks that only make sense for an accent or a heading. */
export const NEUTRAL_SWATCHES = ['#737373', '#94a3b8'] as const;

/** Admin accent: the coral theme default is the "Default" button, not a swatch. */
export const ACCENT_SWATCHES: readonly string[] = [...NEUTRAL_SWATCHES.slice(0, 1), '#7db4dc', ...SWATCHES];
/** A user's presence colour and code accent. */
export const USER_SWATCHES: readonly string[] = SWATCHES;
/** Heading colours. No white: it vanishes on the light page. */
export const HEADING_SWATCHES: readonly string[] = [...SWATCHES, NEUTRAL_SWATCHES[1]];
