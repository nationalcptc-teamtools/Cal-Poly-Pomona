// ─────────────────────────────────────────────────────────────────────────
// The 17 faces typst.ts installs by default (its `text` asset family).
//
// scripts/fonts.ts stages them under public/fonts so the app never touches
// the CDN, and the compiler driver (lib/typst-compiler.driver.ts) fetches
// them from there. One list, so the two can never drift apart.
// ─────────────────────────────────────────────────────────────────────────

export const DEFAULT_FONT_FILES: readonly string[] = [
  'DejaVuSansMono-Bold.ttf', 'DejaVuSansMono-BoldOblique.ttf', 'DejaVuSansMono-Oblique.ttf', 'DejaVuSansMono.ttf',
  'LibertinusSerif-Bold.otf', 'LibertinusSerif-BoldItalic.otf', 'LibertinusSerif-Italic.otf', 'LibertinusSerif-Regular.otf',
  'LibertinusSerif-Semibold.otf', 'LibertinusSerif-SemiboldItalic.otf',
  'NewCM10-Bold.otf', 'NewCM10-BoldItalic.otf', 'NewCM10-Italic.otf', 'NewCM10-Regular.otf',
  'NewCMMath-Bold.otf', 'NewCMMath-Book.otf', 'NewCMMath-Regular.otf',
];

/** Where the app serves them (Vite copies public/fonts to dist/fonts). */
export const DEFAULT_FONT_URL_PREFIX = '/fonts/';
