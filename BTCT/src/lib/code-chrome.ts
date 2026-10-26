// ─────────────────────────────────────────────────────────────────────────
// CodeMirror chrome built from the tokens, for both modes.
//
// Without a theme of its own CodeMirror falls back to its light base theme
// in both modes: a black caret and a light grey selection on a dark code
// block, a pale blue active-line band. This theme sets every one of those
// from the tokens in themes/tokens.css (CSS variables, so the light and
// dark palettes come from the `.dark` class and the admin accent retints
// them live, with no editor rebuild). Token colours stay in code-theme.ts
// (note code blocks) and typst-language.ts (the Report source editor); both
// read the same `--code-*` variables.
//
// Used by the note editor's code blocks (PageEditor, through Crepe's
// CodeMirror feature) and by the Report tab's TypstEditor.
// ─────────────────────────────────────────────────────────────────────────

import { EditorView } from '@codemirror/view';

export const codeChromeTheme = EditorView.theme({
  '&': {
    color: 'var(--code-fg)',
    backgroundColor: 'transparent',
  },
  '&.cm-focused': { outline: 'none' },
  '.cm-content': { caretColor: 'hsl(var(--foreground))' },
  '.cm-cursor, .cm-dropCursor': { borderLeftColor: 'hsl(var(--foreground))' },
  // Selection: the base theme's own selectors, so ours outrank them.
  '& > .cm-scroller > .cm-selectionLayer .cm-selectionBackground': {
    background: 'hsl(var(--selection) / 0.7)',
  },
  '&.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground': {
    background: 'hsl(var(--selection))',
  },
  '.cm-content ::selection': { backgroundColor: 'hsl(var(--selection))' },
  // One surface: no band on the first line of every block. The line being
  // edited gets a faint wash only while the editor has focus.
  '.cm-activeLine': { backgroundColor: 'transparent' },
  '.cm-activeLineGutter': { backgroundColor: 'transparent' },
  '&.cm-focused .cm-activeLine': { backgroundColor: 'hsl(var(--foreground) / 0.035)' },
  '&.cm-focused .cm-activeLineGutter': {
    backgroundColor: 'hsl(var(--foreground) / 0.035)',
    color: 'hsl(var(--foreground))',
  },
  '.cm-gutters': {
    backgroundColor: 'transparent',
    color: 'hsl(var(--muted-foreground))',
    border: 'none',
  },
  '.cm-foldPlaceholder': {
    backgroundColor: 'hsl(var(--muted))',
    color: 'hsl(var(--muted-foreground))',
    border: '1px solid hsl(var(--border))',
  },
  '&.cm-focused .cm-matchingBracket': {
    backgroundColor: 'hsl(var(--primary) / 0.18)',
    outline: '1px solid hsl(var(--primary) / 0.5)',
  },
  '&.cm-focused .cm-nonmatchingBracket': { backgroundColor: 'hsl(var(--status-red) / 0.25)' },
  '.cm-selectionMatch': { backgroundColor: 'hsl(var(--foreground) / 0.12)' },
  '.cm-searchMatch': {
    backgroundColor: 'hsl(var(--status-purple) / 0.3)',
    outline: '1px solid hsl(var(--status-purple) / 0.5)',
  },
  '.cm-searchMatch.cm-searchMatch-selected': { backgroundColor: 'hsl(var(--primary) / 0.45)' },

  // Tooltips (autocomplete, lint) and the Ctrl/Cmd+F search panel.
  '.cm-tooltip': {
    backgroundColor: 'hsl(var(--popover))',
    color: 'hsl(var(--popover-foreground))',
    border: '1px solid hsl(var(--border))',
    borderRadius: 'var(--radius)',
  },
  '.cm-tooltip-autocomplete > ul > li[aria-selected]': {
    backgroundColor: 'hsl(var(--primary) / 0.18)',
    color: 'hsl(var(--foreground))',
  },
  '.cm-panels': {
    backgroundColor: 'hsl(var(--card))',
    color: 'hsl(var(--foreground))',
  },
  '.cm-panels.cm-panels-bottom': { borderTop: '1px solid hsl(var(--border))' },
  '.cm-panels.cm-panels-top': { borderBottom: '1px solid hsl(var(--border))' },
  '.cm-panel.cm-search': { padding: '6px 8px', fontSize: '11px', fontFamily: 'var(--font-ui)' },
  '.cm-panel.cm-search label': {
    fontSize: '10px',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    color: 'hsl(var(--muted-foreground))',
  },
  '.cm-panel.cm-search input[type=text], .cm-textfield': {
    backgroundColor: 'hsl(var(--background))',
    color: 'hsl(var(--foreground))',
    border: '1px solid hsl(var(--border))',
    borderRadius: 'var(--radius)',
    padding: '2px 6px',
    fontSize: '11px',
    fontFamily: 'var(--font-code)',
  },
  '.cm-panel.cm-search input[type=text]:focus, .cm-textfield:focus': {
    outline: 'none',
    borderColor: 'hsl(var(--primary))',
  },
  '.cm-panel.cm-search button, .cm-button': {
    backgroundColor: 'transparent',
    backgroundImage: 'none',
    color: 'hsl(var(--foreground))',
    border: '1px solid hsl(var(--border))',
    borderRadius: 'var(--radius)',
    padding: '2px 7px',
    margin: '0 2px',
    fontSize: '10px',
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    cursor: 'pointer',
  },
  '.cm-panel.cm-search button:hover, .cm-button:hover': { backgroundColor: 'hsl(var(--accent))' },
  '.cm-panel.cm-search button[name=close]': {
    border: 'none',
    fontSize: '15px',
    padding: '0 6px',
    color: 'hsl(var(--muted-foreground))',
  },
});
