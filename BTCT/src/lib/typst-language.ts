// ─────────────────────────────────────────────────────────────────────────
// Minimal CodeMirror 6 syntax highlighting for Typst source.
//
// There's no first-party Typst grammar in our CodeMirror deps, so this is a
// small hand-rolled StreamLanguage covering the common surface: comments,
// strings, headings, function/`#` calls, `@`refs/labels, math `$…$`, and
// numbers (incl. Typst length units). It's deliberately approximate: enough
// to make the raw code readable, not a full parser.
//
// Colors come from the same global `--code-*` CSS variables the Milkdown code
// blocks use (defined in index.css), so the Typst editor matches the rest of
// the app and follows the per-account code accent.
// ─────────────────────────────────────────────────────────────────────────

import { StreamLanguage, LanguageSupport, HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import { tags as t } from '@lezer/highlight';
import { Prec, type Extension } from '@codemirror/state';

interface TypstState {
  blockComment: boolean;
}

// Custom token names → lezer tags. Returning a name not in this table falls
// back to CodeMirror's default mapping, but we keep everything explicit.
const tokenTable = {
  typstComment: t.lineComment,
  typstString: t.string,
  typstHeading: t.heading,
  typstFunction: t.function(t.variableName),
  typstRef: t.labelName,
  typstMath: t.special(t.string),
  typstNumber: t.number,
  typstEscape: t.escape,
};

const typstStreamParser = StreamLanguage.define<TypstState>({
  name: 'typst',
  startState: () => ({ blockComment: false }),
  token(stream, state) {
    // Inside a /* … */ block comment: consume until the closing */.
    if (state.blockComment) {
      if (stream.match(/^.*?\*\//)) state.blockComment = false;
      else stream.skipToEnd();
      return 'typstComment';
    }

    // Leading whitespace: consume so we never spin without advancing.
    if (stream.eatSpace()) return null;

    // Comments.
    if (stream.match('/*')) {
      state.blockComment = true;
      if (stream.match(/^.*?\*\//)) state.blockComment = false; // single-line /* */
      else stream.skipToEnd();
      return 'typstComment';
    }
    if (stream.match('//')) {
      stream.skipToEnd();
      return 'typstComment';
    }

    // Backslash escape (\#, \$, \\, …).
    if (stream.match(/^\\[^\s]/)) return 'typstEscape';

    // Headings: one or more '=' at line start followed by a space.
    if (stream.sol() && stream.match(/^=+(?=\s)/)) return 'typstHeading';

    // Inline / block math: $ … $ (kept on one logical token where possible).
    if (stream.match(/^\$(?:[^$\\]|\\.)*\$/)) return 'typstMath';
    if (stream.match('$')) return 'typstMath';

    // Double-quoted strings with escapes.
    if (stream.match(/^"(?:[^"\\]|\\.)*"/)) return 'typstString';

    // Function / code-mode entry: #ident (e.g. #figure, #let, #import).
    if (stream.match(/^#[A-Za-z_][\w.-]*/)) return 'typstFunction';

    // References / labels: @ref and <label>.
    if (stream.match(/^@[A-Za-z_][\w.:-]*/)) return 'typstRef';
    if (stream.match(/^<[A-Za-z_][\w.:-]*>/)) return 'typstRef';

    // Numbers, optionally with a Typst unit.
    if (stream.match(/^\d+(?:\.\d+)?(?:pt|mm|cm|in|em|fr|deg|rad|%)?/)) return 'typstNumber';

    // Identifiers: unstyled, but consumed in one go for efficiency.
    if (stream.match(/^[A-Za-z_][\w-]*/)) return null;

    // Fallback: always advance by one character.
    stream.next();
    return null;
  },
  tokenTable,
  languageData: {
    commentTokens: { line: '//', block: { open: '/*', close: '*/' } },
  },
});

export function typstLanguage(): LanguageSupport {
  return new LanguageSupport(typstStreamParser);
}

// Token colors, sourced from the --code-* tokens (themes/tokens.css) so the
// editor matches a note's code blocks in both modes and follows the
// per-account code accent.
const typstHighlightStyle = HighlightStyle.define([
  { tag: [t.lineComment, t.blockComment, t.comment], color: 'var(--code-comment)', fontStyle: 'italic' },
  { tag: [t.string, t.special(t.string)], color: 'var(--code-string)' },
  { tag: t.heading, color: 'var(--code-keyword)', fontWeight: 'bold' },
  { tag: [t.function(t.variableName), t.macroName], color: 'var(--code-function)' },
  { tag: t.labelName, color: 'var(--code-type)' },
  { tag: t.number, color: 'var(--code-number)' },
  { tag: t.escape, color: 'var(--code-accent)' },
]);

// Elevated so it wins over any default highlight style appended later.
export const typstHighlightExtension: Extension = Prec.high(
  syntaxHighlighting(typstHighlightStyle),
);
