import type { Node as DocumentNode } from '@milkdown/prose/model';
const decorationCache = new WeakMap<DocumentNode, DecorationSet>();
// ─────────────────────────────────────────────────────────────────────────
// Per-account code-block syntax theme.
//
// Crepe code blocks are CodeMirror instances. We give the CodeMirror feature
// the full `@codemirror/language-data` language list (so the language picker
// has options and blocks actually get highlighted) plus a custom highlight
// style whose token colors are driven entirely by CSS variables. That lets a
// user recolor every code block *live*: `applyCodeAccent(hex)` just rewrites
// the `--code-*` variables on :root; nothing in the editor is rebuilt (which
// matters because a rebuild would tear down the Yjs collab binding).
// ─────────────────────────────────────────────────────────────────────────

import { HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import { languages } from '@codemirror/language-data';
import { Prec, type Extension } from '@codemirror/state';
import { tags as t } from '@lezer/highlight';
import { Plugin, PluginKey } from '@milkdown/prose/state';
import { Decoration, DecorationSet } from '@milkdown/prose/view';
import { $prose } from '@milkdown/utils';


// The language descriptions handed to Crepe's CodeMirror feature. Each lazily
// loads its grammar on first use (see the loader in @milkdown/components).
export const codeLanguages = languages;

// Token → CSS class. Colors come from the `--code-*` tokens (tokens.css,
// applied in index.css) and are overridden live by `applyCodeAccent`.
const themedHighlightStyle = HighlightStyle.define([
  { tag: [t.keyword, t.controlKeyword, t.moduleKeyword, t.operatorKeyword, t.definitionKeyword], class: 'cm-tok-keyword' },
  { tag: [t.string, t.special(t.string), t.regexp, t.character], class: 'cm-tok-string' },
  { tag: [t.lineComment, t.blockComment, t.comment, t.docComment, t.meta], class: 'cm-tok-comment' },
  { tag: [t.number, t.integer, t.float, t.bool, t.atom, t.null], class: 'cm-tok-number' },
  { tag: [t.function(t.variableName), t.function(t.propertyName), t.macroName, t.labelName], class: 'cm-tok-function' },
  { tag: [t.typeName, t.className, t.namespace, t.tagName, t.standard(t.name)], class: 'cm-tok-type' },
  { tag: [t.operator, t.derefOperator, t.compareOperator, t.logicOperator, t.arithmeticOperator], class: 'cm-tok-operator' },
  { tag: [t.variableName, t.propertyName, t.attributeName, t.definition(t.variableName)], class: 'cm-tok-variable' },
  // `builtin` is the token the shell and PowerShell legacy modes tag their
  // commands / cmdlets with (StreamLanguage maps it to variableName.standard).
  // It has its own CSS var so a terminal palette can paint commands like a
  // real prompt; the default var falls back to the identifier colour, so no
  // other language changes look.
  { tag: [t.standard(t.variableName)], class: 'cm-tok-builtin' },
]);

// basicSetup already registers `defaultHighlightStyle`; appended extensions
// have *lower* precedence in CodeMirror, so we must elevate ours to win.
export const codeSyntaxThemeExtension: Extension = Prec.highest(
  syntaxHighlighting(themedHighlightStyle),
);

/**
 * Apply the per-account code accent. The base palettes are the light and
 * dark `--code-*` tokens in themes/tokens.css; the account accent only
 * retints the most prominent token (keywords) in both modes. No-op when the
 * hex is malformed.
 */
export { applyCodeAccent } from './code-accent';

// ── Per-language theming hook ────────────────────────────────────────────
//
// Shell/bash aliases collapse to a single canonical `shell` so CSS only needs
// to target one value. Other languages keep their lowercased name.
const SHELL_ALIASES = new Set([
  'shell', 'bash', 'sh', 'zsh', 'ksh', 'console', 'shell-session', 'shellscript',
]);

// Every spelling of PowerShell folds to `powershell` so the terminal palette
// (keyed on the `data-language` attribute) applies whether the block was
// opened from the picker ("PowerShell") or a ```ps1 / ```pwsh fence.
const POWERSHELL_ALIASES = new Set([
  'powershell', 'pwsh', 'posh', 'ps', 'ps1', 'psm1', 'psd1',
]);

/**
 * Canonical `data-language` value for a code block. Shell/bash aliases fold to
 * `shell` and PowerShell aliases to `powershell` so the terminal palettes in
 * index.css only need one selector each; everything else keeps its lowercased
 * name. Exported so the highlighting and the CSS agree on the same key.
 */
export function canonicalLanguage(raw: unknown): string {
  const lang = String(raw ?? '').trim().toLowerCase();
  if (!lang) return '';
  if (SHELL_ALIASES.has(lang)) return 'shell';
  if (POWERSHELL_ALIASES.has(lang)) return 'powershell';
  return lang;
}

/**
 * The display name `@codemirror/language-data` uses for a language, matched
 * case-insensitively against both names and aliases: `shell`, `sh` and
 * `bash` all resolve to `Shell`.
 *
 * The code block's language button prints the stored attribute verbatim while
 * the picker lists these canonical names, so storing anything else makes a
 * freshly-inserted block read `shell` and the same block read `Shell` the
 * moment you pick from the dropdown. Returns null when nothing matches, so
 * callers can leave an unknown language untouched rather than mangling it.
 */
export function displayLanguageName(raw: unknown): string | null {
  const needle = String(raw ?? '').trim().toLowerCase();
  if (!needle) return null;
  for (const lang of languages) {
    if (lang.name.toLowerCase() === needle) return lang.name;
    if (lang.alias?.some((a) => a.toLowerCase() === needle)) return lang.name;
  }
  return null;
}

/** Canonical display name for the language new code blocks start in. */
export const DEFAULT_CODE_LANGUAGE = displayLanguageName('shell') ?? 'Shell';

/**
 * Language for a code block opened by typing a ``` fence. The text after the
 * backticks wins when there is any (```py stays py); a bare fence gets the
 * same default `/code` uses instead of the empty string commonmark's own rule
 * would store, which rendered as a plain-text block.
 */
export function fenceLanguage(captured: string | undefined): string {
  return captured || DEFAULT_CODE_LANGUAGE;
}

// Stamps each code block's DOM node with `data-language` (via a node
// decoration) so index.css can give specific languages their own look: e.g.
// the Linux-terminal palette for shell. Recomputed when a block's language
// changes (slash default, ``` fence, or the picker).
const codeLanguageAttrKey = new PluginKey('code-language-attr');
export const codeLanguageAttrPlugin = $prose(
  () =>
    new Plugin({
      key: codeLanguageAttrKey,
      props: {
        decorations(state) {
          const hit = decorationCache.get(state.doc);
          if (hit !== undefined) return hit;
          const decos: Decoration[] = [];
          // Code blocks are always top-level, so a shallow scan suffices.
          state.doc.forEach((node, offset) => {
            if (node.type.name !== 'code_block') return;
            const lang = canonicalLanguage(node.attrs.language);
            if (lang) {
              decos.push(
                Decoration.node(offset, offset + node.nodeSize, { 'data-language': lang }),
              );
            }
          });
          const result = decos.length ? DecorationSet.create(state.doc, decos) : DecorationSet.empty;
          decorationCache.set(state.doc, result);
          return result;
        },
      },
    }),
);
