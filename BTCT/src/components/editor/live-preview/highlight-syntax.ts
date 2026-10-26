// ─────────────────────────────────────────────────────────────────────────
// `==highlight==` syntax for the Live preview style.
//
// Obsidian highlights `==text==`. BTCT's highlight mark has no markdown
// form (it is dropped on save, see lib/highlight-plugin.ts), so the
// markdown parser leaves `==text==` as literal text, and that stays the
// rule for parsing: an import or a seeded page keeps its `==` characters.
// Two live editing paths convert it instead, both real editing commands
// in the document and both only in the Live preview style:
//
// - typing the closing `==` (an input rule, like `**bold**`);
// - pasting: text that arrives with a paste is scanned once, after the
//   paste lands, so a markdown paste and an HTML paste both convert.
//
// Never inside a code block or inline code.
// ─────────────────────────────────────────────────────────────────────────

import { InputRule } from '@milkdown/prose/inputrules';
import type { MarkType, Node as ProseNode } from '@milkdown/prose/model';
import type { Transaction } from '@milkdown/prose/state';
import { $inputRule } from '@milkdown/utils';
import { highlightMark } from '@/lib/highlight-plugin';
import { isLivePreview } from './editor-style';

/** `==text==` with no space just inside the delimiters, one line. */
export const HIGHLIGHT_SYNTAX = /==([^=\s](?:[^=\n]*?[^=\s])?)==/g;

/** Typing the second `=` of the closing pair. */
export const HIGHLIGHT_INPUT = /(?<![=\\])==([^=\s](?:[^=\n]*?[^=\s])?)==$/;

function isCode(node: ProseNode): boolean {
  return !!node.type.spec.code;
}

/**
 * Turn every `==text==` in the textblocks between `from` and `to` of
 * `tr.doc` into highlighted text, in place. Returns how many it converted.
 */
export function convertHighlightSyntax(tr: Transaction, from: number, to: number, type: MarkType): number {
  const found: Array<{ start: number; end: number }> = [];
  tr.doc.nodesBetween(Math.max(0, from), Math.min(tr.doc.content.size, to), (node, pos) => {
    if (!node.isTextblock) return true;
    if (isCode(node) || !node.type.allowsMarkType(type)) return false;
    const text = node.textBetween(0, node.content.size, undefined, '\ufffc');
    for (const m of text.matchAll(HIGHLIGHT_SYNTAX)) {
      const start = pos + 1 + m.index!;
      const end = start + m[0].length;
      // Leave inline code alone, and anything already highlighted.
      let skip = false;
      tr.doc.nodesBetween(start, end, (child) => {
        if (child.isText && child.marks.some((mk) => mk.type.name === 'inlineCode' || mk.type === type)) skip = true;
        return !skip;
      });
      if (!skip) found.push({ start, end });
    }
    return false;
  });
  // Last first, so earlier positions stay valid.
  found.sort((a, b) => b.start - a.start);
  for (const { start, end } of found) {
    tr.delete(end - 2, end);
    tr.addMark(start + 2, end - 2, type.create());
    tr.delete(start, start + 2);
  }
  return found.length;
}

/** The input rule handler, exported for tests. */
export function highlightInputHandler(type: MarkType) {
  return (state: { tr: Transaction; doc: ProseNode }, match: RegExpMatchArray, start: number, end: number): Transaction | null => {
    if (!isLivePreview()) return null;
    const $start = state.doc.resolve(start);
    if (isCode($start.parent) || !$start.parent.type.allowsMarkType(type)) return null;
    const inner = match[1]!;
    // `start` is where the opening `==` begins, `end` the caret; the doc
    // holds `==inner=` between them and the typed `=` is never inserted.
    const offset = match[0].indexOf('==' + inner);
    const open = start + offset;
    const tr = state.tr;
    let inCode = false;
    state.doc.nodesBetween(open, end, (child) => {
      if (child.isText && child.marks.some((mk) => mk.type.name === 'inlineCode')) inCode = true;
      return !inCode;
    });
    if (inCode) return null;
    tr.delete(open + 2 + inner.length, end);
    tr.delete(open, open + 2);
    tr.addMark(open, open + inner.length, type.create());
    tr.removeStoredMark(type);
    return tr;
  };
}

export const highlightInputRule = $inputRule((ctx) => {
  const type = highlightMark.type(ctx);
  return new InputRule(HIGHLIGHT_INPUT, highlightInputHandler(type));
});
