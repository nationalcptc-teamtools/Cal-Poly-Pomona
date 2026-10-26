// ─────────────────────────────────────────────────────────────────────────
// Editor keybinds + code-block default language.
//
// Three pieces wired into the Crepe editor in PageEditor.tsx:
//
//   • `codeBlockShellDefault`: overrides the commonmark code-block schema so
//     the `/code` slash command defaults to the `shell` language.
//
//   • `codeFenceInputRule`: replaces commonmark's ``` input rule so a bare
//     fence + Enter lands on `shell` too, instead of an empty language.
//
//   • `userKeybindsPlugin`: a ProseMirror plugin whose `handleKeyDown` runs
//     *before* commonmark's own keymap, so per-account shortcut overrides win.
//     It also implements backtick-wraps-selection → inline code.
//
//   • `focusLanguageKeymap`: a CodeMirror keymap. Keys typed inside a code
//     block never reach ProseMirror (the node view sets `stopEvent`), so the
//     "focus the language picker" shortcut has to live in the CM layer for the
//     caret-inside-the-block case. `userKeybindsPlugin` mirrors it at the
//     ProseMirror layer so the same shortcut also opens the picker when the
//     block is node-selected (Esc-selected, or via the drag handle), where CM
//     is not focused and the CM keymap never sees the key.
//
// All three read the *current* keybinds from a module-level ref updated by
// `setEditorKeybinds`, so changing a shortcut takes effect live without
// rebuilding the editor (which would break the Yjs collab binding).
// ─────────────────────────────────────────────────────────────────────────

import { keymap, type EditorView as CodeMirrorView } from '@codemirror/view';
import { Prec } from '@codemirror/state';
import { commandsCtx, editorViewCtx, type CommandManager } from '@milkdown/core';
import { codeBlockSchema, inlineCodeSchema } from '@milkdown/preset-commonmark';
import { textblockTypeInputRule } from '@milkdown/prose/inputrules';
import { Plugin } from '@milkdown/prose/state';
import type { EditorView } from '@milkdown/prose/view';
import { $inputRule, $prose } from '@milkdown/utils';

import { getLastHighlightColor, toggleHighlightCommand } from '@/lib/highlight-plugin';
import { getActiveMilkdownEditor } from '@/lib/active-editor';
import { openLinkEditor } from '@/lib/link-editor';
import { selectBlockAt } from '@/lib/block-select';
import { DEFAULT_CODE_LANGUAGE, fenceLanguage } from '@/lib/code-theme';
import { digitToTarget, turnIntoBlock } from '@/lib/turn-into';
import {
  matchShortcut,
  type KeybindAction,
} from '@/lib/editor-prefs';

// ── Live keybind registry ────────────────────────────────────────────────

import { currentKeybinds } from './editor-keybind-registry';
export { setEditorKeybinds, getEditorKeybinds } from './editor-keybind-registry';

// ── /code defaults to shell ──────────────────────────────────────────────
//
// Stored in the picker's own casing (`Shell`, not `shell`). The language
// button prints the stored attribute verbatim while the picker lists
// `@codemirror/language-data` names, so a lowercase default made a new block
// read `shell` until you touched the dropdown, at which point the same block
// read `Shell`. Matching everywhere else (highlighting, the `data-language`
// decoration, markdown fences) is case-insensitive, so this only affects
// what's displayed.

export const codeBlockShellDefault = codeBlockSchema.extendSchema((prev) => (ctx) => {
  const base = prev(ctx);
  return {
    ...base,
    attrs: {
      ...base.attrs,
      language: { ...(base.attrs?.language ?? {}), default: DEFAULT_CODE_LANGUAGE },
    },
  };
});

// ── Bare ``` fence → shell ───────────────────────────────────────────────
//
// The schema default above only applies when a node is created *without* a
// language, and commonmark's own ``` rule never does that: it stores whatever
// the regex captured, which for a bare fence is "". So `/code` opened a shell
// block while ``` + Enter opened a plain-text one. This is the same rule
// (same regex, so ```py still keeps py) with the empty capture routed through
// `fenceLanguage()`. ProseMirror runs input rules first-match-wins, so
// PageEditor *removes* the preset's copy rather than just adding this one.
export const codeFenceInputRule = $inputRule((ctx) =>
  textblockTypeInputRule(
    /^```(?<language>[a-z]*)?[\s\n]$/,
    codeBlockSchema.type(ctx),
    (match) => ({ language: fenceLanguage(match.groups?.language) }),
  ),
);

// ── Inline code: don't let the mark "trap" the caret ─────────────────────
//
// Commonmark's `inlineCode` mark ships without an `inclusive` flag, so it
// defaults to ProseMirror's `inclusive: true`. That means the caret parked at
// the end of a `` `code` `` span is treated as *inside* the mark: the padded
// code background visually swallows the caret (it looks like it disappears),
// and the next character you type inherits the code styling: the highlight
// "bleeds" past the closing backtick. Flipping `inclusive` to false parks the
// caret just outside the closing boundary instead, so it stays visible and
// plain text resumes when you keep typing.
export const inlineCodeNonInclusive = inlineCodeSchema.extendSchema((prev) => (ctx) => {
  const base = prev(ctx);
  return {
    ...base,
    inclusive: false,
  };
});

// ── ProseMirror keybinds + backtick-wrap ─────────────────────────────────

// Actions handled at the ProseMirror layer (focusLanguage is CM-only), in
// match order.
const PM_ACTIONS: readonly KeybindAction[] = [
  'bold',
  'italic',
  'strikethrough',
  'inlineCode',
  'highlight',
  'link',
];

function runAction(action: KeybindAction, commands: CommandManager): void {
  switch (action) {
    case 'bold': commands.call('ToggleStrong'); break;
    case 'italic': commands.call('ToggleEmphasis'); break;
    case 'strikethrough': commands.call('ToggleStrikeThrough'); break;
    case 'inlineCode': commands.call('ToggleInlineCode'); break;
    // Notion re-applies "the last color you used"; so do we.
    case 'highlight': commands.call(toggleHighlightCommand.key, getLastHighlightColor()); break;
    case 'link': {
      // Inline link input (Crepe's tooltip), not a browser prompt.
      const editor = getActiveMilkdownEditor();
      if (editor) openLinkEditor(editor);
      break;
    }
    case 'focusLanguage': break; // handled in the CodeMirror layer
  }
}

export const userKeybindsPlugin = $prose((ctx) =>
  new Plugin({
    // The language picker's keys (arrows, Enter, Escape) must work however
    // it was opened, the mouse included, so install them with the editor.
    view() {
      installLanguagePickerNav();
      return {};
    },
    props: {
      handleKeyDown(view, event) {
        // Backtick over a non-empty selection → wrap as inline code. Empty
        // selection keeps the existing type-to-convert input rule.
        if (event.key === '`' && !view.state.selection.empty) {
          event.preventDefault();
          ctx.get(commandsCtx).call('ToggleInlineCode');
          return true;
        }

        // Notion's create-a-block digit family: Ctrl/⌘+Shift+0..8 turns the
        // current block into text / H1-H3 / to-do / bulleted / numbered /
        // code. Matched on `event.code` because Shift+digit produces symbol
        // characters in `event.key` on most layouts.
        if (
          (event.ctrlKey || event.metaKey) &&
          event.shiftKey &&
          !event.altKey &&
          event.code.startsWith('Digit')
        ) {
          const target = digitToTarget(Number(event.code.slice(5)));
          if (target) {
            event.preventDefault();
            turnIntoBlock(ctx, target);
            return true;
          }
        }

        // Language picker at the ProseMirror layer. The CM keymap covers the
        // caret-inside-the-block case; this covers the block being
        // node-selected (Esc-selected or dragged) or the caret sitting in a
        // code block while ProseMirror still holds focus, where CM never sees
        // the key. With no code block in context we let the key fall through.
        const langShortcut = currentKeybinds.focusLanguage;
        if (langShortcut && matchShortcut(event, langShortcut)) {
          const block = codeBlockForLanguagePicker(view);
          if (block) {
            event.preventDefault();
            return openLanguagePickerForBlock(block);
          }
        }

        for (const action of PM_ACTIONS) {
          const shortcut = currentKeybinds[action];
          if (shortcut && matchShortcut(event, shortcut)) {
            event.preventDefault();
            runAction(action, ctx.get(commandsCtx));
            return true;
          }
        }
        return false;
      },
    },
  }),
);

// ── CodeMirror: focus the language picker ────────────────────────────────

function openLanguagePicker(cmView: CodeMirrorView): boolean {
  const root = cmView.dom.closest('.milkdown-code-block');
  return root ? openLanguagePickerForBlock(root) : false;
}

/** Open (or focus) the language picker of a specific code-block element. */
function openLanguagePickerForBlock(block: Element): boolean {
  const btn = block.querySelector<HTMLButtonElement>('.language-button');
  if (!btn) return false;
  installLanguagePickerNav();
  // Clicking the button toggles the picker open and auto-focuses its search
  // input (see @milkdown/components language-picker). Avoid toggling it closed
  // if it's already open: focus the search box instead.
  if (btn.dataset.expanded === 'true') {
    block.querySelector<HTMLInputElement>('.search-input')?.focus();
  } else {
    btn.click();
  }
  return true;
}

// Find the code block the language shortcut should act on when ProseMirror
// (not CodeMirror) holds focus: a single block-selected code block, else a
// code block the caret is sitting inside. Returns null when neither applies,
// so the shortcut is a no-op rather than grabbing an unrelated block.
function codeBlockForLanguagePicker(view: EditorView): Element | null {
  // block-select.ts marks the selected block(s) with `pm-block-selected`.
  const selected = view.dom.querySelectorAll('.milkdown-code-block.pm-block-selected');
  if (selected.length === 1) return selected[0]!;

  const { $from } = view.state.selection;
  for (let depth = $from.depth; depth >= 0; depth--) {
    if ($from.node(depth).type.name === 'code_block') {
      const dom = view.nodeDOM($from.before(depth));
      if (dom instanceof Element) return dom.closest('.milkdown-code-block') ?? dom;
    }
  }
  return null;
}

// Which language item Enter should jump to from the search box. The picker
// pins the current language at index 0 even when it doesn't match the query,
// so a bare "focus items[0]" would re-pick the current language instead of the
// thing the user just typed. Skip that pinned entry when it doesn't textually
// match, landing on the first real match. Pure + exported for tests.
export function closestMatchIndex(languages: string[], query: string): number {
  const q = query.trim().toLowerCase();
  if (!q || languages.length <= 1) return 0;
  return languages[0]!.toLowerCase().includes(q) ? 0 : 1;
}

// The bundled (Vue) language picker only handles Enter-to-select. We add
// roving arrow-key navigation and Escape-to-close with one document-level
// keydown listener, installed once when the first page editor mounts (it was
// installed only by the keyboard shortcut, so a picker opened with the mouse
// ignored Escape). It's a cheap no-op unless focus is inside an open
// `.language-picker`.
let languagePickerNavInstalled = false;
function installLanguagePickerNav(): void {
  if (languagePickerNavInstalled || typeof document === 'undefined') return;
  languagePickerNavInstalled = true;

  const focusEditor = (picker: Element) => {
    const cm = picker.closest('.milkdown-code-block')?.querySelector<HTMLElement>('.cm-content');
    // Defer so we don't race the picker's own close/focus handling.
    setTimeout(() => cm?.focus(), 0);
  };

  document.addEventListener(
    'keydown',
    (event) => {
      const active = document.activeElement as HTMLElement | null;
      const picker = active?.closest('.language-picker');
      if (!picker) return;

      const items = Array.from(
        picker.querySelectorAll<HTMLElement>('.language-list-item[data-language]'),
      );
      const idx = active ? items.indexOf(active) : -1;

      switch (event.key) {
        case 'ArrowDown': {
          if (!items.length) return;
          event.preventDefault();
          let next: HTMLElement | undefined;
          if (idx < 0) {
            // Coming from the search box: skip the pinned current language when
            // it doesn't match, same as Enter, so the arrows and Enter agree.
            const query = active?.classList.contains('search-input')
              ? (active as HTMLInputElement).value
              : '';
            next = items[closestMatchIndex(items.map((el) => el.dataset.language || ''), query)];
          } else {
            next = items[Math.min(idx + 1, items.length - 1)];
          }
          next?.focus();
          next?.scrollIntoView({ block: 'nearest' });
          break;
        }
        case 'ArrowUp': {
          if (!items.length) return;
          event.preventDefault();
          if (idx <= 0) {
            picker.querySelector<HTMLInputElement>('.search-input')?.focus();
          } else {
            const prev = items[idx - 1];
            prev?.focus();
            prev?.scrollIntoView({ block: 'nearest' });
          }
          break;
        }
        case 'Enter': {
          if (!items.length) return;
          // From the search box, Enter moves focus to the closest matching
          // language and keeps the picker open, so the user can refine with
          // the arrows before committing (their described flow). From a list
          // item, Enter selects it and closes.
          if (active?.classList.contains('search-input')) {
            event.preventDefault();
            event.stopPropagation();
            const query = (active as HTMLInputElement).value;
            const target = items[closestMatchIndex(items.map((el) => el.dataset.language || ''), query)];
            target?.focus();
            target?.scrollIntoView({ block: 'nearest' });
            break;
          }
          const target = idx >= 0 ? items[idx] : items[0];
          if (!target) return;
          // Click selects AND closes the picker (the Enter handler in the Vue
          // component only selects). Stop propagation so it doesn't double-fire.
          event.preventDefault();
          event.stopPropagation();
          target.click();
          focusEditor(picker);
          break;
        }
        case 'Escape': {
          event.preventDefault();
          event.stopPropagation();
          const btn = picker
            .closest('.milkdown-code-block')
            ?.querySelector<HTMLButtonElement>('.language-button');
          if (btn?.dataset.expanded === 'true') btn.click(); // close it
          focusEditor(picker);
          break;
        }
      }
    },
    true, // capture: beat the component's own Enter/Escape handlers
  );
}

// A single Escape inside a code block selects that block (Notion-style, mirrors
// block-select.ts). Keys typed in a code block never reach ProseMirror's
// block-select plugin, so we activate block selection on the enclosing block
// here. The one case where Escape must NOT grab the block is when CodeMirror has
// its own overlay open (autocomplete popup or search panel): there the key
// should close that, so we let it fall through.
function codeMirrorOverlayOpen(cmView: CodeMirrorView): boolean {
  return !!cmView.dom.querySelector('.cm-tooltip-autocomplete, .cm-panel');
}

function selectEnclosingCodeBlock(cmView: CodeMirrorView): boolean {
  const editor = getActiveMilkdownEditor();
  const codeBlockEl = cmView.dom.closest('.milkdown-code-block');
  if (!editor || !codeBlockEl) return false;
  let handled = false;
  try {
    editor.action((ctx) => {
      const pmView = ctx.get(editorViewCtx);
      const pos = pmView.posAtDOM(codeBlockEl, 0);
      if (pos < 0) return;
      handled = selectBlockAt(pmView, pos);
    });
  } catch {
    return false;
  }
  return handled;
}

export const focusLanguageKeymap = Prec.highest(
  keymap.of([
    {
      any: (cmView, event) => {
        const shortcut = currentKeybinds.focusLanguage;
        if (!shortcut || !matchShortcut(event, shortcut)) return false;
        event.preventDefault();
        return openLanguagePicker(cmView);
      },
    },
    {
      key: 'Escape',
      run: (cmView) => {
        // Let CodeMirror handle Escape when it has an overlay to dismiss
        // (autocomplete / search); otherwise select the enclosing code block.
        if (codeMirrorOverlayOpen(cmView)) return false;
        return selectEnclosingCodeBlock(cmView);
      },
    },
  ]),
);
