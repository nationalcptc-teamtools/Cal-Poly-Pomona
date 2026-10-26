import { useEffect, useState, useMemo, useCallback, useRef } from 'react';
import { readableTextOn } from '@/lib/contrast';
import { SWATCHES } from '@/lib/swatches';
import { createPortal } from 'react-dom';
import { Crepe } from '@milkdown/crepe';
import { Milkdown, MilkdownProvider, useEditor } from '@milkdown/react';
import { listener, listenerCtx } from '@milkdown/plugin-listener';
import { collab, collabServiceCtx } from '@milkdown/plugin-collab';
import { callCommand } from '@milkdown/utils';
import type { Editor } from '@milkdown/core';
// Crepe's structural stylesheet only. Its colour themes (frame, frame-dark)
// are not imported: themes/tokens.css maps Crepe's variables to the tokens.
import '@milkdown/crepe/theme/common/style.css';
import {
  Bold, Italic, Strikethrough, Code, Link as LinkIcon,
  ChevronDown, Highlighter, Keyboard,
} from 'lucide-react';
import {
  HIGHLIGHT_COLORS,
  highlightPlugin,
  setLastHighlightColor,
  toggleHighlightCommand,
  type HighlightColor,
} from '@/lib/highlight-plugin';
import { codeLanguages, codeSyntaxThemeExtension, codeLanguageAttrPlugin } from '@/lib/code-theme';
import { codeChromeTheme } from '@/lib/code-chrome';
import type { Extension } from '@codemirror/state';
import {
  codeBlockShellDefault,
  codeFenceInputRule,
  getEditorKeybinds,
  inlineCodeNonInclusive,
  userKeybindsPlugin,
  focusLanguageKeymap,
} from '@/lib/editor-keybinds';
import { formatShortcut } from '@/lib/editor-prefs';
import { getUiZoom } from '@/lib/ui-zoom';
import { openLinkEditor } from '@/lib/link-editor';
import { notionTypingRules } from '@/lib/notion-typing';
import { TURN_INTO_ITEMS, turnIntoBlock, type TurnIntoTarget } from '@/lib/turn-into';
import { editorViewCtx, getDoc, parserCtx, schemaCtx } from '@milkdown/core';
import { createCodeBlockInputRule } from '@milkdown/preset-commonmark';
import { blockSelectPlugin } from '@/lib/block-select';
import { editorChromeClickPlugin } from '@/lib/editor-chrome-click';
import { imageResizePlugin, imageResizableSchema, imageBlockResizableSchema } from '@/lib/image-resize';
import { assetImageSchema, assetImageView } from '@/lib/asset-image';
import { noteImagePastePlugin, noteImageContextPlugin, noteImageCleanupPlugin } from '@/lib/note-image-paste';
import {
  DEFAULT_HEADER_LABELS,
  insertTable,
  TABLE_ICON,
  tableHeaderStatePlugin,
} from '@/lib/table-plugin';
import { tableKeysPlugin } from '@/lib/table-keys';
import { selectionWantsFormatToolbar } from '@/lib/format-toolbar';
import { listItemView } from '@/lib/list-item-view';
import { livePreviewPlugin } from '@/components/editor/live-preview/live-preview-plugin';
import { highlightInputRule } from '@/components/editor/live-preview/highlight-syntax';
import { pageRefSchema, pageRefView, insertPageRef, PAGE_REF_ICON } from '@/lib/page-ref';
import { KeybindsDialog } from '@/components/editor/KeybindsDialog';
import type { Ctx } from '@milkdown/ctx';
import { setActiveMilkdownEditor, clearActiveMilkdownEditor, registerPageEditor, unregisterPageEditor } from '@/lib/active-editor';
import { seedPageFragment } from '@/lib/page-seed';
import { useAppStore } from '@/stores';
import { normalizePageContent } from '@/export/markdown';
import { getPageYContext, retainPageYContext } from '@/realtime/yjs-providers';
import { textKey } from '@/realtime/shared-doc';
import { useYTextInput } from '@/realtime/use-y-text';
import { pageRepo } from '@/db/page-repo';
import type {
  Page,
} from '@/types';

/**
 * Minimal shape of Crepe's slash-menu builder.
 *
 * Crepe keeps `GroupBuilder`/`SlashMenuItem` internal to the package, so this
 * types just the two calls we make rather than reaching into its internals.
 */
interface TableMenuBuilder {
  getGroup: (key: string) => {
    addItem: (
      key: string,
      item: { label: string; icon: string; onRun: (ctx: Ctx) => void },
    ) => unknown;
  };
}

export function PageEditor({ pageId }: { pageId: string }) {
  // Read the page reactively from the shared store so remote edits
  // (title, slug, tags, icon, content) propagate to this view in real time.
  const storePage = useAppStore((s) => s.pages.find((p) => p.id === pageId) ?? null);
  // Legacy pages created for retired graph nodes are excluded from
  // `loadPages()`, so a tab can point at a page id that is not in the
  // store. Fetch it from the repo so the editor can still render, and
  // follow shared-doc page events so remote edits reach this copy.
  const [fallbackPage, setFallbackPage] = useState<Page | null>(null);
  useEffect(() => {
    if (storePage) { setFallbackPage(null); return; }
    let cancelled = false;
    const refetch = () => {
      void pageRepo.getById(pageId).then((p) => {
        if (!cancelled) setFallbackPage(p ?? null);
      });
    };
    refetch();
    // Re-fetch only when the pages table identity actually changes. A bare
    // subscribe(refetch) fired on EVERY store write, including this
    // editor's own 400ms content save, doing a repo read + setState each
    // time such a page is open.
    const unsub = useAppStore.subscribe((state, prev) => {
      if (state.pages !== prev.pages) refetch();
    });
    return () => { cancelled = true; unsub(); };
  }, [pageId, storePage]);

  const page = storePage ?? fallbackPage;

  if (!page) return <div className="flex-1 p-4">Loading...</div>;

  return <PageEditorInner page={page} />;
}

function PageEditorInner({ page }: { page: Page }) {
  const updatePage = useAppStore((s) => s.updatePage);
  const [editingSlug, setEditingSlug] = useState(false);

  // Bind the title and slug inputs to Y.Text CRDTs so concurrent edits
  // from multiple users merge character-by-character (insert/delete
  // deltas), exactly how Google Docs / Notion do it. The `mirrorTextsToRecords`
  // observer in shared-doc keeps page.title / page.slug in the JSON
  // snapshot in sync for sidebar / tab-label / search consumers.
  const [titleValue, setTitleValue, titleInputRef] = useYTextInput(
    textKey('page', page.id, 'title'),
    page.title,
  );
  const [slugYValue, setSlugYValue, slugInputRef] = useYTextInput(
    textKey('page', page.id, 'slug'),
    page.slug ?? '',
  );

  // The slug input also runs a sanitizer (lowercase, hyphens) over the
  // user's typed value before committing it to the CRDT.
  const handleTitleChange = (value: string) => {
    setTitleValue(value);
  };

  const handleSlugInputChange = (raw: string) => {
    const sanitized = raw.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-');
    setSlugYValue(sanitized);
  };
  const commitSlug = () => {
    setEditingSlug(false);
    const trimmed = slugYValue.replace(/(^-|-$)/g, '');
    if (trimmed !== slugYValue) setSlugYValue(trimmed);
  };

  // Keep a ref to the live markdown so the debounced persister always sees
  // the latest value without re-subscribing the Milkdown listener.
  const latestMarkdown = useRef<string>(normalizePageContent(page.content));
  const saveTimer = useRef<number | null>(null);

  // Shared ref to the Milkdown editor so the side format panel can dispatch
  // commands. `MarkdownEditor` assigns this on mount.
  const editorRef = useRef<Editor | null>(null);

  // The record copy is a cold-start/export mirror, not the live document
  // (that's the per-page Y.Doc), so it doesn't need a 400ms cadence. Each
  // save re-broadcasts the ENTIRE page record body to the server and every
  // peer, so: save after 2s of idle, with a 10s ceiling during continuous
  // typing, and the unmount flush below still catches page switches.
  const lastRecordSave = useRef(Date.now());
  const queueSave = useCallback(() => {
    if (saveTimer.current != null) window.clearTimeout(saveTimer.current);
    const deadline = lastRecordSave.current + 10_000;
    const delay = Math.max(0, Math.min(2000, deadline - Date.now()));
    saveTimer.current = window.setTimeout(() => {
      saveTimer.current = null;
      lastRecordSave.current = Date.now();
      void updatePage(page.id, { content: latestMarkdown.current });
    }, delay);
  }, [page.id, updatePage]);

  // Flush any pending save when the active page changes or the component unmounts.
  useEffect(() => {
    return () => {
      if (saveTimer.current != null) {
        window.clearTimeout(saveTimer.current);
        saveTimer.current = null;
        void updatePage(page.id, { content: latestMarkdown.current });
      }
    };
  }, [page.id, updatePage]);

  return (
    <div className="note-scroll flex h-full flex-col overflow-y-auto bg-editor">
      <div className="note-column mx-auto w-full py-8" style={{ maxWidth: 'var(--note-width, 48rem)' }}>
        {/* Title */}
        <div className="mb-1 flex items-center gap-2">
          {page.icon && <span className="text-2xl">{page.icon}</span>}
          <input
            ref={titleInputRef}
            value={titleValue}
            onChange={(e) => handleTitleChange(e.target.value)}
            className="flex-1 bg-transparent text-3xl font-bold outline-none placeholder:text-muted-foreground"
            placeholder="Untitled"
          />
        </div>

        {/* Editable path / slug */}
        <div className="mb-2 flex items-center gap-1.5 text-xs text-muted-foreground">
          <span className="select-none opacity-60">/</span>
          {editingSlug ? (
            <input
              ref={slugInputRef}
              autoFocus
              value={slugYValue}
              onChange={(e) => handleSlugInputChange(e.target.value)}
              onBlur={commitSlug}
              onKeyDown={(e) => { if (e.key === 'Enter') commitSlug(); }}
              className="border-b border-border bg-transparent px-0.5 font-mono text-xs outline-none"
            />
          ) : (
            <button
              onClick={() => setEditingSlug(true)}
              className="rounded-sm px-0.5 font-mono hover:bg-accent hover:text-foreground"
              title="Click to edit path"
            >
              {slugYValue || 'untitled'}
            </button>
          )}
        </div>

        {/* Tags */}
        <div className="mb-2 flex flex-wrap gap-1">
          {page.tags.map((tag) => (
            <span key={tag} className="rounded-full bg-muted px-2.5 py-0.5 text-xs text-muted-foreground">
              {tag}
            </span>
          ))}
        </div>

        {/* Milkdown (Crepe) editor: Obsidian-style live-preview markdown. */}
        <MilkdownProvider>
          <MarkdownEditor
            key={page.id}
            pageId={page.id}
            initialMarkdown={normalizePageContent(page.content)}
            editorRef={editorRef}
            onChange={(md) => {
              latestMarkdown.current = md;
              queueSave();
            }}
          />
        </MilkdownProvider>
      </div>
      {/* Floating format popup: only shown while text is selected. */}
      <FloatingFormatPanel editorRef={editorRef} />
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Milkdown (Crepe) editor wrapper.
//
// Crepe ships with Obsidian-style live preview: you type ``` to open a code
// block, `# ` for headings, `- [ ]` for checklists, `|` tables, etc., and
// rendering happens inline as you type. We mount a single Crepe instance
// per page id (hence the `key={page.id}` in the caller) and subscribe to
// the listener plugin's `markdownUpdated` event to drive persistence.
// ─────────────────────────────────────────────────────────────────────────
function MarkdownEditor({
  pageId,
  initialMarkdown,
  onChange,
  editorRef,
}: {
  pageId: string;
  initialMarkdown: string;
  onChange: (markdown: string) => void;
  editorRef: React.MutableRefObject<Editor | null>;
}) {
  // onChange needs to stay fresh without forcing the editor to remount.
  const onChangeRef = useRef(onChange);
  useEffect(() => { onChangeRef.current = onChange; }, [onChange]);

  // Resolve (or create) the per-page Y.Doc + IndexedDB persistence + cross-tab
  // BroadcastChannel sync. Cached so re-mounts don't lose in-memory state.
  const yctx = useMemo(() => getPageYContext(pageId), [pageId]);

  // The Crepe factory is intentionally synchronous: NO collab binding work
  // happens in here. The factory function runs every mount, but `crepe.create()`
  // (the call that actually builds the ProseMirror view) is async and Milkdown
  // does not give us its promise. If we tried to bind the Y.Doc inside the
  // factory we'd race against `create()` and on subsequent page revisits
  // (when `yctx.whenSynced` is already resolved) our binding would land on a
  // half-built editor and then `create()` would overwrite it with `defaultValue:
  // ''`. That's the source of "notes vanish and cursor stops syncing on revisit".
  //
  // Instead, we attach to the collab service from a useEffect that runs
  // strictly after `useEditor` reports `loading === false`, i.e. after the
  // editor is fully created.
  const { get, loading } = useEditor((root) => {
    const crepe = new Crepe({
      root,
      // When using collab the Y.Doc is the source of truth. Seeding only
      // happens once via applyTemplate in the effect below, so the editor
      // starts empty here.
      defaultValue: '',
      features: {
        [Crepe.Feature.Toolbar]: false,
      },
      featureConfigs: {
        // Notion-style ghost text on the current empty line instead of
        // Crepe's default "Please enter...".
        [Crepe.Feature.Placeholder]: {
          text: "Write, or type '/' for commands…",
          mode: 'block',
        },
        // Give code blocks the full language list (so the picker has options
        // and blocks get highlighted) plus our CSS-variable-driven syntax
        // theme, the token-built chrome (caret, selection, active line) and
        // the "focus the language picker" keybind.
        [Crepe.Feature.CodeMirror]: {
          languages: codeLanguages,
          // Crepe defaults this to One Dark, whose dark chrome (and its own
          // highlight style) showed in light mode too: a black line-number
          // cell, a blue active-line band. null switches it off (Crepe
          // fills in defaults with lodash defaultsDeep, which keeps a null
          // but would deep-merge One Dark into an extension passed here);
          // codeChromeTheme below is the replacement.
          theme: null as unknown as Extension,
          extensions: [codeSyntaxThemeExtension, codeChromeTheme, focusLanguageKeymap],
        },
        // Two table variants in the slash menu. GFM always writes a header
        // row, so the difference is whether that row starts with content:
        // seeded column names render as a shaded header, a blank row renders
        // flat (see lib/table-plugin.ts).
        [Crepe.Feature.BlockEdit]: {
          // Notion's slash-menu vocabulary: filtering matches labels, so
          // "Bulleted list" answers /bullet and "Numbered list" answers /num
          // the way Notion users type them. H4-H6 leave the menu (Notion
          // stops at H3); typing #### etc. still works.
          textGroup: { h4: null, h5: null, h6: null },
          listGroup: {
            bulletList: { label: 'Bulleted list' },
            orderedList: { label: 'Numbered list' },
            taskList: { label: 'To-do list' },
          },
          advancedGroup: {
            // Replace Crepe's built-in entry so the shaded variant is the one
            // that seeds labels; the plain variant is added alongside it.
            table: null,
          },
          buildMenu: (builder: TableMenuBuilder) => {
            const advanced = builder.getGroup('advanced');
            advanced.addItem('table-header', {
              label: 'Table',
              icon: TABLE_ICON,
              onRun: (ctx) => insertTable(ctx, DEFAULT_HEADER_LABELS),
            });
            advanced.addItem('table-plain', {
              label: 'Plain table',
              icon: TABLE_ICON,
              onRun: (ctx) => insertTable(ctx, null),
            });
            advanced.addItem('page', {
              label: 'Page',
              icon: PAGE_REF_ICON,
              onRun: (ctx) => { void insertPageRef(ctx, pageId); },
            });
          },
        },
      },
    });
    // Commonmark's ``` rule stores the captured language verbatim ("" for a
    // bare fence), bypassing the schema default, and input rules are
    // first-match-wins, so the preset's copy has to go rather than be
    // shadowed. `remove()` is async by signature but drops the plugin from
    // the store synchronously while the editor is still idle, which it is
    // here: `create()` only runs after this factory returns.
    void crepe.editor.remove(createCodeBlockInputRule);
    crepe.editor
      .use(listener)
      .use(highlightPlugin)
      // `/code` and a bare ``` both default to shell; Notion typing
      // conversions ([] to-dos, " quotes); inline-code mark made
      // non-inclusive so the caret stays visible and code styling stops at
      // the closing backtick; per-account keybinds + backtick-wrap +
      // Ctrl+Shift+digit turn-into; Notion-style block selection (Esc);
      // per-language data attr.
      .use(codeBlockShellDefault)
      .use(codeFenceInputRule)
      .use(notionTypingRules)
      .use(inlineCodeNonInclusive)
      .use(userKeybindsPlugin)
      .use(blockSelectPlugin)
      .use(codeLanguageAttrPlugin)
      // Drag-to-resize images: a `width` attr on both the inline image and
      // Crepe's image block, plus a corner handle that writes it (see
      // lib/image-resize.ts).
      .use(imageResizableSchema)
      .use(imageBlockResizableSchema)
      .use(imageResizePlugin)
      // Asset-backed images: paste/drop uploads to the shared asset store and
      // inserts an asset_image node (blurrable non-destructively). See
      // lib/asset-image.ts + lib/note-image-paste.ts.
      .use(assetImageSchema)
      .use(assetImageView)
      .use(noteImagePastePlugin)
      .use(noteImageContextPlugin)
      .use(noteImageCleanupPlugin)
      // Page-reference chips inserted by the /page slash command: a live-
      // updating link to a subnote (see lib/page-ref.ts).
      .use(pageRefSchema)
      .use(pageRefView)
      .use(tableHeaderStatePlugin)
      .use(tableKeysPlugin)
      // List items in plain DOM instead of Crepe's Vue view, which moved the
      // caret's paragraph out of the page on a re-render (see
      // lib/list-item-view.ts). Registered after Crepe's, so it wins.
      .use(listItemView)
      // A click on a block's bare chrome (a code block's header bar) keeps
      // the caret where it was instead of dropping one into a nearby line
      // (see lib/editor-chrome-click.ts).
      .use(editorChromeClickPlugin)
      // Live preview (Obsidian) editor style: reveals markdown syntax around
      // the selection as decorations; inert in Blocks style. See
      // components/editor/live-preview/.
      .use(livePreviewPlugin)
      // `==text==` typed in the Live preview style becomes a highlight.
      .use(highlightInputRule)
      .use(collab)
      .config((ctx) => {
        ctx.get(listenerCtx).markdownUpdated((_, md) => {
          onChangeRef.current(md);
        });
      });
    return crepe;
  }, [pageId]);

  // Once the editor is fully created AND the IndexedDB cache has loaded,
  // bind the Y.Doc and connect the collab service. On unmount, disconnect
  // cleanly so the awareness / cursor plugin handlers don't leak across
  // re-mounts (which would also break cursor sync for the next visit).
  useEffect(() => {
    if (loading) return;
    const editor = get();
    if (!editor) return;

    const boundEditor: Editor = editor;
    const releasePage = retainPageYContext(pageId);
    editorRef.current = editor;
    setActiveMilkdownEditor(editor);
    let cancelled = false;
    // Set while an uncached page waits for its first real server sync.
    let waitForSync: ((synced: boolean) => void) | null = null;
    const stopWaitingForSync = () => {
      if (!waitForSync) return;
      yctx.provider.off('sync', waitForSync);
      waitForSync = null;
    };

    void yctx.whenFullySynced.then(() => {
      if (cancelled || editorRef.current !== editor) return;
      try {
        editor.action((ctx) => {
          const service = ctx.get(collabServiceCtx);
          service.bindDoc(yctx.doc).setAwareness(yctx.awareness);

          // Custom remote-cursor renderer: matches the default y-prosemirror
          // structure (caret span + name tag div): just the user's name in
          // their color, no avatar.
          service.setOptions({
            yCursorOpts: {
              cursorBuilder: (user: { id?: number | string; name?: string; color?: string }) => {
                const color = user.color || SWATCHES[1];
                const name = user.name || 'Anonymous';
                const cursor = document.createElement('span');
                cursor.classList.add('ProseMirror-yjs-cursor');
                cursor.setAttribute('style', `border-color: ${color}`);
                // Tag with the user id so the follow feature can locate and
                // scroll a specific teammate's caret into view.
                if (user.id != null) cursor.setAttribute('data-user-id', String(user.id));
                const tag = document.createElement('div');
                // Black or white name text by contrast: a pale presence colour (lime,
                // yellow, cyan) made the old fixed white unreadable.
                tag.setAttribute('style', `background-color: ${color}; color: ${readableTextOn(color)}`);
                tag.appendChild(document.createTextNode(name));
                cursor.appendChild(document.createTextNode('\u2060'));
                cursor.appendChild(tag);
                cursor.appendChild(document.createTextNode('\u2060'));
                return cursor;
              },
            },
          });

          // Only seed the Y.Doc the very first time we ever connect to this
          // fragment. Use an explicit fragment-length check rather than
          // Milkdown's default `textContent.length === 0` predicate, which
          // would wipe structural content (images, empty headings, partially-
          // typed checklists) on every revisit.
          //
          // An empty fragment only means "new page" once the server has
          // answered: whenFullySynced also resolves on a 3 s timer, and
          // seeding then, before the stored body arrives, writes the
          // markdown alongside it and duplicates the page for everyone. So
          // with cached content, bind at once; with nothing cached, bind only
          // after a real sync (the server answers sync after the room has
          // loaded) and seed only if the fragment is still empty then.
          const fragment = yctx.doc.getXmlFragment('prosemirror');
          if (fragment.length > 0 || yctx.provider.synced) {
            connectEditor();
          } else {
            waitForSync = (synced: boolean) => {
              if (!synced || cancelled || editorRef.current !== editor) return;
              stopWaitingForSync();
              try {
                editor.action(() => connectEditor());
              } catch (err) {
                if (import.meta.env.DEV) console.warn('[PageEditor] collab connect aborted:', err);
              }
            };
            yctx.provider.on('sync', waitForSync);
          }

          function connectEditor() {
            if (fragment.length === 0) {
              // Not applyTemplate: its random client id let two clients that
              // first-open an empty room together both seed it and double the
              // body. A seed derived from the page and its text is written
              // by the same Yjs ids on every client, so it merges into one.
              boundEditor.action((c) => {
                const node = getDoc(initialMarkdown, c.get(parserCtx), c.get(schemaCtx));
                if (node) seedPageFragment(yctx.doc, node, pageId, initialMarkdown);
              });
            }
            service.connect();
            // Registered for version restores only once bound: a restore
            // through a view that is not collab-bound yet is thrown away when
            // y-prosemirror renders the fragment (page-snapshots.ts then uses
            // the Yjs path instead).
            registerPageEditor(pageId, boundEditor);
          }
        });
      } catch (err) {
        // Editor was destroyed mid-await; safe to ignore.
        if (import.meta.env.DEV) console.warn('[PageEditor] collab connect aborted:', err);
      }
    });

    return () => {
      cancelled = true;
      stopWaitingForSync();
      releasePage();
      try {
        editor.action((ctx) => {
          const service = ctx.get(collabServiceCtx);
          service.disconnect();
        });
      } catch {
        /* editor already destroyed */
      }
      if (editorRef.current === editor) editorRef.current = null;
      unregisterPageEditor(pageId, editor);
      // Only clear the global reference if it's still pointing to *this*
      // editor, otherwise we'd stomp on a newer editor that registered
      // itself between this effect cleanup and a remount.
      clearActiveMilkdownEditor(editor);
    };
    // initialMarkdown is intentionally NOT in the deps: it would re-run this
    // effect on every keystroke (each save updates page.content → re-renders
    // PageEditorInner with a new initialMarkdown) which would tear down and
    // re-create the collab connection mid-typing. We only need the value
    // captured at first bind; the Y.Doc is authoritative after that.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loading, pageId, yctx]);

  useEffect(() => {
    return () => { editorRef.current = null; };
  }, [editorRef]);

  return (
    <div
      className="milkdown-host min-h-[400px]"
      // The active editor follows focus, so Ctrl+K, the blur keybind and
      // block select act on the pane being typed in, not the one that
      // happened to mount last.
      onFocusCapture={() => { if (!loading) { const ed = get(); if (ed) setActiveMilkdownEditor(ed); } }}
    >
      <Milkdown />
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Floating format toolbar: a Notion-style horizontal bar that appears just
// above the selection (below it when there's no headroom), centered on it.
// Layout mirrors Notion's edit bar: a "Turn into" dropdown showing the
// current block type, the inline marks with live active states, link, a
// highlight-color dropdown, and the keybinds gear. It's a portal overlay,
// so opening/closing it can never remount the editor (invariant #3).
// ─────────────────────────────────────────────────────────────────────────

interface ActiveFormats {
  bold: boolean;
  italic: boolean;
  strike: boolean;
  code: boolean;
  link: boolean;
  /** Label for the "Turn into" button (the selection's block type). */
  block: string;
}

const EMPTY_ACTIVE: ActiveFormats = {
  bold: false, italic: false, strike: false, code: false, link: false, block: 'Text',
};

function sameFormats(a: ActiveFormats, b: ActiveFormats): boolean {
  return a.bold === b.bold && a.italic === b.italic && a.strike === b.strike
    && a.code === b.code && a.link === b.link && a.block === b.block;
}

/** Read which marks cover the selection and what block type it sits in. */
function readActiveFormats(editor: Editor): ActiveFormats {
  const out = { ...EMPTY_ACTIVE };
  try {
    editor.action((ctx) => {
      const { state } = ctx.get(editorViewCtx);
      const { from, to, $from } = state.selection;
      const has = (name: string) => {
        const type = state.schema.marks[name];
        return type ? state.doc.rangeHasMark(from, to, type) : false;
      };
      out.bold = has('strong');
      out.italic = has('emphasis');
      out.strike = has('strike_through');
      out.code = has('inlineCode');
      out.link = has('link');
      for (let d = $from.depth; d > 0; d--) {
        const node = $from.node(d);
        if (node.type.name === 'heading') { out.block = `Heading ${node.attrs.level}`; return; }
        if (node.type.name === 'code_block') { out.block = 'Code'; return; }
        if (node.type.name === 'blockquote') { out.block = 'Quote'; return; }
        if (node.type.name === 'list_item') {
          if (node.attrs.checked != null) { out.block = 'To-do list'; return; }
          out.block = $from.node(d - 1)?.type.name === 'ordered_list'
            ? 'Numbered list'
            : 'Bulleted list';
          return;
        }
      }
    });
  } catch {
    /* editor mid-teardown */
  }
  return out;
}

/** A DOM selection's ends, to tell whether it changed since Escape. */
type SelectionEnds = readonly [Node | null, number, Node | null, number];
function selectionKey(sel: globalThis.Selection): SelectionEnds {
  return [sel.anchorNode, sel.anchorOffset, sel.focusNode, sel.focusOffset];
}
const sameEnds = (a: SelectionEnds, b: SelectionEnds) => a.every((v, i) => v === b[i]);

function editorSelectionWantsToolbar(editor: Editor | null): boolean {
  if (!editor) return true;
  let want = true;
  try {
    editor.action((ctx) => { want = selectionWantsFormatToolbar(ctx.get(editorViewCtx).state.selection); });
  } catch {
    /* editor mid-teardown */
  }
  return want;
}

function FloatingFormatPanel({ editorRef }: { editorRef: React.MutableRefObject<Editor | null> }) {
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  // Hide the text-format popup while the image right-click menu or the
  // crop/blur editor is open: it's for text, not for an image selection.
  const imageEditorOpen = useAppStore((s) => !!s.editingAssetId || !!s.imageMenu);
  const [active, setActive] = useState<ActiveFormats>(EMPTY_ACTIVE);
  const [openMenu, setOpenMenu] = useState<'turninto' | 'highlight' | null>(null);
  const [keybindsOpen, setKeybindsOpen] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  // The selection Escape dismissed the toolbar for: it stays hidden until
  // the selection changes (a scroll or resize must not bring it back).
  const dismissedRef = useRef<SelectionEnds | null>(null);

  useEffect(() => {
    const update = () => {
      const sel = window.getSelection();
      if (!sel || sel.isCollapsed || sel.rangeCount === 0) {
        dismissedRef.current = null;
        setPos(null);
        setOpenMenu(null);
        return;
      }
      const anchor = sel.anchorNode;
      if (!anchor) { setPos(null); setOpenMenu(null); return; }
      const anchorEl = anchor.nodeType === Node.ELEMENT_NODE
        ? (anchor as Element)
        : anchor.parentElement;
      if (!anchorEl || !anchorEl.closest('.milkdown-host .ProseMirror')) {
        setPos(null);
        setOpenMenu(null);
        return;
      }
      // Don't hide when interacting with the panel itself.
      if (panelRef.current && panelRef.current.contains(anchorEl)) return;
      if (dismissedRef.current !== null) {
        if (sameEnds(dismissedRef.current, selectionKey(sel))) return;
        dismissedRef.current = null;
      }
      // A node or cell selection paints as selected text but is not one
      // (the first click into a table cell is a NodeSelection).
      if (!editorSelectionWantsToolbar(editorRef.current)) {
        setPos(null);
        setOpenMenu(null);
        return;
      }

      const rect = sel.getRangeAt(0).getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) {
        setPos(null);
        setOpenMenu(null);
        return;
      }

      // Placement math runs in screen px (the selection rect and the window
      // are); the panel's own size is CSS px, so scale it by the interface zoom.
      const z = getUiZoom();
      const panel = panelRef.current;
      const w = (panel?.offsetWidth ?? 380) * z;
      const h = (panel?.offsetHeight ?? 38) * z;
      const gap = 8;
      const vw = window.innerWidth;
      const vh = window.innerHeight;

      // Notion placement: centered above the selection; flip below when the
      // selection starts too close to the top of the viewport.
      let top = rect.top - gap - h;
      if (top < 8) top = Math.min(vh - h - 8, rect.bottom + gap);
      const left = Math.min(vw - w - 8, Math.max(8, rect.left + rect.width / 2 - w / 2));
      setPos({ top: top / z, left: left / z });

      const editor = editorRef.current;
      if (editor) {
        const next = readActiveFormats(editor);
        setActive((prev) => (sameFormats(prev, next) ? prev : next));
      }
    };

    // Coalesce bursts (a scroll fires this per event, capture-phase, for
    // every scroller in the app; selectionchange fires per caret move) into
    // at most one layout-reading update per frame.
    let frame = 0;
    const onChange = () => {
      if (frame) return;
      frame = requestAnimationFrame(() => { frame = 0; update(); });
    };
    document.addEventListener('selectionchange', onChange);
    window.addEventListener('scroll', onChange, true);
    window.addEventListener('resize', onChange);
    return () => {
      if (frame) cancelAnimationFrame(frame);
      document.removeEventListener('selectionchange', onChange);
      window.removeEventListener('scroll', onChange, true);
      window.removeEventListener('resize', onChange);
    };
  }, [editorRef]);

  // Escape closes an open dropdown first, then the toolbar itself. Capture
  // phase, so a dropdown's Escape does not also reach the editor's block
  // selection. A modal dialog on top keeps its own Escape.
  useEffect(() => {
    if (!pos) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || document.querySelector('[aria-modal="true"]')) return;
      if (openMenu) {
        e.preventDefault();
        e.stopPropagation();
        setOpenMenu(null);
        return;
      }
      const sel = window.getSelection();
      dismissedRef.current = sel ? selectionKey(sel) : null;
      setPos(null);
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [pos, openMenu]);

  const run = useCallback(<P,>(commandKey: string, payload?: P) => {
    const editor = editorRef.current;
    if (!editor) return;
    editor.action(callCommand(commandKey, payload));
  }, [editorRef]);

  const applyTurnInto = useCallback((target: TurnIntoTarget) => {
    const editor = editorRef.current;
    if (!editor) return;
    editor.action((ctx) => turnIntoBlock(ctx, target));
    setOpenMenu(null);
  }, [editorRef]);

  const applyHighlight = useCallback((color: HighlightColor | null) => {
    const editor = editorRef.current;
    if (!editor) return;
    if (color) setLastHighlightColor(color);
    editor.action(callCommand(toggleHighlightCommand.key, color));
    setOpenMenu(null);
  }, [editorRef]);

  const kb = getEditorKeybinds();

  return (
    <>
      {pos && !imageEditorOpen && createPortal(
    <div
      ref={panelRef}
      className="fixed z-[60] flex items-center gap-0.5 rounded-lg border border-border bg-card p-1 shadow-xl animate-[hl-toolbar-in_0.08s_ease-out]"
      style={{ top: pos.top, left: pos.left }}
      role="toolbar"
      aria-label="Text formatting"
      // Preserve the editor selection while clicking inside the panel.
      onMouseDown={(e) => e.preventDefault()}
    >
      {/* Turn into */}
      <div className="relative">
        <button
          type="button"
          title="Turn into"
          aria-label={`Turn into (current: ${active.block})`}
          onClick={() => setOpenMenu((m) => (m === 'turninto' ? null : 'turninto'))}
          className="flex h-7 items-center gap-1 whitespace-nowrap rounded-md px-2 text-xs text-foreground hover:bg-accent"
        >
          {active.block} <ChevronDown size={12} className="text-muted-foreground" />
        </button>
        {openMenu === 'turninto' && (
          <div className="absolute left-0 top-full z-10 mt-1 w-44 rounded-lg border border-border bg-card p-1 shadow-xl">
            <div className="px-2 pb-1 pt-0.5 text-micro font-bold uppercase tracking-widest text-muted-foreground">
              Turn into
            </div>
            {TURN_INTO_ITEMS.map(({ target, label }) => (
              <button
                key={target}
                type="button"
                onClick={() => applyTurnInto(target)}
                className={`flex w-full items-center justify-between rounded-md px-2 py-1 text-left text-xs hover:bg-accent ${
                  label === active.block ? 'text-primary' : ''
                }`}
              >
                {label}
                {label === active.block && <span aria-hidden>✓</span>}
              </button>
            ))}
          </div>
        )}
      </div>

      <ToolbarDivider />

      <ToolbarButton title={`Bold (${formatShortcut(kb.bold)})`} active={active.bold} onClick={() => run('ToggleStrong')}>
        <Bold size={14} />
      </ToolbarButton>
      <ToolbarButton title={`Italic (${formatShortcut(kb.italic)})`} active={active.italic} onClick={() => run('ToggleEmphasis')}>
        <Italic size={14} />
      </ToolbarButton>
      <ToolbarButton title={`Strikethrough (${formatShortcut(kb.strikethrough)})`} active={active.strike} onClick={() => run('ToggleStrikeThrough')}>
        <Strikethrough size={14} />
      </ToolbarButton>
      <ToolbarButton title={`Inline code (${formatShortcut(kb.inlineCode)})`} active={active.code} onClick={() => run('ToggleInlineCode')}>
        <Code size={14} />
      </ToolbarButton>

      <ToolbarDivider />

      <ToolbarButton
        title={`Link (${formatShortcut(kb.link)})`}
        active={active.link}
        onClick={() => { const editor = editorRef.current; if (editor) openLinkEditor(editor); }}
      >
        <LinkIcon size={14} />
      </ToolbarButton>

      {/* Highlight color */}
      <div className="relative">
        <ToolbarButton
          title={`Highlight (${formatShortcut(kb.highlight)} re-applies the last color)`}
          active={openMenu === 'highlight'}
          onClick={() => setOpenMenu((m) => (m === 'highlight' ? null : 'highlight'))}
        >
          <Highlighter size={14} />
        </ToolbarButton>
        {openMenu === 'highlight' && (
          <div className="absolute right-0 top-full z-10 mt-1 rounded-lg border border-border bg-card p-2 shadow-xl">
            <div className="pb-1 text-micro font-bold uppercase tracking-widest text-muted-foreground">
              Highlight
            </div>
            <div className="grid grid-cols-4 gap-1.5">
              {HIGHLIGHT_COLORS.map((color) => (
                <button
                  key={color}
                  type="button"
                  title={`Highlight ${color}`}
                  aria-label={`Highlight ${color}`}
                  onClick={() => applyHighlight(color)}
                  className="hl-swatch"
                  style={{ backgroundColor: swatchCssColor(color) }}
                />
              ))}
              <button
                type="button"
                title="Remove highlight"
                aria-label="Remove highlight"
                onClick={() => applyHighlight(null)}
                className="hl-swatch hl-swatch--clear"
              />
            </div>
          </div>
        )}
      </div>

      <ToolbarDivider />

      <ToolbarButton title="Customize keybinds" onClick={() => setKeybindsOpen(true)}>
        <Keyboard size={13} />
      </ToolbarButton>
    </div>,
    document.body,
      )}
      {keybindsOpen && <KeybindsDialog onClose={() => setKeybindsOpen(false)} />}
    </>
  );
}

function ToolbarDivider() {
  return <div aria-hidden className="mx-0.5 h-4 w-px bg-border" />;
}

function ToolbarButton({ title, active, onClick, children }: {
  title: string;
  active?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      title={title}
      aria-label={title}
      aria-pressed={active ?? false}
      onClick={onClick}
      className={`flex h-7 w-7 items-center justify-center rounded-md hover:bg-accent ${
        active
          ? 'bg-accent text-primary'
          : 'text-foreground'
      }`}
    >
      {children}
    </button>
  );
}

function swatchCssColor(color: HighlightColor): string {
  switch (color) {
    case 'yellow': return 'var(--hl-yellow)';
    case 'green':  return 'var(--hl-green)';
    case 'blue':   return 'var(--hl-blue)';
    case 'pink':   return 'var(--hl-pink)';
    case 'orange': return 'var(--hl-orange)';
    case 'purple': return 'var(--hl-purple)';
    case 'red':    return 'var(--hl-red)';
  }
}
