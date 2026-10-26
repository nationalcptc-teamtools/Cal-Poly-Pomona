// ─────────────────────────────────────────────────────────────────────────
// Typst tab: a typst.app-style split view rendered entirely locally.
//
// Left: the raw Typst source in a collaborative CodeMirror editor.
// Right: the live, in-browser-compiled preview.
//
// The source is a single per-workspace Y.Text (`typst:<workspaceId>:source`)
// in the shared doc, so it's persisted and collaboratively edited like every
// other text field in BTCT. There is one Typst scratchpad document per
// workspace.
// ─────────────────────────────────────────────────────────────────────────

import { useState, useEffect, useMemo, useRef, useCallback, lazy, Suspense } from 'react';
import { PanelLeftClose, PanelLeftOpen, FileDown, FileUp, FileArchive, Image, FileText, Images, Search, ListFilter } from 'lucide-react';
import { useAppStore } from '@/stores';
import type { BlurRegion, CropRect, ID, TypstAsset } from '@/types';
import { updateYTextContent } from '@/realtime/use-y-text';
import { useTypstSource } from './use-typst-source';
import {
  TypstEditor,
  revealTypstRange,
  getTypstCaret,
  insertAtTypstCursor,
  setTypstSearchRequest,
  setTypstFindingFocus,
} from './TypstEditor';
import type { FindingsPanelProps } from './FindingsPanel';
import type { FindingTarget } from '@/lib/finding-jump';

// Lazy so the Findings mode's rail and form code sit in the Report
// tab's own chunk, not the entry bundle (invariant #17).
const FindingsPanel = lazy(() =>
  import('./FindingsPanel').then((m) => ({ default: m.FindingsPanel })),
);
import { TypstPreview, type SourceCandidate } from './TypstPreview';
import { TypstSearchPanel } from './TypstSearchPanel';
import { usePreviewLock } from './use-preview-lock';
import { AssetsPanel } from '@/components/assets/AssetsPanel';
import { Button } from '@/components/ui/Button';
import { Banner } from '@/components/ui/Banner';
import { Splitter } from '@/components/ui/Splitter';
import {
  cancelTypstRelease,
  compileTypstPdf,
  compileTypstSvg,
  getFontInfo,
  scheduleTypstRelease,
  setTypstFonts,
  setTypstShadowFiles,
  typstErrorMessage,
} from '@/lib/typst-compiler';
import {
  exportOnServer,
  loadExportCapabilities,
  serverExportNotice,
  type ExportCapabilities,
} from '@/lib/typst-export-api';
import { assetPath, fetchAssetBytes, resolveAssetBytes } from '@/lib/assets';
import { matchAssetByHref } from '@/lib/asset-folders';
import { toLayoutPx } from '@/lib/ui-zoom';
import {
  appendSlot,
  ensureHelper,
  ensureHelperWidth,
  findScreenshotSlots,
  setSlotHeight,
  setSlotPath,
  setSlotWidth,
  type ScreenshotSlot,
} from '@/lib/typst-placeholders';
import { findSourceRange, type SourceRange } from '@/lib/typst-source-map';
import {
  clampPaneWidth,
  fitPanes,
  loadTypstLayout,
  saveTypstLayout,
  PANE_DEFAULT,
  type PaneKind,
  type TypstLayout,
} from '@/lib/pane-resize';
import { downloadAsZip } from '@/lib/download-zip';
import { ReportImportDialog } from './ReportImportDialog';
import { exportReport, type ImportCallbacks, type ImportResult, type PreparedImport } from './report-bundle-io';

/** Findings rail width bounds, in layout px. */
const FINDINGS_DEFAULT_WIDTH = 360;
const FINDINGS_MIN_WIDTH = 280;
const FINDINGS_MAX_WIDTH = 760;
function clampFindingsWidth(w: number): number {
  return Math.min(FINDINGS_MAX_WIDTH, Math.max(FINDINGS_MIN_WIDTH, Math.round(w)));
}

/** How long the source must be idle before the figure slots are re-scanned. */
const SLOT_SCAN_DEBOUNCE_MS = 300;

/**
 * Trailing-edge debounce.
 *
 * The source changes on every keystroke, but the slot scan it feeds only
 * labels thumbnails: it does not need to be frame-accurate. Debouncing keeps
 * a fast typist from re-parsing the whole document (and re-rendering the
 * thumbnail grid) ten times a second.
 */
function useDebounced<T>(value: T, delay: number): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return settled;
}

/**
 * Every export leaves the tab as `<workspace>_<date>_<format>.zip` holding the file
 * under its own name (src/lib/download-zip.ts, which hands the ZIP to
 * `downloadBlob`).
 */
function triggerDownload(stem: string, filename: string, data: Blob | Uint8Array | string): Promise<string | null> {
  return downloadAsZip(stem, [{ name: filename, data }]);
}

/**
 * Push the workspace's assets into the compiler's virtual filesystem and
 * font set, and report a revision that changes whenever they do, so the
 * preview recompiles after a drop or a crop, not just on a source edit.
 *
 * Images are resolved through `resolveAssetBytes`, which applies the crop
 * rectangle before the bytes ever reach Typst. Everything is memoized by
 * asset id + crop, so this is a no-op on re-renders where nothing moved.
 *
 * `ready` goes true once the compiler has been told about this workspace's
 * files at least once. Compiling before then renders the document with every
 * `#image("/assets/…")` unresolved, so the preview waits.
 */
function useTypstAssetSync(workspaceId: ID): { revision: number; ready: boolean } {
  const assets = useAppStore((s) => s.typstAssets);
  const loadTypstAssets = useAppStore((s) => s.loadTypstAssets);
  const [revision, setRevision] = useState(0);
  const [ready, setReady] = useState(false);

  // A different workspace means a different set of mounted files: nothing the
  // compiler holds right now belongs to it.
  useEffect(() => { setReady(false); }, [workspaceId]);

  // `loadTypstAssets` loads the *store's* `activeWorkspaceId`, not the
  // `workspaceId` this tab was opened for. They agree only because
  // `setActiveWorkspace` (app-store) empties `tabs`, so a Typst tab cannot
  // outlive the workspace it belongs to. If tabs are ever made to survive a
  // workspace switch, this tab would mount the other workspace's images into
  // the compiler and the rail, and both this effect and the panel's asset
  // list would need a workspace-scoped load instead.
  useEffect(() => { void loadTypstAssets(); }, [loadTypstAssets, workspaceId]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const images = assets.filter((a) => a.kind === 'image');
      const fonts = assets.filter((a) => a.kind === 'font');

      // allSettled: one asset whose bytes went missing (volume wiped, blob
      // deleted out-of-band) must not take down every other image in the
      // document. Failures are simply left unmounted, and Typst reports the
      // unresolved path against the exact line that referenced it.
      const [imageResults, fontResults] = await Promise.all([
        Promise.allSettled(
          images.map(async (a) => ({ path: assetPath(a), bytes: await resolveAssetBytes(a) })),
        ),
        Promise.allSettled(fonts.map((a) => fetchAssetBytes(a.id))),
      ]);
      if (cancelled) return;

      const files = imageResults
        .filter((r): r is PromiseFulfilledResult<{ path: string; bytes: Uint8Array }> =>
          r.status === 'fulfilled')
        .map((r) => r.value);
      const fontBytes = fontResults
        .filter((r): r is PromiseFulfilledResult<Uint8Array> => r.status === 'fulfilled')
        .map((r) => r.value);

      const filesChanged = setTypstShadowFiles(files);
      const fontsChanged = setTypstFonts(fontBytes);
      if (filesChanged || fontsChanged) setRevision((r) => r + 1);
      setReady(true);
    })();
    return () => { cancelled = true; };
  }, [assets]);

  return { revision, ready };
}

export function TypstView({ workspaceId }: { workspaceId: ID }) {
  const ytext = useTypstSource(workspaceId);
  const typstAssets = useAppStore((s) => s.typstAssets);
  const addTypstAsset = useAppStore((s) => s.addTypstAsset);
  const setTypstAssetCrop = useAppStore((s) => s.setTypstAssetCrop);
  const renameTypstAsset = useAppStore((s) => s.renameTypstAsset);
  const unretireTypstAsset = useAppStore((s) => s.unretireTypstAsset);
  const workspaces = useAppStore((s) => s.workspaces);
  const workspaceName = workspaces.find((w) => w.id === workspaceId)?.name;
  // Ref mirror so the preview's click callback stays stable across renders.
  const typstAssetsRef = useRef(typstAssets);
  typstAssetsRef.current = typstAssets;
  const [source, setSource] = useState('');
  const [layout, setLayout] = useState<TypstLayout>(loadTypstLayout);
  const { showEditor, showAssets } = layout;
  // Findings mode: a rail of the report's finding blocks, grouped by
  // severity, with status tags and a single-finding editing form. Local UI
  // state, remembered per device like the rest of the tab's layout.
  const [findingsMode, setFindingsMode] = useState(() => {
    try { return localStorage.getItem('btct.typst.findingsMode') === '1'; } catch { return false; }
  });
  // Four cards (findings, code, preview, assets) do not fit a laptop-width
  // pane, so entering the mode closes the Assets rail and leaving it reopens
  // the rail if the mode closed it. The Assets button still opens it on
  // demand. The "closed by the mode" flag is per device, like the layout.
  const ASSETS_CLOSED_KEY = 'btct.typst.findingsClosedAssets';
  const setFindings = useCallback((next: boolean) => {
    setFindingsMode(next);
    try { localStorage.setItem('btct.typst.findingsMode', next ? '1' : '0'); } catch { /* ignore */ }
    if (!next) setTypstFindingFocus(null);
    setLayout((prev) => {
      let closedByMode = false;
      try { closedByMode = localStorage.getItem(ASSETS_CLOSED_KEY) === '1'; } catch { /* ignore */ }
      let merged = prev;
      if (next && prev.showAssets) {
        merged = { ...prev, showAssets: false };
        try { localStorage.setItem(ASSETS_CLOSED_KEY, '1'); } catch { /* ignore */ }
      } else if (!next && closedByMode) {
        merged = { ...prev, showAssets: true };
        try { localStorage.removeItem(ASSETS_CLOSED_KEY); } catch { /* ignore */ }
      }
      if (merged !== prev) saveTypstLayout(merged);
      return merged;
    });
  }, []);
  // The findings rail is resizable (the step editor wants room for code and
  // thumbnails beside the code and the preview). Per device, like the layout.
  const FINDINGS_WIDTH_KEY = 'btct.typst.findingsWidth';
  const [findingsWidth, setFindingsWidth] = useState(() => {
    try {
      const v = Number(localStorage.getItem(FINDINGS_WIDTH_KEY));
      return Number.isFinite(v) && v > 0 ? clampFindingsWidth(v) : FINDINGS_DEFAULT_WIDTH;
    } catch { return FINDINGS_DEFAULT_WIDTH; }
  });
  const findingsPaneRef = useRef<HTMLDivElement>(null);
  const commitFindingsWidth = useCallback((w: number) => {
    const v = clampFindingsWidth(w);
    setFindingsWidth(v);
    try { localStorage.setItem(FINDINGS_WIDTH_KEY, String(Math.round(v))); } catch { /* ignore */ }
  }, []);
  const findingsWidthRef = useRef(findingsWidth);
  findingsWidthRef.current = findingsWidth;
  // Same drag rules as the other dividers: a DOM write per frame, one commit
  // on release (invariant 3c).
  const startFindingsResize = useCallback((e: React.PointerEvent) => {
    e.preventDefault();
    const el = findingsPaneRef.current;
    if (!el) return;
    const startX = e.clientX;
    const start = findingsWidthRef.current;
    let next = start;
    let frame = 0;
    document.body.style.userSelect = 'none';
    document.body.style.cursor = 'col-resize';
    const onMove = (ev: PointerEvent) => {
      next = clampFindingsWidth(start + toLayoutPx(ev.clientX - startX));
      if (!frame) frame = requestAnimationFrame(() => { frame = 0; el.style.width = `${next}px`; });
    };
    const cleanup = () => {
      if (frame) cancelAnimationFrame(frame);
      document.body.style.userSelect = '';
      document.body.style.cursor = '';
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
      dragCleanupRef.current = null;
    };
    const onUp = () => { cleanup(); commitFindingsWidth(next); };
    dragCleanupRef.current = cleanup;
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onUp);
  }, [commitFindingsWidth]);
  const findingsModeRef = useRef(findingsMode);
  findingsModeRef.current = findingsMode;
  const toggleFindingsMode = useCallback(() => setFindings(!findingsModeRef.current), [setFindings]);
  // Scroll the preview to the selected finding (by its title text).
  // Findings mode's request to bring a finding's block into view in the preview.
  const [findingJump, setFindingJump] = useState<{ target: FindingTarget; nonce: number } | null>(null);
  const [exporting, setExporting] = useState(false);
  // One dismissible banner for anything the tab needs to say: a failed
  // export, or a snippet that went to the clipboard because the code pane
  // was closed. `kind` decides whether it reads as a failure or as a note;
  // an info banner is selectable, because some of them carry a snippet the
  // operator has to copy by hand.
  const [notice, setNotice] = useState<{ kind: 'error' | 'info'; text: string } | null>(null);
  // What the server can export, probed once on mount. Both stay false while
  // the check is in flight, so the two server buttons default to hidden
  // rather than flashing in.
  const [caps, setCaps] = useState<ExportCapabilities>({ pdf: false, docx: false });
  // Which server export (if any) is running. Separate from `exporting`
  // (the in-browser PDF/SVG state) because the server admits only two
  // queued exports at a time: only the two server buttons need to wait on
  // each other, and the browser export stays available regardless.
  const [serverExporting, setServerExporting] = useState<'pdf' | 'docx' | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const editorPaneRef = useRef<HTMLDivElement>(null);
  const assetsPaneRef = useRef<HTMLDivElement>(null);
  const { revision: assetRevision, ready: assetsReady } = useTypstAssetSync(workspaceId);
  // Preview lock: this account's, on this browser, for this workspace only.
  const { locked: previewLocked, toggle: togglePreviewLock } = usePreviewLock(workspaceId);
  // Mirrors `source` so the reveal callback can stay stable across keystrokes.
  const sourceRef = useRef(source);
  sourceRef.current = source;

  // Live pane widths, mirrored into refs so the drag handler reads the current
  // value without re-subscribing and without depending on a render.
  const widthsRef = useRef({ editor: layout.editor, assets: layout.assets });
  widthsRef.current = { editor: layout.editor, assets: layout.assets };
  const visibleRef = useRef({ editor: showEditor, assets: showAssets });
  visibleRef.current = { editor: showEditor, assets: showAssets };

  // Teardown for an in-progress drag (removes the listeners, the cursor lock,
  // and any queued frame). Set while dragging, null otherwise, so the unmount
  // effect can tear down a drag that's still active.
  const dragCleanupRef = useRef<(() => void) | null>(null);

  // Mirror the Y.Text content into React state so the preview re-renders as
  // the source changes (local or remote). Each observer fire does an
  // O(document) toString() and re-renders the preview/assets/search panels,
  // so coalesce a burst of keystrokes into one trailing update per frame-ish
  // window. The first value is set synchronously so first paint has content,
  // and every downstream consumer (compile, slot scan, search) debounces
  // further on top of this, so 120ms of mirror lag is invisible.
  useEffect(() => {
    if (!ytext) return;
    setSource(ytext.toString());
    let timer: number | null = null;
    const update = () => {
      if (timer != null) return;
      timer = window.setTimeout(() => { timer = null; setSource(ytext.toString()); }, 120);
    };
    ytext.observe(update);
    return () => {
      if (timer != null) window.clearTimeout(timer);
      ytext.unobserve(update);
    };
  }, [ytext]);

  // Defensive: if the tab unmounts mid-drag, tear the drag down (removes the
  // orphaned document listeners, cancels the queued frame, and undoes the
  // global cursor/selection lock that mouseup would normally clear).
  useEffect(() => () => { dragCleanupRef.current?.(); }, []);

  // Hold the compiler while the tab is mounted and hand it back when it
  // closes. The release is on a timer rather than immediate, because a pane
  // renders only its active tab and flicking between the report and a note
  // would otherwise rebuild the wasm every time (see lib/typst-compiler).
  useEffect(() => {
    cancelTypstRelease();
    return () => scheduleTypstRelease();
  }, []);

  // Probed on mount, not polled: the flag and the installed tools do not
  // change while the tab is open. A probe that got no answer (network error,
  // 5xx) is retried on a short backoff instead of hiding the server export
  // buttons until the tab is reopened; unmounting cancels it.
  useEffect(() => loadExportCapabilities(setCaps), []);

  // `useTypstSource` refuses to seed a report until the websocket has synced
  // (see its header), so an offline client with no cached report sits on the
  // loading state indefinitely. After a few seconds say which of the two it
  // is, rather than leaving "Loading…" to imply something is still arriving.
  const [slowSync, setSlowSync] = useState(false);
  useEffect(() => {
    if (ytext) { setSlowSync(false); return; }
    const timer = window.setTimeout(() => setSlowSync(true), 4000);
    return () => window.clearTimeout(timer);
  }, [ytext]);

  // Programmatic source rewrites (assigning a screenshot to a figure slot,
  // adding a slot, search replace-all, rename retargeting) go through a
  // minimal CRDT delta rather than replacing the whole text, so a
  // collaborator typing elsewhere keeps their cursor and their edit merges
  // cleanly.
  //
  // Every caller hands over a function of the CURRENT source rather than a
  // finished string: `source` below is a 120 ms trailing mirror of the
  // Y.Text, and a rewrite computed from it deletes whatever arrived inside
  // that window (invariant #3b).
  const applySource = useCallback((compute: (current: string) => string) => {
    if (ytext) updateYTextContent(ytext, compute);
  }, [ytext]);

  // Findings-mode callbacks. Focus reveals the editor pane if it is hidden
  // (so there is something to spotlight), then dims everything but the block.
  // The rail calls it only when the selection was made with the preview
  // unlocked (lib/finding-jump `findingSelectEffects`), or from Show in code.
  const focusFinding = useCallback((range: { from: number; to: number } | null) => {
    if (!range) { setTypstFindingFocus(null); return; }
    if (!visibleRef.current.editor) {
      setLayout((prev) => {
        const merged = { ...prev, showEditor: true };
        saveTypstLayout(merged);
        return merged;
      });
      requestAnimationFrame(() => setTypstFindingFocus(range));
      return;
    }
    setTypstFindingFocus(range);
  }, []);
  const exitFindingsMode = useCallback(() => setFindings(false), [setFindings]);
  const revealFindingInPreview = useCallback((target: FindingTarget) => {
    setFindingJump({ target, nonce: Date.now() });
  }, []);
  // Clear the code spotlight when the tab unmounts or leaves findings mode.
  useEffect(() => () => { setTypstFindingFocus(null); }, []);

  /**
   * Select `[from, to)` in the editor, opening the (possibly hidden) code pane
   * first. Shared by click-to-source and the search panel. When the pane has
   * to be revealed, the CodeMirror instance mounts a frame later, so the
   * selection is deferred to the next frame.
   */
  const revealRange = useCallback((from: number, to: number, focus = true) => {
    if (!visibleRef.current.editor) {
      setLayout((prev) => {
        const merged = { ...prev, showEditor: true };
        saveTypstLayout(merged);
        return merged;
      });
      requestAnimationFrame(() => revealTypstRange(from, to, focus));
      return;
    }
    revealTypstRange(from, to, focus);
  }, []);

  // The search panel selects matches without stealing focus from its input, so
  // repeated Enter keeps stepping through results.
  const revealForSearch = useCallback(
    (from: number, to: number) => revealRange(from, to, false),
    [revealRange],
  );

  const revealSource = useCallback((candidates: SourceCandidate[]) => {
    let hit: SourceRange | null = null;
    for (const c of candidates) {
      hit = findSourceRange(sourceRef.current, c.text, c.occurrence);
      if (hit) break;
    }
    if (hit) revealRange(hit.from, hit.to);
  }, [revealRange]);

  // Assets rail: click-to-reveal from the preview (clicking a rendered figure
  // selects + flashes its asset card).
  const [assetReveal, setAssetReveal] = useState<{ id: ID; nonce: number } | null>(null);
  const revealImage = useCallback((href: string) => {
    void (async () => {
      const images = typstAssetsRef.current.filter((a) => a.kind === 'image');
      const match = await matchAssetByHref(href, images, resolveAssetBytes);
      if (!match) return;
      if (!visibleRef.current.assets) {
        setLayout((prev) => {
          const merged = { ...prev, showAssets: true };
          saveTypstLayout(merged);
          return merged;
        });
      }
      setAssetReveal({ id: match.id, nonce: Date.now() });
    })();
  }, []);

  /**
   * Assets rail "insert": drop a reference to the asset at the caret.
   *
   * Figure slots are the primary route for a screenshot, because they keep
   * captions and numbering consistent, so the image form is the escape hatch
   * for one that belongs inline; a font has no other route at all. With the
   * code pane closed there is no caret to insert at, so the snippet goes to
   * the clipboard rather than nowhere.
   *
   * `navigator.clipboard` only exists in a secure context, and the usual
   * deployment of this app is plain HTTP on a LAN, where it is undefined.
   * Claiming a copy that never happened is worse than not copying, so when
   * there is no clipboard (or it refuses) the snippet goes into the banner
   * itself, where it can be selected by hand.
   */
  const insertAsset = useCallback((asset: TypstAsset) => {
    const snippet = asset.kind === 'font'
      ? `#set text(font: "${asset.fontFamily}")\n`
      : `#image("${assetPath(asset)}")\n`;
    if (insertAtTypstCursor(snippet)) return;
    const byHand = () => setNotice({
      kind: 'info',
      text: `Code editor is hidden and the clipboard is unavailable here. Copy this: ${snippet.trim()}`,
    });
    const clipboard = navigator.clipboard;
    if (!clipboard) { byHand(); return; }
    void clipboard.writeText(snippet).then(
      () => setNotice({ kind: 'info', text: 'Code editor is hidden: snippet copied to the clipboard instead.' }),
      byHand,
    );
  }, []);

  /**
   * Upload a font for the assets rail.
   *
   * The family name is what the operator types into `#set text(font: "…")`,
   * and only typst.ts's own parser knows the name the compiler will match, so
   * it is read here (the tab already owns the compiler) rather than in the
   * shared panel, which would otherwise drag the wasm engine into the Assets
   * Manager tab. A font whose name will not parse still uploads: the compiler
   * can use it, the rail just shows the filename and cannot offer the
   * snippet.
   */
  const addFont = useCallback(async (file: File, folderId: ID | null) => {
    let family: string | null = null;
    try {
      family = (await getFontInfo(new Uint8Array(await file.arrayBuffer())))?.family ?? null;
    } catch { /* family stays unknown; FontRow falls back to the filename */ }
    await addTypstAsset(file, 'font', folderId, family);
  }, [addTypstAsset]);

  // ── Figure slots ───────────────────────────────────────────────────────
  // The assets rail shows which figure each image fills and writes a chosen
  // one back into the document. Every rewrite lands here rather than in the
  // panel, because this component owns the source Y.Text.

  // Which figure (if any) each image currently fills, keyed by asset path.
  // Scanned off a debounced copy of the source: the labels are cosmetic, so
  // they can lag a keystroke rather than re-parsing on each one.
  const settledSource = useDebounced(source, SLOT_SCAN_DEBOUNCE_MS);
  const placements = useMemo(() => {
    const map = new Map<string, string>();
    for (const s of findScreenshotSlots(settledSource)) {
      if (s.path) map.set(s.path, s.caption ?? `figure on line ${s.line}`);
    }
    return map;
  }, [settledSource]);

  /**
   * Commit a crop and (optionally) an assignment to a figure slot.
   *
   * Order matters: the helper definition is upgraded/inserted *first*, then
   * the slots are re-scanned against that new source before rewriting one.
   * Editing the slot using offsets measured against the pre-upgrade source
   * would splice into the wrong position once the helper shifted everything
   * below it.
   */
  const placeAsset = useCallback(
    (
      asset: TypstAsset,
      crop: CropRect | null,
      blurs: BlurRegion[] | null,
      slot: ScreenshotSlot | null,
      path: string | null,
      heightPt: number | null,
      widthFraction: number | null = null,
    ) => {
      void setTypstAssetCrop(asset.id, crop, blurs);
      if (!slot) return;

      // `slot.index` was chosen in the dialog against the debounced mirror,
      // so a collaborator who added a slot above it in the meantime would
      // shift which figure this writes into. Known and deliberately left:
      // fixing it needs a stable slot identity, not a fresher read.
      applySource((current) => {
        // A width needs a helper that takes one; `ensureHelperWidth` adds it
        // to a customized helper without touching its styling.
        let next = widthFraction !== null ? ensureHelperWidth(current).source : ensureHelper(current).source;

        // Each rewrite shifts the offsets of everything after it, so re-scan
        // between edits and re-find the slot by its document order.
        if (widthFraction !== null) {
          const target = findScreenshotSlots(next)[slot.index];
          if (target) next = setSlotWidth(next, target, widthFraction);
        }
        if (heightPt !== null) {
          const target = findScreenshotSlots(next)[slot.index];
          if (target) next = setSlotHeight(next, target, heightPt);
        }
        const target = findScreenshotSlots(next)[slot.index];
        if (target) next = setSlotPath(next, target, path);
        return next;
      });
    },
    [setTypstAssetCrop, applySource],
  );

  /**
   * Rename an asset and repoint the document at its new path in one go.
   *
   * The record is renamed first so the new filename is authoritative, then
   * every `"/assets/<old>"` literal in the source is rewritten. Doing it in
   * the other order would leave a window where the document referenced a
   * path the virtual filesystem no longer served.
   */
  const renameAsset = useCallback(
    (asset: TypstAsset, stem: string) => {
      // The store action also repoints the report source.
      void renameTypstAsset(asset.id, stem)
        .catch((e) => setNotice({ kind: 'error', text: e instanceof Error ? e.message : String(e) }));
    },
    [renameTypstAsset],
  );

  const addSlot = useCallback((caption: string) => {
    applySource((current) => appendSlot(current, caption));
  }, [applySource]);

  // Whole-document find & replace panel (lib/typst-search). Ctrl/⌘+F inside the
  // editor and the header's Find button both route here; opening it reveals the
  // code pane so there's something to search into.
  const [searchOpen, setSearchOpen] = useState(false);
  const openSearch = useCallback(() => {
    if (!visibleRef.current.editor) {
      setLayout((prev) => {
        const merged = { ...prev, showEditor: true };
        saveTypstLayout(merged);
        return merged;
      });
    }
    setSearchOpen(true);
  }, []);
  const closeSearch = useCallback(() => setSearchOpen(false), []);

  // Bridge the editor's Ctrl/⌘+F keybinding to this panel while the tab is
  // mounted.
  useEffect(() => {
    setTypstSearchRequest(openSearch);
    return () => setTypstSearchRequest(null);
  }, [openSearch]);

  /**
   * Drag one of the two dividers.
   *
   * The width is written straight to the pane's own style during the drag and
   * committed to React state only on release, so a resize costs one style
   * mutation per frame instead of a full re-render of the tab. That matters
   * here more than in most layouts: a re-render mid-drag would reconcile the
   * assets rail and (worse) risk remounting the CodeMirror host, which would
   * drop the Yjs collab binding and every remote cursor with it.
   *
   * The container geometry is read once at drag start; reading it per-move
   * forces a synchronous reflow on every event, which is most of the lag in a
   * naive implementation.
   */
  const startResize = useCallback((which: PaneKind) => (e: React.PointerEvent) => {
    e.preventDefault();
    const container = containerRef.current;
    if (!container) return;
    const paneEl = which === 'editor' ? editorPaneRef.current : assetsPaneRef.current;
    if (!paneEl) return;

    const containerWidth = toLayoutPx(container.getBoundingClientRect().width);
    const startX = e.clientX;
    const startWidth = widthsRef.current[which];
    const other = which === 'editor'
      ? (visibleRef.current.assets ? widthsRef.current.assets : 0)
      : (visibleRef.current.editor ? widthsRef.current.editor : 0);

    document.body.style.userSelect = 'none';
    document.body.style.cursor = 'col-resize';

    let frame = 0;
    let next = startWidth;

    const onMove = (ev: PointerEvent) => {
      // The editor grows as the pointer moves right; the assets rail is on
      // the far side, so it grows as the pointer moves left.
      const delta = toLayoutPx(ev.clientX - startX);
      const raw = which === 'editor' ? startWidth + delta : startWidth - delta;
      next = clampPaneWidth(which, raw, containerWidth, other);
      if (!frame) {
        frame = requestAnimationFrame(() => {
          frame = 0;
          paneEl.style.width = `${next}px`;
        });
      }
    };

    const cleanup = () => {
      if (frame) { cancelAnimationFrame(frame); frame = 0; }
      document.body.style.userSelect = '';
      document.body.style.cursor = '';
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
      dragCleanupRef.current = null;
    };

    const onUp = () => {
      cleanup();
      // Single commit: React state catches up to the DOM we've been driving.
      setLayout((prev) => {
        const merged = { ...prev, [which]: next };
        saveTypstLayout(merged);
        return merged;
      });
    };

    dragCleanupRef.current = cleanup;
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onUp);
  }, []);

  /** Double-click a divider to restore that pane's default width. */
  const resetPane = useCallback((which: PaneKind) => () => {
    setLayout((prev) => {
      const merged = { ...prev, [which]: PANE_DEFAULT[which] };
      saveTypstLayout(merged);
      return merged;
    });
  }, []);

  /** Arrow keys on a divider: move it 24px, through the same clamp as a drag. */
  const stepPane = useCallback((which: PaneKind) => (dir: -1 | 1) => {
    const container = containerRef.current;
    if (!container) return;
    const containerWidth = toLayoutPx(container.getBoundingClientRect().width);
    setLayout((prev) => {
      // The editor grows to the right; the assets rail sits on the far side.
      const delta = (which === 'editor' ? dir : -dir) * 24;
      const other = which === 'editor' ? (prev.showAssets ? prev.assets : 0) : (prev.showEditor ? prev.editor : 0);
      const merged = { ...prev, [which]: clampPaneWidth(which, prev[which] + delta, containerWidth, other) };
      saveTypstLayout(merged);
      return merged;
    });
  }, []);

  const togglePane = useCallback((which: PaneKind) => () => {
    setLayout((prev) => {
      const key = which === 'editor' ? 'showEditor' : 'showAssets';
      const merged = { ...prev, [key]: !prev[key] };
      saveTypstLayout(merged);
      return merged;
    });
  }, []);

  // Keep both rails inside the container when it changes size (window resize,
  // sidebar toggle, pane split). Without this a layout saved on a wide monitor
  // can leave no room for the preview on a narrow one.
  useEffect(() => {
    const container = containerRef.current;
    if (!container || typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver((entries) => {
      const width = entries[0]?.contentRect.width ?? 0;
      if (width <= 0) return;
      setLayout((prev) => {
        const fitted = fitPanes(
          { editor: prev.editor, assets: prev.assets },
          { editor: prev.showEditor, assets: prev.showAssets },
          width,
        );
        if (fitted.editor === prev.editor && fitted.assets === prev.assets) return prev;
        return { ...prev, ...fitted };
      });
    });
    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  const exportPdf = useCallback(async () => {
    setExporting(true);
    setNotice(null);
    try {
      const bytes = await compileTypstPdf(source);
      await triggerDownload(workspaceName ?? 'report', 'document.pdf', bytes);
    } catch (err) {
      setNotice({ kind: 'error', text: `PDF export failed: ${typstErrorMessage(err)}` });
    } finally {
      setExporting(false);
    }
  }, [source, workspaceName]);

  const exportSvg = useCallback(async () => {
    setExporting(true);
    setNotice(null);
    try {
      const res = await compileTypstSvg(source);
      if (!res.svg) {
        const msg = res.diagnostics.find((d) => d.severity === 'error')?.message ?? 'document has errors';
        setNotice({ kind: 'error', text: `SVG export failed: ${msg}` });
        return;
      }
      await triggerDownload(workspaceName ?? 'report', 'document.svg', res.svg);
    } catch (err) {
      setNotice({ kind: 'error', text: `SVG export failed: ${typstErrorMessage(err)}` });
    } finally {
      setExporting(false);
    }
  }, [source, workspaceName]);

  /**
   * DOCX / PDF (server): compile (or convert) on the server, with the
   * workspace's redactions baked into the images first. Unlike the in-browser
   * PDF/SVG buttons this leaves the document, so a failure reports whatever
   * the server already scrubbed and worded for an operator (a Typst
   * diagnostic with its file and line, a queue-full sentence, a missing
   * binary) rather than something derived here.
   */
  const serverExport = useCallback(async (format: 'pdf' | 'docx') => {
    setServerExporting(format);
    setNotice(null);
    try {
      const { blob, baked, warnings } = await exportOnServer(workspaceId, format);
      await triggerDownload(workspaceName ?? 'report', `${workspaceName ?? 'report'}.${format}`, blob);
      const text = serverExportNotice(baked, warnings);
      if (text) setNotice({ kind: 'info', text });
    } catch (err) {
      setNotice({ kind: 'error', text: err instanceof Error ? err.message : String(err) });
    } finally {
      setServerExporting(null);
    }
  }, [workspaceId, workspaceName]);

  // ── Import report / Export report ──────────────────────────────────────
  // A template bundle (main.typ + fonts/ + assets/) in or out. The pure
  // rules are lib/typst-report-bundle.ts, the I/O report-bundle-io.ts.
  const [importOpen, setImportOpen] = useState(false);
  const [reportExporting, setReportExporting] = useState(false);
  const importCallbacks: Omit<ImportCallbacks, 'onProgress'> = useMemo(() => ({
    uploadImage: (file: File) => addTypstAsset(file, 'image', null),
    uploadFont: (file: File) => addFont(file, null),
    unretire: (id: ID) => unretireTypstAsset(id),
    // The whole source changes, but still as one minimal delta through the
    // live Y.Text (invariant 3b), so it merges and Ctrl+Z undoes it.
    replaceSource: (next: string) => applySource(() => next),
  }), [addTypstAsset, addFont, unretireTypstAsset, applySource]);
  const importDone = useCallback((result: ImportResult, prepared: PreparedImport) => {
    setImportOpen(false);
    const label = prepared.candidate.label;
    const parts = [`Imported ${label}: ${result.uploaded} uploaded`];
    if (result.reused) parts.push(`${result.reused} already in the workspace`);
    let text = `${parts.join(', ')}.`;
    if (result.renamedByServer.length) {
      text += ` Stored under a corrected name: ${result.renamedByServer.map((r) => `${r.from} as ${r.to}`).join(', ')}.`;
    }
    if (result.failed.length) {
      setNotice({ kind: 'error', text: `${text} Failed: ${result.failed.join('; ')}` });
    } else {
      setNotice({ kind: 'info', text });
    }
  }, []);
  const exportReportZip = useCallback(async () => {
    setReportExporting(true);
    setNotice(null);
    try {
      const current = ytext ? ytext.toString() : sourceRef.current;
      const res = await exportReport(current, typstAssetsRef.current, workspaceName ?? 'report');
      if (res.fileName && res.missing.length) {
        setNotice({ kind: 'info', text: `Exported without ${res.missing.join(', ')}: the report names them but the workspace has no such asset.` });
      }
    } catch (err) {
      setNotice({ kind: 'error', text: `Report export failed: ${err instanceof Error ? err.message : String(err)}` });
    } finally {
      setReportExporting(false);
    }
  }, [ytext, workspaceName]);

  /**
   * The assets rail's props, as one stable object.
   *
   * `AssetsPanel` is memoized, and this view re-renders every 120 ms while
   * anyone is typing, so an object literal in the JSX would re-render the
   * whole rail (thumbnails included) on each of those. The source it carries
   * is the settled one the slot scan already uses: only the placement dialog
   * reads it, and 300 ms old is fresh enough to list the current slots.
   */
  const findingsProps: FindingsPanelProps = useMemo(() => ({
    source: settledSource,
    applySource,
    onFocus: focusFinding,
    onRevealPreview: revealFindingInPreview,
    onExit: exitFindingsMode,
    onRenameAsset: renameAsset,
    previewLocked,
  }), [settledSource, applySource, focusFinding, revealFindingInPreview, exitFindingsMode, renameAsset, previewLocked]);

  const panelMode = useMemo(() => ({
    source: settledSource,
    placements,
    onInsert: insertAsset,
    onAddFont: addFont,
    onPlace: placeAsset,
    onAddSlot: addSlot,
    onRename: renameAsset,
    reveal: assetReveal,
  }), [settledSource, placements, insertAsset, addFont, placeAsset, addSlot, renameAsset, assetReveal]);

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div data-ui="toolbar" className="flex min-h-9 shrink-0 flex-wrap items-center justify-between gap-x-2 border-b border-border bg-card px-3 py-1">
        <div className="flex items-center gap-2">
          <FileText size={13} className="text-status-purple" />
          <span className="text-meta font-bold uppercase tracking-widest text-foreground">Typst</span>
          <span className="text-caption text-muted-foreground">locally rendered</span>
        </div>
        <div className="flex flex-wrap items-center gap-1">
          <Button
            variant={findingsMode ? 'primary' : 'ghost'}
            size="xs"
            aria-pressed={findingsMode}
            icon={<ListFilter size={13} />}
            onClick={toggleFindingsMode}
            title={findingsMode ? 'Leave finding-block editing mode' : 'Edit the report as finding blocks'}
          >
            Findings
          </Button>
          <div aria-hidden className="mx-1 h-4 w-px bg-border" />
          <Button
            variant="ghost"
            size="xs"
            aria-pressed={showEditor}
            icon={showEditor ? <PanelLeftClose size={13} /> : <PanelLeftOpen size={13} />}
            onClick={togglePane('editor')}
            title={showEditor ? 'Hide code editor' : 'Show code editor'}
            className={showEditor ? undefined : 'text-muted-foreground'}
          >
            Code
          </Button>
          <Button variant="ghost" size="xs" icon={<Search size={13} />} onClick={openSearch} title="Search the code (Ctrl/⌘+F in the editor; over the preview it finds in the rendered pages)">
            Find
          </Button>
          <Button
            variant="ghost"
            size="xs"
            aria-pressed={showAssets}
            icon={<Images size={13} />}
            onClick={togglePane('assets')}
            title={showAssets ? 'Hide assets panel' : 'Show assets panel'}
            className={showAssets ? undefined : 'text-muted-foreground'}
          >
            Assets
          </Button>
          <div aria-hidden className="mx-1 h-4 w-px bg-border" />
          <Button
            variant="ghost"
            size="xs"
            icon={<FileUp size={13} />}
            onClick={() => setImportOpen(true)}
            disabled={!ytext}
            title="Import a report: a ZIP (a GitHub download works), a folder or a .typ file. Replaces the source and uploads its fonts and images."
          >
            Import report
          </Button>
          <Button
            variant="ghost"
            size="xs"
            icon={<FileArchive size={13} />}
            onClick={() => void exportReportZip()}
            disabled={!ytext || reportExporting}
            title="Download main.typ with its images (crop and blur baked in) and fonts, in the layout Import report and the typst CLI read."
          >
            {reportExporting ? 'Exporting…' : 'Export report'}
          </Button>
          <div aria-hidden className="mx-1 h-4 w-px bg-border" />
          <Button variant="ghost" size="xs" icon={<Image size={13} />} onClick={exportSvg} disabled={exporting} title="Export SVG">
            SVG
          </Button>
          <Button variant="ghost" size="xs" icon={<FileDown size={13} />} onClick={exportPdf} disabled={exporting} title="Export PDF">
            PDF
          </Button>
          {caps.docx && (
            <Button
              variant="ghost"
              size="xs"
              icon={<FileDown size={13} />}
              onClick={() => void serverExport('docx')}
              disabled={serverExporting !== null}
              title="Word file made on the server from the finished PDF, matching its layout line for line. Redactions are baked in first. The report's fonts travel inside the file when their licence allows it, with PostScript outlines redrawn as TrueType because that is all Word carries; a font it cannot carry is named in a warning."
            >
              {serverExporting === 'docx' ? 'Converting…' : 'DOCX'}
            </Button>
          )}
          {caps.pdf && (
            <Button
              variant="ghost"
              size="xs"
              icon={<FileDown size={13} />}
              onClick={() => void serverExport('pdf')}
              disabled={serverExporting !== null}
              title="Compiled by the server's typst CLI, with redactions baked into the images first."
            >
              {serverExporting === 'pdf' ? 'Compiling…' : 'PDF (server)'}
            </Button>
          )}
        </div>
      </div>
      {notice && (
        <Banner
          tone={notice.kind === 'error' ? 'red' : 'neutral'}
          flush
          className="shrink-0 items-center"
          actions={
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setNotice(null)}
              className={notice.kind === 'error' ? 'text-current hover:bg-status-red/15' : undefined}
            >
              Dismiss
            </Button>
          }
        >
          {/* An info notice can carry a snippet to copy by hand, so it wraps
              and stays selectable instead of being truncated to one line. */}
          <span
            className={`block min-w-0 ${notice.kind === 'error' ? 'truncate' : 'select-text whitespace-pre-wrap break-words'}`}
            title={notice.text}
          >
            {notice.text}
          </span>
        </Banner>
      )}

      {/* Editor | Preview | Assets.
          `contain: layout paint` on each pane keeps a width change from
          relayouting or repainting the other two: the preview's SVG in
          particular can be a very large subtree. */}
      {/* The findings rail sits outside the container the pane-width math
          measures, so the code and assets panes are fitted to what is left
          and the preview keeps its minimum width. */}
      <div className="flex min-h-0 flex-1 bg-background">
      {findingsMode && (
        <div className="flex shrink-0 py-[var(--pane-gap)] pl-[var(--pane-gap)]">
          <div
            ref={findingsPaneRef}
            data-findings-rail
            className="pane-card relative min-w-0 shrink-0 overflow-hidden"
            style={{ width: `${findingsWidth}px`, contain: 'layout paint' }}
          >
            <Suspense fallback={<div className="flex h-full items-center justify-center text-xs text-muted-foreground">Loading findings…</div>}>
              <FindingsPanel {...findingsProps} />
            </Suspense>
          </div>
          <Splitter
            orientation="vertical"
            label="Resize the findings rail"
            onPointerDown={startFindingsResize}
            onReset={() => commitFindingsWidth(FINDINGS_DEFAULT_WIDTH)}
            onKeyStep={(dir) => commitFindingsWidth(findingsWidthRef.current + dir * 24)}
            valueNow={findingsWidth}
            valueMin={FINDINGS_MIN_WIDTH}
            valueMax={FINDINGS_MAX_WIDTH}
          />
        </div>
      )}
      <div ref={containerRef} className="relative flex min-h-0 min-w-0 flex-1 bg-background p-[var(--pane-gap)]">
        {showEditor && (
          <>
            <div
              ref={editorPaneRef}
              className="pane-card relative min-w-0 shrink-0 bg-editor"
              style={{ width: `${layout.editor}px`, contain: 'layout paint' }}
            >
              {searchOpen && ytext && (
                <TypstSearchPanel
                  source={source}
                  caret={getTypstCaret()}
                  onReveal={revealForSearch}
                  onReplaceSource={applySource}
                  onClose={closeSearch}
                />
              )}
              {ytext ? (
                <TypstEditor ytext={ytext} />
              ) : (
                <div className="flex h-full items-center justify-center px-6 text-center text-xs text-muted-foreground">
                  {slowSync ? 'Waiting for the workspace to sync…' : 'Loading…'}
                </div>
              )}
            </div>
            <PaneDivider label="Resize the code pane" onPointerDown={startResize('editor')} onReset={resetPane('editor')} onKeyStep={stepPane('editor')} value={layout.editor} />
          </>
        )}

        <div className="pane-card min-w-0 flex-1" style={{ contain: 'layout paint' }}>
          <TypstPreview
            source={source}
            revision={assetRevision}
            mainPath="/main.typ"
            docKey={workspaceId}
            ready={ytext !== null && assetsReady}
            onRevealSource={revealSource}
            onRevealImage={revealImage}
            locked={previewLocked}
            onToggleLock={togglePreviewLock}
            jumpToFinding={findingJump}
          />
        </div>

        {showAssets && (
          <>
            <PaneDivider label="Resize the assets pane" onPointerDown={startResize('assets')} onReset={resetPane('assets')} onKeyStep={stepPane('assets')} value={layout.assets} />
            <div
              ref={assetsPaneRef}
              className="pane-card min-w-0 shrink-0"
              style={{ width: `${layout.assets}px`, contain: 'layout paint' }}
            >
              {/* The same panel the Assets Manager tab renders. The `typst`
                  prop is what turns it into the report's rail: figure-slot
                  placement, insert-at-caret and the narrow layout. */}
              <AssetsPanel typst={panelMode} />
            </div>
          </>
        )}
      </div>
      </div>
      {importOpen && (
        <ReportImportDialog
          assets={typstAssets}
          callbacks={importCallbacks}
          onClose={() => setImportOpen(false)}
          onDone={importDone}
        />
      )}
    </div>
  );
}

/**
 * Drag handle between two panes: the --pane-gap between the cards, with the
 * shell's accent bar on hover (the shared Splitter), arrow keys to step the
 * width and double-click or Enter to reset it.
 */
function PaneDivider({
  label,
  onPointerDown,
  onReset,
  onKeyStep,
  value,
}: {
  label: string;
  onPointerDown: (e: React.PointerEvent) => void;
  onReset: () => void;
  onKeyStep: (dir: -1 | 1) => void;
  value: number;
}) {
  return (
    <Splitter
      orientation="vertical"
      label={label}
      onPointerDown={onPointerDown}
      onReset={onReset}
      onKeyStep={onKeyStep}
      valueNow={value}
    />
  );
}
