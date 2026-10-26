import { WorkspaceOverview } from './WorkspaceOverview';
import { useCallback, useRef, useState, lazy, Suspense } from 'react';
import { useAppStore } from '@/stores';
import { useThemeStore } from '@/stores/theme-store';
import type { PaneNode, LeafPane, SplitPane, TabItem, DropPosition } from '@/types';
const PageEditor = lazy(() => import('@/components/editor/PageEditor').then((m) => ({ default: m.PageEditor })));
const NmapScanView = lazy(() => import('@/components/nmap/NmapScanView').then((m) => ({ default: m.NmapScanView })));
const NmapMachineView = lazy(() => import('@/components/nmap/NmapScanView').then((m) => ({ default: m.NmapMachineView })));
const WebScanView = lazy(() => import('@/components/nmap/WebScanView').then((m) => ({ default: m.WebScanView })));
const CommandLogView = lazy(() => import('@/components/cmdlog/CommandLogView').then((m) => ({ default: m.CommandLogView })));
const HistoryView = lazy(() => import('@/components/history/HistoryView').then((m) => ({ default: m.HistoryView })));
const AssetsManager = lazy(() => import('@/components/assets/AssetsManager').then((m) => ({ default: m.AssetsManager })));
const ShortcutsView = lazy(() => import('@/components/help/ShortcutsView').then((m) => ({ default: m.ShortcutsView })));
const TypstView = lazy(() => import('@/components/typst/TypstView').then((m) => ({ default: m.TypstView })));
import { cn } from '@/lib/utils';
import { allLeaves, firstLeaf, findLeaf, topRightLeaf } from '@/lib/pane-layout';
import { useNarrowLayout } from '@/lib/use-layout-width';
import { ErrorBoundary } from './ErrorBoundary';
import { Splitter } from './Splitter';
import { ShellLeadTools, ShellTrailTools, TabStrip, TAB_DRAG_TYPE } from './TabBar';

export { TAB_DRAG_TYPE };

/** Which leaves carry the shell's own header controls. */
interface ShellSlots { leadId: string; trailId: string }

// ── Main entry ──

/**
 * The pane row. Every leaf is a floating card on the canvas; the gap between
 * two cards is their resize handle. On a narrow screen a split layout shows
 * one pane at a time, with a numbered switcher in its header.
 */
export function SplitContainer() {
  const paneLayout = useAppStore((s) => s.paneLayout);
  const tabs = useAppStore((s) => s.tabs);
  const activePaneId = useAppStore((s) => s.activePaneId);
  const narrow = useNarrowLayout();

  if (tabs.length === 0) return <WorkspaceOverview />;

  if (narrow && paneLayout.type === 'split') {
    const leaves = allLeaves(paneLayout);
    const shown = (activePaneId && findLeaf(paneLayout, activePaneId)) || firstLeaf(paneLayout);
    return (
      <div data-ui="panes" className="flex min-h-0 min-w-0 flex-1">
        <PaneLeaf pane={shown} slots={{ leadId: shown.id, trailId: shown.id }} switcher={leaves} />
      </div>
    );
  }

  const slots: ShellSlots = { leadId: firstLeaf(paneLayout).id, trailId: topRightLeaf(paneLayout).id };
  return (
    <div data-ui="panes" className="flex min-h-0 min-w-0 flex-1">
      <PaneRenderer node={paneLayout} slots={slots} />
    </div>
  );
}

// ── Recursive renderer ──

function PaneRenderer({ node, slots }: { node: PaneNode; slots: ShellSlots }) {
  if (node.type === 'leaf') return <PaneLeaf pane={node} slots={slots} />;
  return <PaneSplit split={node} slots={slots} />;
}

// ── Split node: two cards with the gap between them as the resize handle ──

const HALF_GAP = 'var(--pane-gap) / 2';
const sizeOf = (ratio: number) => `calc(${ratio * 100}% - ${HALF_GAP})`;
const clampRatio = (r: number) => Math.min(0.85, Math.max(0.15, r));

function PaneSplit({ split, slots }: { split: SplitPane; slots: ShellSlots }) {
  const updateSplitRatio = useAppStore((s) => s.updateSplitRatio);
  const containerRef = useRef<HTMLDivElement>(null);
  const firstRef = useRef<HTMLDivElement>(null);
  const secondRef = useRef<HTMLDivElement>(null);
  const [resizing, setResizing] = useState(false);

  const isH = split.direction === 'horizontal';

  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      setResizing(true);

      // Write pane sizes straight to the DOM during the drag and commit the
      // ratio to the store only on mouseup. Driving the store per mousemove
      // produced a new paneLayout object on every event, which (a) fired the
      // synchronous localStorage persist and (b) re-rendered every mounted
      // tab view (Milkdown, CodeMirror). One rAF-throttled style write per
      // frame instead.
      const dim = isH ? 'width' : 'height';
      let latest = split.ratio;
      let frame = 0;
      const apply = () => {
        frame = 0;
        if (firstRef.current) firstRef.current.style[dim] = sizeOf(latest);
        if (secondRef.current) secondRef.current.style[dim] = sizeOf(1 - latest);
      };

      const onMove = (ev: MouseEvent) => {
        if (!containerRef.current) return;
        const rect = containerRef.current.getBoundingClientRect();
        const ratio = isH
          ? (ev.clientX - rect.left) / rect.width
          : (ev.clientY - rect.top) / rect.height;
        latest = clampRatio(ratio);
        if (!frame) frame = requestAnimationFrame(apply);
      };

      const onUp = () => {
        if (frame) cancelAnimationFrame(frame);
        setResizing(false);
        window.removeEventListener('mousemove', onMove);
        window.removeEventListener('mouseup', onUp);
        updateSplitRatio(split.id, latest);
      };

      window.addEventListener('mousemove', onMove);
      window.addEventListener('mouseup', onUp);
    },
    [isH, split.id, split.ratio, updateSplitRatio],
  );

  return (
    <div ref={containerRef} className={cn('flex h-full w-full min-h-0 min-w-0', isH ? 'flex-row' : 'flex-col')}>
      <div
        ref={firstRef}
        style={{ [isH ? 'width' : 'height']: sizeOf(split.ratio) }}
        className="flex min-h-0 min-w-0"
      >
        <PaneRenderer node={split.children[0]} slots={slots} />
      </div>
      <Splitter
        orientation={isH ? 'vertical' : 'horizontal'}
        label={isH ? 'Resize the panes side by side' : 'Resize the stacked panes'}
        onMouseDown={handleMouseDown}
        onKeyStep={(dir) => updateSplitRatio(split.id, clampRatio(split.ratio + dir * 0.05))}
        onReset={() => updateSplitRatio(split.id, 0.5)}
        dragging={resizing}
        valueNow={split.ratio * 100}
        valueMin={15}
        valueMax={85}
      />
      <div
        ref={secondRef}
        style={{ [isH ? 'width' : 'height']: sizeOf(1 - split.ratio) }}
        className="flex min-h-0 min-w-0"
      >
        <PaneRenderer node={split.children[1]} slots={slots} />
      </div>
    </div>
  );
}

// ── Leaf pane: tab strip + content + drop zones ──

/**
 * What a `typst` tab should render, given the flag-loading state.
 *
 * A Report tab is never pruned when the flag reads off (see `reconcileTabs`
 * in app-store.ts): `features` starts at `DEFAULT_FEATURES` (typst false)
 * and only flips once `GET /api/settings` resolves, so treating "false" as
 * "prune" would delete every flag-ON user's Report tab on each reload. The
 * render is gated here instead, and only once the fetch that carries
 * `features` has actually resolved (theme-store's `featuresLoaded`, not
 * `loaded`, which also flips true from the live `settingsPublic` mirror and
 * carries no `features` data), so a restored tab on a flag-off box never
 * mounts `TypstView` (and never requests its lazy chunk, so the compiler is
 * never downloaded) while a flag-on box never flashes the "off" notice
 * during the load window.
 */
export function typstTabState(features: { typst: boolean }, featuresLoaded: boolean): 'loading' | 'on' | 'off' {
  if (!featuresLoaded) return 'loading';
  return features.typst ? 'on' : 'off';
}

/**
 * What a `typst` tab shows while `GET /api/settings` has not answered.
 *
 * The pane used to render an empty div in this state, which reads as a
 * broken tab rather than as a wait. The fetch backs off and retries
 * (theme-store), so this can be on screen for a few seconds on a server that
 * is slow to come up. Still no lazy import here: the compiler chunk must not
 * be fetched before the flag is known.
 */
function TypstLoadingNotice() {
  return (
    <div className="flex h-full items-center justify-center px-6 text-center text-xs text-muted-foreground">
      Checking whether the report editor is available…
    </div>
  );
}

/** Plain-text empty state, same shape as the "Drop a tab here" notice below. */
function TypstOffNotice() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-1 px-6 text-center text-xs text-muted-foreground">
      <strong className="text-sm text-foreground">Report tab is turned off</strong>
      <span>This server runs without the Typst report editor. Your report is still saved with the workspace and opens on a server that has it enabled.</span>
    </div>
  );
}

function PaneLeaf({ pane, slots, switcher }: { pane: LeafPane; slots: ShellSlots; switcher?: LeafPane[] }) {
  const tabs = useAppStore((s) => s.tabs);
  const activePaneId = useAppStore((s) => s.activePaneId);
  const setActivePane = useAppStore((s) => s.setActivePane);
  const setActiveTab = useAppStore((s) => s.setActiveTab);
  const closeTab = useAppStore((s) => s.closeTab);
  const moveTabToPane = useAppStore((s) => s.moveTabToPane);
  const reorderTab = useAppStore((s) => s.reorderTab);
  const paneLayout = useAppStore((s) => s.paneLayout);
  const typstFeature = useThemeStore((s) => s.features.typst);
  const typstFeaturesLoaded = useThemeStore((s) => s.featuresLoaded);

  const [dropZone, setDropZone] = useState<DropPosition | null>(null);
  const leafRef = useRef<HTMLDivElement>(null);
  const dragCounter = useRef(0);

  const hasSplits = paneLayout.type === 'split';
  const paneTabs = pane.tabIds.map((id) => tabs.find((t) => t.id === id)).filter(Boolean) as TabItem[];
  const activeTab = paneTabs.find((t) => t.id === pane.activeTabId) ?? paneTabs[0] ?? null;
  const isActive = activePaneId === pane.id;
  const typstState = typstTabState({ typst: typstFeature }, typstFeaturesLoaded);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    if (!e.dataTransfer.types.includes(TAB_DRAG_TYPE)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';

    const rect = leafRef.current?.getBoundingClientRect();
    if (!rect) return;

    const x = (e.clientX - rect.left) / rect.width;
    const y = (e.clientY - rect.top) / rect.height;

    // Edge zones: 20% from each edge
    if (x < 0.2) setDropZone('left');
    else if (x > 0.8) setDropZone('right');
    else if (y < 0.2) setDropZone('top');
    else if (y > 0.8) setDropZone('bottom');
    else setDropZone('center');
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      const tabId = e.dataTransfer.getData(TAB_DRAG_TYPE);
      if (!tabId || !dropZone) return;
      e.preventDefault();
      moveTabToPane(tabId, pane.id, dropZone);
      setDropZone(null);
      dragCounter.current = 0;
    },
    [dropZone, moveTabToPane, pane.id],
  );

  const handleDragEnter = useCallback((e: React.DragEvent) => {
    if (!e.dataTransfer.types.includes(TAB_DRAG_TYPE)) return;
    e.preventDefault();
    dragCounter.current += 1;
  }, []);

  const handleDragLeave = useCallback(() => {
    dragCounter.current -= 1;
    if (dragCounter.current <= 0) {
      setDropZone(null);
      dragCounter.current = 0;
    }
  }, []);

  const clearZone = useCallback(() => {
    setDropZone(null);
    dragCounter.current = 0;
  }, []);
  const onReorder = useCallback((dragged: string, target: string, place: 'before' | 'after') => {
    reorderTab(dragged, target, place);
    setDropZone(null);
    dragCounter.current = 0;
  }, [reorderTab]);

  return (
    <div
      ref={leafRef}
      data-ui="pane"
      data-active={isActive && hasSplits ? 'true' : undefined}
      className={cn(
        'pane-card relative flex h-full w-full min-w-0 flex-col',
        // The focused pane of a split: a quiet accent ring, not a border.
        isActive && hasSplits && 'ring-1 ring-inset ring-primary/40',
      )}
      onClick={() => setActivePane(pane.id)}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
    >
      {/* 32px pane header: shell controls, the narrow-screen pane switcher, the tab strip. */}
      <div data-ui="tabbar" className="flex h-8 shrink-0 items-stretch gap-0.5 border-b border-border px-1">
        {slots.leadId === pane.id && <ShellLeadTools />}
        {switcher && switcher.length > 1 && <PaneSwitcher leaves={switcher} shownId={pane.id} />}
        <TabStrip
          tabs={paneTabs}
          activeId={activeTab?.id ?? null}
          onActivate={setActiveTab}
          onClose={closeTab}
          onReorder={onReorder}
          onDragOverStrip={clearZone}
        />
        {slots.trailId === pane.id && <ShellTrailTools />}
      </div>

      {/* Content */}
      <div className="min-h-0 flex-1 overflow-hidden">
        {/* Every tab view, including the note editor, loads on first use, so
            the nmap, command-log, assets and history code stays out of the
            initial bundle. */}
        {/* One boundary per pane, keyed on the tab: a view that throws (or a
            lazy chunk gone after a redeploy) shows a card with Reload and
            Close this tab, and the other panes keep working. */}
        <ErrorBoundary
          key={activeTab?.id ?? 'empty'}
          label={activeTab ? `the "${activeTab.title}" tab` : 'this pane'}
          onClose={activeTab ? () => closeTab(activeTab.id) : undefined}
        >
        <Suspense fallback={<div className="flex h-full items-center justify-center text-xs text-muted-foreground">Loading…</div>}>
        {activeTab?.kind === 'page' && <PageEditor pageId={activeTab.entityId} />}
        {activeTab?.kind === 'nmap' && <NmapScanView scanId={activeTab.entityId} />}
        {activeTab?.kind === 'nmap-machine' && <NmapMachineView machineId={activeTab.entityId} />}
        {activeTab?.kind === 'web-scan' && <WebScanView machineId={activeTab.entityId} />}
        {activeTab?.kind === 'cmdlog' && <CommandLogView />}
        {activeTab?.kind === 'history' && <HistoryView pageId={activeTab.entityId} />}
        {activeTab?.kind === 'assets' && <AssetsManager />}
        {activeTab?.kind === 'shortcuts' && <ShortcutsView />}
        {activeTab?.kind === 'typst' && typstState === 'on' && <TypstView workspaceId={activeTab.entityId} />}
        {activeTab?.kind === 'typst' && typstState === 'off' && <TypstOffNotice />}
        {activeTab?.kind === 'typst' && typstState === 'loading' && <TypstLoadingNotice />}
        {!activeTab && (
          <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
            Drop a tab here
          </div>
        )}
        </Suspense>
        </ErrorBoundary>
      </div>

      {/* Drop zone overlay */}
      {dropZone && <DropZoneOverlay zone={dropZone} />}
    </div>
  );
}

// ── Narrow-screen pane switcher ──

/** Numbered buttons for the panes of a split, shown when only one fits. */
function PaneSwitcher({ leaves, shownId }: { leaves: LeafPane[]; shownId: string }) {
  const setActivePane = useAppStore((s) => s.setActivePane);
  return (
    <div role="group" aria-label="Panes" className="my-auto mr-1 flex shrink-0 overflow-hidden rounded border border-border">
      {leaves.map((leaf, i) => (
        <button
          key={leaf.id}
          type="button"
          aria-pressed={leaf.id === shownId}
          aria-label={`Show pane ${i + 1}`}
          title={`Pane ${i + 1}`}
          onClick={(e) => { e.stopPropagation(); setActivePane(leaf.id); }}
          className={cn(
            'px-1.5 py-0.5 font-mono text-caption',
            leaf.id === shownId ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-accent',
          )}
        >
          {i + 1}
        </button>
      ))}
    </div>
  );
}

// ── Drop zone visual overlay ──

function DropZoneOverlay({ zone }: { zone: DropPosition }) {
  const base = 'absolute pointer-events-none rounded-lg bg-primary/10 border-2 border-dashed border-primary/60 transition-all duration-100';
  const style: Record<DropPosition, string> = {
    left: `${base} inset-y-0 left-0 w-1/2`,
    right: `${base} inset-y-0 right-0 w-1/2`,
    top: `${base} inset-x-0 top-0 h-1/2`,
    bottom: `${base} inset-x-0 bottom-0 h-1/2`,
    center: `${base} inset-0`,
  };
  return <div className={style[zone]} />;
}
