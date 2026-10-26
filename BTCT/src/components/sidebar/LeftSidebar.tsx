import { lazy, Suspense, useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { useAppStore } from '@/stores';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { readableTextOn } from '@/lib/contrast';
import { useShallow } from 'zustand/react/shallow';
import { useAuthStore } from '@/auth/auth-store';
import { WorkspaceSelector } from '@/components/ui/WorkspaceSelector';
const AdminPanel = lazy(() => import('@/components/sidebar/AdminPanel').then((m) => ({ default: m.AdminPanel })));
const ProfileEditor = lazy(() => import('@/components/sidebar/ProfileEditor').then((m) => ({ default: m.ProfileEditor })));
const ThemePicker = lazy(() => import('@/components/sidebar/ThemePicker').then((m) => ({ default: m.ThemePicker })));
const ScanUploadDialog = lazy(() => import('@/components/nmap/ScanUploadDialog').then((m) => ({ default: m.ScanUploadDialog })));
import {
  ChevronRight,
  Plus,
  FilePlus,
  Search,
  PanelLeftClose,
  PanelLeftOpen,
  X,
  Sun,
  Moon,
  Trash2,
  Pencil,
  Radar,
  Upload,
  Globe,
  FileText,
  Shield,
  LogOut,
  Palette,
  Terminal,
  Images,
  Keyboard,
  CornerLeftUp,
} from 'lucide-react';
import type { Page, NmapScan, NmapMachine } from '@/types';
import { v4 as uuidv4 } from 'uuid';
import { cn } from '@/lib/utils';
import { toLayoutPx } from '@/lib/ui-zoom';
import { Portal } from '@/components/ui/Portal';
import { ConnectionDot } from '@/components/ui/ConnectionBanner';
import { Button, IconButton } from '@/components/ui/Button';
import { MenuItem, MenuSeparator, MenuSurface } from '@/components/ui/Menu';
import { Splitter } from '@/components/ui/Splitter';
import { focusables } from '@/components/ui/Dialog';

// Custom drag MIME for moving a page row into another page row (or out
// to the root level). Distinct from the tab drag MIME so the two flows
// don't ever collide.
const PAGE_DRAG_TYPE = 'application/x-btct-page';
const PAGES_EXPANDED_KEY = 'btct.pages.expanded.v1';

// Cycle guard: returns true if `candidateAncestor` already exists in
// `target`'s ancestor chain. Used before reparenting so we never let a
// user drag a parent into one of its own descendants.
function isAncestor(candidateAncestor: string, target: string, pages: Page[]): boolean {
  const byId = new Map(pages.map((p) => [p.id, p]));
  let cursor: string | null = target;
  const seen = new Set<string>();
  while (cursor) {
    if (seen.has(cursor)) break;
    seen.add(cursor);
    if (cursor === candidateAncestor) return true;
    const node = byId.get(cursor);
    if (!node) break;
    cursor = node.parentId;
  }
  return false;
}

/**
 * The left navigation. `docked` is the 280px card (resizable by the gap on
 * its right), `rail` the collapsed 44px icon rail, `drawer` the narrow-screen
 * overlay (opened from the pane header's menu button).
 */
export function LeftSidebar({ mode = 'docked' }: { mode?: 'docked' | 'rail' | 'drawer' }) {
  const {
    pages,
    createPage,
    deletePage,
    openTab,
    searchQuery,
    setSearchQuery,
    runSearch,
    searchResults,
    toggleLeftSidebar,
    darkMode,
    toggleDarkMode,
    activeWorkspaceId,
    nmapScans,
    loadNmapScans,
    createNmapGroup,
    deleteNmapScan,
    renameNmapScan,
    webScanHosts,
    loadWebScanHosts,
    leftSidebarWidth,
    setLeftSidebarWidth,
  } = useAppStore(useShallow((s) => ({
    pages: s.pages,
    createPage: s.createPage,
    deletePage: s.deletePage,
    openTab: s.openTab,
    searchQuery: s.searchQuery,
    setSearchQuery: s.setSearchQuery,
    runSearch: s.runSearch,
    searchResults: s.searchResults,
    toggleLeftSidebar: s.toggleLeftSidebar,
    darkMode: s.darkMode,
    toggleDarkMode: s.toggleDarkMode,
    activeWorkspaceId: s.activeWorkspaceId,
    nmapScans: s.nmapScans,
    loadNmapScans: s.loadNmapScans,
    createNmapGroup: s.createNmapGroup,
    deleteNmapScan: s.deleteNmapScan,
    renameNmapScan: s.renameNmapScan,
    webScanHosts: s.webScanHosts,
    loadWebScanHosts: s.loadWebScanHosts,
    leftSidebarWidth: s.leftSidebarWidth,
    setLeftSidebarWidth: s.setLeftSidebarWidth,
  })));
  const [toolsExpanded, setToolsExpanded] = useState(true);
  const [pagesExpanded, setPagesExpanded] = useState(true);
  const [nmapExpanded, setNmapExpanded] = useState(true);
  const [webScansExpanded, setWebScansExpanded] = useState(true);
  const [scanUploadOpen, setScanUploadOpen] = useState(false);
  const [creatingGroup, setCreatingGroup] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [adminPanelOpen, setAdminPanelOpen] = useState(false);
  const [profileEditorOpen, setProfileEditorOpen] = useState(false);
  const [themePickerOpen, setThemePickerOpen] = useState(false);
  const authUser = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);

  // Per-page expansion state, persisted across reloads. Used to remember
  // which page-tree nodes the user has opened so subpages stay visible.
  const [expandedPages, setExpandedPages] = useState<Set<string>>(() => {
    if (typeof localStorage === 'undefined') return new Set();
    try {
      const raw = localStorage.getItem(PAGES_EXPANDED_KEY);
      if (raw) return new Set(JSON.parse(raw) as string[]);
    } catch { /* ignore */ }
    return new Set();
  });
  const togglePageExpanded = useCallback((id: string) => {
    setExpandedPages((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      try { localStorage.setItem(PAGES_EXPANDED_KEY, JSON.stringify([...next])); } catch { /* ignore */ }
      return next;
    });
  }, []);
  const expandPage = useCallback((id: string) => {
    setExpandedPages((prev) => {
      if (prev.has(id)) return prev;
      const next = new Set(prev);
      next.add(id);
      try { localStorage.setItem(PAGES_EXPANDED_KEY, JSON.stringify([...next])); } catch { /* ignore */ }
      return next;
    });
  }, []);

  // Children grouped by parent once per pages change. Each tree row used to
  // filter the whole pages array for its own children, which made every
  // remote save cost O(rows x pages) in this tree.
  const rootPages = useMemo(() => computeRootPages(pages), [pages]);
  const childrenByParent = useMemo(() => groupChildren(pages, rootPages), [pages, rootPages]);

  // Drop-zone state on the Pages section header: hovering with a page
  // drag here re-parents the dragged page back to root level.
  const [rootDropOver, setRootDropOver] = useState(false);
  const updatePageFromStore = useAppStore((s) => s.updatePage);
  const handleRootDragOver = (e: React.DragEvent) => {
    if (!e.dataTransfer.types.includes(PAGE_DRAG_TYPE)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    setRootDropOver(true);
  };
  const handleRootDrop = (e: React.DragEvent) => {
    const draggedId = e.dataTransfer.getData(PAGE_DRAG_TYPE);
    setRootDropOver(false);
    if (!draggedId) return;
    e.preventDefault();
    const dragged = pages.find((p) => p.id === draggedId);
    if (!dragged || dragged.parentId === null) return;
    void updatePageFromStore(draggedId, { parentId: null });
  };

  useEffect(() => {
    if (activeWorkspaceId) { void loadNmapScans(); void loadWebScanHosts(); }
  }, [activeWorkspaceId, loadNmapScans, loadWebScanHosts]);

  const handleSearch = (value: string) => {
    setSearchQuery(value);
    void runSearch();
  };

  const handleCreatePage = async () => {
    if (!activeWorkspaceId) return;
    const page = await createPage(null, 'Untitled');
    openTab({ id: uuidv4(), kind: 'page', entityId: page.id, title: page.title });
  };

  // Right-click a page → "New note inside": a child page under it. Expand the
  // parent so the new note is visible, then open it for editing.
  const handleCreateChildPage = async (parentId: string) => {
    if (!activeWorkspaceId) return;
    const page = await createPage(parentId, 'Untitled');
    expandPage(parentId);
    openTab({ id: uuidv4(), kind: 'page', entityId: page.id, title: page.title });
  };

  const openPage = (page: Page) => {
    openTab({ id: uuidv4(), kind: 'page', entityId: page.id, title: page.title });
  };

  const openScan = (scan: NmapScan) => {
    openTab({ id: uuidv4(), kind: 'nmap', entityId: scan.id, title: scan.name });
  };

  const openWebScan = (host: NmapMachine) => {
    openTab({ id: uuidv4(), kind: 'web-scan', entityId: host.id, title: `${host.hostname || host.ip} scans` });
  };

  const handleCreateGroup = async () => {
    const name = newGroupName.trim();
    if (!name || !activeWorkspaceId) return;
    const group = await createNmapGroup(name);
    setNewGroupName('');
    setCreatingGroup(false);
    openScan(group);
  };



  const openCommandLog = () => {
    openTab({ id: uuidv4(), kind: 'cmdlog', entityId: 'cmdlog', title: 'Command Log' });
  };

  const openAssets = () => {
    openTab({ id: uuidv4(), kind: 'assets', entityId: 'assets', title: 'Assets' });
  };

  const openShortcuts = () => {
    openTab({ id: uuidv4(), kind: 'shortcuts', entityId: 'shortcuts', title: 'Shortcuts' });
  };

  // ── Resize handle (the gap right of the card) ──
  const [resizing, setResizing] = useState(false);
  const rootRef = useRef<HTMLElement>(null);
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setResizing(true);
    const startX = e.clientX;
    const startWidth = leftSidebarWidth;
    let latest = startWidth;
    // Write the width straight to the DOM while dragging (one mutation per
    // event) and commit to the store on release: a store write per mousemove
    // re-rendered the whole rail for every pixel.
    const onMove = (ev: MouseEvent) => {
      latest = Math.max(180, startWidth + toLayoutPx(ev.clientX - startX));
      if (rootRef.current) rootRef.current.style.width = `${latest}px`;
    };
    const onUp = () => {
      setResizing(false);
      setLeftSidebarWidth(latest);
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }, [leftSidebarWidth, setLeftSidebarWidth]);

  // ── Narrow screens: the sidebar is an overlay drawer ──
  const drawerOpen = useAppStore((s) => s.navDrawerOpen);
  const setDrawerOpen = useAppStore((s) => s.setNavDrawerOpen);
  const isDrawer = mode === 'drawer';
  // Leaving the narrow layout closes the drawer, so it never reappears stale.
  useEffect(() => { if (!isDrawer) setDrawerOpen(false); }, [isDrawer, setDrawerOpen]);
  // Opening something from the drawer (a page, a tool) closes it.
  useEffect(() => {
    if (!isDrawer) return;
    return useAppStore.subscribe((st, prev) => {
      if (st.activeTabId !== prev.activeTabId && st.navDrawerOpen) st.setNavDrawerOpen(false);
    });
  }, [isDrawer]);
  // Focus moves into the drawer on open and back to the toggle on close;
  // Tab stays inside while it is open; Escape closes it unless a dialog
  // (Admin, Profile, a confirm) is on top and owns the key.
  useEffect(() => {
    if (!isDrawer || !drawerOpen) return;
    const panel = rootRef.current;
    const previous = document.activeElement as HTMLElement | null;
    if (panel) (panel.querySelector<HTMLElement>('[data-autofocus]') ?? focusables(panel)[0] ?? panel).focus({ preventScroll: true });
    const onKey = (e: KeyboardEvent) => {
      if (document.querySelector('[aria-modal="true"]:not(#btct-nav)')) return;
      // A menu or popover inside the drawer (row context menu, workspace
      // list) takes Escape first; the drawer closes on the next press.
      if (e.key === 'Escape' && panel?.querySelector('[role="menu"]')) return;
      if (e.key === 'Escape' && !e.defaultPrevented) {
        e.preventDefault();
        setDrawerOpen(false);
        return;
      }
      if (e.key === 'Tab' && panel) {
        const list = focusables(panel);
        if (list.length === 0) return;
        const first = list[0]!;
        const last = list[list.length - 1]!;
        const active = document.activeElement as HTMLElement | null;
        const inside = !!active && panel.contains(active);
        if (e.shiftKey && (active === first || !inside)) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && (active === last || !inside)) { e.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      const toggle = document.querySelector<HTMLElement>('[data-ui="drawer-toggle"]');
      const back = previous && previous.isConnected && !panel?.contains(previous) ? previous : toggle;
      back?.focus({ preventScroll: true });
    };
  }, [isDrawer, drawerOpen, setDrawerOpen]);

  const dialogs = (
    <>
      {adminPanelOpen && <Portal><Suspense fallback={<div role="status" className="panel-loading">Loading panel…</div>}><AdminPanel onClose={() => setAdminPanelOpen(false)} /></Suspense></Portal>}
      {profileEditorOpen && <Portal><Suspense fallback={<div role="status" className="panel-loading">Loading panel…</div>}><ProfileEditor onClose={() => setProfileEditorOpen(false)} /></Suspense></Portal>}
      {themePickerOpen && <Portal><Suspense fallback={<div role="status" className="panel-loading">Loading panel…</div>}><ThemePicker onClose={() => setThemePickerOpen(false)} /></Suspense></Portal>}
      {scanUploadOpen && <Suspense fallback={null}><ScanUploadDialog open onClose={() => setScanUploadOpen(false)} /></Suspense>}
    </>
  );

  const avatar = (size: 'sm' | 'md') => authUser && (
    <span
      className={cn(
        'inline-flex shrink-0 items-center justify-center rounded-full font-semibold',
        size === 'sm' ? 'h-6 w-6 text-meta' : 'h-7 w-7 text-xs',
      )}
      style={{ backgroundColor: authUser.color, color: readableTextOn(authUser.color) }}
      aria-hidden="true"
    >
      {authUser.username.charAt(0).toUpperCase()}
    </span>
  );

  // ── Collapsed: the 44px icon rail ──
  if (mode === 'rail') {
    const railBtn = 'h-8 w-8';
    return (
      <>
        <aside ref={rootRef} data-ui="sidebar" data-rail="true" aria-label="Navigation" className="pane-card flex h-full w-11 shrink-0 flex-col items-center gap-0.5 py-2">
          <span className="op-brand-mark mb-1.5 !h-5 !w-5" aria-hidden>BT</span>
          <IconButton label="Expand sidebar" className={railBtn} onClick={toggleLeftSidebar}>
            <PanelLeftOpen size={15} />
          </IconButton>
          <IconButton label="Find a page or command (Ctrl+K)" className={railBtn} onClick={() => useAppStore.getState().setCommandPaletteOpen(true)}>
            <Search size={15} />
          </IconButton>
          <IconButton label="New note" className={railBtn} onClick={() => void handleCreatePage()}>
            <FilePlus size={15} />
          </IconButton>
          <span aria-hidden className="my-1 h-px w-5 bg-border" />
          <IconButton label="Command Log" className={railBtn} onClick={openCommandLog}><Terminal size={15} className="text-status-green" /></IconButton>
          <IconButton label="Assets" className={railBtn} onClick={openAssets}><Images size={15} className="text-status-amber" /></IconButton>
          <IconButton label="Shortcuts" className={railBtn} onClick={openShortcuts}><Keyboard size={15} /></IconButton>
          <span className="flex-1" />
          <IconButton label={darkMode ? 'Light mode' : 'Dark mode'} className={railBtn} onClick={toggleDarkMode}>
            {darkMode ? <Sun size={15} /> : <Moon size={15} />}
          </IconButton>
          {authUser?.isAdmin && (
            <>
              <IconButton label="Admin Panel" className={railBtn} onClick={() => setAdminPanelOpen(true)}><Shield size={15} className="text-status-amber" /></IconButton>
              <IconButton label="Workspace accent, default heading colours and the theme lock" className={railBtn} onClick={() => setThemePickerOpen(true)}><Palette size={15} className="text-primary" /></IconButton>
            </>
          )}
          {authUser && (
            <button type="button" onClick={() => setProfileEditorOpen(true)} title="Edit profile" aria-label="Edit profile" className="relative mt-1 rounded-full">
              {avatar('sm')}
              {/* A badge on the avatar's corner. `flex` keeps the ring the dot's own
                  size: as an inline box it took the text line's height and
                  cut a card-coloured slab into the avatar. */}
              <span className="absolute -bottom-0.5 -right-0.5 flex rounded-full bg-card p-0.5"><ConnectionDot /></span>
            </button>
          )}
        </aside>
        <div aria-hidden className="w-[var(--pane-gap)] shrink-0" />
        {dialogs}
      </>
    );
  }

  const sectionHead = (label: string, expanded: boolean, toggle: () => void, action?: React.ReactNode, extra?: React.HTMLAttributes<HTMLDivElement> & { className?: string }) => (
    <div {...extra} className={cn('flex h-7 items-center gap-1 rounded pl-1 pr-0.5', extra?.className)}>
      <button
        type="button"
        onClick={toggle}
        aria-expanded={expanded}
        className="flex min-w-0 flex-1 items-center gap-1 rounded py-0.5 text-caption font-bold uppercase tracking-widest text-muted-foreground hover:text-foreground"
      >
        <ChevronRight size={11} className={cn('shrink-0 transition-transform duration-150', expanded && 'rotate-90')} />
        <span className="truncate">{label}</span>
      </button>
      {action}
    </div>
  );
  const toolRow = (label: string, icon: React.ReactNode, onClick: () => void) => (
    <button type="button" data-op="nav" onClick={onClick} className="flex h-6 w-full items-center gap-1.5 rounded pl-[18px] pr-2 text-left text-xs hover:bg-accent">
      <span className="shrink-0">{icon}</span>
      <span className="truncate">{label}</span>
    </button>
  );

  const body = (
    <>
      {/* Header */}
      <div className="flex h-10 shrink-0 items-center gap-2 pl-3 pr-1.5">
        <span className="op-brand-mark !h-5 !w-5" role="img" aria-label="BTCT">BT</span>
        <span className="min-w-0 flex-1 truncate text-caption font-bold uppercase tracking-widest text-muted-foreground">Operations</span>
        <IconButton label={darkMode ? 'Light mode' : 'Dark mode'} title="Toggle theme" onClick={toggleDarkMode}>
          {darkMode ? <Sun size={14} /> : <Moon size={14} />}
        </IconButton>
        {isDrawer ? (
          <IconButton label="Close navigation" onClick={() => setDrawerOpen(false)}>
            <X size={14} />
          </IconButton>
        ) : (
          <IconButton label="Collapse sidebar" title="Collapse sidebar" onClick={toggleLeftSidebar}>
            <PanelLeftClose size={14} />
          </IconButton>
        )}
      </div>

      {/* Search */}
      <div className="shrink-0 px-2 pb-2">
        <div className="flex h-7 items-center gap-1.5 rounded border border-input bg-background px-2 focus-within:border-primary">
          <Search size={12} className="shrink-0 text-muted-foreground" />
          <input
            type="text"
            aria-label="Search pages"
            data-autofocus
            placeholder="Search pages..."
            value={searchQuery}
            onChange={(e) => handleSearch(e.target.value)}
            className="min-w-0 flex-1 bg-transparent text-xs outline-none placeholder:text-muted-foreground"
          />
        </div>
      </div>

      {/* Search results */}
      {searchQuery.trim() && (
        <div className="shrink-0 border-b border-border px-2 pb-2">
          <div className="px-1 pb-1 text-caption font-bold uppercase tracking-widest text-muted-foreground">Results</div>
          {searchResults.map((p) => (
            <button
              key={p.id}
              onClick={() => openPage(p)}
              className="flex h-6 w-full items-center gap-1.5 rounded px-1 text-left text-xs hover:bg-accent focus-visible:bg-accent"
            >
              <FileText size={12} className="shrink-0 text-muted-foreground" />
              <span className="truncate">{p.title}</span>
            </button>
          ))}
          {searchResults.length === 0 && <span className="px-1 text-xs text-muted-foreground">No results</span>}
        </div>
      )}

      {/* Scrollable tree */}
      <nav aria-label="Workspace" className="min-h-0 flex-1 overflow-y-auto px-2 pb-2">
        {/* Tools section: the dedicated tool tabs, grouped on their own. */}
        {sectionHead('Tools', toolsExpanded, () => setToolsExpanded(!toolsExpanded))}
        {toolsExpanded && (
          <div className="flex flex-col gap-px pb-1">
            {toolRow('Command Log', <Terminal size={12} className="text-status-green" />, openCommandLog)}
            {toolRow('Assets', <Images size={12} className="text-status-amber" />, openAssets)}
            {toolRow('Shortcuts', <Keyboard size={12} className="text-muted-foreground" />, openShortcuts)}
          </div>
        )}

        {/* Notes section: the actual note pages. The heading is also the
            drop target that moves a dragged page back to the root. */}
        {sectionHead(
          'Notes',
          pagesExpanded,
          () => setPagesExpanded(!pagesExpanded),
          <IconButton label="New note" size="sm" onClick={(e) => { e.stopPropagation(); void handleCreatePage(); }}>
            <Plus size={13} />
          </IconButton>,
          {
            className: cn('mt-1 transition-colors', rootDropOver && 'bg-primary/15'),
            onDragOver: handleRootDragOver,
            onDragLeave: () => setRootDropOver(false),
            onDrop: handleRootDrop,
          },
        )}
        {pagesExpanded && (
          <div role="tree" aria-label="Notes" className="flex flex-col gap-px pb-1">
            {rootPages.map((page) => (
              <PageTreeItem
                key={page.id}
                page={page}
                pages={pages}
                childrenByParent={childrenByParent}
                openPage={openPage}
                deletePage={deletePage}
                createChildPage={handleCreateChildPage}
                depth={0}
                expandedPages={expandedPages}
                toggleExpanded={togglePageExpanded}
                expandPage={expandPage}
              />
            ))}
            {rootPages.length === 0 && (
              <span className="py-1 pl-[18px] text-xs text-muted-foreground">No notes yet</span>
            )}
          </div>
        )}

        {/* Nmap Scans section */}
        {sectionHead(
          'Nmap Scans',
          nmapExpanded,
          () => setNmapExpanded(!nmapExpanded),
          <>
            <IconButton label="Upload scan" size="sm" onClick={() => setScanUploadOpen(true)}>
              <Upload size={13} />
            </IconButton>
            <IconButton label="Create group" size="sm" onClick={() => { setCreatingGroup(true); setNmapExpanded(true); }}>
              <Plus size={13} />
            </IconButton>
          </>,
          { className: 'mt-1' },
        )}
        {nmapExpanded && (
          <div className="flex flex-col gap-px pb-1">
            {creatingGroup && (
              <div className="flex h-6 w-full items-center gap-1.5 rounded bg-accent pl-[18px] pr-2">
                <Radar size={12} className="shrink-0 text-status-green" />
                <input
                  autoFocus
                  aria-label="Group name"
                  value={newGroupName}
                  onChange={(e) => setNewGroupName(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') void handleCreateGroup(); if (e.key === 'Escape') { setCreatingGroup(false); setNewGroupName(''); } }}
                  onBlur={() => { if (!newGroupName.trim()) { setCreatingGroup(false); setNewGroupName(''); } }}
                  placeholder="Group name..."
                  className="min-w-0 flex-1 border-b border-primary bg-transparent text-xs outline-none"
                />
              </div>
            )}
            {nmapScans.filter((scan) => scan.workspaceId === activeWorkspaceId).map((scan) => (
              <NmapScanItem key={scan.id} scan={scan} openScan={openScan} deleteNmapScan={deleteNmapScan} renameNmapScan={renameNmapScan} />
            ))}
            {nmapScans.filter((scan) => scan.workspaceId === activeWorkspaceId).length === 0 && !creatingGroup && (
              <span className="py-1 pl-[18px] text-xs text-muted-foreground">No groups yet</span>
            )}
          </div>
        )}

        {/* Web Scans section: hosts with gobuster/sqlmap/sstimap/dalfox findings */}
        {sectionHead(
          'Web Scans',
          webScansExpanded,
          () => setWebScansExpanded(!webScansExpanded),
          <IconButton label="Upload scan" size="sm" onClick={() => setScanUploadOpen(true)}>
            <Upload size={13} />
          </IconButton>,
          { className: 'mt-1' },
        )}
        {webScansExpanded && (
          <div className="flex flex-col gap-px pb-1">
            {webScanHosts.map((host) => (
              <WebScanItem key={host.id} host={host} openWebScan={openWebScan} />
            ))}
            {webScanHosts.length === 0 && (
              <span className="py-1 pl-[18px] text-xs text-muted-foreground">No web scans yet</span>
            )}
          </div>
        )}
      </nav>

      {/* Footer: workspace, signed-in user, admin tools */}
      <div className="flex shrink-0 flex-col gap-1 border-t border-border p-2">
        <WorkspaceSelector />

        {authUser && (
          <div className="flex items-center gap-1 rounded px-1 py-1">
            <button
              onClick={() => setProfileEditorOpen(true)}
              title="Edit profile"
              className="flex min-w-0 flex-1 items-center gap-2 rounded text-left"
            >
              {avatar('md')}
              <span className="flex min-w-0 flex-col leading-tight">
                <span className="truncate text-xs font-medium">{authUser.username}</span>
                <span className="flex items-center gap-1.5 truncate text-micro uppercase tracking-wider text-muted-foreground">
                  <ConnectionDot />
                  {authUser.isAdmin ? 'administrator' : 'signed in'}
                </span>
              </span>
            </button>
            <IconButton label="Log out" onClick={logout}>
              <LogOut size={14} />
            </IconButton>
          </div>
        )}

        {authUser?.isAdmin && (
          <div className="grid grid-cols-2 gap-1">
            <Button variant="ghost" size="sm" icon={<Shield size={12} className="text-status-amber" />} onClick={() => setAdminPanelOpen(true)} className="justify-start">
              Admin Panel
            </Button>
            <Button
              variant="ghost"
              size="sm"
              icon={<Palette size={12} className="text-primary" />}
              onClick={() => setThemePickerOpen(true)}
              className="justify-start"
              title="Workspace accent, default heading colours and the theme lock"
            >
              Theme
            </Button>
          </div>
        )}
      </div>
    </>
  );

  if (isDrawer) {
    return (
      <>
        {drawerOpen && (
          <div data-ui="drawer-scrim" aria-hidden className="fixed inset-0 z-[90] bg-overlay" onMouseDown={() => setDrawerOpen(false)} />
        )}
        <aside
          ref={rootRef}
          id="btct-nav"
          data-ui="sidebar"
          data-drawer="true"
          role="dialog"
          aria-modal={drawerOpen || undefined}
          aria-label="Navigation"
          tabIndex={-1}
          hidden={!drawerOpen}
          className="pane-card fixed bottom-2 left-2 top-2 z-[95] flex w-[min(300px,calc(100*var(--vw)-16px))] flex-col outline-none"
        >
          {body}
        </aside>
        {dialogs}
      </>
    );
  }

  return (
    <>
      <aside ref={rootRef} id="btct-nav" data-ui="sidebar" aria-label="Navigation" className="pane-card flex h-full shrink-0 flex-col" style={{ width: leftSidebarWidth }}>
        {body}
      </aside>
      <Splitter
        orientation="vertical"
        label="Resize the sidebar"
        onMouseDown={handleMouseDown}
        onKeyStep={(dir) => setLeftSidebarWidth(leftSidebarWidth + dir * 16)}
        onReset={() => setLeftSidebarWidth(280)}
        dragging={resizing}
        valueNow={leftSidebarWidth}
        valueMin={200}
        valueMax={480}
      />
      {dialogs}
    </>
  );
}

const NO_CHILDREN: Page[] = [];
/**
 * Top-level pages. Besides parentId null/undefined, a page whose parent is
 * gone (concurrent delete) or that sits on a parent loop (concurrent moves)
 * is still in the shared doc, so it is shown at the root; a loop is broken
 * at its lowest id.
 */
export function computeRootPages(pages: Page[]): Page[] {
  const byId = new Map<string, Page>();
  for (const p of pages) if (!p.isGraphPage) byId.set(p.id, p);
  const cycleRoots = new Set<string>();
  for (const p of byId.values()) {
    if (p.parentId == null || !byId.has(p.parentId)) continue;
    const seen = new Set<string>([p.id]);
    let cur = byId.get(p.parentId);
    while (cur && cur.id !== p.id && !seen.has(cur.id)) {
      seen.add(cur.id);
      cur = cur.parentId == null ? undefined : byId.get(cur.parentId);
    }
    if (cur && cur.id === p.id && [...seen].every((id) => p.id <= id)) cycleRoots.add(p.id);
  }
  return pages.filter((p) => !p.isGraphPage
    && (p.parentId == null || !byId.has(p.parentId) || cycleRoots.has(p.id)));
}
/** Pages grouped by parent id, in their original order. */
function groupChildren(pages: Page[], roots: Page[]): Map<string, Page[]> {
  const out = new Map<string, Page[]>();
  const rootIds = new Set(roots.map((r) => r.id));
  for (const p of pages) {
    if (!p.parentId || rootIds.has(p.id)) continue;
    const list = out.get(p.parentId);
    if (list) list.push(p); else out.set(p.parentId, [p]);
  }
  return out;
}

function PageTreeItem({
  page,
  pages,
  childrenByParent,
  openPage,
  deletePage,
  createChildPage,
  depth,
  expandedPages,
  toggleExpanded,
  expandPage,
}: {
  page: Page;
  pages: Page[];
  childrenByParent: Map<string, Page[]>;
  openPage: (p: Page) => void;
  deletePage: (id: string) => Promise<void>;
  createChildPage: (parentId: string) => void | Promise<void>;
  depth: number;
  expandedPages: Set<string>;
  toggleExpanded: (id: string) => void;
  expandPage: (id: string) => void;
}) {
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number } | null>(null);
  const [editingSlug, setEditingSlug] = useState(false);
  const [slugValue, setSlugValue] = useState(page.slug ?? '');
  const [renaming, setRenaming] = useState(false);
  const [nameValue, setNameValue] = useState(page.title);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const updatePage = useAppStore((s) => s.updatePage);
  const isActive = useAppStore((s) => {
    const tab = s.tabs.find((t) => t.id === s.activeTabId);
    return tab?.kind === 'page' && tab.entityId === page.id;
  });
  const slugRef = useRef<HTMLInputElement>(null);
  const nameRef = useRef<HTMLInputElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const children = childrenByParent.get(page.id) ?? NO_CHILDREN;
  const hasChildren = children.length > 0;
  const isExpanded = expandedPages.has(page.id);

  const handleDragStart = (e: React.DragEvent) => {
    e.dataTransfer.setData(PAGE_DRAG_TYPE, page.id);
    e.dataTransfer.effectAllowed = 'move';
  };
  const handleDragOver = (e: React.DragEvent) => {
    if (!e.dataTransfer.types.includes(PAGE_DRAG_TYPE)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    setDragOver(true);
  };
  const handleDragLeave = () => setDragOver(false);
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const draggedId = e.dataTransfer.getData(PAGE_DRAG_TYPE);
    if (!draggedId || draggedId === page.id) return;
    // Cycle guard: refuse if the page we'd reparent is already an
    // ancestor of the drop target.
    if (isAncestor(draggedId, page.id, pages)) return;
    const dragged = pages.find((p) => p.id === draggedId);
    if (!dragged || dragged.parentId === page.id) return;
    void updatePage(draggedId, { parentId: page.id });
    // Auto-expand so the user sees the page they just dropped in.
    expandPage(page.id);
  };

  useEffect(() => {
    if (editingSlug && slugRef.current) slugRef.current.focus();
  }, [editingSlug]);

  useEffect(() => {
    if (renaming && nameRef.current) nameRef.current.focus();
  }, [renaming]);

  useEffect(() => {
    if (!ctxMenu) return;
    const close = (e: MouseEvent) => {
      if (menuRef.current && menuRef.current.contains(e.target as Node)) return;
      setCtxMenu(null);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setCtxMenu(null); };
    window.addEventListener('mousedown', close);
    window.addEventListener('keydown', onKey);
    return () => { window.removeEventListener('mousedown', close); window.removeEventListener('keydown', onKey); };
  }, [ctxMenu]);

  const commitSlug = () => {
    setEditingSlug(false);
    const trimmed = slugValue.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').replace(/(^-|-$)/g, '');
    setSlugValue(trimmed);
    void updatePage(page.id, { slug: trimmed });
  };

  const commitRename = () => {
    setRenaming(false);
    const trimmed = nameValue.trim();
    if (trimmed && trimmed !== page.title) {
      void updatePage(page.id, { title: trimmed });
    } else {
      setNameValue(page.title);
    }
  };

  const indent = 4 + depth * 12;
  return (
    <div role="treeitem" aria-expanded={hasChildren ? isExpanded : undefined} aria-selected={isActive} className="group relative">
      <div
        draggable
        data-active={isActive || undefined}
        onDragStart={handleDragStart}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        style={{ paddingLeft: indent }}
        className={cn(
          'flex h-6 w-full items-center gap-0.5 rounded pr-1 hover:bg-accent',
          isActive && 'bg-accent font-medium',
          dragOver && 'ring-2 ring-inset ring-primary',
        )}
        onContextMenu={(e) => {
          e.preventDefault();
          setCtxMenu({ x: e.clientX, y: e.clientY });
        }}
      >
        {/* Chevron column. Reserved width even when there are no
            children so every row's icon + title line up horizontally. */}
        {hasChildren ? (
          <button
            onClick={(e) => { e.stopPropagation(); toggleExpanded(page.id); }}
            className="flex h-4 w-3.5 shrink-0 items-center justify-center rounded text-muted-foreground hover:text-foreground"
            aria-label={isExpanded ? `Collapse ${page.title}` : `Expand ${page.title}`}
            title={isExpanded ? 'Collapse' : 'Expand'}
          >
            <ChevronRight size={11} className={cn('transition-transform duration-150', isExpanded && 'rotate-90')} />
          </button>
        ) : (
          <span className="inline-block w-3.5 shrink-0" aria-hidden />
        )}
        {editingSlug ? (
          <div className="flex min-w-0 flex-1 items-center gap-1 px-1">
            <span className="text-caption text-muted-foreground">/</span>
            <input
              ref={slugRef}
              aria-label="Page path"
              value={slugValue}
              onChange={(e) => setSlugValue(e.target.value)}
              onBlur={commitSlug}
              onKeyDown={(e) => { if (e.key === 'Enter') commitSlug(); if (e.key === 'Escape') setEditingSlug(false); }}
              className="min-w-0 w-24 border-b border-primary bg-transparent font-mono text-caption outline-none"
            />
          </div>
        ) : renaming ? (
          <div className="flex min-w-0 flex-1 items-center gap-1.5 px-1">
            <FileText size={12} className="shrink-0 text-muted-foreground" />
            <input
              ref={nameRef}
              aria-label="Page name"
              value={nameValue}
              onChange={(e) => setNameValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') commitRename();
                if (e.key === 'Escape') { setRenaming(false); setNameValue(page.title); }
              }}
              onBlur={commitRename}
              className="min-w-0 flex-1 border-b border-primary bg-transparent text-xs outline-none"
            />
          </div>
        ) : (
          <button
            onClick={() => openPage(page)}
            className="flex h-full min-w-0 flex-1 items-center gap-1.5 rounded px-1 text-left text-xs"
          >
            <FileText size={12} className={cn('shrink-0', isActive ? 'text-primary' : 'text-muted-foreground')} />
            <span className="truncate">{page.title}</span>
          </button>
        )}
      </div>

      {/* Delete confirmation */}
      {confirmDelete && (
        <ConfirmDeleteDialog
          name={page.title}
          kind="page"
          onConfirm={() => { setConfirmDelete(false); void deletePage(page.id); }}
          onCancel={() => setConfirmDelete(false)}
        />
      )}

      {/* Context menu */}
      {ctxMenu && (
        <MenuSurface
          ref={menuRef}
          className="fixed z-50"
          style={{ left: toLayoutPx(ctxMenu.x), top: toLayoutPx(ctxMenu.y) }}
        >
          <MenuItem icon={<Pencil size={12} />} onClick={() => { setCtxMenu(null); setEditingSlug(true); }}>Edit Path</MenuItem>
          <MenuItem icon={<Pencil size={12} />} onClick={() => { setCtxMenu(null); setNameValue(page.title); setRenaming(true); }}>Rename</MenuItem>
          <MenuItem icon={<FilePlus size={12} />} onClick={() => { setCtxMenu(null); void createChildPage(page.id); }}>New note inside</MenuItem>
          <MenuItem icon={<FileText size={12} />} onClick={() => { setCtxMenu(null); openPage(page); }}>Open</MenuItem>
          {page.parentId !== null && (
            <MenuItem icon={<CornerLeftUp size={12} />} onClick={() => { setCtxMenu(null); void updatePage(page.id, { parentId: null }); }}>Move to root</MenuItem>
          )}
          <MenuSeparator />
          <MenuItem danger icon={<Trash2 size={12} />} onClick={() => { setCtxMenu(null); setConfirmDelete(true); }}>Delete</MenuItem>
        </MenuSurface>
      )}

      {/* Children: indented 12px per level by the row padding. */}
      {isExpanded && hasChildren && (
        <div role="group" className="mt-px flex flex-col gap-px">
          {children.map((child) => (
            <PageTreeItem
              key={child.id}
              page={child}
              pages={pages}
              childrenByParent={childrenByParent}
              openPage={openPage}
              deletePage={deletePage}
              createChildPage={createChildPage}
              depth={depth + 1}
              expandedPages={expandedPages}
              toggleExpanded={toggleExpanded}
              expandPage={expandPage}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function WebScanItem({ host, openWebScan }: { host: NmapMachine; openWebScan: (h: NmapMachine) => void }) {
  const isActive = useAppStore((s) => {
    const tab = s.tabs.find((t) => t.id === s.activeTabId);
    return tab?.kind === 'web-scan' && tab.entityId === host.id;
  });
  const count = host.toolFindings?.length ?? 0;
  return (
    <button
      type="button"
      data-active={isActive || undefined}
      onClick={() => openWebScan(host)}
      title={host.hostname ? `${host.hostname} (${host.ip})` : host.ip}
      className={cn(
        'flex h-6 w-full items-center gap-1.5 rounded pl-[18px] pr-2 text-left hover:bg-accent',
        isActive && 'bg-accent font-medium',
      )}
    >
      <Globe size={12} className="shrink-0 text-status-blue" />
      <span className="min-w-0 flex-1 truncate text-xs">{host.hostname || host.ip}</span>
      <span className="shrink-0 text-micro text-muted-foreground">{count}</span>
    </button>
  );
}

function NmapScanItem({
  scan,
  openScan,
  deleteNmapScan,
  renameNmapScan,
}: {
  scan: NmapScan;
  openScan: (s: NmapScan) => void;
  deleteNmapScan: (id: string) => Promise<void>;
  renameNmapScan: (id: string, name: string) => Promise<void>;
}) {
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number } | null>(null);
  const [renaming, setRenaming] = useState(false);
  const [nameValue, setNameValue] = useState(scan.name);
  const isActive = useAppStore((s) => {
    const tab = s.tabs.find((t) => t.id === s.activeTabId);
    return tab?.kind === 'nmap' && tab.entityId === scan.id;
  });
  const [confirmDelete, setConfirmDelete] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (renaming && inputRef.current) inputRef.current.focus();
  }, [renaming]);

  useEffect(() => {
    if (!ctxMenu) return;
    const close = (e: MouseEvent) => {
      if (menuRef.current && menuRef.current.contains(e.target as Node)) return;
      setCtxMenu(null);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setCtxMenu(null); };
    window.addEventListener('mousedown', close);
    window.addEventListener('keydown', onKey);
    return () => { window.removeEventListener('mousedown', close); window.removeEventListener('keydown', onKey); };
  }, [ctxMenu]);

  const commitRename = () => {
    setRenaming(false);
    const trimmed = nameValue.trim();
    if (trimmed && trimmed !== scan.name) {
      void renameNmapScan(scan.id, trimmed);
    } else {
      setNameValue(scan.name);
    }
  };

  return (
    <div
      data-active={isActive || undefined}
      className={cn(
        'group flex h-6 w-full items-center rounded hover:bg-accent',
        isActive && 'bg-accent font-medium',
      )}
      onContextMenu={(e) => { e.preventDefault(); setCtxMenu({ x: e.clientX, y: e.clientY }); }}
    >
      {renaming ? (
        <div className="flex min-w-0 flex-1 items-center gap-1.5 pl-[18px] pr-2">
          <Radar size={12} className="shrink-0 text-status-green" />
          <input
            ref={inputRef}
            aria-label="Group name"
            value={nameValue}
            onChange={(e) => setNameValue(e.target.value)}
            onBlur={commitRename}
            onKeyDown={(e) => { if (e.key === 'Enter') commitRename(); if (e.key === 'Escape') { setRenaming(false); setNameValue(scan.name); } }}
            className="min-w-0 flex-1 border-b border-primary bg-transparent text-xs outline-none"
          />
        </div>
      ) : (
        <button
          onClick={() => openScan(scan)}
          className="flex h-full min-w-0 flex-1 items-center gap-1.5 rounded pl-[18px] pr-2 text-left text-xs"
        >
          <Radar size={12} className="shrink-0 text-status-green" />
          <span className="truncate">{scan.name}</span>
        </button>
      )}

      {confirmDelete && (
        <ConfirmDeleteDialog
          name={scan.name}
          kind="nmap scan"
          onConfirm={() => { setConfirmDelete(false); void deleteNmapScan(scan.id); }}
          onCancel={() => setConfirmDelete(false)}
        />
      )}

      {ctxMenu && (
        <MenuSurface
          ref={menuRef}
          className="fixed z-50"
          style={{ left: toLayoutPx(ctxMenu.x), top: toLayoutPx(ctxMenu.y) }}
        >
          <MenuItem icon={<Pencil size={12} />} onClick={() => { setCtxMenu(null); setNameValue(scan.name); setRenaming(true); }}>Rename</MenuItem>
          <MenuItem icon={<Radar size={12} />} onClick={() => { setCtxMenu(null); openScan(scan); }}>Open</MenuItem>
          <MenuSeparator />
          <MenuItem danger icon={<Trash2 size={12} />} onClick={() => { setCtxMenu(null); setConfirmDelete(true); }}>Delete</MenuItem>
        </MenuSurface>
      )}
    </div>
  );
}

// ── Shared confirmation dialog ──

/** Delete confirm for a page or an nmap scan: the shared ConfirmDialog. */
function ConfirmDeleteDialog({
  name,
  kind,
  onConfirm,
  onCancel,
}: {
  name: string;
  kind: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <ConfirmDialog
      title={`Delete ${kind}`}
      destructive
      message={<>Are you sure you want to delete <span className="font-semibold text-foreground">{name}</span>? This action cannot be undone.</>}
      confirmLabel="Delete"
      onConfirm={onConfirm}
      onCancel={onCancel}
    />
  );
}
