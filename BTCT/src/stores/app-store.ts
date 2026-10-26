import { workspaceRepo, pageRepo, changeLogRepo, nmapScanRepo, nmapMachineRepo, typstAssetRepo, commandLogRepo } from '@/db';
import { create } from 'zustand';
import type { Workspace, Page, TabItem, ID, ChangeLogEntry, NmapScan, NmapMachine, PaneNode, DropPosition, TypstAsset, AssetFolder, TypstAssetKind, CropRect, BlurRegion, CommandLogEntry } from '@/types';
import { getSharedDoc, textKey } from '@/realtime/shared-doc';
import { updateYTextContent } from '@/realtime/use-y-text';
import { retargetAssetPath } from '@/lib/asset-retarget';
import { ASSET_DIR } from '@/lib/assets';
import { assetFolderRepo } from '@/db/asset-folder-repo';
import { isDescendantFolder } from '@/lib/asset-folders';
import type { LogAuthor, LogDelta } from '@/db/changelog-repo';
import { db } from '@/db/database';
import { useAuthStore } from '@/auth/auth-store';
import { buildPageTreeSnapshot, pagesFromDeleteSnapshot, shouldLogContentSave } from '@/lib/change-log-policy';
import { createLeaf, findLeaf, findLeafContainingTab, firstLeaf, addTabToPane, removeTab as removeTabFromLayout, collapse, moveTab, moveWithin, reorderTabInLeaf, removeTabsWhere, setActiveInPane, updateRatio } from '@/lib/pane-layout';
import { currentColorMode, setColorMode } from '@/lib/color-mode';

// ─────────────────────────────────────────────────────────────────────────
// UI persistence: keep tabs / active tab / pane layout / active workspace
// across page refreshes so the user lands back on the page they left off.
// Stored as a single JSON blob in localStorage.
// ─────────────────────────────────────────────────────────────────────────
const UI_PERSIST_KEY = 'btct.ui.v1';

/**
 * After tabs left a layout, keep activeTabId / activePaneId pointing at
 * things that still exist: a deleted page used to leave both aimed at a
 * collapsed pane, so the next openTab landed in a pane nobody rendered.
 */
function reconcileActive(tabs: TabItem[], layout: PaneNode, activeTabId: string | null, activePaneId: string | null) {
  const tabAlive = activeTabId && tabs.some((t) => t.id === activeTabId) ? activeTabId : null;
  const leaf =
    (tabAlive && findLeafContainingTab(layout, tabAlive)) ||
    (activePaneId && findLeaf(layout, activePaneId)) ||
    firstLeaf(layout);
  return { activeTabId: tabAlive ?? leaf.activeTabId ?? leaf.tabIds[0] ?? null, activePaneId: leaf.id };
}

interface PersistedUi {
  activeWorkspaceId: ID | null;
  tabs: TabItem[];
  activeTabId: string | null;
  paneLayout: PaneNode;
  activePaneId: string | null;
}

function loadPersistedUi(): Partial<PersistedUi> {
  if (typeof localStorage === 'undefined') return {};
  try {
    const raw = localStorage.getItem(UI_PERSIST_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Partial<PersistedUi>;
    if (!parsed || typeof parsed !== 'object') return {};
    return parsed;
  } catch {
    return {};
  }
}

function savePersistedUi(snapshot: PersistedUi): void {
  if (typeof localStorage === 'undefined') return;
  try {
    localStorage.setItem(UI_PERSIST_KEY, JSON.stringify(snapshot));
  } catch {
    /* quota / serialization errors: non-fatal */
  }
}

const persistedUi = loadPersistedUi();

interface AppState {
  // Workspace
  workspaces: Workspace[];
  activeWorkspaceId: ID | null;
  loadWorkspaces: () => Promise<void>;
  /** Load every workspace-scoped list (pages, change log, scans, assets, asset folders, command log) for the active workspace. */
  loadWorkspaceData: () => Promise<void>;
  setActiveWorkspace: (id: ID) => void;
  createWorkspace: (name: string, description: string) => Promise<Workspace>;
  deleteWorkspace: (id: ID) => Promise<void>;

  // Pages
  pages: Page[];
  loadPages: () => Promise<void>;
  createPage: (parentId: ID | null, title: string) => Promise<Page>;
  updatePage: (id: ID, data: Partial<Omit<Page, 'id' | 'workspaceId' | 'createdAt'>>) => Promise<void>;
  deletePage: (id: ID) => Promise<void>;

  // Tabs
  tabs: TabItem[];
  activeTabId: string | null;
  openTab: (tab: TabItem) => void;
  closeTab: (tabId: string) => void;
  setActiveTab: (tabId: string) => void;

  // Split panes
  paneLayout: PaneNode;
  activePaneId: string | null;
  setActivePane: (paneId: string) => void;
  moveTabToPane: (tabId: string, targetPaneId: string, position: DropPosition) => void;
  /** Drag a tab left or right: place it before or after another tab (same strip, or into that tab's pane). */
  reorderTab: (tabId: string, targetTabId: string, place: 'before' | 'after') => void;
  /** Drop tabs whose entity no longer exists (deleted remotely or while this browser was closed) and keep the active ids valid. */
  reconcileTabs: () => void;
  updateSplitRatio: (splitId: string, ratio: number) => void;
  /**
   * Collapse every split pane into a single pane holding all current tabs
   * (the "take over everything" follow layout). Tabs are preserved; only the
   * split structure is removed. `activeTabId`, when given, becomes active.
   */
  mergePanesIntoOne: (activeTabId?: string | null) => void;

  // Live presence / follow (ephemeral: not persisted)
  followPanelOpen: boolean;
  setFollowPanelOpen: (open: boolean) => void;
  /** User id of the teammate currently being followed, or null. */
  followingUserId: number | null;
  setFollowingUserId: (userId: number | null) => void;
  /** Currently-inspected nmap host id (broadcast for followers). */
  selectedNmapMachineId: ID | null;
  setSelectedNmapMachineId: (id: ID | null) => void;

  // UI
  leftSidebarOpen: boolean;
  leftSidebarWidth: number;
  setLeftSidebarWidth: (width: number) => void;
  rightSidebarOpen: boolean;
  toggleLeftSidebar: () => void;
  toggleRightSidebar: () => void;
  /** Narrow screens (under 900 layout px): the sidebar is an overlay drawer. Not persisted. */
  navDrawerOpen: boolean;
  setNavDrawerOpen: (open: boolean) => void;
  darkMode: boolean;
  toggleDarkMode: () => void;
  setDarkMode: (dark: boolean) => void;
  commandPaletteOpen: boolean;
  setCommandPaletteOpen: (open: boolean) => void;

  // Search
  searchQuery: string;
  setSearchQuery: (query: string) => void;
  searchResults: Page[];
  runSearch: () => Promise<void>;

  // Change log
  changeLogs: ChangeLogEntry[];
  loadChangeLogs: () => Promise<void>;
  /**
   * Re-apply the prevValue of an `update` log entry, or recreate the
   * entity from the captured snapshot of a `delete` entry. Returns true
   * if the restore was applied; false if the entry is not reversible
   * or its target is no longer addressable. Always records a new
   * `restore` action entry for audit.
   */
  restoreFromLog: (entryId: ID) => Promise<boolean>;

  // Nmap scans
  nmapScans: NmapScan[];
  nmapMachines: NmapMachine[];
  // Hosts in the active workspace that have web/app tool findings attached
  // (uploaded via the scan-ingest API). Populated for the Web Scans section.
  webScanHosts: NmapMachine[];
  loadWebScanHosts: () => Promise<void>;
  loadNmapScans: () => Promise<void>;
  createNmapGroup: (name: string) => Promise<NmapScan>;
  importToNmapGroup: (groupId: ID, xml: string) => Promise<void>;
  importNmapScan: (name: string, xml: string) => Promise<NmapScan>;
  renameNmapScan: (id: ID, name: string) => Promise<void>;
  deleteNmapScan: (id: ID) => Promise<void>;
  loadNmapMachines: (scanId: ID) => Promise<void>;
  updateNmapMachine: (id: ID, data: Partial<Pick<NmapMachine, 'hostname' | 'os'>>) => Promise<void>;
  deleteNmapMachine: (id: ID) => Promise<void>;

  // Navigation

  // Typst assets (report screenshots + custom fonts)
  typstAssets: TypstAsset[];
  loadTypstAssets: () => Promise<void>;
  /**
   * `fontFamily` is what `#set text(font: "…")` matches, and only a `font`
   * upload has one. It is passed in rather than read here because reading it
   * means asking the Typst compiler, and the store must not pull the wasm
   * engine into the entry bundle: the report tab, which already has the
   * compiler, resolves it and hands it over.
   */
  addTypstAsset: (file: File, kind: TypstAssetKind, folderId?: ID | null, fontFamily?: string | null) => Promise<TypstAsset>;
  moveTypstAssetToFolder: (assetId: ID, folderId: ID | null) => Promise<void>;
  // Asset folders: the Typst assets panel's hierarchy (organizational only).
  assetFolders: AssetFolder[];
  loadAssetFolders: () => Promise<void>;
  createAssetFolder: (name: string, parentId?: ID | null) => Promise<AssetFolder>;
  renameAssetFolder: (id: ID, name: string) => Promise<void>;
  moveAssetFolder: (id: ID, parentId: ID | null) => Promise<void>;
  deleteAssetFolder: (id: ID) => Promise<void>;
  setTypstAssetCrop: (id: ID, crop: CropRect | null, blurs?: BlurRegion[] | null) => Promise<void>;
  /** Rename an asset's file stem. Returns the resulting filename. */
  renameTypstAsset: (id: ID, stem: string) => Promise<string>;
  deleteTypstAsset: (id: ID) => Promise<void>;
  retireTypstAsset: (id: ID) => Promise<void>;
  /** An image referencing a retired asset was put back into a note: un-hide it and keep it from retention. */
  unretireTypstAsset: (id: ID) => Promise<void>;

  // Command log (team pentest command activity: ingested server-side, read-only here)
  commandLogs: CommandLogEntry[];
  loadCommandLogs: () => Promise<void>;
  // Note-image blur/crop editor: the asset id currently being edited (from a
  // note image), and the right-click menu over a note image.
  editingAssetId: ID | null;
  setEditingAssetId: (id: ID | null) => void;
  imageMenu: { x: number; y: number; assetId: ID } | null;
  setImageMenu: (menu: { x: number; y: number; assetId: ID } | null) => void;

  // Database
  deleteDatabase: () => Promise<void>;
}

export const useAppStore = create<AppState>((set, get) => {
  const currentAuthor = (): LogAuthor => {
    const u = useAuthStore.getState().user;
    if (!u) return { userId: null, userName: null, userColor: null };
    return { userId: u.id, userName: u.username, userColor: u.color };
  };
  const log = (
    action: ChangeLogEntry['action'],
    target: ChangeLogEntry['target'],
    targetId: string,
    summary: string,
    delta: LogDelta = {},
  ) => {
    const wsId = get().activeWorkspaceId;
    if (!wsId) return;
    void changeLogRepo.add(wsId, action, target, targetId, summary, currentAuthor(), delta).then((entry) => {
      set((s) => ({ changeLogs: [entry, ...s.changeLogs].slice(0, 200) }));
    });
  };
  // Stringify any JSON-serialisable value so prev/new round-trip safely
  // through the log entry. Returns null for nullish so the DB column
  // stays sparse rather than holding the string "null".
  const encodeValue = (v: unknown): string | null =>
    v === null || v === undefined ? null : JSON.stringify(v);
  const decodeValue = <T = unknown>(s: string | null | undefined): T | null =>
    s == null ? null : (JSON.parse(s) as T);
  // When this client last logged a content save, per page.
  const lastContentLog = new Map<string, number>();

  return ({
  // Workspace
  workspaces: [],
  activeWorkspaceId: persistedUi.activeWorkspaceId ?? null,

  loadWorkspaces: async () => {
    const workspaces = await workspaceRepo.getAll();
    set({ workspaces });
    // Validate the (possibly persisted) active workspace still exists.
    const current = get().activeWorkspaceId;
    const stillValid = current ? workspaces.some((w) => w.id === current) : false;
    if (!stillValid) {
      // Persisted workspace is gone: clear stale tabs/pane layout that
      // referenced it so we don't render dead tabs from a deleted workspace.
      const first = workspaces[0];
      set({
        activeWorkspaceId: first ? first.id : null,
        tabs: [],
        activeTabId: null,
        paneLayout: createLeaf(),
        activePaneId: null,
      });
      // Picking the default workspace is a workspace switch: load all of its
      // lists, as setActiveWorkspace does. Only pages, change log and scans
      // used to load here (through App.tsx), so a fresh browser showed every
      // note image as "not found in assets" and an empty Assets panel.
      if (first) await get().loadWorkspaceData();
    }
  },

  loadWorkspaceData: async () => {
    if (!get().activeWorkspaceId) return;
    await Promise.all([
      get().loadPages(),
      get().loadChangeLogs(),
      get().loadNmapScans(),
      get().loadTypstAssets(),
      get().loadAssetFolders(),
      get().loadCommandLogs(),
    ]);
  },

  setActiveWorkspace: (id) => {
    set({ activeWorkspaceId: id, tabs: [], activeTabId: null, paneLayout: createLeaf(), activePaneId: null, pages: [], nmapScans: [], nmapMachines: [], webScanHosts: [], typstAssets: [], assetFolders: [], commandLogs: [] });
    // Reload workspace-scoped lists for the newly-active workspace so stale
    // entries from the previous workspace don't appear before the per-view
    // useEffects fire (and so newly-created scans never inherit the prior
    // workspace's list in state).
    void get().loadWorkspaceData();
  },

  createWorkspace: async (name, description) => {
    const ws = await workspaceRepo.create({ name, description });
    set((s) => ({ workspaces: [...s.workspaces, ws] }));
    return ws;
  },

  deleteWorkspace: async (id) => {
    await workspaceRepo.remove(id);
    const wasActive = get().activeWorkspaceId === id;
    set((s) => ({
      workspaces: s.workspaces.filter((w) => w.id !== id),
      activeWorkspaceId: wasActive ? null : s.activeWorkspaceId,
      ...(wasActive ? {
        pages: [],
        nmapScans: [],
        nmapMachines: [],
        webScanHosts: [],
        tabs: [],
        activeTabId: null,
        paneLayout: createLeaf(),
        activePaneId: null,
      } : {}),
    }));
  },

  // Pages
  pages: [],

  loadPages: async () => {
    const wsId = get().activeWorkspaceId;
    if (!wsId) return;
    const pages = await pageRepo.getByWorkspace(wsId);
    set({ pages });
  },

  createPage: async (parentId, title) => {
    const wsId = get().activeWorkspaceId;
    if (!wsId) throw new Error('No active workspace');
    const page = await pageRepo.create({ workspaceId: wsId, parentId, title });
    set((s) => ({ pages: [...s.pages, page] }));
    log('create', 'page', page.id, `Created page "${title}"`);
    return page;
  },

  updatePage: async (id, data) => {
    const prev = get().pages.find((p) => p.id === id);
    await pageRepo.update(id, data);
    set((s) => ({
      pages: s.pages.map((p) => (p.id === id ? { ...p, ...data, updatedAt: Date.now() } : p)),
    }));
    if (data.title && prev && prev.title !== data.title) {
      log('update', 'page', id, `Renamed page "${prev.title}" → "${data.title}"`, {
        field: 'title',
        prevValue: encodeValue(prev.title),
        newValue: encodeValue(data.title),
        reversible: true,
      });
    } else if (data.content) {
      // Page bodies are persisted via Yjs per-page docs; per-keystroke
      // change-log entries would be noisy. Page snapshots (see Page
      // History panel) provide rollback for body content instead.
      // Coalesced per page for this user: one entry per page per window.
      // Comparing against the newest entry by anyone (the old check) let
      // several typists interleaving log nearly every 2-10 s save.
      if (shouldLogContentSave(lastContentLog, id, Date.now())) log('update', 'page', id, 'Updated page content');
    }
  },

  deletePage: async (id) => {
    const page = get().pages.find((p) => p.id === id);
    const removed = await pageRepo.removeTree(id);
    const gone = new Set(removed.length > 0 ? removed.map((p) => p.id) : [id]);
    set((s) => ({
      pages: s.pages.filter((p) => !gone.has(p.id)),
      tabs: s.tabs.filter((t) => !(t.kind === 'page' && gone.has(t.entityId))),
      paneLayout: collapse(removeTabsWhere(s.paneLayout, (tid) => {
        const tab = s.tabs.find((t) => t.id === tid);
        return !!tab && tab.kind === 'page' && gone.has(tab.entityId);
      })),
    }));
    get().reconcileTabs();
    // One entry for the whole tree, so a restore brings the subpages back
    // too (it used to log the parent alone, and its children were lost).
    const sub = removed.length - 1;
    log('delete', 'page', id, `Deleted page "${page?.title ?? removed[0]?.title ?? id}"${sub > 0 ? ` and ${sub} subpage${sub === 1 ? '' : 's'}` : ''}`, {
      prevValue: removed.length > 0 ? encodeValue(buildPageTreeSnapshot(removed)) : encodeValue(page),
      reversible: removed.length > 0 || !!page,
    });
  },

  // Tabs & Panes
  tabs: persistedUi.tabs ?? [],
  activeTabId: persistedUi.activeTabId ?? null,
  paneLayout: persistedUi.paneLayout ?? createLeaf(),
  activePaneId: persistedUi.activePaneId ?? null,

  openTab: (tab) => {
    set((s) => {
      // Deduplicate: if a tab with same kind+entityId exists, just activate it in its pane
      const existing = s.tabs.find((t) => t.kind === tab.kind && t.entityId === tab.entityId);
      if (existing) {
        const leaf = findLeafContainingTab(s.paneLayout, existing.id);
        if (leaf) {
          return {
            activeTabId: existing.id,
            activePaneId: leaf.id,
            paneLayout: setActiveInPane(s.paneLayout, leaf.id, existing.id),
          };
        }
        // A tab with no pane (left over from an older layout bug): put it
        // back in the active pane instead of activating a ghost.
        const paneId = s.activePaneId ?? firstLeaf(s.paneLayout).id;
        return { activeTabId: existing.id, activePaneId: paneId, paneLayout: addTabToPane(s.paneLayout, paneId, existing.id) };
      }
      // Add to active pane (or first leaf)
      const targetPaneId = s.activePaneId ?? firstLeaf(s.paneLayout).id;
      return {
        tabs: [...s.tabs, tab],
        activeTabId: tab.id,
        activePaneId: targetPaneId,
        paneLayout: addTabToPane(s.paneLayout, targetPaneId, tab.id),
      };
    });
  },

  closeTab: (tabId) => {
    set((s) => {
      const idx = s.tabs.findIndex((t) => t.id === tabId);
      const newTabs = s.tabs.filter((t) => t.id !== tabId);
      // Remove from pane layout and collapse empty panes
      let newLayout = removeTabFromLayout(s.paneLayout, tabId);
      newLayout = collapse(newLayout);
      // Figure out new active tab
      const leaf = findLeafContainingTab(s.paneLayout, tabId);
      let newActive = s.activeTabId;
      let newActivePane = s.activePaneId;
      if (s.activeTabId === tabId) {
        // Try to activate sibling in same pane
        if (leaf) {
          const remaining = leaf.tabIds.filter((id) => id !== tabId);
          const prevIdx = Math.max(0, leaf.tabIds.indexOf(tabId) - 1);
          newActive = remaining[Math.min(prevIdx, remaining.length - 1)] ?? null;
          if (!newActive) {
            // The pane emptied and collapsed away: fall through to whatever
            // the surviving pane shows instead of leaving nothing active.
            const surviving = firstLeaf(newLayout);
            newActive = surviving.activeTabId ?? surviving.tabIds[0] ?? null;
          }
        } else {
          const prev = newTabs[Math.max(0, idx - 1)];
          newActive = prev?.id ?? null;
        }
        if (newActive) {
          const newLeaf = findLeafContainingTab(newLayout, newActive);
          newActivePane = newLeaf?.id ?? firstLeaf(newLayout).id;
        } else {
          newActivePane = firstLeaf(newLayout).id;
        }
      }
      return { tabs: newTabs, activeTabId: newActive, paneLayout: newLayout, activePaneId: newActivePane };
    });
  },

  setActiveTab: (tabId) => {
    set((s) => {
      const leaf = findLeafContainingTab(s.paneLayout, tabId);
      if (leaf) {
        return {
          activeTabId: tabId,
          activePaneId: leaf.id,
          paneLayout: setActiveInPane(s.paneLayout, leaf.id, tabId),
        };
      }
      if (!s.tabs.some((t) => t.id === tabId)) return { activeTabId: tabId };
      // Known tab with no pane: re-attach it to the active pane (self-heal).
      const paneId = s.activePaneId ?? firstLeaf(s.paneLayout).id;
      return { activeTabId: tabId, activePaneId: paneId, paneLayout: addTabToPane(s.paneLayout, paneId, tabId) };
    });
  },

  setActivePane: (paneId) => {
    set((s) => {
      const leaf = (() => {
        const find = (n: PaneNode): PaneNode | null => {
          if (n.type === 'leaf') return n.id === paneId ? n : null;
          return find(n.children[0]) ?? find(n.children[1]);
        };
        return find(s.paneLayout);
      })();
      if (leaf && leaf.type === 'leaf') {
        return { activePaneId: paneId, activeTabId: leaf.activeTabId ?? s.activeTabId };
      }
      return { activePaneId: paneId };
    });
  },

  moveTabToPane: (tabId, targetPaneId, position) => {
    set((s) => {
      const newLayout = moveTab(s.paneLayout, tabId, targetPaneId, position);
      // Find where the tab ended up
      const newLeaf = findLeafContainingTab(newLayout, tabId);
      return {
        paneLayout: newLayout,
        activeTabId: tabId,
        activePaneId: newLeaf?.id ?? s.activePaneId,
      };
    });
  },

  reorderTab: (tabId, targetTabId, place) => {
    if (tabId === targetTabId) return;
    set((s) => {
      const tabs = moveWithin(s.tabs, tabId, targetTabId, place, (t) => t.id);
      const from = findLeafContainingTab(s.paneLayout, tabId);
      const to = findLeafContainingTab(s.paneLayout, targetTabId);
      let paneLayout = s.paneLayout;
      if (from && to) {
        if (from.id !== to.id) paneLayout = moveTab(paneLayout, tabId, to.id, 'center');
        const leaf = findLeafContainingTab(paneLayout, targetTabId);
        if (leaf) paneLayout = reorderTabInLeaf(paneLayout, leaf.id, tabId, targetTabId, place);
      }
      const leaf = findLeafContainingTab(paneLayout, tabId);
      return { tabs, paneLayout, activeTabId: tabId, activePaneId: leaf?.id ?? s.activePaneId };
    });
  },

  reconcileTabs: () => {
    const c = getSharedDoc();
    // Before the doc has loaded every map is empty; pruning then would drop
    // every restored tab.
    if (c.tables.workspaces.size === 0) return;
    const alive = (t: TabItem): boolean => {
      switch (t.kind) {
        case 'page':
        case 'history': return c.tables.pages.has(t.entityId);
        case 'nmap': return c.tables.nmapScans.has(t.entityId);
        case 'nmap-machine':
        case 'web-scan': return c.tables.nmapMachines.has(t.entityId);
        // comp-ready: the report feature is removed, so a stale report tab
        // persisted from before (or synced from another client) is dropped.
        case 'typst': return false;
        default: return ['cmdlog', 'assets', 'shortcuts'].includes(t.kind);
      }
    };
    set((s) => {
      const dead = new Set(s.tabs.filter((t) => !alive(t)).map((t) => t.id));
      const tabs = dead.size ? s.tabs.filter((t) => !dead.has(t.id)) : s.tabs;
      const paneLayout = dead.size ? collapse(removeTabsWhere(s.paneLayout, (id) => dead.has(id))) : s.paneLayout;
      const next = reconcileActive(tabs, paneLayout, s.activeTabId, s.activePaneId);
      if (!dead.size && next.activeTabId === s.activeTabId && next.activePaneId === s.activePaneId) return {};
      return { tabs, paneLayout, ...next };
    });
  },

  updateSplitRatio: (splitId, ratio) => {
    set((s) => ({ paneLayout: updateRatio(s.paneLayout, splitId, ratio) }));
  },

  mergePanesIntoOne: (activeTabId) => {
    set((s) => {
      const nextActive = activeTabId ?? s.activeTabId;
      const leaf = createLeaf(s.tabs.map((t) => t.id), nextActive);
      return { paneLayout: leaf, activePaneId: leaf.id, activeTabId: nextActive };
    });
  },

  followPanelOpen: false,
  setFollowPanelOpen: (open) => set({ followPanelOpen: open }),
  followingUserId: null,
  setFollowingUserId: (userId) => set({ followingUserId: userId }),
  selectedNmapMachineId: null,
  setSelectedNmapMachineId: (id) => set({ selectedNmapMachineId: id }),

  // UI
  leftSidebarOpen: true,
  leftSidebarWidth: 280,
  setLeftSidebarWidth: (width: number) => set({ leftSidebarWidth: Math.min(480, Math.max(200, width)) }),
  rightSidebarOpen: true,
  toggleLeftSidebar: () => set((s) => ({ leftSidebarOpen: !s.leftSidebarOpen })),
  toggleRightSidebar: () => set((s) => ({ rightSidebarOpen: !s.rightSidebarOpen })),
  navDrawerOpen: false,
  setNavDrawerOpen: (open) => set({ navDrawerOpen: open }),
  // Seeded from <html>, which index.html's inline script already set from
  // the stored per-device mode (src/lib/color-mode.ts).
  darkMode: currentColorMode() === 'dark',
  toggleDarkMode: () =>
    set((s) => {
      const next = !s.darkMode;
      setColorMode(next ? 'dark' : 'light');
      return { darkMode: next };
    }),
  setDarkMode: (dark: boolean) => {
    setColorMode(dark ? 'dark' : 'light');
    set({ darkMode: dark });
  },
  commandPaletteOpen: false,
  setCommandPaletteOpen: (open) => set({ commandPaletteOpen: open }),

  // Search
  searchQuery: '',
  setSearchQuery: (query) => set({ searchQuery: query }),
  searchResults: [],
  runSearch: async () => {
    const { searchQuery, activeWorkspaceId } = get();
    if (!activeWorkspaceId || !searchQuery.trim()) {
      set({ searchResults: [] });
      return;
    }
    const results = await pageRepo.search(activeWorkspaceId, searchQuery);
    set({ searchResults: results });
  },

  // Change log
  changeLogs: [],
  loadChangeLogs: async () => {
    const wsId = get().activeWorkspaceId;
    if (!wsId) return;
    const logs = await changeLogRepo.getByWorkspace(wsId);
    set({ changeLogs: logs });
  },

  restoreFromLog: async (entryId: ID) => {
    const entry = get().changeLogs.find((e) => e.id === entryId);
    if (!entry || !entry.reversible) return false;

    if (entry.action === 'update' && entry.field) {
      const value = decodeValue<unknown>(entry.prevValue);
      switch (entry.target) {
        case 'page':
          await get().updatePage(entry.targetId, { [entry.field]: value } as Partial<Page>);
          break;
        default:
          return false;
      }
      log('restore', entry.target, entry.targetId,
          `Restored ${entry.field} to previous value`);
      return true;
    }

    if (entry.action === 'delete') {
      const prev = decodeValue<Record<string, unknown>>(entry.prevValue);
      if (!prev || typeof prev !== 'object') return false;
      try {
        // Recreate via the same Y.Map the original entity lived in. We
        // reuse the original id so any references to it keep
        // resolving. Cast via `unknown` because the stored JSON is opaque
        // to the type system but the runtime shape matches the entity.
        let label = (prev['name'] ?? prev['title'] ?? prev['label'] ?? entry.targetId) as string;
        let suffix = '';
        switch (entry.target) {
          case 'page': {
            // The whole deleted tree (or the single record older builds
            // logged), in one transaction, with its Y.Texts re-seeded.
            const recs = pagesFromDeleteSnapshot(prev);
            if (recs.length === 0) return false;
            label = recs[0]!.title;
            if (recs.length > 1) suffix = ` and ${recs.length - 1} subpage${recs.length === 2 ? '' : 's'}`;
            await pageRepo.restoreTree(recs);
            const ids = new Set(recs.map((r) => r.id));
            set((s) => ({ pages: [...s.pages.filter((p) => !ids.has(p.id)), ...recs] }));
            break;
          }
          default:
            return false;
        }
        log('restore', entry.target, entry.targetId,
            `Restored deleted ${entry.target} "${label}"${suffix}`);
        return true;
      } catch {
        return false;
      }
    }

    return false;
  },

  // Nmap scans
  nmapScans: [],
  nmapMachines: [],
  webScanHosts: [],
  loadWebScanHosts: async () => {
    const wsId = get().activeWorkspaceId;
    if (!wsId) { set({ webScanHosts: [] }); return; }
    const scans = await nmapScanRepo.getByWorkspace(wsId);
    const scanIds = new Set(scans.map((sc) => sc.id));
    const all = await nmapMachineRepo.getAll();
    const hosts = all
      .filter((m) => scanIds.has(m.scanId) && (m.toolFindings?.length ?? 0) > 0)
      .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
    set({ webScanHosts: hosts });
  },
  loadNmapScans: async () => {
    const wsId = get().activeWorkspaceId;
    if (!wsId) return;
    const scans = await nmapScanRepo.getByWorkspace(wsId);
    set({ nmapScans: scans });
  },
  createNmapGroup: async (name: string) => {
    const wsId = get().activeWorkspaceId;
    if (!wsId) throw new Error('No active workspace');
    const scan = await nmapScanRepo.create(wsId, name);
    set((s) => ({ nmapScans: [scan, ...s.nmapScans] }));
    log('create', 'page', scan.id, `Created nmap group "${name}"`);
    return scan;
  },
  importToNmapGroup: async (groupId: ID, xml: string) => {
    const { parseNmapXml } = await import('@/lib/nmap-parser');
    const parsed = parseNmapXml(xml);
    const machines = parsed.map((h) => ({
      scanId: groupId,
      ip: h.ip,
      hostname: h.hostname,
      os: h.os,
      ports: h.ports,
    }));
    await nmapMachineRepo.upsertByIp(groupId, machines);
    // Reload machines for the group
    const updated = await nmapMachineRepo.getByScan(groupId);
    set({ nmapMachines: updated });
    log('update', 'page', groupId, `Imported ${parsed.length} hosts to nmap group`);
  },
  importNmapScan: async (name: string, xml: string) => {
    const wsId = get().activeWorkspaceId;
    if (!wsId) throw new Error('No active workspace');
    const { parseNmapXml } = await import('@/lib/nmap-parser');
    const scan = await nmapScanRepo.add(wsId, name, xml);
    const parsed = parseNmapXml(xml);
    const machines = parsed.map((h) => ({
      scanId: scan.id,
      ip: h.ip,
      hostname: h.hostname,
      os: h.os,
      ports: h.ports,
    }));
    await nmapMachineRepo.addMany(machines);
    set((s) => ({ nmapScans: [scan, ...s.nmapScans] }));
    log('create', 'page', scan.id, `Imported nmap scan "${name}" (${parsed.length} hosts)`);
    return scan;
  },
  renameNmapScan: async (id: ID, name: string) => {
    await nmapScanRepo.rename(id, name);
    set((s) => ({ nmapScans: s.nmapScans.map((sc) => sc.id === id ? { ...sc, name } : sc) }));
    // Update any open tabs with the old name
    set((s) => ({ tabs: s.tabs.map((t) => t.kind === 'nmap' && t.entityId === id ? { ...t, title: name } : t) }));
  },
  deleteNmapScan: async (id: ID) => {
    await nmapScanRepo.delete(id);
    set((s) => ({
      nmapScans: s.nmapScans.filter((sc) => sc.id !== id),
      tabs: s.tabs.filter((t) => !(t.kind === 'nmap' && t.entityId === id)),
      paneLayout: collapse(removeTabsWhere(s.paneLayout, (tid) => {
        const tab = s.tabs.find((t) => t.id === tid);
        return !!tab && tab.kind === 'nmap' && tab.entityId === id;
      })),
    }));
    get().reconcileTabs();
    log('delete', 'page', id, 'Deleted nmap scan');
  },
  loadNmapMachines: async (scanId: ID) => {
    const machines = await nmapMachineRepo.getByScan(scanId);
    // Merge: keep machines from other scans, replace this scan's slice.
    // (Observer-driven reloads call this for every scan in series; a naive
    // `set({ nmapMachines: machines })` would leave only the last scan's
    // machines in memory and break the live attach UI.)
    set((s) => {
      const others = s.nmapMachines.filter((m) => m.scanId !== scanId);
      return { nmapMachines: [...others, ...machines] };
    });
  },
  updateNmapMachine: async (id: ID, data: Partial<Pick<NmapMachine, 'hostname' | 'os'>>) => {
    await nmapMachineRepo.update(id, data);
    set((s) => ({
      nmapMachines: s.nmapMachines.map((m) => m.id === id ? { ...m, ...data, updatedAt: Date.now() } : m),
    }));
  },
  deleteNmapMachine: async (id: ID) => {
    await nmapMachineRepo.delete(id);
    set((s) => ({ nmapMachines: s.nmapMachines.filter((m) => m.id !== id) }));
    log('delete', 'page', id, 'Deleted nmap machine');
  },

  // Typst assets. Only metadata lives in the shared doc: the bytes are on
  // the server (see lib/assets.ts + server/assets.mjs).
  typstAssets: [],
  loadTypstAssets: async () => {
    const wsId = get().activeWorkspaceId;
    if (!wsId) return;
    set({ typstAssets: await typstAssetRepo.getByWorkspace(wsId) });
  },

  moveTypstAssetToFolder: async (assetId: ID, folderId: ID | null) => {
    const asset = get().typstAssets.find((a) => a.id === assetId);
    if (!asset || (asset.folderId ?? null) === folderId) return;
    await typstAssetRepo.setFolder(assetId, folderId);
    set((s) => ({
      typstAssets: s.typstAssets.map((a) => (a.id === assetId ? { ...a, folderId } : a)),
    }));
    const dest = folderId
      ? `"${get().assetFolders.find((f) => f.id === folderId)?.name ?? 'folder'}"`
      : 'the root';
    log('update', 'page', assetId, `Moved Typst asset "${asset.filename}" to ${dest}`);
  },

  // Asset folders: the Typst assets panel's hierarchy. Organizational only,
  // so nothing here ever rewrites a document (see lib/asset-folders.ts).
  assetFolders: [],
  loadAssetFolders: async () => {
    const wsId = get().activeWorkspaceId;
    if (!wsId) return;
    set({ assetFolders: await assetFolderRepo.getByWorkspace(wsId) });
  },
  createAssetFolder: async (name: string, parentId?: ID | null) => {
    const wsId = get().activeWorkspaceId;
    if (!wsId) throw new Error('No active workspace');
    const folder = await assetFolderRepo.create({ workspaceId: wsId, name, parentId: parentId ?? null });
    set((s) => ({ assetFolders: [...s.assetFolders, folder] }));
    log('create', 'page', folder.id, `Created asset folder "${folder.name}"`);
    return folder;
  },
  renameAssetFolder: async (id: ID, name: string) => {
    const prev = get().assetFolders.find((f) => f.id === id);
    const trimmed = name.trim();
    if (!prev || !trimmed || prev.name === trimmed) return;
    await assetFolderRepo.rename(id, trimmed);
    set((s) => ({
      assetFolders: s.assetFolders.map((f) => (f.id === id ? { ...f, name: trimmed } : f)),
    }));
    log('update', 'page', id, `Renamed asset folder "${prev.name}" to "${trimmed}"`, {
      field: 'name', prevValue: encodeValue(prev.name), newValue: encodeValue(trimmed),
    });
  },
  moveAssetFolder: async (id: ID, parentId: ID | null) => {
    const folders = get().assetFolders;
    const folder = folders.find((f) => f.id === id);
    if (!folder || (folder.parentId ?? null) === parentId) return;
    // Cycle guard: never move a folder into itself or its own subtree.
    if (parentId && isDescendantFolder(folders, parentId, id)) return;
    await assetFolderRepo.move(id, parentId);
    set((s) => ({
      assetFolders: s.assetFolders.map((f) => (f.id === id ? { ...f, parentId } : f)),
    }));
    log('update', 'page', id, `Moved asset folder "${folder.name}"`);
  },
  deleteAssetFolder: async (id: ID) => {
    const folders = get().assetFolders;
    const target = folders.find((f) => f.id === id);
    if (!target) return;
    const parent = target.parentId ?? null;
    // Contents move up a level: deleting a folder never deletes assets.
    for (const child of folders.filter((f) => (f.parentId ?? null) === id)) {
      await assetFolderRepo.move(child.id, parent);
    }
    for (const a of get().typstAssets.filter((x) => (x.folderId ?? null) === id)) {
      await typstAssetRepo.setFolder(a.id, parent);
    }
    await assetFolderRepo.remove(id);
    await get().loadAssetFolders();
    await get().loadTypstAssets();
    log('delete', 'page', id, `Deleted asset folder "${target.name}" (contents moved up)`);
  },

  // Command log: the shared-doc live window. The full archive is fetched over
  // REST by the view; this loader keeps the store in sync as agents ship
  // commands (wired in shared-bindings.ts). Read-only: clients never write.
  commandLogs: [],
  loadCommandLogs: async () => {
    const wsId = get().activeWorkspaceId;
    if (!wsId) return;
    set({ commandLogs: await commandLogRepo.getByWorkspace(wsId) });
  },

  editingAssetId: null,
  setEditingAssetId: (id) => set({ editingAssetId: id }),
  imageMenu: null,
  setImageMenu: (menu) => set({ imageMenu: menu }),
  addTypstAsset: async (file: File, kind: TypstAssetKind, folderId?: ID | null, fontFamily?: string | null) => {
    const wsId = get().activeWorkspaceId;
    if (!wsId) throw new Error('No active workspace');
    const { uploadAsset, readImageSize } = await import('@/lib/assets');

    // Reserve a collision-free name *before* uploading so two screenshots
    // dropped with the same name don't fight over one asset path.
    const filename = await typstAssetRepo.uniqueFilename(wsId, file.name);
    const uploaded = await uploadAsset(file, { workspaceId: wsId, kind, filename });

    // Best-effort enrichment: the dimensions drive the crop editor's frame
    // shape. Not worth failing the upload over.
    let width: number | null = null;
    let height: number | null = null;
    if (kind === 'image' && file.type !== 'image/svg+xml') {
      try { const s = await readImageSize(file); width = s.width; height = s.height; }
      catch { /* dimensions stay unknown; the cropper falls back to the rendered size */ }
    }

    const asset = await typstAssetRepo.create({
      id: uploaded.id,
      workspaceId: wsId,
      kind,
      filename: uploaded.filename,
      mime: uploaded.mime,
      size: uploaded.size,
      width,
      height,
      fontFamily: kind === 'font' ? fontFamily ?? null : null,
      folderId: folderId ?? null,
    });
    set((s) => ({ typstAssets: [...s.typstAssets, asset] }));
    log('create', 'page', asset.id, `Added ${kind} "${asset.filename}"`);
    return asset;
  },
  setTypstAssetCrop: async (id: ID, crop: CropRect | null, blurs?: BlurRegion[] | null) => {
    const prevAsset = get().typstAssets.find((a) => a.id === id);
    const prev = { crop: prevAsset?.crop ?? null, blurs: prevAsset?.blurs ?? null };
    // Omitting `blurs` keeps the existing regions; an empty list clears them.
    const nextBlurs = blurs === undefined ? prev.blurs : blurs && blurs.length > 0 ? blurs : null;
    await typstAssetRepo.setFraming(id, { crop, blurs: nextBlurs });
    set((s) => ({
      typstAssets: s.typstAssets.map((a) => (a.id === id ? { ...a, crop, blurs: nextBlurs } : a)),
    }));
    const name = get().typstAssets.find((a) => a.id === id)?.filename ?? id;
    const blurNote = nextBlurs
      ? ` (${nextBlurs.length} blurred region${nextBlurs.length === 1 ? '' : 's'})`
      : '';
    log(
      'update',
      'page',
      id,
      (crop ? `Cropped "${name}"` : `Cleared crop on "${name}"`) + blurNote,
      {
        field: 'crop',
        prevValue: encodeValue(prev),
        newValue: encodeValue({ crop, blurs: nextBlurs }),
      },
    );
  },
  renameTypstAsset: async (id: ID, stem: string) => {
    const wsId = get().activeWorkspaceId;
    const asset = get().typstAssets.find((a) => a.id === id);
    if (!wsId || !asset) throw new Error('asset not found');

    // The extension is deliberately not editable. It's what tells Typst which
    // decoder to use, and the bytes are normalized to match it, letting
    // someone rename shot.png to shot.jpg would reintroduce exactly the
    // decode failure that normalization exists to prevent.
    const dot = asset.filename.lastIndexOf('.');
    const ext = dot > 0 ? asset.filename.slice(dot) : '';

    // Same rules as the server's sanitizer, since this becomes a path in the
    // compiler's virtual filesystem.
    const safeStem = stem.trim().replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[.]+/, '').slice(0, 80);
    if (!safeStem) throw new Error('name cannot be empty');

    const desired = safeStem + ext;
    if (desired === asset.filename) return asset.filename;

    const filename = await typstAssetRepo.uniqueFilename(wsId, desired);
    await typstAssetRepo.rename(id, filename);
    set((s) => ({
      typstAssets: s.typstAssets.map((a) => (a.id === id ? { ...a, filename } : a)),
    }));
    // Keep the report resolving the file: repoint its /assets/<old> literals.
    // Never creates the Y.Text (invariant 1), a workspace without a report has none.
    const report = getSharedDoc().texts.get(textKey('typst', wsId, 'source'));
    if (report) {
      updateYTextContent(report, (cur) => retargetAssetPath(cur, `${ASSET_DIR}/${asset.filename}`, `${ASSET_DIR}/${filename}`));
    }
    log('update', 'page', id, `Renamed Typst image "${asset.filename}" → "${filename}"`, {
      field: 'filename',
      prevValue: encodeValue(asset.filename),
      newValue: encodeValue(filename),
    });
    return filename;
  },
  retireTypstAsset: async (id: ID) => {
    const asset = get().typstAssets.find((a) => a.id === id);
    if (!asset || asset.deletedAt) return;
    const now = Date.now();
    await typstAssetRepo.retire(id);
    set((s) => ({ typstAssets: s.typstAssets.map((a) => (a.id === id ? { ...a, deletedAt: now } : a)) }));
    log('delete', 'page', id, `Removed image "${asset.filename}" (kept for the history retention window)`);
  },
  unretireTypstAsset: async (id: ID) => {
    if (!(await typstAssetRepo.unretire(id))) return;
    set((s) => ({ typstAssets: s.typstAssets.map((a) => (a.id === id ? { ...a, deletedAt: null } : a)) }));
    const asset = get().typstAssets.find((a) => a.id === id);
    log('restore', 'page', id, `Image "${asset?.filename ?? id}" is in a note again`);
  },
  deleteTypstAsset: async (id: ID) => {
    const asset = get().typstAssets.find((a) => a.id === id);
    const { deleteAssetBytes, forgetAsset } = await import('@/lib/assets');
    // Drop the bytes first: if that fails we keep the record, leaving the
    // asset usable rather than stranding a document reference to a file the
    // compiler can no longer resolve.
    await deleteAssetBytes(id);
    forgetAsset(id);
    await typstAssetRepo.remove(id);
    set((s) => ({ typstAssets: s.typstAssets.filter((a) => a.id !== id) }));
    log(
      'delete',
      'page',
      id,
      `Deleted Typst ${asset?.kind ?? 'asset'} "${asset?.filename ?? id}"`,
    );
  },

  // Database
  deleteDatabase: async () => {
    await db.delete();
    await db.open();
    set({
      workspaces: [],
      activeWorkspaceId: null,
      pages: [],
      changeLogs: [],
      nmapScans: [],
      nmapMachines: [],
      webScanHosts: [],
      typstAssets: [],
      commandLogs: [],
      tabs: [],
      activeTabId: null,
      paneLayout: createLeaf(),
      activePaneId: null,
      searchQuery: '',
      searchResults: [],
    });
  },
});
});

// Persist UI state (tabs, panes, active workspace) on every relevant change.
// Lives outside `create()` so it can subscribe to the store after creation.
useAppStore.subscribe((state, prev) => {
  if (
    state.tabs !== prev.tabs ||
    state.activeTabId !== prev.activeTabId ||
    state.paneLayout !== prev.paneLayout ||
    state.activePaneId !== prev.activePaneId ||
    state.activeWorkspaceId !== prev.activeWorkspaceId
  ) {
    savePersistedUi({
      activeWorkspaceId: state.activeWorkspaceId,
      tabs: state.tabs,
      activeTabId: state.activeTabId,
      paneLayout: state.paneLayout,
      activePaneId: state.activePaneId,
    });
  }
});
