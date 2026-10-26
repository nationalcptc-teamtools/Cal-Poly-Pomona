import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { useAppStore } from '@/stores';
import { useShallow } from 'zustand/react/shallow';
import { LeftSidebar } from '@/components/sidebar/LeftSidebar';
import { RightSidebar } from '@/components/sidebar/RightSidebar';
import { SplitContainer } from '@/components/ui/SplitContainer';
import { CommandPalette } from '@/components/ui/CommandPalette';
const AssetImageEditor = lazy(() => import('@/components/editor/AssetImageEditor').then((m) => ({ default: m.AssetImageEditor })));
import { useAuthStore } from '@/auth/auth-store';
import { useThemeStore } from '@/stores/theme-store';
import { resolvePrefs, matchShortcut, applyNoteWidth } from '@/lib/editor-prefs';
import { applyEditorStyle } from '@/components/editor/live-preview/editor-style';
import { applyCodeAccent } from '@/lib/code-accent';
import { applyUiZoom, getUiZoom, stepUiZoom, toLayoutPx } from '@/lib/ui-zoom';
import { applyHeadingColors, resolveEffectiveHeadings } from '@/lib/theme';
import { setEditorKeybinds } from '@/lib/editor-keybind-registry';
import { LoginScreen } from '@/auth/LoginScreen';
import { getSharedDoc } from '@/realtime/shared-doc';
import { syncOpenPageDocs } from '@/realtime/yjs-providers';
import { bindSharedSubscriptions } from '@/stores/shared-bindings';
import { getActiveMilkdownEditor, hasMilkdownSelection } from '@/lib/active-editor';
import { startPresence } from '@/realtime/presence';
import { useFollowEngine } from '@/realtime/use-follow';
import { PresenceAvatars } from '@/realtime/PresenceAvatars';
import { ErrorBoundary } from '@/components/ui/ErrorBoundary';
import { ConnectionBanner } from '@/components/ui/ConnectionBanner';
import { EditorNotices } from '@/components/editor/EditorNotices';
import { installPreloadRecovery } from '@/lib/preload-recovery';
import { createLeaf } from '@/lib/pane-layout';
import { useNarrowLayout } from '@/lib/use-layout-width';

// A lazy chunk that vanished in a redeploy reloads the page once.
installPreloadRecovery();

/** Root fallback's second action: drop every tab, so a tab that crashes on render is not replayed. */
function closeAllTabs(): void {
  useAppStore.setState({ tabs: [], activeTabId: null, paneLayout: createLeaf(), activePaneId: null });
}

export function App() {
  const authStatus = useAuthStore((s) => s.status);
  const bootstrap = useAuthStore((s) => s.bootstrap);
  const loadTheme = useThemeStore((s) => s.loadTheme);
  const adminHeadings = useThemeStore((s) => s.headings);
  const themeLock = useThemeStore((s) => s.lock);
  const user = useAuthStore((s) => s.user);
  const authError = useAuthStore((s) => s.error);

  // Validate any stored token on first mount, and pull the global theme
  // color from the server so login + main UI both render with the
  // configured accent rather than the index.css fallback.
  useEffect(() => {
    void bootstrap();
    void loadTheme();
  }, [bootstrap, loadTheme]);

  // Apply this account's editor preferences (code-block syntax accent,
  // custom keybinds, heading colours) on load and whenever the user object
  // or the admin theme policy changes: after bootstrap, login, a profile
  // save, or an admin toggling the hard-lock. All apply live without
  // rebuilding the editor. Heading colours go through the precedence rule
  // (lock → user prefs → admin defaults → inherit).
  useEffect(() => {
    const prefs = resolvePrefs(user);
    applyCodeAccent(prefs.codeAccent);
    setEditorKeybinds(prefs.keybinds);
    applyNoteWidth(prefs.noteWidth);
    applyEditorStyle(prefs.editorStyle);
    const effective = resolveEffectiveHeadings({ headings: adminHeadings, lock: themeLock }, prefs.theme);
    applyHeadingColors(effective.headings);
  }, [user, adminHeadings, themeLock]);

  if (authStatus === 'unknown') {
    return (
      <div className="flex h-viewport w-viewport flex-col items-center justify-center gap-2 bg-background text-muted-foreground">
        <span>Loading…</span>
        {authError && <span className="text-xs">{authError}</span>}
      </div>
    );
  }
  if (authStatus === 'unauthenticated') {
    return <LoginScreen />;
  }
  return (
    <ErrorBoundary label="the app" fullScreen onReset={{ label: 'Close all tabs', run: closeAllTabs }}>
      <AuthedApp />
    </ErrorBoundary>
  );
}

function AuthedApp() {
  // `AssetImageEditor` hosts BOTH the note-image right-click menu and the
  // crop/redact dialog, so it has to be mounted for either flag. Keying it on
  // `editingAssetId` alone meant a right-click set `imageMenu` with nothing
  // mounted to draw it, and the menu never appeared.
  const editingAssetId = useAppStore((s) => s.editingAssetId);
  const imageMenu = useAppStore((s) => s.imageMenu);
  useEffect(() => {
    const sync = () => syncOpenPageDocs(useAppStore.getState().tabs
      .filter((t) => t.kind === 'page' || t.kind === 'history').map((t) => t.entityId));
    sync();
    const unsubscribe = useAppStore.subscribe((s, prev) => { if (s.tabs !== prev.tabs) sync(); });
    return () => { unsubscribe(); syncOpenPageDocs([]); };
  }, []);

  // Select only what this shell reads: a selectorless useAppStore() snapshot
  // re-renders the entire app tree on every store write (each sync event,
  // each debounced content save).
  const {
    loadWorkspaces,
    activeWorkspaceId,
    loadWorkspaceData,
    leftSidebarOpen,
    rightSidebarOpen,
    workspaces,
  } = useAppStore(useShallow((s) => ({
    loadWorkspaces: s.loadWorkspaces,
    activeWorkspaceId: s.activeWorkspaceId,
    loadWorkspaceData: s.loadWorkspaceData,
    leftSidebarOpen: s.leftSidebarOpen,
    rightSidebarOpen: s.rightSidebarOpen,
    workspaces: s.workspaces,
  })));

  const narrow = useNarrowLayout();
  // Going narrow (a resize, a zoom step) closes the properties overlay, so it
  // does not land on top of the pane the user was looking at.
  useEffect(() => {
    if (!narrow) return;
    const st = useAppStore.getState();
    if (st.rightSidebarOpen) st.toggleRightSidebar();
  }, [narrow]);

  // Live-follow engine: mirrors a followed teammate's view while active.
  useFollowEngine();

  // Broadcast this client's presence (identity + current view) into the
  // shared Yjs awareness channel so teammates can see and follow us.
  useEffect(() => {
    const stop = startPresence();
    return () => stop();
  }, []);

  // On initial mount, auto-collapse the right Properties sidebar when the
  // viewport is narrow so the main editor stays readable. Runs once:
  // after the user opens it manually we leave their preference alone.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const NARROW_BREAKPOINT = 1280;
    if (toLayoutPx(window.innerWidth) < NARROW_BREAKPOINT) {
      const st = useAppStore.getState();
      if (st.rightSidebarOpen) st.toggleRightSidebar();
    }
    // Intentionally empty deps: only run once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Wait for the shared Yjs doc to load (IndexedDB cache + initial WS sync)
  // before populating the store. Otherwise we'd flash an empty sidebar and
  // potentially seed demo data on top of someone else's workspace.
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const c = getSharedDoc();
    let cancelled = false;
    const unsubscribe = bindSharedSubscriptions();
    void c.whenReady.then(() => {
      if (!cancelled) setReady(true);
    });
    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, []);

  useEffect(() => {
    if (!ready) return;
    void loadWorkspaces();
  }, [ready, loadWorkspaces]);

  // Every workspace-scoped list, not only pages, change log and scans: the
  // assets and asset folders are what note images resolve against.
  useEffect(() => {
    if (activeWorkspaceId) void loadWorkspaceData();
  }, [activeWorkspaceId, loadWorkspaceData]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        // If the user has selected text inside the markdown editor, hijack
        // Ctrl+K for inline-link insertion (matches Notion / VS Code-style
        // expectations) instead of opening the command palette.
        if (hasMilkdownSelection()) {
          const editor = getActiveMilkdownEditor();
          if (editor) {
            e.preventDefault();
            // Inline "Paste link..." input at the selection (Crepe's link
            // tooltip), matching Notion's Ctrl+K.
            void import('@/lib/link-editor').then(({ openLinkEditor }) => openLinkEditor(editor));
            return;
          }
        }
        e.preventDefault();
        const st = useAppStore.getState();
        st.setCommandPaletteOpen(!st.commandPaletteOpen);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Global "active users / follow" shortcut (default Ctrl/⌘+Shift+U). The
  // binding is user-configurable and read live from account prefs so a
  // rebind takes effect without a reload.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const shortcut = resolvePrefs(useAuthStore.getState().user).keybinds.openFollowPanel;
      if (!matchShortcut(e, shortcut)) return;
      e.preventDefault();
      const st = useAppStore.getState();
      st.setFollowPanelOpen(!st.followPanelOpen);
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Interface zoom: Ctrl/Cmd+Alt+= / - / 0. Alt keeps the browser's own
  // Ctrl+= zoom free, so the two never fight over the same key.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || !e.altKey || e.shiftKey) return;
      let next: number | null = null;
      if (e.code === 'Equal' || e.code === 'NumpadAdd') next = stepUiZoom(getUiZoom(), 1);
      else if (e.code === 'Minus' || e.code === 'NumpadSubtract') next = stepUiZoom(getUiZoom(), -1);
      else if (e.code === 'Digit0' || e.code === 'Numpad0') next = 1;
      if (next === null) return;
      e.preventDefault();
      applyUiZoom(next);
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Blur/crop the selected note image (default Ctrl/Cmd+Shift+B).
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const shortcut = resolvePrefs(useAuthStore.getState().user).keybinds.blurImage;
      if (!matchShortcut(e, shortcut)) return;
      if (!getActiveMilkdownEditor()) return;
      e.preventDefault();
      void import('@/lib/note-image-paste').then(({ blurSelectedImage }) => blurSelectedImage());
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // ───────────────────────────────────────────────────────────────────────
  // Browser back/forward navigation between tabs.
  //
  // Each time the active tab changes by user action we push a history
  // entry tagged with that tab id. When the user clicks the browser's
  // back/forward arrows we read the tab id from the popstate event and
  // reactivate it WITHOUT pushing a new entry (otherwise back would
  // immediately undo itself).
  // ───────────────────────────────────────────────────────────────────────
  const lastActiveTabId = useRef<string | null>(null);
  const isPopping = useRef(false);
  useEffect(() => {
    // Seed the initial entry with the current tab id so the first push
    // doesn't lose the starting state.
    const initial = useAppStore.getState().activeTabId;
    lastActiveTabId.current = initial;
    if (typeof window !== 'undefined' && window.history.state?.btctTabId == null) {
      window.history.replaceState(
        { ...(window.history.state ?? {}), btctTabId: initial },
        '',
      );
    }

    const onPop = (e: PopStateEvent) => {
      const tabId = (e.state && (e.state as { btctTabId?: string }).btctTabId) ?? null;
      if (!tabId) return;
      const st = useAppStore.getState();
      if (!st.tabs.some((t) => t.id === tabId)) return;
      if (st.activeTabId === tabId) return;
      isPopping.current = true;
      st.setActiveTab(tabId);
      // Reset the guard on the next tick after the store update flushes.
      queueMicrotask(() => { isPopping.current = false; });
    };
    window.addEventListener('popstate', onPop);

    const unsub = useAppStore.subscribe((s, prev) => {
      if (s.activeTabId === prev.activeTabId) return;
      const next = s.activeTabId;
      if (next === lastActiveTabId.current) return;
      lastActiveTabId.current = next;
      if (isPopping.current) return;
      if (!next) return;
      window.history.pushState({ btctTabId: next }, '');
    });

    return () => {
      window.removeEventListener('popstate', onPop);
      unsub();
    };
  }, []);

  // Tab navigation: Left/Right arrows cycle tabs in active pane, Alt+W closes active tab.
  // Skip when user is typing in an input/textarea/contenteditable.
  useEffect(() => {
    const isEditableTarget = (t: EventTarget | null): boolean => {
      if (!(t instanceof HTMLElement)) return false;
      const tag = t.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
      if (t.isContentEditable) return true;
      // Arrow keys nudge a focused React Flow node; do not also switch tabs.
      if (t.closest('.react-flow')) return true;
      return false;
    };
    const handler = (e: KeyboardEvent) => {
      const altW = e.altKey && (e.key === 'w' || e.key === 'W');
      const isArrow = e.key === 'ArrowLeft' || e.key === 'ArrowRight';
      if (!altW && !isArrow) return;
      // Don't hijack typing, text selection, or modifier combos we don't own
      if (isEditableTarget(e.target)) return;
      if (isArrow && (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey)) return;

      const state = useAppStore.getState();
      const { activeTabId, paneLayout, activePaneId, setActiveTab, closeTab } = state;
      // Resolve the current pane: prefer the pane containing the active tab,
      // fall back to activePaneId, then to the first leaf.
      const findLeafById = (node: typeof paneLayout, id: string | null): typeof paneLayout | null => {
        if (!id) return null;
        if (node.type === 'leaf') return node.id === id ? node : null;
        return findLeafById(node.children[0], id) ?? findLeafById(node.children[1], id);
      };
      const findLeafWithTab = (node: typeof paneLayout, tabId: string | null): typeof paneLayout | null => {
        if (!tabId) return null;
        if (node.type === 'leaf') return node.tabIds.includes(tabId) ? node : null;
        return findLeafWithTab(node.children[0], tabId) ?? findLeafWithTab(node.children[1], tabId);
      };
      const firstLeafOf = (node: typeof paneLayout): typeof paneLayout => {
        return node.type === 'leaf' ? node : firstLeafOf(node.children[0]);
      };
      const leaf =
        findLeafWithTab(paneLayout, activeTabId) ??
        findLeafById(paneLayout, activePaneId) ??
        firstLeafOf(paneLayout);
      if (leaf.type !== 'leaf') return;
      const tabIds = leaf.tabIds;
      if (tabIds.length === 0) return;
      const currentId = leaf.activeTabId ?? activeTabId;
      const idx = currentId ? tabIds.indexOf(currentId) : -1;

      if (altW) {
        e.preventDefault();
        const targetId = currentId && idx !== -1 ? currentId : tabIds[tabIds.length - 1];
        if (targetId) closeTab(targetId);
        return;
      }

      // Arrow navigation
      e.preventDefault();
      if (tabIds.length < 2) return;
      const safeIdx = idx === -1 ? 0 : idx;
      const nextIdx =
        e.key === 'ArrowLeft'
          ? (safeIdx - 1 + tabIds.length) % tabIds.length
          : (safeIdx + 1) % tabIds.length;
      const nextId = tabIds[nextIdx];
      if (nextId && nextId !== currentId) setActiveTab(nextId);
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Create one empty workspace if there are none. `ready` is not enough to decide that: it
  // also resolves on a timer (250 ms after connecting, or 4 s), so a fresh
  // browser that connects before the server answers would see zero
  // workspaces and write a workspace into the team's shared doc. Seed only once
  // the provider has really synced, and only if the doc is still empty then.
  useEffect(() => {
    if (!ready || workspaces.length > 0) return;
    const { provider, tables } = getSharedDoc();
    let cancelled = false;
    const seedIfEmpty = () => {
      if (cancelled || tables.workspaces.size > 0) return;
      void import('@/db/seed').then(({ seedDefaultWorkspace }) => seedDefaultWorkspace()).then(() => loadWorkspaces());
    };
    const onSync = (synced: boolean) => {
      if (!synced) return;
      provider.off('sync', onSync);
      seedIfEmpty();
    };
    if (provider.synced) seedIfEmpty();
    else provider.on('sync', onSync);
    return () => {
      cancelled = true;
      provider.off('sync', onSync);
    };
  }, [ready, workspaces.length, loadWorkspaces]);

  if (!ready) {
    return (
      <div className="flex h-viewport w-viewport items-center justify-center bg-background text-muted-foreground">
        Connecting…
      </div>
    );
  }

  // Floating panes on the canvas (Typst Studio): every region is a card,
  // --pane-gap apart, and the gaps are the resize handles. Under 900 layout
  // px the sidebar becomes a drawer and the properties pane an overlay.
  return (
    <div data-ui="shell" data-narrow={narrow || undefined} className="flex h-viewport w-viewport overflow-hidden bg-background p-[var(--pane-gap)] text-foreground">
      <LeftSidebar mode={narrow ? 'drawer' : leftSidebarOpen ? 'docked' : 'rail'} />
      <main data-ui="main" className="flex min-w-0 flex-1 flex-col gap-[var(--pane-gap)]">
        <ConnectionBanner />
        <SplitContainer />
      </main>
      {rightSidebarOpen && <RightSidebar overlay={narrow} />}
      <CommandPalette />
      {(editingAssetId || imageMenu) && <Suspense fallback={null}><AssetImageEditor /></Suspense>}
      <PresenceAvatars />
      <EditorNotices />
    </div>
  );
}
