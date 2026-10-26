/**
 * The "follow a teammate" engine.
 *
 * `useFollowEngine()` (mounted once, app-wide) watches the `followingUserId`
 * in the app store. While set, it subscribes to that teammate's awareness
 * `focus` and mirrors it into the local view: opening the right tab and,
 * when precision allows, jumping to their exact node / caret / host. It also
 * auto-detaches the moment the local user manually switches tabs.
 *
 * Navigation reuses the app's existing primitives: `openTab` (dedupes by
 * kind+entityId), `setPendingFocusNodeId` (the graph fitView/flash path
 * already consumed by GraphCanvas), and the `nmap-machine` tab for hosts.
 */
import { useEffect, useRef } from 'react';
import { v4 as uuidv4 } from 'uuid';
import { useAppStore } from '@/stores';
import { useAuthStore } from '@/auth/auth-store';
import { resolvePrefs, type FollowPrecision } from '@/lib/editor-prefs';
import { isSplit } from '@/lib/pane-layout';
import type { TabItem } from '@/types';
import { getSharedAwareness, getPeerFocus, type FocusPayload } from './presence';

/** Precision to use for a given teammate (per-user override → account default). */
function precisionFor(userId: number): FollowPrecision {
  const follow = resolvePrefs(useAuthStore.getState().user).follow;
  return follow.precisionByUserId[String(userId)] ?? follow.defaultPrecision;
}

/** Open a followed tab and honor the remembered pane-placement preference. */
function openAndPlace(tab: TabItem): void {
  const store = useAppStore.getState();
  store.openTab(tab);
  const placement = resolvePrefs(useAuthStore.getState().user).follow.panePlacement;
  if (placement === 'takeover') {
    const st = useAppStore.getState();
    if (isSplit(st.paneLayout)) st.mergePanesIntoOne(st.activeTabId);
  }
  // 'split' (or a single pane): openTab already dropped the view into the
  // active pane, which is exactly "open it in one of my current panes".
}

/**
 * Scroll a teammate's live remote caret into view. The caret element is
 * rendered by y-prosemirror and tagged with `data-user-id` in PageEditor's
 * cursorBuilder. Retries briefly because the editor + caret mount async after
 * the tab opens. Best-effort: silently gives up if it never appears.
 */
function revealRemoteCaret(userId: number): void {
  let attempts = 0;
  const tick = () => {
    attempts += 1;
    const el = document.querySelector(
      `.ProseMirror-yjs-cursor[data-user-id="${userId}"]`,
    ) as HTMLElement | null;
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      return;
    }
    if (attempts < 12) setTimeout(tick, 150);
  };
  setTimeout(tick, 150);
}

/** Mirror a teammate's focus into the local view. */
function applyFocus(focus: FocusPayload, userId: number): void {
  const precise = precisionFor(userId) === 'precise';

  switch (focus.kind) {
    case 'page': {
      openAndPlace({ id: uuidv4(), kind: 'page', entityId: focus.entityId, title: focus.title || 'Page' });
      if (precise) revealRemoteCaret(userId);
      break;
    }
    case 'nmap':
    case 'nmap-machine': {
      if (precise && focus.machineId) {
        openAndPlace({ id: uuidv4(), kind: 'nmap-machine', entityId: focus.machineId, title: focus.title || 'Host' });
      } else {
        openAndPlace({ id: uuidv4(), kind: focus.kind, entityId: focus.entityId, title: focus.title || 'Nmap' });
      }
      break;
    }
    default: {
      // typst / cmdlog / assets / shortcuts: singleton or entity-backed tabs.
      openAndPlace({ id: uuidv4(), kind: focus.kind, entityId: focus.entityId, title: focus.title || focus.kind });
    }
  }
}

export function useFollowEngine(): void {
  const followingUserId = useAppStore((s) => s.followingUserId);
  // True only while WE are driving a navigation, so the manual-detach watcher
  // can tell follow-induced tab changes from the user clicking another tab.
  const applyingRef = useRef(false);

  // Mirror the followed teammate's focus.
  useEffect(() => {
    if (followingUserId == null) return;
    const awareness = getSharedAwareness();
    let lastKey = '';

    const apply = () => {
      const focus = getPeerFocus(followingUserId);
      if (!focus) return;
      const key = `${focus.kind}|${focus.entityId}|${focus.nodeId ?? ''}|${focus.machineId ?? ''}`;
      if (key === lastKey) return;
      lastKey = key;
      applyingRef.current = true;
      try {
        applyFocus(focus, followingUserId);
      } finally {
        // Store updates fire subscribers synchronously inside applyFocus; reset
        // on the next microtask so the manual-detach watcher saw the flag set.
        queueMicrotask(() => {
          applyingRef.current = false;
        });
      }
    };

    apply();
    awareness.on('change', apply);
    return () => awareness.off('change', apply);
  }, [followingUserId]);

  // Auto-detach when the local user manually switches the active tab.
  useEffect(() => {
    if (followingUserId == null) return;
    const unsub = useAppStore.subscribe((s, prev) => {
      if (s.activeTabId === prev.activeTabId) return;
      if (applyingRef.current) return; // this change came from following
      useAppStore.getState().setFollowingUserId(null);
    });
    return () => unsub();
  }, [followingUserId]);
}
