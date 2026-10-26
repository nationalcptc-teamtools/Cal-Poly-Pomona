// The signed-in account's preview lock for one workspace (lib/preview-lock).
// Local to this browser and this account: nothing here reaches the shared doc.

import { useCallback, useEffect, useState } from 'react';
import { useAuthStore } from '@/auth/auth-store';
import { isPreviewLockKey, loadLockedWorkspaces, saveLockedWorkspaces, toggleLocked } from '@/lib/preview-lock';

export function usePreviewLock(workspaceId: string): { locked: boolean; toggle: () => void } {
  const userId = useAuthStore((s) => s.user?.id ?? null);
  const read = useCallback(() => loadLockedWorkspaces(userId).has(workspaceId), [userId, workspaceId]);
  const [locked, setLocked] = useState(read);

  // A different account or workspace: its own lock, read fresh.
  useEffect(() => { setLocked(read()); }, [read]);

  // Another tab of the same account flipped it.
  useEffect(() => {
    const onStorage = (e: StorageEvent) => { if (isPreviewLockKey(e.key, userId)) setLocked(read()); };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, [read, userId]);

  const toggle = useCallback(() => {
    // Read-modify-write against storage, not state: another tab may have
    // changed a different workspace's lock since this one rendered.
    const next = toggleLocked(loadLockedWorkspaces(userId), workspaceId);
    saveLockedWorkspaces(userId, next);
    setLocked(next.has(workspaceId));
  }, [userId, workspaceId]);

  return { locked, toggle };
}
