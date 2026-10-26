import { useEffect, useState } from 'react';
import { changeLogRepo } from '@/db';
import { useAppStore } from '@/stores';
import type { ChangeLogEntry, ChangeTarget } from '@/types';

/**
 * "Edited by Alice · 12m ago" chip. Reads the most-recent changeLog entry
 * for the given target id; updates when changeLogs change (the panel
 * subscribes to the store so any new write triggers a re-query).
 */
export function LastEditedBadge({ target, targetId }: { target: ChangeTarget; targetId: string }) {
  const activeWorkspaceId = useAppStore((s) => s.activeWorkspaceId);
  const changeLogs = useAppStore((s) => s.changeLogs);
  const [entry, setEntry] = useState<ChangeLogEntry | null>(null);

  useEffect(() => {
    if (!activeWorkspaceId) { setEntry(null); return; }
    let cancelled = false;
    void changeLogRepo.latestForTarget(activeWorkspaceId, target, targetId).then((e) => {
      if (!cancelled) setEntry(e);
    });
    return () => { cancelled = true; };
  // changeLogs is included so the badge refreshes when a new entry for this entity lands.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeWorkspaceId, target, targetId, changeLogs]);

  if (!entry) return null;
  return (
    <div className="flex items-center gap-1.5 text-caption text-muted-foreground">
      {entry.userName ? (
        <>
          <span
            className="inline-block h-2 w-2 rounded-full"
            style={{ backgroundColor: entry.userColor ?? 'hsl(var(--muted-foreground))' }}
            aria-hidden
          />
          <span>Edited by {entry.userName}</span>
          <span aria-hidden>·</span>
        </>
      ) : null}
      <span>{formatTimeAgo(entry.timestamp)}</span>
    </div>
  );
}

function formatTimeAgo(ts: number): string {
  const diff = Date.now() - ts;
  const s = Math.floor(diff / 1000);
  if (s < 60) return 'just now';
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}
