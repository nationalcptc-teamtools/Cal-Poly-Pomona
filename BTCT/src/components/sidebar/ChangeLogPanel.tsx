import { useEffect, useState } from 'react';
import { useAppStore } from '@/stores';
import { History, Undo2 } from 'lucide-react';
import type { ChangeLogEntry } from '@/types';
import { Button } from '@/components/ui/Button';
import { Banner } from '@/components/ui/Banner';
import { SectionHeading } from '@/components/ui/Panel';

/**
 * Workspace activity: renames, creations, deletions and other metadata
 * events from the change log, newest first, each restorable to its previous
 * value. Page bodies are versioned separately (PageHistoryPanel).
 */
export function ChangeLogPanel() {
  const changeLogs = useAppStore((s) => s.changeLogs);
  const loadChangeLogs = useAppStore((s) => s.loadChangeLogs);
  const restoreFromLog = useAppStore((s) => s.restoreFromLog);
  const [pendingId, setPendingId] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    void loadChangeLogs();
  }, [loadChangeLogs]);

  const handleRestore = async (entry: ChangeLogEntry) => {
    setPendingId(entry.id);
    setStatus(null);
    try {
      const ok = await restoreFromLog(entry.id);
      setStatus(ok ? 'Restored.' : 'Could not restore (entity may no longer exist).');
    } catch (err) {
      setStatus(`Restore failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setPendingId(null);
      window.setTimeout(() => setStatus(null), 3000);
    }
  };

  return (
    <div className="space-y-3">
      <SectionHeading className="mb-0 flex items-center gap-1.5 text-caption">
        <History size={12} />
        Change log
      </SectionHeading>

      {status && <Banner tone="neutral">{status}</Banner>}

      {changeLogs.length === 0 ? (
        <div className="text-xs text-muted-foreground">No changes recorded yet.</div>
      ) : (
        <ol className="relative ml-1 border-l border-border pl-4">
          {changeLogs.map((entry) => (
            <li key={entry.id} className="relative py-2 first:pt-0 last:pb-0">
              <span
                className="absolute -left-[21px] top-2.5 h-2 w-2 rounded-full ring-2 ring-card first:top-1"
                style={{ backgroundColor: entry.userColor ?? 'hsl(var(--muted-foreground))' }}
                aria-hidden
              />
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="text-xs leading-snug break-words">{entry.summary}</div>
                  <div className="mt-1 flex flex-wrap items-center gap-x-1.5 text-meta text-muted-foreground">
                    {entry.userName && <span>{entry.userName}</span>}
                    {entry.userName && <span aria-hidden>·</span>}
                    <span title={new Date(entry.timestamp).toLocaleString()}>{formatTimeAgo(entry.timestamp)}</span>
                  </div>
                </div>
                {entry.reversible && entry.action !== 'restore' && (
                  <Button
                    variant="outline"
                    size="sm"
                    icon={<Undo2 size={11} />}
                    className="px-2 py-0.5 text-meta"
                    onClick={() => void handleRestore(entry)}
                    disabled={pendingId === entry.id}
                    title="Restore to the previous value"
                  >
                    Undo
                  </Button>
                )}
              </div>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function formatTimeAgo(ts: number): string {
  const diff = Date.now() - ts;
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
