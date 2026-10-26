import { pollWhileVisible } from '@/lib/visible-poll';
import { useCallback, useEffect, useState } from 'react';
import { Clock, History, Save, X } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Field';
import { Banner } from '@/components/ui/Banner';
import { SectionHeading } from '@/components/ui/Panel';
import { useAppStore } from '@/stores';
import { createVersion, listVersions, type VersionListResponse } from '@/realtime/page-history-api';
import { formatVersionTime, dayLabel, versionLabel } from '@/lib/page-history';

/**
 * Properties-panel entry point for a page's version history: a one-line
 * summary of the latest version, a "save a named version" field, and the
 * button that opens the full History tab (viewer + timeline + restore).
 */
export function PageHistoryPanel({ pageId }: { pageId: string }) {
  const page = useAppStore((s) => s.pages.find((p) => p.id === pageId));
  const openTab = useAppStore((s) => s.openTab);
  const closeTab = useAppStore((s) => s.closeTab);
  // The History tab for this page, if open: the button below toggles it.
  const historyTab = useAppStore((s) => s.tabs.find((t) => t.kind === 'history' && t.entityId === pageId));
  const [data, setData] = useState<VersionListResponse | null>(null);
  const [label, setLabel] = useState('');
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  const refresh = useCallback(() => {
    return listVersions(pageId).then(setData).catch(() => setData(null));
  }, [pageId]);

  useEffect(() => {
    return pollWhileVisible(refresh, 60_000);
  }, [refresh]);

  const flash = (msg: string) => {
    setStatus(msg);
    window.setTimeout(() => setStatus(null), 3000);
  };

  const saveNamed = async () => {
    setBusy(true);
    try {
      await createVersion(pageId, { name: label.trim() || null, trigger: 'named' });
      setLabel('');
      flash('Version saved.');
      refresh();
    } catch (err) {
      flash(`Save failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const openHistory = () => {
    openTab({
      id: `history:${pageId}`,
      kind: 'history',
      entityId: pageId,
      title: `History: ${page?.title ?? 'page'}`,
    });
  };

  const latest = data?.versions[0] ?? null;
  const count = data?.versions.length ?? 0;
  const latestUser = latest ? data?.users[String(latest.changedBy[0] ?? latest.createdBy ?? 0)] : null;

  return (
    <div className="space-y-3">
      <SectionHeading className="mb-0 flex items-center gap-1.5 text-caption">
        <Clock size={12} />
        Page Versions
      </SectionHeading>

      <div className="text-xs text-muted-foreground">
        {latest ? (
          <>
            <span className="text-foreground">{count} version{count === 1 ? '' : 's'}</span>
            <span aria-hidden> · </span>
            latest {versionLabel(latest).toLowerCase()} {dayLabel(latest.createdAt).toLowerCase()} at {formatVersionTime(latest.createdAt)}
            {latestUser && (
              <>
                {' '}by{' '}
                <span className="inline-flex items-center gap-1 text-foreground">
                  <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: latestUser.color }} aria-hidden />
                  {latestUser.username}
                </span>
              </>
            )}
          </>
        ) : (
          'No versions yet. One is recorded about two minutes after editing stops.'
        )}
      </div>

      <div className="flex items-center gap-2">
        <Input
          type="text"
          aria-label="Version name"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && !busy) void saveNamed(); }}
          placeholder="Name this version"
          className="min-w-0 flex-1"
        />
        <Button variant="outline" size="sm" icon={<Save size={12} />} onClick={() => void saveNamed()} disabled={busy} title="Save the current page body as a named version">
          Save
        </Button>
      </div>

      <Button
        variant="outline"
        size="sm"
        className="w-full"
        icon={historyTab ? <X size={13} /> : <History size={13} />}
        onClick={historyTab ? () => closeTab(historyTab.id) : openHistory}
      >
        {historyTab ? 'Close version history' : 'Open version history'}
      </Button>

      {status && <Banner tone="neutral">{status}</Banner>}
    </div>
  );
}
