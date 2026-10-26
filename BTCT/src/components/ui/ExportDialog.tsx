import { useEffect, useState } from 'react';
import { useAppStore } from '@/stores';
import { useShallow } from 'zustand/react/shallow';
import { listWorkspacesInZip, importStatus, pagesMarkdownArchive, REPLACE_BODY_NOTE } from '@/export';
import type { ImportMode } from '@/export';
import { exportStatusMany, exportWorkspacesFromApp, importWorkspaceIntoApp } from '@/export/export-workspace';
import { downloadBlob } from '@/lib/download';
import { Download, Upload } from 'lucide-react';
import { Dialog } from '@/components/ui/Dialog';
import { SectionHeading } from '@/components/ui/Panel';
import { AskWhereToSaveToggle, FirefoxSaveHint } from '@/components/ui/SaveLocationSetting';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Field';
import { Banner } from '@/components/ui/Banner';
import { cn } from '@/lib/utils';

export function ExportDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const {
    pages, workspaces, activeWorkspaceId,
    loadWorkspaces, setActiveWorkspace, loadPages, loadChangeLogs, loadNmapScans, loadTypstAssets, loadAssetFolders,
  } = useAppStore(useShallow((s) => ({
    pages: s.pages,
    workspaces: s.workspaces,
    activeWorkspaceId: s.activeWorkspaceId,
    loadWorkspaces: s.loadWorkspaces,
    setActiveWorkspace: s.setActiveWorkspace,
    loadPages: s.loadPages,
    loadChangeLogs: s.loadChangeLogs,
    loadNmapScans: s.loadNmapScans,
    loadTypstAssets: s.loadTypstAssets,
    loadAssetFolders: s.loadAssetFolders,
  })));
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const [importMode, setImportMode] = useState<ImportMode>('new');
  const [selected, setSelected] = useState<string[]>([]);

  // The active workspace is pre-checked each time the dialog opens.
  useEffect(() => {
    if (open) setSelected(activeWorkspaceId ? [activeWorkspaceId] : []);
    // Only on open: later active-workspace changes must not undo the user's picks.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  if (!open) return null;

  // Only workspaces that still exist count (one may have been deleted since).
  const selectedIds = workspaces.filter((w) => selected.includes(w.id)).map((w) => w.id);

  const handleExportPagesMarkdown = async () => {
    const visiblePages = pages.filter((p) => !p.isGraphPage);
    if (visiblePages.length === 0) { setStatus('No pages to export'); return; }
    const ws = workspaces.find((w) => w.id === activeWorkspaceId);
    const { blob, fileName, files } = await pagesMarkdownArchive(visiblePages, { id: activeWorkspaceId ?? '', name: ws?.name ?? 'Workspace' });
    if (await downloadBlob(blob, fileName, 'application/zip') === 'cancelled') { setStatus('Export cancelled.'); return; }
    setStatus(`Exported ${files} page${files === 1 ? '' : 's'} as markdown (${fileName}).`);
  };

  // The workspace archive: a browsable notes and images tree plus the
  // lossless `.btct/` copy another server imports. Several workspaces go
  // into one ZIP, one root folder each.
  const handleExportWorkspaces = async () => {
    const ids = selectedIds;
    if (ids.length === 0) { setStatus('No workspace selected'); return; }
    setBusy(true);
    try {
      const { blob, reports, fileName, notes, failed } = await exportWorkspacesFromApp(ids, setStatus);
      if (await downloadBlob(blob, fileName, 'application/zip') === 'cancelled') { setStatus('Export cancelled.'); return; }
      setStatus([exportStatusMany(reports, notes), ...failed.map((f) => `${f.name}: not exported, ${f.error}`)].join('\n'));
    } catch (err) {
      setStatus(`Export failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const toggleWorkspace = (id: string, on: boolean) =>
    setSelected((cur) => (on ? (cur.includes(id) ? cur : [...cur, id]) : cur.filter((x) => x !== id)));

  const handleImportWorkspace = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.zip';
    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) return;
      setBusy(true);
      setStatus('Reading import…');
      try {
        const all = await listWorkspacesInZip(file);
        const lines: string[] = [];
        let single = '';
        let firstId: string | null = null;
        let okCount = 0;
        const doneIds = new Set<string>();
        // Sequential, one workspace parsed and released at a time; a failure
        // does not stop the rest. A single workspace still throws.
        for (let i = 0; i < all.length; i++) {
          const entry = all[i]!;
          let name = entry.root || 'Workspace';
          try {
            const data = await entry.parse();
            name = data.workspace.name || name;
            if (importMode === 'replace' && all.length > 1 && doneIds.has(data.workspace.id)) {
              lines.push(`${name}: skipped, same workspace as an earlier folder in this ZIP`);
              continue;
            }
            doneIds.add(data.workspace.id);
            const prefix = all.length > 1 ? `${name} (${i + 1}/${all.length}): ` : '';
            const report = await importWorkspaceIntoApp(data, importMode, (m) => setStatus(`${prefix}${m}`));
            okCount++;
            firstId ??= report.workspaceId;
            single = importStatus(report);
            lines.push(`${name}: ${single}`);
          } catch (err) {
            if (all.length === 1) throw err;
            lines.push(`${name}: failed, ${err instanceof Error ? err.message : 'Unknown error'}`);
          }
        }
        await loadWorkspaces();
        if (firstId) setActiveWorkspace(firstId);
        await Promise.all([loadPages(), loadNmapScans(), loadChangeLogs(), loadTypstAssets(), loadAssetFolders()]);
        if (all.length === 1) setStatus(single);
        else {
          const head = okCount === all.length
            ? `Imported ${okCount} workspaces:`
            : `Import finished: ${okCount} of ${all.length} workspaces imported:`;
          setStatus(`${head}\n${lines.join('\n')}`);
        }
      } catch (err) {
        setStatus(`Import failed: ${err instanceof Error ? err.message : 'Unknown error'}`);
      } finally {
        setBusy(false);
      }
    };
    input.click();
  };

  const row = 'w-full justify-start py-2 text-xs font-normal';
  return (
    <Dialog title="Export / Import" onClose={onClose} dismissible={!busy} size="lg" className="max-w-[560px]">
      <div className="space-y-3">
        <SectionHeading className="mb-0">Export</SectionHeading>
        <Button variant="outline" icon={<Download size={14} />} disabled={busy} onClick={() => void handleExportPagesMarkdown()} className={row}>
          All Pages → Markdown
        </Button>

        <div role="group" aria-label="Workspaces to export" className="rounded-md border border-border p-2">
          <div className="mb-1.5 flex items-center gap-3 text-xs">
            <span className="font-medium">Workspaces</span>
            <Button variant="ghost" size="sm" disabled={busy} onClick={() => setSelected(workspaces.map((w) => w.id))}>Select all</Button>
            <Button variant="ghost" size="sm" disabled={busy} onClick={() => setSelected([])}>None</Button>
          </div>
          <div className="max-h-40 space-y-1 overflow-auto text-xs">
            {workspaces.map((w) => (
              <Checkbox key={w.id} checked={selected.includes(w.id)} disabled={busy} onChange={(on) => toggleWorkspace(w.id, on)} label={<span className="truncate">{w.name || 'Untitled'}</span>} className="text-xs" />
            ))}
          </div>
        </div>

        <Button variant="outline" icon={<Download size={14} />} disabled={busy || selectedIds.length === 0} onClick={() => void handleExportWorkspaces()} className={cn(row, 'flex-wrap whitespace-normal text-left')}>
          Selected Workspaces → ZIP ({selectedIds.length}) <span className="ml-auto text-caption text-muted-foreground">(notes, images, command log; lossless)</span>
        </Button>

        <AskWhereToSaveToggle className="text-xs" />
        <FirefoxSaveHint />

        <div className="border-t border-border pt-3">
          <SectionHeading>Import</SectionHeading>
          <div role="radiogroup" aria-label="Import mode" className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
            <label className="flex cursor-pointer items-center gap-1.5">
              <input type="radio" name="importMode" checked={importMode === 'new'} onChange={() => setImportMode('new')} />
              Import as new (fresh ids, a separate copy)
            </label>
            <label className="flex cursor-pointer items-center gap-1.5" title={REPLACE_BODY_NOTE}>
              <input type="radio" name="importMode" checked={importMode === 'replace'} onChange={() => setImportMode('replace')} />
              Replace existing
            </label>
          </div>
          {importMode === 'replace' && (
            <p className="mb-2 text-meta text-muted-foreground">{REPLACE_BODY_NOTE}</p>
          )}
          <Button variant="outline" icon={<Upload size={14} />} disabled={busy} onClick={handleImportWorkspace} className={row}>
            Workspace ZIP
          </Button>
          <p className="mt-2 text-meta text-muted-foreground">A ZIP with several workspaces imports every workspace in it.</p>
        </div>
      </div>

      {status && <Banner tone="neutral" icon={false} className="mt-3 max-h-40 overflow-auto"><span className="whitespace-pre-wrap break-words">{status}</span></Banner>}
    </Dialog>
  );
}
