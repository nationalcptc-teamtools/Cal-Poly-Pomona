// ─────────────────────────────────────────────────────────────────────────
// "Import report": pick a ZIP, a folder or a .typ, choose one report when
// the input holds several (a GitHub "Download ZIP" of a templates repo),
// confirm what will change, then upload the fonts and images and replace
// the source. Decisions are pure (lib/typst-report-bundle.ts), the I/O is
// report-bundle-io.ts; this file is only the dialog's stages.
// ─────────────────────────────────────────────────────────────────────────

import { useCallback, useEffect, useRef, useState } from 'react';
import { FileUp, FolderOpen, Upload } from 'lucide-react';
import { Dialog } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/utils';
import type { TypstAsset } from '@/types';
import { baseName, candidateDisplayNames } from '@/lib/typst-report-bundle';
import {
  filesFromInput,
  openBundle,
  prepareImport,
  readDroppedItems,
  runImport,
  type ImportCallbacks,
  type ImportResult,
  type PreparedImport,
  type ReportBundle,
} from './report-bundle-io';

type Stage =
  | { kind: 'pick' }
  | { kind: 'reading' }
  | { kind: 'choose'; bundle: ReportBundle; index: number }
  | { kind: 'confirm'; prepared: PreparedImport }
  | { kind: 'running'; done: number; total: number };

export interface ReportImportDialogProps {
  assets: TypstAsset[];
  callbacks: Omit<ImportCallbacks, 'onProgress'>;
  onClose: () => void;
  onDone: (result: ImportResult, prepared: PreparedImport) => void;
}

export function ReportImportDialog({ assets, callbacks, onClose, onDone }: ReportImportDialogProps) {
  const [stage, setStage] = useState<Stage>({ kind: 'pick' });
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const folderRef = useRef<HTMLInputElement>(null);
  const assetsRef = useRef(assets);
  assetsRef.current = assets;

  // React has no typed prop for these; set them on the element.
  useEffect(() => {
    const el = folderRef.current;
    if (el) { el.setAttribute('webkitdirectory', ''); el.setAttribute('directory', ''); }
  }, [stage.kind]);

  const prepare = useCallback(async (bundle: ReportBundle, index: number) => {
    setStage({ kind: 'reading' });
    setError(null);
    try {
      const prepared = await prepareImport(bundle, bundle.candidates[index]!, assetsRef.current);
      setStage({ kind: 'confirm', prepared });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStage(bundle.candidates.length > 1 ? { kind: 'choose', bundle, index } : { kind: 'pick' });
    }
  }, []);

  const open = useCallback(async (name: string, files: { file: File; path: string }[]) => {
    if (!files.length) return;
    setStage({ kind: 'reading' });
    setError(null);
    try {
      const bundle = await openBundle(name, files);
      if (bundle.candidates.length === 1) await prepare(bundle, 0);
      else setStage({ kind: 'choose', bundle, index: 0 });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStage({ kind: 'pick' });
    }
  }, [prepare]);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const dt = e.dataTransfer;
    void (async () => {
      try {
        const files = await readDroppedItems(dt);
        const first = files[0]?.path ?? 'dropped files';
        await open(first.includes('/') ? first.slice(0, first.indexOf('/')) : first, files);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      }
    })();
  }, [open]);

  const confirm = useCallback(async (prepared: PreparedImport) => {
    setStage({ kind: 'running', done: 0, total: prepared.plan.length });
    const result = await runImport(prepared, {
      ...callbacks,
      onProgress: (done, total) => setStage({ kind: 'running', done, total }),
    });
    onDone(result, prepared);
  }, [callbacks, onDone]);

  const busy = stage.kind === 'running' || stage.kind === 'reading';

  let body: React.ReactNode;
  let footer: React.ReactNode;
  if (stage.kind === 'pick' || stage.kind === 'reading') {
    body = (
      <div
        data-report-dropzone
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={cn(
          'flex flex-col items-center gap-3 rounded-lg border border-dashed border-border px-4 py-8 text-center',
          dragging && 'border-primary bg-primary/10',
        )}
      >
        <Upload size={20} className="text-muted-foreground" />
        <div className="text-xs text-muted-foreground">
          {stage.kind === 'reading'
            ? 'Reading…'
            : 'Drop a report ZIP, a report folder or a .typ file here, or choose one.'}
        </div>
        <div className="flex flex-wrap justify-center gap-2">
          <Button variant="outline" icon={<FileUp size={13} />} disabled={busy} onClick={() => fileRef.current?.click()}>
            ZIP or .typ file
          </Button>
          <Button variant="outline" icon={<FolderOpen size={13} />} disabled={busy} onClick={() => folderRef.current?.click()}>
            Folder
          </Button>
        </div>
        <div className="text-caption text-muted-foreground">
          A GitHub "Download ZIP" works as it is: when it holds several reports you pick one. The report's
          fonts/ and assets/ folders come with it.
        </div>
        <input
          ref={fileRef}
          type="file"
          accept=".zip,.typ,application/zip"
          className="hidden"
          data-report-file-input
          onChange={(e) => {
            const list = e.target.files;
            if (list?.length) void open(list[0]!.name, filesFromInput(list).map((f) => ({ ...f, path: f.file.name })));
            e.target.value = '';
          }}
        />
        <input
          ref={folderRef}
          type="file"
          multiple
          className="hidden"
          data-report-folder-input
          onChange={(e) => {
            const list = e.target.files;
            if (list?.length) {
              const files = filesFromInput(list);
              const first = files[0]!.path;
              void open(first.includes('/') ? first.slice(0, first.indexOf('/')) : 'folder', files);
            }
            e.target.value = '';
          }}
        />
      </div>
    );
    footer = <Button variant="ghost" onClick={onClose} disabled={busy}>Cancel</Button>;
  } else if (stage.kind === 'choose') {
    const { bundle, index } = stage;
    const names = candidateDisplayNames(bundle.candidates);
    body = (
      <div>
        <div className="mb-2 text-xs text-muted-foreground">
          {bundle.name} holds {bundle.candidates.length} reports. Choose the one to import:
        </div>
        <div role="radiogroup" aria-label="Report to import" className="max-h-80 overflow-y-auto rounded-md border border-border">
          {bundle.candidates.map((c, i) => (
            <label
              key={c.mainPath}
              className={cn(
                'flex cursor-pointer items-start gap-2 border-b border-border px-3 py-2 last:border-b-0 hover:bg-accent',
                i === index && 'bg-primary/10',
              )}
            >
              <input
                type="radio"
                name="report-candidate"
                className="mt-0.5"
                checked={i === index}
                onChange={() => setStage({ kind: 'choose', bundle, index: i })}
              />
              <span className="min-w-0">
                <span className="block text-xs font-medium text-foreground">{names[i]}</span>
                <span className="block truncate text-caption text-muted-foreground" title={c.mainPath}>{c.mainPath}</span>
              </span>
            </label>
          ))}
        </div>
      </div>
    );
    footer = (
      <>
        <Button variant="ghost" onClick={() => setStage({ kind: 'pick' })}>Back</Button>
        <Button variant="primary" onClick={() => void prepare(bundle, index)}>Continue</Button>
      </>
    );
  } else if (stage.kind === 'confirm') {
    body = <ImportSummary prepared={stage.prepared} />;
    footer = (
      <>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" data-report-import-confirm onClick={() => void confirm(stage.prepared)}>
          Replace report and import
        </Button>
      </>
    );
  } else {
    body = (
      <div className="py-6 text-center text-xs text-muted-foreground">
        Uploading {stage.done} of {stage.total}…
      </div>
    );
    footer = null;
  }

  return (
    <Dialog
      title="Import report"
      icon={<FileUp size={14} />}
      onClose={onClose}
      size="lg"
      dismissible={!busy}
      footer={footer}
    >
      {error && (
        <div role="alert" className="mb-3 rounded-md bg-status-red/10 px-3 py-2 text-xs text-status-red">
          {error}
        </div>
      )}
      {body}
    </Dialog>
  );
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** What the confirm stage says: everything that will change, before it does. */
function ImportSummary({ prepared }: { prepared: PreparedImport }) {
  const { plan, selection, candidate, source, unresolved, fromWorkspace, duplicateFonts } = prepared;
  const fonts = plan.filter((p) => p.kind === 'font');
  const images = plan.filter((p) => p.kind === 'image');
  const upFonts = fonts.filter((p) => p.action !== 'reuse');
  const upImages = images.filter((p) => p.action !== 'reuse');
  const reused = plan.filter((p) => p.action === 'reuse');
  const renamed = plan.filter((p) => p.action === 'upload-renamed');
  const lines = source.split('\n').length;
  return (
    <div className="space-y-3 text-xs" data-report-import-summary>
      <div className="rounded-md bg-status-amber/10 px-3 py-2 text-foreground">
        The report source will be <strong>replaced</strong> by <span className="font-mono">{candidate.mainPath}</span> ({plural(lines, 'line')}).
        Undo in the code editor (Ctrl/⌘+Z) brings the old one back.
      </div>
      <ul className="list-disc space-y-1 pl-5 text-foreground">
        <li>{plural(upFonts.length, 'font')} and {plural(upImages.length, 'image')} will be uploaded to this workspace's assets.</li>
        {reused.length > 0 && (
          <li>
            {plural(reused.length, 'file')} already in the workspace with the same name and bytes, not uploaded again:{' '}
            <span className="font-mono">{reused.map((p) => p.name).join(', ')}</span>.
          </li>
        )}
        {duplicateFonts.length > 0 && (
          <li>{plural(duplicateFonts.length, 'font')} skipped as copies of another font in the import.</li>
        )}
      </ul>
      {renamed.length > 0 && (
        <div>
          <div className="mb-1 font-medium text-foreground">Same name, different file</div>
          <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
            {renamed.map((p) => (
              <li key={p.path}>
                <span className="font-mono">{p.wanted}</span>: {p.keptId ? 'the workspace already has a different file of this name. It is kept as it is' : 'another file of the import has this name'};
                the imported one is uploaded as <span className="font-mono text-foreground">{p.name}</span>
                {p.kind === 'image' ? ' and the report is pointed at it.' : '.'}
              </li>
            ))}
          </ul>
        </div>
      )}
      {(unresolved.length > 0 || fromWorkspace.length > 0) && (
        <div>
          <div className="mb-1 font-medium text-foreground">Images the report names that the import does not hold</div>
          <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
            {fromWorkspace.map((p) => <li key={p}><span className="font-mono">{p}</span>: uses the workspace's existing asset.</li>)}
            {unresolved.map((p) => <li key={p}><span className="font-mono">{p}</span>: not found; the preview reports it until you upload it.</li>)}
          </ul>
        </div>
      )}
      {(selection.ignored.length > 0 || selection.outside > 0) && (
        <details className="text-muted-foreground">
          <summary className="cursor-pointer">
            Not imported: {plural(selection.ignored.length, 'file')}
            {selection.outside > 0 ? `, plus ${plural(selection.outside, 'file')} outside this report's folder` : ''}
          </summary>
          <ul className="mt-1 max-h-40 list-disc space-y-0.5 overflow-y-auto pl-5">
            {selection.ignored.map((f) => (
              <li key={f.path}><span className="font-mono" title={f.path}>{baseName(f.path) || f.path}</span>: {f.reason}</li>
            ))}
          </ul>
        </details>
      )}
      {plan.length > 0 && (
        <details className="text-muted-foreground">
          <summary className="cursor-pointer">Files to import ({plan.length})</summary>
          <ul className="mt-1 max-h-40 list-disc space-y-0.5 overflow-y-auto pl-5 font-mono">
            {plan.map((p) => <li key={p.path} title={p.path}>{p.name}{p.action === 'reuse' ? ' (already there)' : ''}</li>)}
          </ul>
        </details>
      )}
    </div>
  );
}
