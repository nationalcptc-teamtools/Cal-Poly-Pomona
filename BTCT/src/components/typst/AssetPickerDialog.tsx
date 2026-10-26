// ─────────────────────────────────────────────────────────────────────────
// Pick an image asset: the "Add screenshot" window of a finding's
// exploitation step.
//
// A thumbnail grid of the workspace's images (the same store records, the
// same lazily fetched thumbnails as the Assets panel), filtered by folder and
// by a search over file names, plus an upload button for a screenshot that
// is not in the workspace yet. Pasting a copied asset link (`btct-asset:<id>`)
// anywhere in the window picks that asset.
//
// Lives under components/typst/ and is only reached from the lazy Findings
// mode, so it costs the shell bundle nothing (invariant 17).
// ─────────────────────────────────────────────────────────────────────────

import { memo, useCallback, useMemo, useRef, useState } from 'react';
import { AlertTriangle, Folder, ImagePlus, Loader2, Search, Upload } from 'lucide-react';
import { useAppStore } from '@/stores';
import type { AssetFolder, ID, TypstAsset } from '@/types';
import { Dialog } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Field';
import { Banner } from '@/components/ui/Banner';
import { childFolders } from '@/lib/asset-folders';
import { parseAssetLinkList } from '@/lib/asset-link';
import { useAssetPreview, useNearViewport } from '@/components/assets/use-asset-preview';
import { cn } from '@/lib/utils';

type FolderPick = 'all' | ID | null;

const IMAGE_ACCEPT = 'image/png,image/jpeg,image/gif,image/webp,image/svg+xml';

/** Folders in tree order with their depth, for an indented list. */
function flattenFolders(folders: AssetFolder[], parent: ID | null = null, depth = 0, out: { f: AssetFolder; depth: number }[] = []) {
  for (const f of childFolders(folders, parent)) {
    out.push({ f, depth });
    if (depth < 12) flattenFolders(folders, f.id, depth + 1, out);
  }
  return out;
}

const PickCard = memo(function PickCard({ asset, onPick }: { asset: TypstAsset; onPick: (a: TypstAsset) => void }) {
  const ref = useRef<HTMLButtonElement | null>(null);
  const near = useNearViewport(ref);
  const { url, error } = useAssetPreview(asset, near);
  return (
    <button
      ref={ref}
      type="button"
      onClick={() => onPick(asset)}
      title={`Use ${asset.filename}`}
      data-pick-asset={asset.filename}
      className="group overflow-hidden rounded border border-border bg-muted/30 text-left hover:border-primary focus-visible:border-primary"
    >
      <span className="block h-24 w-full">
        {error ? (
          <span className="flex h-full items-center justify-center gap-1 text-caption text-status-red">
            <AlertTriangle size={11} /> missing
          </span>
        ) : url ? (
          <img src={url} alt={asset.filename} loading="lazy" decoding="async" className="h-full w-full object-contain" />
        ) : (
          <span className="flex h-full items-center justify-center">
            <Loader2 size={13} className="animate-spin text-muted-foreground" />
          </span>
        )}
      </span>
      <span className="block truncate border-t border-border px-1.5 py-1 font-mono text-micro text-muted-foreground group-hover:text-foreground">
        {asset.filename}
      </span>
    </button>
  );
});

export function AssetPickerDialog({
  title = 'Add screenshot',
  onPick,
  onClose,
}: {
  title?: string;
  onPick: (asset: TypstAsset) => void;
  onClose: () => void;
}) {
  const assets = useAppStore((s) => s.typstAssets);
  const folders = useAppStore((s) => s.assetFolders);
  const addTypstAsset = useAppStore((s) => s.addTypstAsset);
  const [query, setQuery] = useState('');
  const [folder, setFolder] = useState<FolderPick>('all');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  const images = useMemo(() => assets.filter((a) => a.kind === 'image' && !a.deletedAt), [assets]);
  const tree = useMemo(() => flattenFolders(folders), [folders]);
  const counts = useMemo(() => {
    const m = new Map<string, number>();
    for (const a of images) m.set(a.folderId ?? '', (m.get(a.folderId ?? '') ?? 0) + 1);
    return m;
  }, [images]);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    // A search looks in every folder: the operator remembers a name, not where it was filed.
    const inFolder = q || folder === 'all' ? images : images.filter((a) => (a.folderId ?? null) === folder);
    const hits = q ? inFolder.filter((a) => a.filename.toLowerCase().includes(q)) : inFolder;
    return [...hits].sort((a, b) => b.createdAt - a.createdAt);
  }, [images, folder, query]);

  const pick = useCallback((a: TypstAsset) => onPick(a), [onPick]);

  const upload = useCallback(async (files: FileList) => {
    const list = [...files];
    if (list.length === 0) return;
    setBusy(true);
    setError(null);
    const target = folder === 'all' ? null : folder;
    let first: TypstAsset | null = null;
    const failures: string[] = [];
    for (const file of list) {
      try {
        const created = await addTypstAsset(file, 'image', target);
        first ??= created;
      } catch (e) {
        failures.push(`${file.name}: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
    setBusy(false);
    if (failures.length) setError(failures.join('\n'));
    // One file: that is the screenshot the operator meant. Several: let them pick.
    if (first && list.length === 1) onPick(first);
  }, [addTypstAsset, folder, onPick]);

  // Paste a copied asset link anywhere in the window to pick it.
  const onPaste = useCallback((e: React.ClipboardEvent) => {
    const ids = parseAssetLinkList(e.clipboardData.getData('text/plain'));
    if (!ids) return;
    const hit = images.find((a) => a.id === ids[0]);
    e.preventDefault();
    if (hit) onPick(hit);
    else setError('That link points to an asset that is not in this workspace.');
  }, [images, onPick]);

  const folderButton = (key: FolderPick, label: string, count: number, depth = 0, icon = <Folder size={12} className="shrink-0 text-status-amber" />) => (
    <button
      key={key ?? 'root'}
      type="button"
      onClick={() => setFolder(key)}
      aria-pressed={folder === key}
      className={cn(
        'flex w-full items-center gap-1.5 rounded px-1.5 py-1 text-left text-meta hover:bg-accent',
        folder === key && !query.trim() && 'bg-accent text-foreground',
      )}
      style={{ paddingLeft: `${6 + depth * 12}px` }}
    >
      {icon}
      <span className="min-w-0 flex-1 truncate">{label}</span>
      {count > 0 && <span className="shrink-0 font-mono text-micro text-muted-foreground">{count}</span>}
    </button>
  );

  return (
    <Dialog
      title={title}
      icon={<ImagePlus size={14} />}
      onClose={onClose}
      size="xl"
      initialFocus={searchRef}
      bodyClassName="p-0"
      footer={
        <div className="flex w-full items-center justify-between gap-2">
          <span className="text-caption text-muted-foreground">
            Tip: Copy link on any image in the Assets tab, then paste it here or into a step.
          </span>
          <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
        </div>
      }
    >
      <div className="flex h-[min(70vh,560px)] min-h-0 flex-col" onPaste={onPaste}>
        <div className="flex shrink-0 items-center gap-2 border-b border-border px-3 py-2">
          <div className="relative flex-1">
            <Search size={12} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <Input
              ref={searchRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search images by file name"
              aria-label="Search images"
              className="pl-6"
            />
          </div>
          <Button
            variant="outline"
            size="sm"
            icon={busy ? <Loader2 size={12} className="animate-spin" /> : <Upload size={12} />}
            onClick={() => fileRef.current?.click()}
            disabled={busy}
            title="Upload a new screenshot into the selected folder"
          >
            Upload
          </Button>
          <input
            ref={fileRef}
            type="file"
            multiple
            accept={IMAGE_ACCEPT}
            className="hidden"
            onChange={(e) => {
              if (e.target.files) void upload(e.target.files);
              e.target.value = '';
            }}
          />
        </div>
        {error && (
          <Banner tone="red" flush onDismiss={() => setError(null)} className="shrink-0">
            <span className="whitespace-pre-wrap break-words">{error}</span>
          </Banner>
        )}
        <div className="flex min-h-0 flex-1">
          <nav aria-label="Folders" className="w-48 shrink-0 space-y-0.5 overflow-y-auto border-r border-border p-2">
            {folderButton('all', 'All images', images.length, 0, <ImagePlus size={12} className="shrink-0 text-muted-foreground" />)}
            {tree.length > 0 && folderButton(null, 'Not in a folder', counts.get('') ?? 0)}
            {tree.map(({ f, depth }) => folderButton(f.id, f.name, counts.get(f.id) ?? 0, depth))}
          </nav>
          <div className="min-h-0 flex-1 overflow-y-auto p-2">
            {shown.length > 0 ? (
              <div className="grid gap-1.5" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))' }}>
                {shown.map((a) => <PickCard key={a.id} asset={a} onPick={pick} />)}
              </div>
            ) : (
              <p className="p-4 text-center text-caption text-muted-foreground">
                {images.length === 0
                  ? 'No images in this workspace yet. Upload a screenshot, or drop one on the Assets tab.'
                  : query.trim()
                    ? 'No image name matches that search.'
                    : 'No images in this folder.'}
              </p>
            )}
          </div>
        </div>
      </div>
    </Dialog>
  );
}
