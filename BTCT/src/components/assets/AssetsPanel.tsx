// ─────────────────────────────────────────────────────────────────────────
// Assets browser: the screenshots a note can embed.
//
// Assets live in a folder hierarchy (engagement phase, host, whatever shape
// the work wants). Folders are organizational only: an image keeps its flat
// `/assets/<name>` path wherever it sits, so re-filing one never breaks a
// note that references it. The tree mirrors the sidebar's page tree.
//
// Clicking a thumbnail opens the crop-and-redact editor. Both are render-time
// metadata on the record, never baked into the upload, so the thumbnails show
// the cropped result while the original bytes stay recoverable.
//
// The same panel is the Typst report's assets rail, via the optional `typst`
// prop. With it set, a thumbnail opens the figure-placement dialog instead of
// the plain crop editor, each card gets an insert-at-the-caret button, font
// files become uploadable, and the layout stacks for a narrow rail. Without
// it (the Assets Manager tab) fonts are rejected exactly as they are today,
// and none of the Typst code is even downloaded: the dialog is a `lazy()`
// import and the font-family read happens in the report tab.
// ─────────────────────────────────────────────────────────────────────────

import { lazy, memo, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle, ChevronRight, Code2, Crop, EyeOff, FileType, Folder, FolderPlus, ImagePlus,
  Link2, Loader2, MapPin, Pencil, Plus, Trash2, Type, Upload,
} from 'lucide-react';
import { useAppStore } from '@/stores';
import type { AssetFolder, BlurRegion, CropRect, ID, TypstAsset, TypstAssetKind } from '@/types';
import type { ScreenshotSlot } from '@/lib/typst-placeholders';
import { hasBlurs } from '@/lib/blur-math';
import { assetsInFolder, childFolders, folderTrail, isDescendantFolder } from '@/lib/asset-folders';
import { assetPath, isFullFrame } from '@/lib/assets';
import { useAssetPreview, useNearViewport } from './use-asset-preview';
import { ImageEditorDialog } from './ImageEditorDialog';
import { Portal } from '@/components/ui/Portal';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Badge } from '@/components/ui/Badge';
import { useNarrowLayout } from '@/lib/use-layout-width';
import { Banner } from '@/components/ui/Banner';
import { Button, IconButton } from '@/components/ui/Button';
import { MenuItem, MenuSeparator, MenuSurface } from '@/components/ui/Menu';
import { assetLink, assetTypstSnippet } from '@/lib/asset-link';
import { copyText } from '@/lib/clipboard';
import { toLayoutPx } from '@/lib/ui-zoom';

// Lazy, and referenced only under `typst`: the Assets Manager tab must not
// pull the figure-placement dialog (and with it the Typst geometry and
// placeholder code) into its chunk. `ScreenshotSlot` above is a type-only
// import, so it is erased rather than linked.
const PlaceScreenshotDialog = lazy(() =>
  import('@/components/typst/PlaceScreenshotDialog').then((m) => ({ default: m.PlaceScreenshotDialog })),
);

/**
 * What the Typst report tab hands the panel to turn it into its assets rail.
 * Absent everywhere else, which is what keeps Typst code out of the Assets
 * Manager tab.
 *
 * Every source rewrite is a callback rather than something the panel does
 * itself: the report tab owns the source `Y.Text`, and it is the only place
 * that may write to it (invariant #3b).
 */
export interface TypstPanelMode {
  /** Live Typst source: the dialog reads the slots and page geometry from it. */
  source: string;
  /** Caption of the figure each asset path currently fills, keyed by path. */
  placements: ReadonlyMap<string, string>;
  /**
   * Put a snippet for this asset at the editor's caret: `#image(…)` for an
   * image, `#set text(font: …)` for a font.
   */
  onInsert: (asset: TypstAsset) => void;
  /**
   * Upload a font file. The report tab does it rather than the panel because
   * the family name comes from the Typst compiler, and reaching that from
   * here would pull the wasm engine into the Assets Manager tab's bundle.
   */
  onAddFont: (file: File, folderId: ID | null) => Promise<void>;
  /**
   * Commit the framing, and, when `slot` is set, write `path` into that slot
   * (`null` to empty it). `heightPt` is set when the figure's height changed,
   * `widthFraction` when its width did.
   */
  onPlace: (
    asset: TypstAsset,
    crop: CropRect | null,
    blurs: BlurRegion[] | null,
    slot: ScreenshotSlot | null,
    path: string | null,
    heightPt: number | null,
    widthFraction?: number | null,
  ) => void;
  /** Append a new empty figure slot to the document. */
  onAddSlot: (caption: string) => void;
  /** Rename the asset's file stem and repoint the document's references. */
  onRename: (asset: TypstAsset, stem: string) => void;
  /** Click-to-reveal from the preview: select + flash this asset. */
  reveal?: { id: ID; nonce: number } | null;
}

/** Drag payload types for moving things between folders. */
const ASSET_DRAG = 'application/x-btct-asset';
const FOLDER_DRAG = 'application/x-btct-asset-folder';

const IMAGE_ACCEPT = 'image/png,image/jpeg,image/gif,image/webp,image/svg+xml';
const FONT_ACCEPT = '.ttf,.otf,.woff,.woff2,.ttc';
const FONT_EXTS = ['.ttf', '.otf', '.woff', '.woff2', '.ttc'];

/**
 * Route a dropped file to the right asset kind, or null for one this panel
 * will not store. Fonts are only a kind in the report tab: the Assets Manager
 * has nothing to do with them, and the compiler is what reads their family.
 */
function kindForFile(file: File, fonts: boolean): TypstAssetKind | null {
  const name = file.name.toLowerCase();
  if (fonts && FONT_EXTS.some((e) => name.endsWith(e))) return 'font';
  if (file.type.startsWith('image/')) return 'image';
  if (/\.(png|jpe?g|gif|webp|svg)$/.test(name)) return 'image';
  return null;
}

// Memoized: a thumbnail only actually changes when its asset record does,
// so a re-render of the grid does not rebuild every <img> in it.
const ImageCard = memo(function ImageCard({
  asset,
  placedIn,
  flash,
  onOpen,
  onDelete,
  onInsert,
  onCopyLink,
  onContextMenu,
  onDragStartAsset,
  registerEl,
}: {
  asset: TypstAsset;
  /** Caption of the figure this image currently fills, if any (Typst mode). */
  placedIn: string | null;
  /** Pulse-highlight this card. */
  flash: boolean;
  // Take the asset as an argument rather than closing over it, so the parent
  // can pass one stable callback instead of minting a new closure per card on
  // every render, which would defeat the memo above entirely.
  onOpen: (asset: TypstAsset) => void;
  onDelete: (asset: TypstAsset) => void;
  /** Typst mode only: insert a reference to this image at the caret. */
  onInsert?: (asset: TypstAsset) => void;
  /** Copy the asset's internal link (`btct-asset:<id>`). */
  onCopyLink: (asset: TypstAsset) => void;
  /** Right-click: open the card's menu at the pointer. */
  onContextMenu: (e: React.MouseEvent, asset: TypstAsset) => void;
  onDragStartAsset: (e: React.DragEvent, asset: TypstAsset) => void;
  registerEl: (id: ID, el: HTMLDivElement | null) => void;
}) {
  const cardRef = useRef<HTMLDivElement | null>(null);
  const near = useNearViewport(cardRef);
  const { url, error } = useAssetPreview(asset, near);
  const cropped = !isFullFrame(asset.crop);
  const blurred = hasBlurs(asset.blurs);

  return (
    <div
      ref={(el) => { cardRef.current = el; registerEl(asset.id, el); }}
      draggable
      onDragStart={(e) => onDragStartAsset(e, asset)}
      onContextMenu={(e) => onContextMenu(e, asset)}
      data-asset-card={asset.id}
      className={`group relative overflow-hidden rounded border border-border bg-muted/30 ${flash ? 'asset-flash' : ''}`}
    >
      <button
        onClick={() => onOpen(asset)}
        title={placedIn ? `Placed in "${placedIn}": click to re-crop or move` : `Crop or redact ${asset.filename}`}
        className="block h-20 w-full"
      >
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
      </button>

      <div className="pointer-events-none absolute left-1 top-1 flex flex-col items-start gap-0.5">
        {cropped && <Badge tone="purple" solid><Crop size={8} /> cropped</Badge>}
        {blurred && <Badge tone="purple" solid><EyeOff size={8} /> redacted</Badge>}
        {placedIn && <Badge tone="primary" solid><MapPin size={8} /> placed</Badge>}
      </div>

      {/* Hover actions */}
      <div className="absolute right-1 top-1 flex gap-0.5 opacity-0 transition-opacity group-focus-within:opacity-100 group-hover:opacity-100">
        {onInsert && (
          <IconButton
            label="Insert #image(…) at the cursor"
            onClick={() => onInsert(asset)}
            className="bg-media text-media-foreground hover:bg-primary hover:text-primary-foreground"
          >
            <Plus size={11} />
          </IconButton>
        )}
        <IconButton
          label={`Copy link to ${asset.filename}`}
          title="Copy link (paste it into a finding's exploitation step, the report code or a note)"
          onClick={() => onCopyLink(asset)}
          className="bg-media text-media-foreground hover:bg-primary hover:text-primary-foreground"
        >
          <Link2 size={11} />
        </IconButton>
        <IconButton
          label={`Delete ${asset.filename}`}
          title="Delete asset"
          onClick={() => onDelete(asset)}
          className="bg-media text-media-foreground hover:bg-destructive hover:text-destructive-foreground"
        >
          <Trash2 size={11} />
        </IconButton>
      </div>

      <div
        className="truncate border-t border-border px-1.5 py-1 font-mono text-micro text-muted-foreground"
        title={placedIn ? `${assetPath(asset)}: in "${placedIn}"` : assetPath(asset)}
      >
        {placedIn ?? asset.filename}
      </div>
    </div>
  );
});

// Typst mode only: a font asset is a name and two actions, not a thumbnail.
const FontRow = memo(function FontRow({
  asset,
  onInsert,
  onDelete,
  onDragStartAsset,
}: {
  asset: TypstAsset;
  onInsert: (asset: TypstAsset) => void;
  onDelete: (asset: TypstAsset) => void;
  onDragStartAsset: (e: React.DragEvent, asset: TypstAsset) => void;
}) {
  return (
    <div
      draggable
      onDragStart={(e) => onDragStartAsset(e, asset)}
      className="group flex items-center gap-1.5 rounded border border-border bg-muted/30 px-2 py-1.5"
    >
      <Type size={12} className="shrink-0 text-status-purple" />
      <div className="min-w-0 flex-1">
        <div className="truncate text-meta text-foreground" title={asset.filename}>
          {asset.fontFamily || asset.filename}
        </div>
        {asset.fontFamily && (
          <div className="truncate font-mono text-micro text-muted-foreground">
            {asset.filename}
          </div>
        )}
      </div>
      <div className="flex shrink-0 gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
        <IconButton label="Insert #set text(font: …) at the cursor" disabled={!asset.fontFamily} onClick={() => onInsert(asset)}>
          <Plus size={11} />
        </IconButton>
        <IconButton label={`Delete font ${asset.filename}`} title="Delete font" tone="danger" onClick={() => onDelete(asset)}>
          <Trash2 size={11} />
        </IconButton>
      </div>
    </div>
  );
});

// ── Folder tree ──────────────────────────────────────────────────────────

interface FolderNodeProps {
  folder: AssetFolder;
  folders: AssetFolder[];
  selected: ID | null;
  expanded: Set<ID>;
  counts: Map<string, number>;
  renamingId: ID | null;
  onSelect: (id: ID | null) => void;
  onToggle: (id: ID) => void;
  onStartRename: (id: ID | null) => void;
  onCommitRename: (id: ID, name: string) => void;
  onNewSubfolder: (parentId: ID) => void;
  onDeleteFolder: (folder: AssetFolder) => void;
  onDropInto: (e: React.DragEvent, folderId: ID | null) => void;
}

function FolderNode(props: FolderNodeProps) {
  const {
    folder, folders, selected, expanded, counts, renamingId,
    onSelect, onToggle, onStartRename, onCommitRename, onNewSubfolder, onDeleteFolder, onDropInto,
  } = props;
  const [dragOver, setDragOver] = useState(false);
  const [draft, setDraft] = useState(folder.name);
  const inputRef = useRef<HTMLInputElement>(null);
  const kids = childFolders(folders, folder.id);
  const isExpanded = expanded.has(folder.id);
  const renaming = renamingId === folder.id;
  const count = counts.get(folder.id) ?? 0;

  useEffect(() => {
    if (renaming) {
      setDraft(folder.name);
      inputRef.current?.focus();
      inputRef.current?.select();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [renaming]);

  const acceptsDrag = (e: React.DragEvent) =>
    e.dataTransfer.types.includes(ASSET_DRAG) ||
    e.dataTransfer.types.includes(FOLDER_DRAG) ||
    e.dataTransfer.types.includes('Files');

  return (
    <div className="atree-item">
      <div
        draggable={!renaming}
        data-active={selected === folder.id || undefined}
        onDragStart={(e) => {
          e.dataTransfer.setData(FOLDER_DRAG, folder.id);
          e.dataTransfer.effectAllowed = 'move';
        }}
        onDragOver={(e) => { if (acceptsDrag(e)) { e.preventDefault(); e.stopPropagation(); setDragOver(true); } }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => { setDragOver(false); onDropInto(e, folder.id); }}
        className={`group/row flex w-full items-center rounded-lg border border-transparent hover:bg-accent ${
          selected === folder.id ? 'bg-accent' : ''
        } ${dragOver ? 'ring-2 ring-primary' : ''}`}
      >
        {kids.length > 0 ? (
          <IconButton
            size="sm"
            label={isExpanded ? `Collapse ${folder.name}` : `Expand ${folder.name}`}
            title={isExpanded ? 'Collapse' : 'Expand'}
            onClick={(e) => { e.stopPropagation(); onToggle(folder.id); }}
            className="ml-0.5"
          >
            <ChevronRight size={10} className={`transition-transform duration-150 ${isExpanded ? 'rotate-90' : ''}`} />
          </IconButton>
        ) : (
          <span className="ml-0.5 inline-block w-[14px] shrink-0" aria-hidden />
        )}
        {renaming ? (
          <div className="flex flex-1 items-center gap-1.5 px-1 py-1.5">
            <Folder size={12} className="shrink-0 text-status-amber" />
            <input
              ref={inputRef}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onBlur={() => onCommitRename(folder.id, draft)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') onCommitRename(folder.id, draft);
                if (e.key === 'Escape') onStartRename(null);
              }}
              className="min-w-0 flex-1 border-b border-primary bg-transparent text-meta outline-none"
            />
          </div>
        ) : (
          <button
            onClick={() => onSelect(folder.id)}
            onDoubleClick={() => onStartRename(folder.id)}
            className="flex min-w-0 flex-1 items-center gap-1.5 px-1 py-1.5 text-meta"
            title={`${folder.name}${count ? ` (${count} asset${count === 1 ? '' : 's'})` : ''}`}
          >
            <Folder size={12} className="shrink-0 text-status-amber" />
            <span className="truncate">{folder.name}</span>
            {count > 0 && (
              <span className="ml-auto shrink-0 rounded-full bg-muted px-1.5 font-mono text-micro text-muted-foreground">
                {count}
              </span>
            )}
          </button>
        )}
        {!renaming && (
          <div className="mr-1 flex shrink-0 gap-0.5 opacity-0 transition-opacity group-hover/row:opacity-100">
            <IconButton size="sm" label="New subfolder" onClick={() => onNewSubfolder(folder.id)}>
              <FolderPlus size={11} />
            </IconButton>
            <IconButton size="sm" label="Rename folder" onClick={() => onStartRename(folder.id)}>
              <Pencil size={11} />
            </IconButton>
            <IconButton size="sm" tone="danger" label="Delete folder (contents move up a level)" onClick={() => onDeleteFolder(folder)}>
              <Trash2 size={11} />
            </IconButton>
          </div>
        )}
      </div>

      {isExpanded && kids.length > 0 && (
        <div className="atree-kids">
          {kids.map((child) => (
            <FolderNode key={child.id} {...props} folder={child} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Panel ────────────────────────────────────────────────────────────────

export const AssetsPanel = memo(function AssetsPanel({ typst }: { typst?: TypstPanelMode }) {
  const assets = useAppStore((s) => s.typstAssets);
  const folders = useAppStore((s) => s.assetFolders);
  const addTypstAsset = useAppStore((s) => s.addTypstAsset);
  const deleteTypstAsset = useAppStore((s) => s.deleteTypstAsset);
  const setTypstAssetCrop = useAppStore((s) => s.setTypstAssetCrop);
  const renameTypstAsset = useAppStore((s) => s.renameTypstAsset);
  const createAssetFolder = useAppStore((s) => s.createAssetFolder);
  const renameAssetFolder = useAppStore((s) => s.renameAssetFolder);
  const moveAssetFolder = useAppStore((s) => s.moveAssetFolder);
  const deleteAssetFolder = useAppStore((s) => s.deleteAssetFolder);
  const moveTypstAssetToFolder = useAppStore((s) => s.moveTypstAssetToFolder);

  const [dragOver, setDragOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<TypstAsset | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Folder navigation. `null` is the root level.
  const [selectedFolder, setSelectedFolder] = useState<ID | null>(null);
  const [expanded, setExpanded] = useState<Set<ID>>(new Set());
  const [renamingId, setRenamingId] = useState<ID | null>(null);
  const [pendingDelete, setPendingDelete] = useState<AssetFolder | null>(null);
  const [pendingDeleteAsset, setPendingDeleteAsset] = useState<TypstAsset | null>(null);
  const [flashId, setFlashId] = useState<ID | null>(null);
  const cardEls = useRef(new Map<ID, HTMLDivElement>());

  // A folder deleted remotely (or a workspace switch) must not leave the
  // grid pointing at a ghost.
  useEffect(() => {
    if (selectedFolder && !folders.some((f) => f.id === selectedFolder)) setSelectedFolder(null);
  }, [folders, selectedFolder]);

  const live = useMemo(() => assets.filter((a) => !a.deletedAt), [assets]);
  const images = useMemo(
    () => assetsInFolder(live.filter((a) => a.kind === 'image'), selectedFolder),
    [live, selectedFolder],
  );
  // Only the report tab has a fonts section, but a workspace that predates
  // the Typst tab's removal may still hold font records, so the filter above
  // keeps them out of the image grid either way.
  const fonts = useMemo(
    () => assetsInFolder(live.filter((a) => a.kind === 'font'), selectedFolder),
    [live, selectedFolder],
  );
  const counts = useMemo(() => {
    const map = new Map<string, number>();
    for (const a of live) {
      const key = a.folderId ?? '';
      map.set(key, (map.get(key) ?? 0) + 1);
    }
    return map;
  }, [live]);
  const rootFolders = useMemo(() => childFolders(folders, null), [folders]);
  const trail = useMemo(() => folderTrail(folders, selectedFolder), [folders, selectedFolder]);

  // Present exactly when the panel is the report's rail, so it doubles as the
  // "are fonts a thing here" test and narrows for TypeScript.
  const onAddFont = typst?.onAddFont;

  const ingest = useCallback(
    async (files: FileList | File[], folderId: ID | null) => {
      const list = [...files];
      if (!list.length) return;
      setBusy(true);
      setError(null);
      const failures: string[] = [];
      let firstImage: TypstAsset | null = null;
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      // Sequential rather than parallel: filename de-duplication reads the
      // current asset list, so two concurrent uploads of `shot.png` would
      // both see the name as free and collide in the virtual FS.
      for (const file of list) {
        const kind = kindForFile(file, !!onAddFont);
        if (!kind) {
          failures.push(`${file.name}: ${onAddFont ? 'unsupported file type' : 'not an image'}`);
          continue;
        }
        try {
          if (kind === 'font' && onAddFont) {
            await onAddFont(file, folderId);
            continue;
          }
          const created = await addTypstAsset(file, 'image', folderId);
          if (!firstImage) firstImage = created;
        } catch (e) {
          failures.push(`${file.name}: ${e instanceof Error ? e.message : String(e)}`);
        }
      }
      setBusy(false);
      if (failures.length) setError(failures.join('\n'));
      // Drop → immediately offer crop + redaction, which is usually why a
      // screenshot went in. Only for the first of a batch, so dragging in
      // ten files doesn't open ten dialogs.
      if (firstImage) setEditing(firstImage);
    },
    [addTypstAsset, onAddFont],
  );

  /** Panel-wide drop: OS files land in the folder currently being viewed. */
  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      if (e.dataTransfer.types.includes(ASSET_DRAG) || e.dataTransfer.types.includes(FOLDER_DRAG)) return;
      if (e.dataTransfer?.files?.length) void ingest(e.dataTransfer.files, selectedFolder);
    },
    [ingest, selectedFolder],
  );

  /** Drop onto a folder row (or the root row, folderId = null). */
  const onDropInto = useCallback(
    (e: React.DragEvent, folderId: ID | null) => {
      e.preventDefault();
      e.stopPropagation();
      setDragOver(false);
      const assetId = e.dataTransfer.getData(ASSET_DRAG);
      if (assetId) { void moveTypstAssetToFolder(assetId, folderId); return; }
      const movedFolder = e.dataTransfer.getData(FOLDER_DRAG);
      if (movedFolder) {
        if (folderId && isDescendantFolder(folders, folderId, movedFolder)) return; // cycle
        if (movedFolder === folderId) return;
        void moveAssetFolder(movedFolder, folderId);
        return;
      }
      if (e.dataTransfer.files?.length) void ingest(e.dataTransfer.files, folderId);
    },
    [folders, ingest, moveAssetFolder, moveTypstAssetToFolder],
  );

  const onDragStartAsset = useCallback((e: React.DragEvent, asset: TypstAsset) => {
    e.dataTransfer.setData(ASSET_DRAG, asset.id);
    e.dataTransfer.effectAllowed = 'move';
  }, []);

  const registerEl = useCallback((id: ID, el: HTMLDivElement | null) => {
    if (el) cardEls.current.set(id, el);
    else cardEls.current.delete(id);
  }, []);

  // Preview click-to-reveal: jump to the asset's folder, scroll it into
  // view and pulse its card.
  const reveal = typst?.reveal ?? null;
  useEffect(() => {
    if (!reveal) return;
    const asset = assets.find((a) => a.id === reveal.id);
    if (!asset) return;
    setSelectedFolder(asset.folderId ?? null);
    setFlashId(reveal.id);
    const raf = requestAnimationFrame(() => {
      cardEls.current.get(reveal.id)?.scrollIntoView({ block: 'center', behavior: 'smooth' });
    });
    const timer = window.setTimeout(() => setFlashId(null), 3400);
    return () => { cancelAnimationFrame(raf); window.clearTimeout(timer); };
    // Only a new click should re-trigger; the asset list refreshing must not.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reveal?.nonce]);

  const toggleExpanded = useCallback((id: ID) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const newFolder = useCallback((parentId: ID | null) => {
    void createAssetFolder('New folder', parentId)
      .then((f) => {
        if (parentId) setExpanded((prev) => new Set(prev).add(parentId));
        setSelectedFolder(f.id);
        setRenamingId(f.id);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [createAssetFolder]);

  const commitRename = useCallback((id: ID, name: string) => {
    setRenamingId(null);
    const trimmed = name.trim();
    if (trimmed) void renameAssetFolder(id, trimmed);
  }, [renameAssetFolder]);

  // Stable per-card handlers. Defined once for the whole grid so the memoized
  // cards actually skip re-rendering when the panel does.
  const openAsset = useCallback((a: TypstAsset) => setEditing(a), []);
  // Deleting an asset removes its bytes permanently, so confirm first.
  const removeAsset = useCallback((a: TypstAsset) => setPendingDeleteAsset(a), []);

  // Copy link / Copy Typst snippet. The clipboard API is missing over plain
  // HTTP (the usual LAN deployment), so lib/clipboard falls back to
  // execCommand; when even that fails the text is shown to copy by hand.
  const [copied, setCopied] = useState<{ text: string; ok: boolean; nonce: number } | null>(null);
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number; asset: TypstAsset } | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const copy = useCallback((text: string, what: string) => {
    void copyText(text).then((ok) => setCopied({ text: ok ? `${what} copied` : text, ok, nonce: Date.now() }));
  }, []);
  const copyLink = useCallback((a: TypstAsset) => copy(assetLink(a.id), 'Link'), [copy]);
  const openMenu = useCallback((e: React.MouseEvent, a: TypstAsset) => {
    e.preventDefault();
    setCtxMenu({ x: e.clientX, y: e.clientY, asset: a });
  }, []);
  useEffect(() => {
    if (!copied?.ok) return;
    const t = window.setTimeout(() => setCopied(null), 2200);
    return () => window.clearTimeout(t);
  }, [copied]);
  useEffect(() => {
    if (!ctxMenu) return;
    const close = (e: MouseEvent) => {
      if (menuRef.current && menuRef.current.contains(e.target as Node)) return;
      setCtxMenu(null);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setCtxMenu(null); };
    window.addEventListener('mousedown', close);
    window.addEventListener('keydown', onKey);
    return () => { window.removeEventListener('mousedown', close); window.removeEventListener('keydown', onKey); };
  }, [ctxMenu]);

  // Keep the open dialog in sync if the record changes underneath us (a
  // collaborator cropping the same image, say).
  const editingLive = editing ? assets.find((a) => a.id === editing.id) ?? null : null;

  // The report's rail is ~240px wide, so it stacks the tree above the grid;
  // the Assets Manager tab has the whole tab and puts them side by side.
  // The Assets tab lays the tree beside the grid; the report rail, and any
  // narrow screen, stacks them.
  const narrow = useNarrowLayout();
  const wide = !typst && !narrow;
  const rootCount = counts.get('') ?? 0;
  const acceptsRowDrag = (e: React.DragEvent) =>
    e.dataTransfer.types.includes(ASSET_DRAG) ||
    e.dataTransfer.types.includes(FOLDER_DRAG) ||
    e.dataTransfer.types.includes('Files');

  return (
    <div
      className="relative flex h-full flex-col bg-card"
      onDragOver={(e) => {
        if (e.dataTransfer.types.includes(ASSET_DRAG) || e.dataTransfer.types.includes(FOLDER_DRAG)) return;
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={onDrop}
    >
      {/* Header */}
      <div className="flex h-8 shrink-0 items-center gap-1 border-b border-border px-2">
        <span className="text-caption font-bold uppercase tracking-widest text-muted-foreground">
          Assets
        </span>
        <div className="flex-1" />
        <Button variant="ghost" size="xs" icon={<FolderPlus size={11} />} title="New folder here" onClick={() => newFolder(selectedFolder)}>
          Folder
        </Button>
        <Button
          variant="ghost"
          size="xs"
          icon={busy ? <Loader2 size={11} className="animate-spin" /> : <Upload size={11} />}
          title={onAddFont ? 'Add images or fonts to this folder' : 'Add images to this folder'}
          onClick={() => fileInputRef.current?.click()}
        >
          Add
        </Button>
        <input
          ref={fileInputRef}
          type="file"
          multiple
          // Offering a font in the picker only to reject it on upload is the
          // bug this used to have; the two lists now agree with kindForFile.
          accept={onAddFont ? `${IMAGE_ACCEPT},${FONT_ACCEPT}` : IMAGE_ACCEPT}
          className="hidden"
          onChange={(e) => {
            if (e.target.files) void ingest(e.target.files, selectedFolder);
            e.target.value = '';
          }}
        />
      </div>

      {error && (
        <Banner tone="red" flush onDismiss={() => setError(null)} className="shrink-0">
          <span className="whitespace-pre-wrap break-words">{error}</span>
        </Banner>
      )}

      <div className={`min-h-0 flex-1 ${wide ? 'flex' : 'flex flex-col'} overflow-hidden`}>
        {/* Folder tree */}
        <div className={`atree shrink-0 overflow-y-auto p-2 ${
          wide
            ? 'w-64 border-r border-border'
            : 'max-h-[45%] border-b border-border'
        }`}>
          <div
            data-active={selectedFolder === null || undefined}
            onDragOver={(e) => { if (acceptsRowDrag(e)) { e.preventDefault(); e.stopPropagation(); } }}
            onDrop={(e) => onDropInto(e, null)}
            className={`flex w-full items-center rounded-lg border border-transparent hover:bg-accent ${
              selectedFolder === null ? 'bg-accent' : ''
            }`}
          >
            <span className="ml-0.5 inline-block w-[14px] shrink-0" aria-hidden />
            <button
              onClick={() => setSelectedFolder(null)}
              className="flex min-w-0 flex-1 items-center gap-1.5 px-1 py-1.5 text-meta"
              title="Assets outside any folder"
            >
              <ImagePlus size={12} className="shrink-0 text-muted-foreground" />
              <span className="truncate font-medium">All assets</span>
              {rootCount > 0 && (
                <span className="ml-auto shrink-0 rounded-full bg-muted px-1.5 font-mono text-micro text-muted-foreground">
                  {rootCount}
                </span>
              )}
            </button>
          </div>
          {rootFolders.length > 0 && (
            <div className="atree-kids">
              {rootFolders.map((f) => (
                <FolderNode
                  key={f.id}
                  folder={f}
                  folders={folders}
                  selected={selectedFolder}
                  expanded={expanded}
                  counts={counts}
                  renamingId={renamingId}
                  onSelect={setSelectedFolder}
                  onToggle={toggleExpanded}
                  onStartRename={setRenamingId}
                  onCommitRename={commitRename}
                  onNewSubfolder={newFolder}
                  onDeleteFolder={setPendingDelete}
                  onDropInto={onDropInto}
                />
              ))}
            </div>
          )}
          {rootFolders.length === 0 && (
            <p className="mt-1 px-1 text-caption leading-relaxed text-muted-foreground">
              Group screenshots by report section: one folder per finding, images inside.
            </p>
          )}
        </div>

        {/* Contents of the selected folder */}
        <div className="min-h-0 flex-1 overflow-y-auto p-2">
          {trail.length > 0 && (
            <div className="mb-2 flex flex-wrap items-center gap-0.5 text-caption text-muted-foreground">
              <Button variant="ghost" size="sm" className="px-1 py-0.5 text-caption text-muted-foreground" onClick={() => setSelectedFolder(null)}>
                Assets
              </Button>
              {trail.map((f) => (
                <span key={f.id} className="flex items-center gap-0.5">
                  <ChevronRight size={9} />
                  <Button
                    variant="ghost"
                    size="sm"
                    aria-current={f.id === selectedFolder ? 'page' : undefined}
                    className={`px-1 py-0.5 text-caption ${f.id === selectedFolder ? 'text-foreground' : 'text-muted-foreground'}`}
                    onClick={() => setSelectedFolder(f.id)}
                  >
                    {f.name}
                  </Button>
                </span>
              ))}
            </div>
          )}

          {/* Images */}
          <div className="mb-1 flex items-center gap-1 text-micro font-bold uppercase tracking-widest text-muted-foreground">
            <ImagePlus size={10} /> Images
          </div>
          {images.length > 0 ? (
            <div
              className={`mb-3 grid gap-1.5 ${wide ? '' : 'grid-cols-2'}`}
              style={wide ? { gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))' } : undefined}
            >
              {images.map((a) => (
                <ImageCard
                  key={a.id}
                  asset={a}
                  placedIn={typst?.placements.get(assetPath(a)) ?? null}
                  flash={flashId === a.id}
                  onOpen={openAsset}
                  onDelete={removeAsset}
                  onInsert={typst?.onInsert}
                  onCopyLink={copyLink}
                  onContextMenu={openMenu}
                  onDragStartAsset={onDragStartAsset}
                  registerEl={registerEl}
                />
              ))}
            </div>
          ) : (
            <p className="mb-3 text-caption leading-relaxed text-muted-foreground">
              {selectedFolder
                ? 'No images in this folder. Drop screenshots here, or drag cards onto a folder in the tree.'
                : "Drop screenshots here. You'll get a window to crop the image and redact anything sensitive."}
            </p>
          )}

          {/* Fonts. Report tab only: a note has no `#set text(font: …)`. */}
          {typst && (
            <>
              <div className="mb-1 flex items-center gap-1 text-micro font-bold uppercase tracking-widest text-muted-foreground">
                <FileType size={10} /> Fonts
              </div>
              {fonts.length > 0 ? (
                <div className={`flex flex-col gap-1 ${wide ? 'max-w-md' : ''}`}>
                  {fonts.map((a) => (
                    <FontRow
                      key={a.id}
                      asset={a}
                      onInsert={typst.onInsert}
                      onDelete={removeAsset}
                      onDragStartAsset={onDragStartAsset}
                    />
                  ))}
                </div>
              ) : (
                <p className="text-caption leading-relaxed text-muted-foreground">
                  Drop .ttf / .otf / .woff files here to use them in the document.
                </p>
              )}
            </>
          )}
        </div>
      </div>

      {/* Drop overlay */}
      {dragOver && (
        <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center border-2 border-dashed border-primary bg-primary/10">
          <span className="rounded bg-card px-2 py-1 text-caption font-semibold uppercase tracking-widest">
            Drop to add{trail.length > 0 ? ` to "${trail[trail.length - 1]!.name}"` : ''}
          </span>
        </div>
      )}

      {copied && (
        <div
          role="status"
          className={`absolute bottom-2 left-2 right-2 z-20 flex items-start gap-2 rounded-md bg-popover px-2 py-1.5 text-caption text-popover-foreground shadow-pane ${copied.ok ? '' : 'select-text'}`}
        >
          {copied.ok ? (
            <span className="flex-1">{copied.text}</span>
          ) : (
            <span className="min-w-0 flex-1 break-all">
              The clipboard is not available here. Copy this by hand: <code className="font-mono">{copied.text}</code>
            </span>
          )}
          {!copied.ok && (
            <Button variant="ghost" size="xs" onClick={() => setCopied(null)}>Dismiss</Button>
          )}
        </div>
      )}

      {ctxMenu && (
        <Portal>
          <MenuSurface
            ref={menuRef}
            className="fixed z-50"
            style={{ left: toLayoutPx(ctxMenu.x), top: toLayoutPx(ctxMenu.y) }}
            aria-label={`Actions for ${ctxMenu.asset.filename}`}
          >
            <MenuItem icon={<Link2 size={12} />} onClick={() => { const a = ctxMenu.asset; setCtxMenu(null); copyLink(a); }}>
              Copy link
            </MenuItem>
            <MenuItem icon={<Code2 size={12} />} onClick={() => { const a = ctxMenu.asset; setCtxMenu(null); copy(assetTypstSnippet(a), 'Typst snippet'); }}>
              Copy Typst snippet
            </MenuItem>
            <MenuSeparator />
            <MenuItem icon={<Crop size={12} />} onClick={() => { const a = ctxMenu.asset; setCtxMenu(null); setEditing(a); }}>
              {typst ? 'Crop, redact or place' : 'Crop or redact'}
            </MenuItem>
            <MenuItem danger icon={<Trash2 size={12} />} onClick={() => { const a = ctxMenu.asset; setCtxMenu(null); setPendingDeleteAsset(a); }}>
              Delete
            </MenuItem>
          </MenuSurface>
        </Portal>
      )}

      {pendingDeleteAsset && (
        <Portal>
          <ConfirmDialog
            title="Delete asset"
            message={`Delete "${pendingDeleteAsset.filename}"? This permanently removes the file and cannot be undone. Any document that references it will lose the image.`}
            confirmLabel="Delete"
            destructive
            onCancel={() => setPendingDeleteAsset(null)}
            onConfirm={() => {
              const a = pendingDeleteAsset;
              setPendingDeleteAsset(null);
              void deleteTypstAsset(a.id).catch((e) => setError(e instanceof Error ? e.message : String(e)));
            }}
          />
        </Portal>
      )}

      {pendingDelete && (
        <Portal>
          <ConfirmDialog
            title="Delete folder"
            message={`Delete "${pendingDelete.name}"? Its subfolders and assets move up one level; no files are deleted.`}
            confirmLabel="Delete folder"
            destructive
            onCancel={() => setPendingDelete(null)}
            onConfirm={() => {
              const f = pendingDelete;
              setPendingDelete(null);
              if (selectedFolder === f.id) setSelectedFolder(f.parentId ?? null);
              void deleteAssetFolder(f.id);
            }}
          />
        </Portal>
      )}

      {editingLive && (typst ? (
        <Portal>
          {/* No fallback chrome: the dialog is a portal sheet, and a spinner
              behind the panel for the length of one chunk fetch would read as
              a glitch rather than as progress. */}
          <Suspense fallback={null}>
            <PlaceScreenshotDialog
              asset={editingLive}
              source={typst.source}
              onApply={(crop, blurs, slot, heightPt, widthFraction) => {
                typst.onPlace(editingLive, crop, blurs, slot, assetPath(editingLive), heightPt, widthFraction);
                setEditing(null);
              }}
              onUnplace={(crop, blurs, slot) => {
                typst.onPlace(editingLive, crop, blurs, slot, null, null);
                setEditing(null);
              }}
              onAddSlot={typst.onAddSlot}
              onRename={(stem) => typst.onRename(editingLive, stem)}
              onClose={() => setEditing(null)}
            />
          </Suspense>
        </Portal>
      ) : (
        <Portal>
          <ImageEditorDialog
            asset={editingLive}
            onApply={(crop, blurs) => {
              void setTypstAssetCrop(editingLive.id, crop, blurs);
              setEditing(null);
            }}
            onRename={(stem) => {
              void renameTypstAsset(editingLive.id, stem)
                .catch((e) => setError(e instanceof Error ? e.message : String(e)));
            }}
            onClose={() => setEditing(null)}
          />
        </Portal>
      ))}
    </div>
  );
});
