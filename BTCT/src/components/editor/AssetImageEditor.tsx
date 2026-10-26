// ─────────────────────────────────────────────────────────────────────────
// App-level host for editing a note image's asset:
//   • the right-click menu over a note image (from the `imageMenu` store flag),
//     which also copies the image as the note shows it (crop and blur baked)
//     and sizes it (a share of the column, keeping its aspect ratio)
//   • the crop/blur editor dialog (from the `editingAssetId` store flag)
//
// The editor is the same non-destructive ImageEditorDialog the Assets Manager
// uses: it edits the shared asset's crop/blur metadata, never the original
// bytes, so a blur can always be removed. The note image (asset_image node
// view) re-renders from the asset, so the change shows in the note
// immediately.
// ─────────────────────────────────────────────────────────────────────────

import { Suspense, lazy, useEffect } from 'react';
import { Copy, EyeOff, FolderOpen, Scaling } from 'lucide-react';
import { useAppStore } from '@/stores';
import { Portal } from '@/components/ui/Portal';
import { openAssetImageEditor, resizeMenuImage } from '@/lib/note-image-paste';
import { toLayoutPx } from '@/lib/ui-zoom';
import { v4 as uuidv4 } from 'uuid';
import { resolveAssetBytes } from '@/lib/assets';
import { sniffImageFormat, mimeForFormat } from '@/lib/image-format';
import { copyImage, toPngBlob } from '@/lib/clipboard';
import { pushNotice } from '@/lib/editor-notices';
import type { TypstAsset } from '@/types';

/** Over plain http the HTML-only copy is explained once per page load. */
let explainedHtmlCopy = false;

/**
 * Copy the image exactly as the note shows it: `resolveAssetBytes` is the
 * render the note's view uses (crop and every blur region baked in), so the
 * clipboard never gets the unredacted original.
 */
async function copyRenderedImage(asset: TypstAsset): Promise<void> {
  const png = resolveAssetBytes(asset).then((bytes) => {
    const fmt = sniffImageFormat(bytes);
    return toPngBlob(bytes, fmt ? mimeForFormat(fmt) : 'image/png');
  });
  const result = await copyImage(png, asset.filename);
  if (result === 'html' && !explainedHtmlCopy) {
    explainedHtmlCopy = true;
    pushNotice({
      tone: 'info',
      message: 'Image copied with its blur. BTCT is on plain http here, so the browser only lets it copy the picture as HTML: it pastes into notes, Word, Google Docs and Outlook, but not into apps that take only a bitmap (Paint, most chat apps).',
    });
  } else if (result === false) {
    pushNotice({ tone: 'error', message: 'The browser refused to copy the image. Open it in the Assets Manager to download it instead.' });
  }
}

const ImageEditorDialog = lazy(() =>
  import('@/components/assets/ImageEditorDialog').then((m) => ({ default: m.ImageEditorDialog })),
);

export function AssetImageEditor() {
  const imageMenu = useAppStore((s) => s.imageMenu);
  const setImageMenu = useAppStore((s) => s.setImageMenu);
  const editingAssetId = useAppStore((s) => s.editingAssetId);
  const setEditingAssetId = useAppStore((s) => s.setEditingAssetId);
  const assets = useAppStore((s) => s.typstAssets);
  const setTypstAssetCrop = useAppStore((s) => s.setTypstAssetCrop);
  const renameTypstAsset = useAppStore((s) => s.renameTypstAsset);
  const openTab = useAppStore((s) => s.openTab);

  // Close the context menu on any outside click / Escape.
  useEffect(() => {
    if (!imageMenu) return;
    const close = () => setImageMenu(null);
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setImageMenu(null); };
    window.addEventListener('mousedown', close);
    window.addEventListener('keydown', onKey);
    return () => { window.removeEventListener('mousedown', close); window.removeEventListener('keydown', onKey); };
  }, [imageMenu, setImageMenu]);

  // Start the render as soon as the menu opens, so the copy that follows a
  // click finishes inside the click's gesture window (it is cached anyway
  // when the note already shows the image).
  const menuAsset = imageMenu ? assets.find((a) => a.id === imageMenu.assetId) ?? null : null;
  useEffect(() => {
    if (menuAsset?.kind === 'image') void resolveAssetBytes(menuAsset).catch(() => {});
  }, [menuAsset]);

  const editingAsset = editingAssetId ? assets.find((a) => a.id === editingAssetId) ?? null : null;

  return (
    <>
      {imageMenu && (
        <Portal>
          <div
            role="menu"
          className="fixed z-[130] min-w-44 rounded-md bg-popover p-1 text-xs text-popover-foreground shadow-pane"
            style={{ left: toLayoutPx(imageMenu.x), top: toLayoutPx(imageMenu.y) }}
            onMouseDown={(e) => e.stopPropagation()}
          >
            <button
              onClick={() => openAssetImageEditor(imageMenu.assetId)}
              role="menuitem"
            className="flex w-full items-center gap-2 rounded px-2 py-1 text-left hover:bg-accent"
            >
              <EyeOff size={12} /> Blur / edit image
            </button>
            {menuAsset?.kind === 'image' && (
              <button
                onClick={() => { setImageMenu(null); void copyRenderedImage(menuAsset); }}
                role="menuitem"
                className="flex w-full items-center gap-2 rounded px-2 py-1 text-left hover:bg-accent"
              >
                <Copy size={12} /> Copy image with blur
              </button>
            )}
            <button
              onClick={() => {
                setImageMenu(null);
                openTab({ id: uuidv4(), kind: 'assets', entityId: 'assets', title: 'Assets' });
              }}
              role="menuitem"
            className="flex w-full items-center gap-2 rounded px-2 py-1 text-left hover:bg-accent"
            >
              <FolderOpen size={12} /> Open in Assets Manager
            </button>
            {/* Shrink or grow keeping the aspect ratio; cropping is in the
                editor above. The corner handle on the image does the same
                by dragging. */}
            <div className="mt-1 flex items-center gap-1 border-t border-border px-2 pt-1.5 pb-0.5" role="group" aria-label="Image size">
              <Scaling size={12} className="shrink-0 text-muted-foreground" />
              {[0.25, 0.5, 0.75, 1].map((f) => (
                <button
                  key={f}
                  onClick={() => resizeMenuImage(f)}
                  role="menuitem"
                  title={`${f * 100}% of the column, keeping the aspect ratio`}
                  className="rounded px-1.5 py-0.5 hover:bg-accent"
                >
                  {f * 100}%
                </button>
              ))}
              <button
                onClick={() => resizeMenuImage(null)}
                role="menuitem"
                title="Back to the image's natural size"
                className="rounded px-1.5 py-0.5 text-muted-foreground hover:bg-accent"
              >
                Auto
              </button>
            </div>
          </div>
        </Portal>
      )}

      {editingAsset && (
        <Portal>
          <Suspense fallback={null}>
            <ImageEditorDialog
              asset={editingAsset}
              onApply={(crop, blurs) => { void setTypstAssetCrop(editingAsset.id, crop, blurs); setEditingAssetId(null); }}
              onRename={(stem) => {
                void renameTypstAsset(editingAsset.id, stem).catch((e) => {
                  pushNotice({ tone: 'error', message: e instanceof Error ? e.message : String(e) });
                });
              }}
              onClose={() => setEditingAssetId(null)}
            />
          </Suspense>
        </Portal>
      )}
    </>
  );
}
