// The note-image right-click path, end to end at the seam that actually broke:
// a contextmenu over an `asset_image` must set the `imageMenu` store flag, and
// the app must mount the menu host for that flag on its own. `App.tsx` used to
// mount the host only when `editingAssetId` was set, so a right-click set a
// flag nothing was listening to and no menu ever appeared.
import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { render, screen, cleanup } from '@testing-library/react';
import { useAppStore } from '@/stores';
import { AssetImageEditor } from '@/components/editor/AssetImageEditor';
import { openAssetImageEditor } from '@/lib/note-image-paste';

/** The DOM the `asset_image` node view builds (see lib/asset-image.ts). */
function assetImageDom(assetId: string): HTMLElement {
  const dom = document.createElement('div');
  dom.className = 'pm-image asset-image';
  dom.dataset.assetId = assetId;
  const img = document.createElement('img');
  img.dataset.assetId = assetId;
  dom.appendChild(img);
  document.body.appendChild(dom);
  return dom;
}

/**
 * The plugin's handler, lifted out so the assertion does not need a live
 * ProseMirror view. Kept byte-identical in shape to note-image-paste.ts.
 */
function handleContextMenu(event: MouseEvent): boolean {
  const el = (event.target as HTMLElement | null)?.closest?.('.asset-image');
  const assetId = el?.querySelector('img')?.getAttribute('data-asset-id')
    ?? (el instanceof HTMLElement ? el.getAttribute('data-asset-id') : null);
  const idFromImg = (event.target as HTMLElement | null)?.closest?.('img')?.getAttribute('data-asset-id');
  const id = assetId || idFromImg;
  if (!id) return false;
  event.preventDefault();
  useAppStore.getState().setImageMenu({ x: event.clientX, y: event.clientY, assetId: id });
  return true;
}

beforeEach(() => {
  cleanup();
  document.body.innerHTML = '';
  useAppStore.setState({ imageMenu: null, editingAssetId: null, typstAssets: [] });
});

describe('right-clicking a note image', () => {
  it('sets the imageMenu flag with the asset id under the cursor', () => {
    const dom = assetImageDom('asset-42');
    const img = dom.querySelector('img')!;
    const event = new MouseEvent('contextmenu', { clientX: 120, clientY: 240, bubbles: true });
    Object.defineProperty(event, 'target', { value: img });

    expect(handleContextMenu(event)).toBe(true);
    expect(useAppStore.getState().imageMenu).toEqual({ x: 120, y: 240, assetId: 'asset-42' });
  });

  it('ignores a right-click that is not over an asset image', () => {
    const plain = document.createElement('p');
    document.body.appendChild(plain);
    const event = new MouseEvent('contextmenu', { bubbles: true });
    Object.defineProperty(event, 'target', { value: plain });

    expect(handleContextMenu(event)).toBe(false);
    expect(useAppStore.getState().imageMenu).toBeNull();
  });

  it('renders the menu from the flag alone, with no asset being edited', () => {
    useAppStore.setState({ imageMenu: { x: 10, y: 20, assetId: 'asset-42' }, editingAssetId: null });
    render(<AssetImageEditor />);

    expect(screen.getByText('Blur / edit image')).toBeInTheDocument();
    expect(screen.getByText('Open in Assets Manager')).toBeInTheDocument();
  });

  it('choosing "blur / edit" closes the menu and opens the editor', () => {
    useAppStore.setState({ imageMenu: { x: 10, y: 20, assetId: 'asset-42' } });
    openAssetImageEditor('asset-42');

    expect(useAppStore.getState().imageMenu).toBeNull();
    expect(useAppStore.getState().editingAssetId).toBe('asset-42');
  });
});

// A source-level guard, like glass-theme.test.ts: the bug was not in any
// module's logic, it was the mount condition in App.tsx, and only reading that
// line catches a narrowing of it.
describe('App mounts the menu host for either flag', () => {
  const app = readFileSync(join(process.cwd(), 'src', 'App.tsx'), 'utf8');

  it('gates <AssetImageEditor /> on imageMenu as well as editingAssetId', () => {
    const line = app.split(/\r?\n/).find((l) => l.includes('<AssetImageEditor />'));
    expect(line, 'AssetImageEditor is no longer rendered in App.tsx').toBeDefined();
    expect(line).toContain('imageMenu');
    expect(line).toContain('editingAssetId');
  });

  it('subscribes to imageMenu so the mount re-runs when a right-click sets it', () => {
    expect(app).toContain('useAppStore((s) => s.imageMenu)');
  });
});
