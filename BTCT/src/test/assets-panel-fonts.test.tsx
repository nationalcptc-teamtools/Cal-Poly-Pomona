// `AssetsPanel` is shared between the Assets Manager tab and the report's
// rail, and the only thing that separates them is the optional `typst` prop.
// Two properties hang off it: fonts are accepted there and nowhere else, and
// the Assets Manager must never pull the figure-placement dialog (and with it
// the Typst geometry and placeholder code) into its chunk.
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { useAppStore } from '@/stores';
import { AssetsPanel } from '@/components/assets/AssetsPanel';
import type { TypstAsset } from '@/types';

const placeDialog = vi.hoisted(() => ({ loads: 0 }));

vi.mock('@/components/typst/PlaceScreenshotDialog', () => {
  placeDialog.loads++;
  return { PlaceScreenshotDialog: () => <div>place dialog</div> };
});

function dropFiles(target: Element, files: File[]) {
  fireEvent.drop(target, { dataTransfer: { types: [], files } });
}

const fontFile = () => new File([new Uint8Array([0, 1, 2, 3])], 'Inter.ttf', { type: '' });

describe('AssetsPanel font handling', () => {
  beforeEach(() => {
    placeDialog.loads = 0;
    useAppStore.setState({ typstAssets: [], assetFolders: [] });
  });

  it('rejects a dropped font in the Assets Manager, and never loads the place dialog', async () => {
    const { container } = render(<AssetsPanel />);
    dropFiles(container.firstElementChild!, [fontFile()]);

    expect(await screen.findByText(/Inter\.ttf: not an image/)).toBeTruthy();
    expect(placeDialog.loads).toBe(0);
  });

  it('routes a dropped font to onAddFont in the report rail', async () => {
    const onAddFont = vi.fn().mockResolvedValue(undefined);
    const { container } = render(
      <AssetsPanel
        typst={{
          source: '',
          placements: new Map<string, string>(),
          onInsert: vi.fn(),
          onAddFont,
          onPlace: vi.fn(),
          onAddSlot: vi.fn(),
          onRename: vi.fn(),
          reveal: null,
        }}
      />,
    );
    dropFiles(container.firstElementChild!, [fontFile()]);

    await waitFor(() => expect(onAddFont).toHaveBeenCalledTimes(1));
    const [file, folderId] = onAddFont.mock.calls[0] as [File, string | null];
    expect(file.name).toBe('Inter.ttf');
    expect(folderId).toBeNull();
    expect(screen.queryByText(/not an image/)).toBeNull();
    // Uploading a font opens no dialog, so the lazy chunk stays unfetched.
    expect(placeDialog.loads).toBe(0);
  });

  it('keeps the fonts section out of the Assets Manager', () => {
    const asset: TypstAsset = {
      id: 'a1',
      workspaceId: 'ws-1',
      kind: 'font',
      filename: 'Inter.ttf',
      mime: 'font/ttf',
      size: 4,
      fontFamily: 'Inter',
      folderId: null,
      createdAt: 0,
      updatedAt: 0,
    };
    useAppStore.setState({ typstAssets: [asset] });

    render(<AssetsPanel />);
    expect(screen.queryByText('Fonts')).toBeNull();
  });
});
