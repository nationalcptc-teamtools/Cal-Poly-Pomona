import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { useAppStore } from '@/stores';
import { AssetsPanel } from '@/components/assets/AssetsPanel';
import type { TypstAsset } from '@/types';

// C8: a failed asset delete (403, 5xx, network) must tell the user, not
// vanish as an unhandled rejection after the dialog has closed.
afterEach(() => { vi.unstubAllGlobals(); });

describe('C8 asset delete failure', () => {
  it('shows the error when the server refuses the delete', async () => {
    const asset: TypstAsset = {
      id: 'c8', workspaceId: 'ws-c8', kind: 'image', filename: 'shot.png', mime: 'image/png', size: 4,
      folderId: null, createdAt: 0, updatedAt: 0,
    };
    useAppStore.setState({ activeWorkspaceId: 'ws-c8', typstAssets: [asset], assetFolders: [] });
    const unhandled: unknown[] = [];
    const onUnhandled = (r: unknown) => { unhandled.push(r); };
    process.on('unhandledRejection', onUnhandled);
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'delete refused by server' }), { status: 500 })));
    try {
      render(<AssetsPanel />);
      fireEvent.click(await screen.findByLabelText('Delete shot.png'));
      fireEvent.click(await screen.findByRole('button', { name: 'Delete' }));
      await new Promise((r) => setTimeout(r, 50));
      expect(unhandled).toEqual([]);
      await waitFor(() => expect(screen.getByText(/delete refused by server/)).toBeTruthy(), { timeout: 500 });
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });
});
