// ─────────────────────────────────────────────────────────────────────────
// Assets Manager tab.
//
// The folder browser and the non-destructive crop/redact editor for every
// image in the workspace. Note images land here: pasting one into a page
// uploads it as a shared asset and inserts a reference, so the picture in the
// note and the card in this tab are the same object. A crop or a blur made
// here shows up in the note immediately, and can always be removed again
// because the original bytes are never overwritten.
// ─────────────────────────────────────────────────────────────────────────

import { useAppStore } from '@/stores';
import { AssetsPanel } from './AssetsPanel';

export function AssetsManager() {
  const workspaceId = useAppStore((s) => s.activeWorkspaceId);

  if (!workspaceId) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
        Select a workspace to manage assets.
      </div>
    );
  }

  return <AssetsPanel />;
}
