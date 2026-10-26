import { db } from './database';
import { workspaceRepo } from './workspace-repo';

/**
 * First-run workspace: one empty workspace, so a fresh server opens on
 * something to write in. No sample pages, findings or report text.
 */
export const DEFAULT_WORKSPACE_NAME = 'Engagement';

export async function seedDefaultWorkspace(): Promise<void> {
  if ((await db.workspaces.count()) > 0) return;
  await workspaceRepo.create({ name: DEFAULT_WORKSPACE_NAME, description: '' });
}
