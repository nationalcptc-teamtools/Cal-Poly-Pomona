/**
 * Repo for asset folders: the hierarchy the assets panel shows.
 *
 * Folders are organizational only. An asset's path stays the flat
 * `/assets/<filename>` wherever it sits, so nothing here ever touches a
 * document. Like `typstAssets` these records have no Y.Text fields (a
 * folder is renamed through a dialog, not co-typed), so they stay plain
 * last-writer-wins JSON and the Y.Text pre-seeding invariant doesn't apply.
 */
import { v4 as uuidv4 } from 'uuid';
import { db } from './database';
import type { AssetFolder, ID } from '@/types';

export const assetFolderRepo = {
  async getByWorkspace(workspaceId: ID): Promise<AssetFolder[]> {
    const all = await db.assetFolders.where('workspaceId').equals(workspaceId).toArray();
    return all.sort((a, b) => a.createdAt - b.createdAt);
  },

  async create(data: { workspaceId: ID; name: string; parentId?: ID | null }): Promise<AssetFolder> {
    const now = Date.now();
    const folder: AssetFolder = {
      id: uuidv4(),
      workspaceId: data.workspaceId,
      name: data.name.trim() || 'Untitled folder',
      parentId: data.parentId ?? null,
      createdAt: now,
      updatedAt: now,
    };
    await db.assetFolders.add(folder);
    return folder;
  },

  async rename(id: ID, name: string): Promise<void> {
    const trimmed = name.trim();
    if (!trimmed) return;
    await db.assetFolders.update(id, { name: trimmed, updatedAt: Date.now() });
  },

  /** Re-parent. The cycle guard lives in the store action (it has the list). */
  async move(id: ID, parentId: ID | null): Promise<void> {
    await db.assetFolders.update(id, { parentId, updatedAt: Date.now() });
  },

  async remove(id: ID): Promise<void> {
    await db.assetFolders.delete(id);
  },
};
