import { v4 as uuidv4 } from 'uuid';
import { db } from './database';
import { getOrInitYText, setYTextValue, textKey } from '@/realtime/shared-doc';
import type { Workspace } from '@/types';

export const workspaceRepo = {
  async getAll(): Promise<Workspace[]> {
    return db.workspaces.toArray();
  },

  async getById(id: string): Promise<Workspace | undefined> {
    return db.workspaces.get(id);
  },

  async create(data: Pick<Workspace, 'name' | 'description'>): Promise<Workspace> {
    const now = Date.now();
    const workspace: Workspace = {
      id: uuidv4(),
      name: data.name,
      description: data.description,
      createdAt: now,
      updatedAt: now,
    };
    await db.workspaces.add(workspace);
    getOrInitYText(textKey('workspace', workspace.id, 'name'), workspace.name); // invariant #1
    return workspace;
  },

  async update(id: string, data: Partial<Pick<Workspace, 'name' | 'description'>>): Promise<void> {
    await db.workspaces.update(id, { ...data, updatedAt: Date.now() });
    // `name` is a collaborative Y.Text: keep it in sync (invariant #2).
    if (data.name !== undefined) setYTextValue('workspace', id, 'name', data.name);
  },

  async remove(id: string): Promise<void> {
    await db.transaction('rw', [db.workspaces, db.pages], async () => {
      await db.pages.where('workspaceId').equals(id).delete();
      await db.workspaces.delete(id);
    });
  },
};
