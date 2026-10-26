import { v4 as uuidv4 } from 'uuid';
import { db } from './database';
import type { Page, PartialBlockContent } from '@/types';
import { normalizePageContent } from '@/export/markdown';
import { getOrInitYText, getSharedDoc, seedMissingYTexts, setYTextValue, sharedTransact, textKey } from '@/realtime/shared-doc';
import { collectSubtree } from '@/lib/change-log-policy';

function normalize(p: Page): Page {
  const md = normalizePageContent(p.content);
  if (md === p.content) return p;
  return { ...p, content: md };
}

export const pageRepo = {
  async getByWorkspace(workspaceId: string, includeGraphPages = false): Promise<Page[]> {
    const pages = await db.pages.where('workspaceId').equals(workspaceId).toArray();
    const result = includeGraphPages ? pages : pages.filter((p) => !p.isGraphPage);
    return result.map(normalize);
  },

  async getById(id: string): Promise<Page | undefined> {
    const p = await db.pages.get(id);
    return p ? normalize(p) : undefined;
  },

  async getChildren(parentId: string): Promise<Page[]> {
    const rows = await db.pages.where('parentId').equals(parentId).sortBy('sortOrder');
    return rows.map(normalize);
  },

  async getByTag(workspaceId: string, tag: string): Promise<Page[]> {
    const rows = await db.pages
      .where('workspaceId')
      .equals(workspaceId)
      .and((p) => p.tags.includes(tag))
      .toArray();
    return rows.map(normalize);
  },

  async create(data: {
    workspaceId: string;
    parentId: string | null;
    title: string;
    slug?: string;
    icon?: string;
    tags?: string[];
    content?: PartialBlockContent;
    isGraphPage?: boolean;
    sortOrder?: number;
  }): Promise<Page> {
    const now = Date.now();
    const siblings = data.parentId
      ? await db.pages.where('parentId').equals(data.parentId).count()
      : await db.pages
          .where('workspaceId')
          .equals(data.workspaceId)
          .and((p) => p.parentId === null && !p.isGraphPage)
          .count();

    const page: Page = {
      id: uuidv4(),
      workspaceId: data.workspaceId,
      parentId: data.parentId,
      title: data.title,
      slug: data.slug ?? data.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, ''),
      icon: data.icon ?? '',
      tags: data.tags ?? [],
      content: normalizePageContent(data.content ?? ''),
      sortOrder: data.sortOrder ?? siblings,
      isGraphPage: data.isGraphPage ?? false,
      createdAt: now,
      updatedAt: now,
    };
    await db.pages.add(page);
    // Pre-seed Y.Text fields so concurrent first-edits on different
    // machines don't both create their own Y.Text and orphan one.
    getOrInitYText(textKey('page', page.id, 'title'), page.title);
    getOrInitYText(textKey('page', page.id, 'slug'), page.slug);
    return page;
  },

  async update(id: string, data: Partial<Omit<Page, 'id' | 'workspaceId' | 'createdAt'>>): Promise<void> {
    const patch: Partial<Page> = { ...data, updatedAt: Date.now() };
    if ('content' in data) {
      patch.content = normalizePageContent(data.content);
    }
    await db.pages.update(id, patch);
    // title/slug are collaborative Y.Texts: keep them in sync (invariant #2).
    if (typeof data.title === 'string') setYTextValue('page', id, 'title', data.title);
    if (typeof data.slug === 'string') setYTextValue('page', id, 'slug', data.slug);
  },

  async remove(id: string): Promise<void> {
    await this.removeTree(id);
  },

  /**
   * Delete a page and every page under it in ONE shared-doc transaction
   * (it used to be one transaction, and one observer round, per page), and
   * return the removed records, root first, so the caller can log them.
   */
  async removeTree(id: string): Promise<Page[]> {
    const root = await db.pages.get(id);
    if (!root) return [];
    const inWorkspace = await db.pages.where('workspaceId').equals(root.workspaceId).toArray();
    const removed = collectSubtree(inWorkspace, id);
    await db.pages.bulkDelete(removed.map((p) => p.id));
    return removed;
  },

  /**
   * Put deleted pages back (a change-log restore) in ONE transaction, then
   * give them their title/slug Y.Texts: the delete dropped those, and a
   * record without its Y.Text drops inline edits until a reload (#16).
   */
  async restoreTree(records: readonly Page[]): Promise<void> {
    if (records.length === 0) return;
    sharedTransact(() => {
      const map = getSharedDoc().tables.pages;
      for (const r of records) map.set(r.id, { ...r });
    });
    seedMissingYTexts(getSharedDoc());
  },

  async search(workspaceId: string, query: string): Promise<Page[]> {
    const lower = query.toLowerCase();
    return db.pages
      .where('workspaceId')
      .equals(workspaceId)
      .and((p) => p.title.toLowerCase().includes(lower) || p.tags.some((t) => t.toLowerCase().includes(lower)))
      .toArray();
  },
};
