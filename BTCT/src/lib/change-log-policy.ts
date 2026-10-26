/**
 * Pure rules for the shared change log (`changeLogs` table) and the page-tree
 * snapshots a page delete records. Kept apart from the store so they test
 * without a shared doc.
 */
import type { ChangeLogEntry, Page } from '@/types';

/** Entries kept per workspace by an explicit `changeLogRepo.prune()`; nothing prunes automatically. */
export const CHANGE_LOG_CAP = 2000;
/** Prune only once the log is this far over the cap, so not every write prunes. */
export const CHANGE_LOG_PRUNE_SLACK = 100;
/** One "Updated page content" entry per page per window from this client. */
export const CONTENT_LOG_WINDOW_MS = 5 * 60_000;
/**
 * A page body over this many characters is left out of a delete snapshot
 * (flagged `contentDropped`). The body itself stays in the page's room and
 * its server history; the snapshot copy only makes a restore (and a ZIP
 * re-import into a fresh BTCT) carry the text without opening the page.
 */
export const SNAPSHOT_CONTENT_MAX_CHARS = 256_000;

/**
 * Coalesce content-save log entries per page (this client is one user).
 * Returns true when this save should log, and records the time if so. The
 * old check compared against the newest entry by anyone, so with several
 * typists interleaving nearly every 2-10 s save logged a new entry.
 */
export function shouldLogContentSave(last: Map<string, number>, pageId: string, now: number, windowMs = CONTENT_LOG_WINDOW_MS): boolean {
  const prev = last.get(pageId);
  if (prev !== undefined && now - prev < windowMs) return false;
  last.set(pageId, now);
  return true;
}

/**
 * Which entries to delete to bring a workspace's log back to `cap`, or none
 * while it is within `cap + slack`. Non-reversible entries (content saves,
 * creates) go first, oldest first; reversible ones (renames, delete
 * snapshots a user can restore) only once nothing else is left to drop.
 */
export function pickPruneIds(entries: readonly ChangeLogEntry[], cap = CHANGE_LOG_CAP, slack = CHANGE_LOG_PRUNE_SLACK): string[] {
  if (entries.length <= cap + slack) return [];
  const excess = entries.length - cap;
  const order = [...entries].sort((a, b) => {
    const ra = a.reversible ? 1 : 0;
    const rb = b.reversible ? 1 : 0;
    if (ra !== rb) return ra - rb;
    return (a.timestamp ?? 0) - (b.timestamp ?? 0);
  });
  return order.slice(0, excess).map((e) => e.id);
}

/** A page and every page under it, root first (breadth-first), cycle-safe. */
export function collectSubtree(pages: readonly Page[], rootId: string): Page[] {
  const byParent = new Map<string, Page[]>();
  for (const p of pages) {
    if (!p.parentId) continue;
    const list = byParent.get(p.parentId);
    if (list) list.push(p); else byParent.set(p.parentId, [p]);
  }
  const root = pages.find((p) => p.id === rootId);
  if (!root) return [];
  const out: Page[] = [];
  const seen = new Set<string>();
  const queue: Page[] = [root];
  while (queue.length > 0) {
    const p = queue.shift()!;
    if (seen.has(p.id)) continue;
    seen.add(p.id);
    out.push(p);
    for (const c of byParent.get(p.id) ?? []) queue.push(c);
  }
  return out;
}

export interface PageTreeSnapshot {
  kind: 'pageTree';
  version: 1;
  pages: Array<Page & { contentDropped?: boolean }>;
}

/** What a page delete logs: every record of the removed tree, bodies bounded. */
export function buildPageTreeSnapshot(removed: readonly Page[], maxContentChars = SNAPSHOT_CONTENT_MAX_CHARS): PageTreeSnapshot {
  return {
    kind: 'pageTree',
    version: 1,
    pages: removed.map((p) => {
      const content = typeof p.content === 'string' ? p.content : '';
      return content.length > maxContentChars ? { ...p, content: '', contentDropped: true } : { ...p, content };
    }),
  };
}

/**
 * The page records a delete entry can restore: a page-tree snapshot (this
 * build), or the single record older builds logged. Anything else is none.
 */
export function pagesFromDeleteSnapshot(prev: unknown): Page[] {
  if (!prev || typeof prev !== 'object') return [];
  const rec = prev as Record<string, unknown>;
  const list = rec.kind === 'pageTree' && Array.isArray(rec.pages) ? rec.pages : [rec];
  const out: Page[] = [];
  for (const raw of list) {
    if (!raw || typeof raw !== 'object') continue;
    const p = raw as Record<string, unknown>;
    if (typeof p.id !== 'string' || typeof p.workspaceId !== 'string') continue;
    const { contentDropped: _dropped, ...rest } = p;
    out.push({
      ...(rest as unknown as Page),
      title: typeof p.title === 'string' ? p.title : 'Untitled',
      slug: typeof p.slug === 'string' ? p.slug : '',
      tags: Array.isArray(p.tags) ? (p.tags as string[]) : [],
      content: typeof p.content === 'string' ? p.content : '',
      parentId: typeof p.parentId === 'string' ? p.parentId : null,
    });
  }
  return out;
}
