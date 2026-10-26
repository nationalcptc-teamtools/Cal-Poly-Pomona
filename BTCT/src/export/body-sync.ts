import { bodyIsEmpty, bytesToBase64 } from './page-body-codec';

// ─────────────────────────────────────────────────────────────────────────
// How an export reads page bodies and an import writes them, over an
// injected `PageBodyIO` so the policy (retry an empty body, list what could
// not be confirmed, four at a time) is tested without a server. The browser
// implementation is `browserPageBodyIO` in ./page-bodies.
// ─────────────────────────────────────────────────────────────────────────

export interface PageBodyIO {
  /** The body as the server holds it, or null when the server did not answer in time. */
  readFromServer(pageId: string, timeoutMs: number): Promise<Uint8Array | null>;
  /** This browser's offline copy, or null when it has none. */
  readLocal(pageId: string): Promise<Uint8Array | null>;
  /** Apply `update` to the page room and resolve true once the server confirms it. */
  write(pageId: string, update: Uint8Array, timeoutMs: number): Promise<boolean>;
}

export interface BodyReadResult {
  updates: Record<string, string>;
  incomplete: Array<{ pageId: string; reason: string }>;
}

export interface BodyReadOptions {
  timeoutMs?: number;
  concurrency?: number;
  retryDelayMs?: number;
  onProgress?: (done: number, total: number) => void;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function runLimited<T>(items: T[], limit: number, work: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (next < items.length) await work(items[next++]!);
  }));
}

/**
 * Collect every page body for an export. `pages` carries each page's
 * markdown mirror, which is how an empty body is told apart from a page
 * that really is empty.
 */
export async function readPageBodies(
  pages: Array<{ id: string; content: unknown }>,
  io: PageBodyIO,
  opts: BodyReadOptions = {},
): Promise<BodyReadResult> {
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const retryDelayMs = opts.retryDelayMs ?? 1_000;
  const updates: Record<string, string> = {};
  const incomplete: BodyReadResult['incomplete'] = [];
  let done = 0;
  // After four timeouts in a row the server is gone: stop paying 15 s a page.
  let consecutiveTimeouts = 0;
  await runLimited(pages, opts.concurrency ?? 4, async (page) => {
    const expectsBody = typeof page.content === 'string' ? page.content.trim().length > 0 : Array.isArray(page.content) && page.content.length > 0;
    const wait = consecutiveTimeouts >= 4 ? Math.min(timeoutMs, 2_000) : timeoutMs;
    let body = await io.readFromServer(page.id, wait).catch(() => null);
    if (body && expectsBody && bodyIsEmpty(body)) {
      await sleep(retryDelayMs);
      const again = await io.readFromServer(page.id, wait).catch(() => null);
      if (again) body = again;
    }
    if (body) {
      consecutiveTimeouts = 0;
      updates[page.id] = bytesToBase64(body);
      if (expectsBody && bodyIsEmpty(body)) {
        incomplete.push({ pageId: page.id, reason: 'the server returned an empty body although the page has text' });
      }
    } else {
      consecutiveTimeouts++;
      const local = await io.readLocal(page.id).catch(() => null);
      if (local && !bodyIsEmpty(local)) {
        updates[page.id] = bytesToBase64(local);
        incomplete.push({ pageId: page.id, reason: 'the server did not answer; this browser\'s offline copy was used' });
      } else {
        if (local) updates[page.id] = bytesToBase64(local);
        if (expectsBody) incomplete.push({ pageId: page.id, reason: 'the server did not answer and this browser has no copy; only the markdown is in the archive' });
      }
    }
    opts.onProgress?.(++done, pages.length);
  });
  return { updates, incomplete };
}

export interface BodyWriteOptions {
  timeoutMs?: number;
  concurrency?: number;
  onProgress?: (done: number, total: number) => void;
}

/** Write bodies four at a time; returns the page ids the server did not confirm. */
export async function writePageBodies(
  bodies: Array<{ pageId: string; update: Uint8Array }>,
  io: PageBodyIO,
  opts: BodyWriteOptions = {},
): Promise<{ unconfirmed: string[]; failed: Array<{ pageId: string; error: string }> }> {
  const unconfirmed: string[] = [];
  const failed: Array<{ pageId: string; error: string }> = [];
  let done = 0;
  await runLimited(bodies, opts.concurrency ?? 4, async ({ pageId, update }) => {
    try {
      const ok = await io.write(pageId, update, opts.timeoutMs ?? 30_000);
      if (!ok) unconfirmed.push(pageId);
    } catch (e) {
      failed.push({ pageId, error: e instanceof Error ? e.message : String(e) });
    }
    opts.onProgress?.(++done, bodies.length);
  });
  return { unconfirmed, failed };
}
