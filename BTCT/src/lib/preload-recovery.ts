/**
 * Recover from a lazy chunk that no longer exists.
 *
 * After a redeploy the hashed chunk names change; a tab that was open before
 * asks for the old name, the server answers with index.html, and the dynamic
 * import fails. Vite announces that as a `vite:preloadError` event on window
 * (https://vite.dev/guide/build#load-error-handling). Reloading once fetches
 * the new index and its new chunk names. A timestamp in sessionStorage keeps
 * it to one reload per minute, so a chunk that is broken for some other
 * reason falls through to the error boundary instead of a reload loop.
 */
export const PRELOAD_RELOAD_KEY = 'btct.preloadReloadAt';
export const PRELOAD_RELOAD_WINDOW_MS = 60_000;

interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/** True (and the reload time recorded) when this preload error should reload the page. */
export function shouldReloadForPreloadError(storage: StorageLike | null, now: number): boolean {
  if (!storage) return false;
  let last = 0;
  try { last = Number(storage.getItem(PRELOAD_RELOAD_KEY) ?? 0) || 0; } catch { return false; }
  if (now - last < PRELOAD_RELOAD_WINDOW_MS) return false;
  try { storage.setItem(PRELOAD_RELOAD_KEY, String(now)); } catch { return false; }
  return true;
}

/** A failed dynamic import, as the browsers word it. */
export function isChunkLoadError(error: unknown): boolean {
  const msg = error instanceof Error ? `${error.name} ${error.message}` : String(error);
  return /Failed to fetch dynamically imported module|error loading dynamically imported module|Importing a module script failed|ChunkLoadError|Unable to preload CSS/i.test(msg);
}

let installed = false;
export function installPreloadRecovery(): void {
  if (installed || typeof window === 'undefined') return;
  installed = true;
  window.addEventListener('vite:preloadError', (event) => {
    let storage: StorageLike | null = null;
    try { storage = window.sessionStorage; } catch { storage = null; }
    if (!shouldReloadForPreloadError(storage, Date.now())) return;
    event.preventDefault();
    window.location.reload();
  });
}
