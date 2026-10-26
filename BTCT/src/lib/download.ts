// ─────────────────────────────────────────────────────────────────────────
// The one way this app hands a file to the browser.
//
// Every download goes through `downloadBlob`: the anchor is attached to the
// document for the click (Firefox ignores a click on a detached anchor in
// some versions) and the object URL is revoked on a timer, never on the next
// line, because a synchronous revoke races the browser's own read of the blob
// and can cancel the download before it starts. Sixty seconds covers a
// multi-hundred-megabyte workspace ZIP on a slow disk.
//
// Where the browser can open the system save dialog and the device's
// "Ask where to save each export" preference is on (`save-dialog.ts`), the
// same call opens that dialog instead and writes the file where the user
// chose; a cancelled dialog downloads nothing. Otherwise (Firefox, Safari,
// or the preference off) it is the anchor download described above.
//
// Imports nothing typst-related, so the Report tab can use it without
// pulling anything into the entry bundle (invariant #17), and nothing but
// `save-dialog.ts`, so it costs the shell a few KB at most.
// ─────────────────────────────────────────────────────────────────────────
import { pickSaveTarget, usesSaveDialog, type SaveOutcome } from './save-dialog';

export type { SaveOutcome } from './save-dialog';

/** How long an object URL stays alive after its download was started. */
export const REVOKE_DELAY_MS = 60_000;

/**
 * Hand `data` to the user as `filename`: the system save dialog where there
 * is one and the preference is on, else a download into the browser's
 * Downloads folder. Resolves with what happened ('saved', 'downloaded' or
 * 'cancelled'); the anchor download starts synchronously, before the
 * returned promise exists.
 *
 * A Blob that already has the right type is used as is: wrapping it in
 * another Blob copies it, so a 100 MB export would sit in memory twice for
 * as long as the URL lives.
 */
export function downloadBlob(data: BlobPart | Blob, filename: string, mime: string): Promise<SaveOutcome> {
  const blob = data instanceof Blob && (data.type === mime || !mime) ? data : new Blob([data], { type: mime });
  if (!usesSaveDialog()) {
    anchorDownload(URL.createObjectURL(blob), filename, true);
    return Promise.resolve('downloaded');
  }
  return (async () => {
    const target = await pickSaveTarget(filename, mime);
    if (target === 'cancelled') return 'cancelled';
    if (target === 'unavailable') {
      anchorDownload(URL.createObjectURL(blob), filename, true);
      return 'downloaded';
    }
    await target.writeBlob(blob);
    return 'saved';
  })();
}

/**
 * Let the browser download `href` itself (a same-origin route answering
 * with `Content-Disposition: attachment`), so a large file streams to disk
 * and never passes through page memory. The URL must not carry a session
 * token; see the backup download's one-time ticket.
 */
export function downloadUrl(href: string, filename: string): void {
  anchorDownload(href, filename, false);
}

function anchorDownload(href: string, filename: string, revoke: boolean): void {
  const a = document.createElement('a');
  a.href = href;
  a.download = filename;
  a.rel = 'noopener';
  a.style.display = 'none';
  document.body.appendChild(a);
  try {
    a.click();
  } finally {
    a.remove();
    if (revoke) setTimeout(() => URL.revokeObjectURL(href), REVOKE_DELAY_MS);
  }
}

/** Text convenience wrapper: `downloadBlob` with a string body. */
export function downloadText(text: string, filename: string, mime = 'text/plain'): Promise<SaveOutcome> {
  return downloadBlob(new Blob([text], { type: mime }), filename, mime);
}
