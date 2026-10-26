// ─────────────────────────────────────────────────────────────────────────
// Copy plain text to the clipboard, over plain HTTP too.
//
// `navigator.clipboard` exists only in a secure context (https or
// localhost), and BTCT usually runs over http on the team's LAN, where it is
// undefined. There the old `document.execCommand('copy')` on a hidden
// textarea still works inside a click handler, so that is the fallback. It
// must run in the same task as the click (the user gesture), which is why the
// insecure case never awaits anything before it.
//
// Resolves true only when a copy happened, so the caller can show the text
// for a manual copy instead of claiming one that never happened.
// ─────────────────────────────────────────────────────────────────────────

function copyWithTextarea(text: string): boolean {
  if (typeof document === 'undefined') return false;
  const active = document.activeElement as HTMLElement | null;
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.setAttribute('aria-hidden', 'true');
  // Off screen but rendered: a display:none element cannot be selected.
  ta.style.position = 'fixed';
  ta.style.top = '0';
  ta.style.left = '-9999px';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  let ok = false;
  try {
    ta.select();
    ta.setSelectionRange(0, text.length);
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  } finally {
    ta.remove();
    try { active?.focus({ preventScroll: true }); } catch { /* ignore */ }
  }
  return ok;
}

export async function copyText(text: string): Promise<boolean> {
  const secure = typeof window !== 'undefined' && window.isSecureContext;
  const clip = typeof navigator !== 'undefined' ? navigator.clipboard : undefined;
  if (!secure || !clip?.writeText) return copyWithTextarea(text);
  try {
    await clip.writeText(text);
    return true;
  } catch {
    // Permission refused or the document lost focus: try the old way.
    return copyWithTextarea(text);
  }
}

// ── images ───────────────────────────────────────────────────────────────
// A picture goes on the clipboard as PNG, the one image type every browser
// accepts. `navigator.clipboard.write` with an image exists only in a secure
// context, so over plain http the fallback is a `copy` event that carries
// the picture as HTML with a data: URL: Word, Google Docs, Outlook, OneNote
// and BTCT's own notes paste that as an image; a paint program or chat app
// that reads only bitmaps does not, and the caller then offers a download.

/** `bytes` as a PNG blob, re-encoded through a canvas unless already PNG. */
export async function toPngBlob(bytes: Uint8Array, mime: string): Promise<Blob> {
  const src = new Blob([bytes as BlobPart], { type: mime });
  if (mime === 'image/png') return src;
  const bitmap = await createImageBitmap(src);
  try {
    const canvas = document.createElement('canvas');
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    canvas.getContext('2d')!.drawImage(bitmap, 0, 0);
    const out = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/png'));
    if (!out) throw new Error('could not encode PNG');
    return out;
  } finally {
    bitmap.close();
  }
}

function blobToDataUrl(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result));
    r.onerror = () => reject(r.error);
    r.readAsDataURL(blob);
  });
}

function copyHtmlWithEvent(html: string): boolean {
  if (typeof document === 'undefined') return false;
  let wrote = false;
  const onCopy = (e: ClipboardEvent) => {
    if (!e.clipboardData) return;
    e.clipboardData.setData('text/html', html);
    e.preventDefault();
    wrote = true;
  };
  document.addEventListener('copy', onCopy, true);
  try {
    document.execCommand('copy');
  } catch {
    wrote = false;
  } finally {
    document.removeEventListener('copy', onCopy, true);
  }
  return wrote;
}

/**
 * Copy a PNG. Resolves 'image' when the bitmap itself went on the clipboard,
 * 'html' when only the HTML form could (plain http), false when neither did.
 * Call it from a click: both paths need the user's gesture.
 */
export async function copyImage(png: Blob | Promise<Blob>, alt = 'image'): Promise<'image' | 'html' | false> {
  const secure = typeof window !== 'undefined' && window.isSecureContext;
  const clip = typeof navigator !== 'undefined' ? navigator.clipboard : undefined;
  if (secure && clip?.write && typeof ClipboardItem !== 'undefined') {
    try {
      // A promise inside the item keeps the gesture alive while it encodes.
      await clip.write([new ClipboardItem({ 'image/png': Promise.resolve(png) })]);
      return 'image';
    } catch {
      // Refused or unfocused: fall through to the HTML form.
    }
  }
  try {
    const url = await blobToDataUrl(await png);
    const safeAlt = alt.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);
    return copyHtmlWithEvent(`<img src="${url}" alt="${safeAlt}">`) ? 'html' : false;
  } catch {
    return false;
  }
}
