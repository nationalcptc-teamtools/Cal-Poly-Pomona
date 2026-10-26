// ─────────────────────────────────────────────────────────────────────────
// Binary asset store: screenshots and custom fonts for the Typst reports.
//
// This is the one place the server holds workspace *content* on disk. It is
// deliberately dumb about meaning: it takes bytes, writes them to a file
// named by a server-generated uuid, and hands them back on request. All the
// domain-level metadata a human cares about (display name, crop rectangle,
// which font family a .ttf provides) lives in the shared Yjs doc alongside
// every other record, so it syncs live between collaborators.
//
// Why not base64 in the CRDT: a pentest report carries dozens of multi-MB
// screenshots. In the shared doc every byte would be broadcast to and then
// permanently cached by every connected client. Keeping blobs out of the
// CRDT keeps the doc small enough to stay snappy.
//
// Bytes are immutable once written: a crop is a render-time transform of
// the original, never a destructive edit, so responses are safe to cache
// forever, and re-cropping never loses the pixels outside the crop.
// ─────────────────────────────────────────────────────────────────────────

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { pipeline } from 'node:stream';
import { fileURLToPath } from 'node:url';

import { createAsset, getAsset, listAssets, deleteAssetRow } from './db.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Blobs live next to the SQLite DB so a single volume mount (and the
// existing backup scripts, which archive /data) covers everything.
const ASSETS_DIR = process.env.ASSETS_DIR
  ? path.resolve(process.env.ASSETS_DIR)
  : path.join(
      process.env.DB_PATH ? path.dirname(path.resolve(process.env.DB_PATH)) : __dirname,
      'assets',
    );

fs.mkdirSync(ASSETS_DIR, { recursive: true });

// 25 MB. Comfortably fits a 4K PNG screenshot or any real-world font file
// while bounding what a single request can write to the volume.
const MAX_ASSET_BYTES = 25 * 1024 * 1024;

const IMAGE_MIME = {
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
};
const FONT_MIME = {
  '.ttf': 'font/ttf',
  '.otf': 'font/otf',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttc': 'font/collection',
};

/**
 * Reduce an arbitrary client-supplied name to something safe to use both as
 * a path segment and as a Typst virtual-FS filename. Strips directories,
 * collapses anything outside [A-Za-z0-9._-] to '_', and guarantees a
 * non-empty result with the original extension preserved.
 *
 * Note this is defence-in-depth only: the on-disk file is named by uuid, so
 * even a malicious name can't escape ASSETS_DIR. The sanitized name matters
 * because it becomes the path the operator types into `#image("...")`.
 */
export function sanitizeFilename(raw, fallbackExt = '') {
  const base = path.basename(String(raw || '')).replace(/\\/g, '/').split('/').pop() || '';
  const ext = (path.extname(base) || fallbackExt).toLowerCase();
  const stem = base.slice(0, base.length - path.extname(base).length);
  const safeStem = stem.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[.]+/, '').slice(0, 80);
  const safeExt = ext.replace(/[^A-Za-z0-9.]/g, '');
  return (safeStem || 'asset') + safeExt;
}

/** Resolve the MIME type for an upload, or null if the extension isn't allowed. */
function mimeFor(kind, filename) {
  const ext = path.extname(filename).toLowerCase();
  const table = kind === 'font' ? FONT_MIME : IMAGE_MIME;
  return table[ext] || null;
}

// Canonical extension per detected image format.
const EXT_BY_FORMAT = {
  png: '.png',
  jpeg: '.jpg',
  gif: '.gif',
  webp: '.webp',
  svg: '.svg',
};

function bytesStartWith(buf, sig, offset = 0) {
  if (buf.length < offset + sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (buf[offset + i] !== sig[i]) return false;
  return true;
}

/**
 * Identify an image by its magic number, ignoring whatever the filename says.
 *
 * Mirrors `src/lib/image-format.ts` on the client. It's duplicated rather
 * than shared because the server is plain `.mjs` with no build step and can't
 * import the TypeScript module: the two are small, and both are covered by
 * tests that use the same fixtures.
 */
export function sniffImageFormat(buf) {
  if (!buf || buf.length < 4) return null;
  if (bytesStartWith(buf, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'png';
  if (bytesStartWith(buf, [0xff, 0xd8, 0xff])) return 'jpeg';
  if (bytesStartWith(buf, [0x47, 0x49, 0x46, 0x38])) return 'gif';
  if (bytesStartWith(buf, [0x52, 0x49, 0x46, 0x46]) && bytesStartWith(buf, [0x57, 0x45, 0x42, 0x50], 8)) {
    return 'webp';
  }
  let i = 0;
  if (bytesStartWith(buf, [0xef, 0xbb, 0xbf])) i = 3;
  while (i < buf.length && buf[i] <= 0x20) i++;
  const head = buf.slice(i, i + 256).toString('utf8').toLowerCase();
  if (head.startsWith('<svg') || head.startsWith('<?xml')) return 'svg';
  return null;
}

/**
 * Force an image's extension to match its actual contents.
 *
 * Typst chooses its decoder from the file extension, so a PNG that someone
 * saved as `screenshot.jpg` would fail to decode at compile time with a
 * message about illegal start bytes. Correcting the name at upload (before
 * any document references it) means that mismatch can never reach a
 * document in the first place.
 *
 * Returns the (possibly renamed) filename and its true MIME type.
 */
export function reconcileImageName(filename, buf) {
  const actual = sniffImageFormat(buf);
  if (!actual) return { filename, mime: mimeFor('image', filename), corrected: false };

  const wantExt = EXT_BY_FORMAT[actual];
  const currentExt = path.extname(filename).toLowerCase();
  // .jpeg and .jpg are the same format: don't churn a name over spelling.
  const alreadyCorrect =
    currentExt === wantExt || (actual === 'jpeg' && (currentExt === '.jpeg' || currentExt === '.jfif'));
  if (alreadyCorrect) {
    return { filename, mime: mimeFor('image', filename), corrected: false };
  }

  const stem = filename.slice(0, filename.length - currentExt.length) || 'image';
  const renamed = stem + wantExt;
  return { filename: renamed, mime: IMAGE_MIME[wantExt] || null, corrected: true };
}

function blobPath(id) {
  // `id` is always a server-generated uuid; assert the shape anyway so a
  // future caller can't turn this into a path-traversal primitive.
  if (!/^[0-9a-f-]{36}$/i.test(id)) return null;
  return path.join(ASSETS_DIR, id);
}

/** Read a request body as raw bytes, rejecting anything over `limit`. */
function readBinaryBody(req, limit = MAX_ASSET_BYTES) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > limit) {
        reject(new Error(`file too large (max ${Math.floor(limit / 1024 / 1024)} MB)`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/**
 * POST /api/assets?workspaceId=…&kind=image|font&filename=…
 * Body is the raw file bytes (not multipart: there is exactly one file per
 * request, so a multipart parser would be pure overhead).
 */
export async function handleAssetUpload(req, res, { user, sendJson }) {
  const url = new URL(req.url, 'http://x');
  const workspaceId = String(url.searchParams.get('workspaceId') || '').trim();
  const kind = String(url.searchParams.get('kind') || 'image').trim();
  const rawName = url.searchParams.get('filename') || '';

  if (!workspaceId) return sendJson(res, 400, { error: 'missing workspaceId' });
  if (kind !== 'image' && kind !== 'font') {
    return sendJson(res, 400, { error: "kind must be 'image' or 'font'" });
  }

  let filename = sanitizeFilename(rawName);
  let mime = mimeFor(kind, filename);
  if (!mime) {
    const allowed = Object.keys(kind === 'font' ? FONT_MIME : IMAGE_MIME).join(', ');
    return sendJson(res, 400, { error: `unsupported ${kind} type (allowed: ${allowed})` });
  }

  let bytes;
  try {
    bytes = await readBinaryBody(req);
  } catch (e) {
    return sendJson(res, 413, { error: String(e?.message || e) });
  }
  if (!bytes.length) return sendJson(res, 400, { error: 'empty file' });

  // Make the extension tell the truth about the contents before anything can
  // reference it (see reconcileImageName).
  if (kind === 'image') {
    const reconciled = reconcileImageName(filename, bytes);
    if (reconciled.mime) {
      if (reconciled.corrected) {
        console.warn(
          `[assets] "${filename}" contains ${sniffImageFormat(bytes)} data: stored as "${reconciled.filename}"`,
        );
      }
      filename = reconciled.filename;
      mime = reconciled.mime;
    }
  }

  const id = crypto.randomUUID();
  const dest = blobPath(id);
  // Write under a temporary name and rename, then add the row. A full disk
  // can fail either step: whichever one fails, no blob is left behind without
  // a row (or a row without its blob), and the client gets a 507 it can show
  // instead of the request taking the server down.
  const tmp = `${dest}.tmp`;
  let asset;
  try {
    await fs.promises.writeFile(tmp, bytes);
    await fs.promises.rename(tmp, dest);
    asset = createAsset({
      id,
      workspaceId,
      kind,
      filename,
      mime,
      size: bytes.length,
      uploadedBy: user?.id ?? null,
    });
  } catch (err) {
    for (const f of [tmp, dest]) { try { fs.unlinkSync(f); } catch { /* not written */ } }
    throw err;
  }
  return sendJson(res, 201, { asset });
}

/** GET /api/assets/:id: the raw bytes. */
export function handleAssetGet(req, res, id, { sendJson }) {
  const asset = getAsset(id);
  if (!asset) return sendJson(res, 404, { error: 'asset not found' });
  const file = blobPath(asset.id);
  // Open before answering: once the fd is held, a concurrent delete or a
  // retention prune cannot fail the stream halfway, and a blob that is
  // already gone (or unreadable) is a clean 404 instead of an 'error' event
  // with no listener, which exits the process.
  let fd = null;
  let stat = null;
  try {
    fd = fs.openSync(file, 'r');
    stat = fs.fstatSync(fd);
  } catch {
    stat = null;
  }
  if (!stat || !stat.isFile()) {
    if (fd !== null) { try { fs.closeSync(fd); } catch { /* already closed */ } }
    // Row exists but the blob is gone (volume wiped, manual delete). Report
    // it as missing rather than streaming a zero-byte file that would fail
    // deep inside the Typst compiler with an unhelpful message.
    return sendJson(res, 404, { error: 'asset bytes missing on disk' });
  }
  res.writeHead(200, {
    'Content-Type': asset.mime,
    'Content-Length': stat.size,
    // Blob bytes never change for a given id, so this is safe forever.
    'Cache-Control': 'private, max-age=31536000, immutable',
  });
  if (req.method === 'HEAD') { fs.closeSync(fd); res.end(); return; }
  streamFileTo(req, res, fs.createReadStream(file, { fd }), `asset ${asset.id}`);
}

/**
 * Stream a file into a response without the two ways a plain `.pipe` hurts
 * a long-running relay: a read error with no listener exits the process, and
 * a client that goes away leaves the file open. `pipeline` handles the first.
 * For the second, Bun's node:http (1.3.14) does not emit 'close' on the
 * response when several clients abort at once (measured: 49 of 50 aborted
 * downloads kept their file open), only on the request, so the stream is
 * also destroyed when the request closes before the response has finished.
 */
export function streamFileTo(req, res, stream, label) {
  pipeline(stream, res, (err) => {
    if (err && err.code !== 'ERR_STREAM_PREMATURE_CLOSE') {
      console.warn(`[stream] ${label} failed:`, err.message);
    }
  });
  req.once('close', () => { if (!res.writableFinished) stream.destroy(); });
}

/** GET /api/assets?workspaceId=…: metadata inventory for one workspace. */
export function handleAssetList(req, res, { sendJson }) {
  const url = new URL(req.url, 'http://x');
  const workspaceId = String(url.searchParams.get('workspaceId') || '').trim();
  if (!workspaceId) return sendJson(res, 400, { error: 'missing workspaceId' });
  return sendJson(res, 200, { assets: listAssets(workspaceId) });
}

/**
 * DELETE /api/assets/:id: drop the row and the file. The uploader or any
 * admin may delete; this mirrors how the rest of the app treats workspace
 * data as shared between everyone on the engagement.
 */
export function handleAssetDelete(req, res, id, { user, sendJson }) {
  const asset = getAsset(id);
  if (!asset) return sendJson(res, 404, { error: 'asset not found' });
  if (!user?.is_admin && asset.uploadedBy != null && asset.uploadedBy !== user?.id) {
    return sendJson(res, 403, { error: 'only the uploader or an admin can delete this asset' });
  }
  const file = blobPath(asset.id);
  if (file) { try { fs.unlinkSync(file); } catch { /* already gone */ } }
  deleteAssetRow(asset.id);
  return sendJson(res, 200, { ok: true });
}

export { ASSETS_DIR, MAX_ASSET_BYTES };
