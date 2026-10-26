// ─────────────────────────────────────────────────────────────────────────
// Image format detection.
//
// Typst picks its decoder from a file's *extension*, not its contents. So
// every byte we mount into the compiler's virtual filesystem has to actually
// be in the format its path claims: hand it PNG bytes at a `.jpg` path and
// you get "failed to decode image (Format error decoding Jpeg: Illegal start
// bytes: 8950)", where 0x8950 is the PNG magic number.
//
// Two things can break that agreement:
//   1. cropping, which re-encodes through a canvas, and
//   2. a mislabelled upload (a PNG someone saved as `screenshot.jpg`).
//
// These helpers let both the crop pipeline and the upload endpoint keep bytes
// and extension in sync. Pure and DOM-free so they're directly testable.
// ─────────────────────────────────────────────────────────────────────────

export type ImageFormat = 'png' | 'jpeg' | 'gif' | 'webp' | 'svg';

/** Formats a browser canvas can actually *produce* via `toBlob`. */
export const ENCODABLE_FORMATS: ReadonlySet<ImageFormat> = new Set<ImageFormat>([
  'png',
  'jpeg',
  'webp',
]);

const MIME_BY_FORMAT: Record<ImageFormat, string> = {
  png: 'image/png',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  svg: 'image/svg+xml',
};

const FORMAT_BY_EXT: Record<string, ImageFormat> = {
  png: 'png',
  jpg: 'jpeg',
  jpeg: 'jpeg',
  jfif: 'jpeg',
  gif: 'gif',
  webp: 'webp',
  svg: 'svg',
};

/** Canonical extension for a format: used when correcting a mislabelled name. */
const EXT_BY_FORMAT: Record<ImageFormat, string> = {
  png: '.png',
  jpeg: '.jpg',
  gif: '.gif',
  webp: '.webp',
  svg: '.svg',
};

export function mimeForFormat(format: ImageFormat): string {
  return MIME_BY_FORMAT[format];
}

export function extensionForFormat(format: ImageFormat): string {
  return EXT_BY_FORMAT[format];
}

/** The format a filename's extension claims, or null if unrecognized. */
export function formatFromFilename(filename: string): ImageFormat | null {
  const dot = filename.lastIndexOf('.');
  if (dot === -1) return null;
  const ext = filename.slice(dot + 1).toLowerCase();
  return FORMAT_BY_EXT[ext] ?? null;
}

export function formatFromMime(mime: string): ImageFormat | null {
  const normalized = mime.toLowerCase().split(';')[0]!.trim();
  for (const [format, m] of Object.entries(MIME_BY_FORMAT)) {
    if (m === normalized) return format as ImageFormat;
  }
  if (normalized === 'image/jpg') return 'jpeg'; // non-standard but common
  return null;
}

function startsWith(bytes: Uint8Array, sig: readonly number[], offset = 0): boolean {
  if (bytes.length < offset + sig.length) return false;
  for (let i = 0; i < sig.length; i++) {
    if (bytes[offset + i] !== sig[i]) return false;
  }
  return true;
}

/**
 * Identify an image by its magic number: the ground truth, independent of
 * whatever the filename claims.
 *
 * SVG has no magic number, so it's detected by sniffing for an `<svg` or
 * `<?xml` opening in the first chunk (skipping a UTF-8 BOM and leading
 * whitespace, both of which real files carry).
 */
export function sniffImageFormat(bytes: Uint8Array): ImageFormat | null {
  if (bytes.length < 4) return null;

  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'png';
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return 'jpeg';
  if (startsWith(bytes, [0x47, 0x49, 0x46, 0x38])) return 'gif'; // "GIF8"
  // WebP is a RIFF container: "RIFF" <u32 size> "WEBP".
  if (startsWith(bytes, [0x52, 0x49, 0x46, 0x46]) && startsWith(bytes, [0x57, 0x45, 0x42, 0x50], 8)) {
    return 'webp';
  }

  // SVG: text-based, so look at the head of the file.
  let i = 0;
  if (startsWith(bytes, [0xef, 0xbb, 0xbf])) i = 3; // UTF-8 BOM
  while (i < bytes.length && bytes[i]! <= 0x20) i++; // leading whitespace
  const head = new TextDecoder('utf-8', { fatal: false })
    .decode(bytes.slice(i, i + 256))
    .toLowerCase();
  if (head.startsWith('<svg') || head.startsWith('<?xml')) return 'svg';

  return null;
}

/**
 * Decide whether bytes need re-encoding to match the path they'll be mounted
 * at, and to which format.
 *
 * Returns null when the bytes can be mounted as-is: either they already
 * agree with the extension, or the target format is one a canvas can't
 * produce (`gif`, `svg`), where re-encoding would do more harm than the
 * mismatch. Callers pass the bytes through unchanged in that case.
 */
export function reencodeTargetFor(
  filename: string,
  actual: ImageFormat | null,
): ImageFormat | null {
  const claimed = formatFromFilename(filename);
  if (!claimed) return null;
  if (!ENCODABLE_FORMATS.has(claimed)) return null;
  if (actual === claimed) return null;
  return claimed;
}
