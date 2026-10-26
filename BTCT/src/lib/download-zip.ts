// ─────────────────────────────────────────────────────────────────────────
// Every file the browser hands the user arrives as a .zip.
//
// `downloadAsZip(stem, files)` packs the original file(s), under their
// original names, into `<portable stem>_<YYYY-MM-DD_HHMM>_<format>.zip`
// (format: the files' extensions, so a PDF and a DOCX made in the same
// minute do not share a name) and hands it to `downloadBlob` (system save
// dialog or plain download, see `save-dialog.ts`). Text is DEFLATEd; formats that are
// compressed already (images, PDF, Office files, archives, fonts) are
// STORED, since deflating them again costs CPU and saves nothing. The
// workspace archive is a ZIP of its own and does not come through here (no
// ZIP inside a ZIP).
//
// JSZip is loaded on first use, so the shell and the Report tab pay nothing
// until someone downloads (invariant #17).
// ─────────────────────────────────────────────────────────────────────────
import { downloadBlob } from './download';
import { DirectoryNames, exportRootName, sanitizeFileName, splitExtension } from './export-names';

export interface ZipDownloadFile {
  /** The file's own name, kept inside the ZIP (sanitized and deduplicated). */
  name: string;
  data: Blob | string | Uint8Array | ArrayBuffer;
}

/** Extensions stored without compression: their bytes are compressed already. */
const STORED_EXTENSIONS = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'heic',
  'pdf', 'docx', 'xlsx', 'pptx', 'odt',
  'zip', 'gz', 'tgz', 'bz2', 'xz', '7z', 'zst',
  'woff', 'woff2', 'mp4', 'webm', 'mp3', 'ogg',
]);

/** How an entry is written: STORE for already-compressed formats, DEFLATE for the rest. */
export function zipCompressionFor(name: string): 'STORE' | 'DEFLATE' {
  return STORED_EXTENSIONS.has(splitExtension(name).ext) ? 'STORE' : 'DEFLATE';
}

/**
 * The format tag of a download: the files' extensions, lower case, in order,
 * joined by `-` (`pdf`, `csv`, `md`). Empty when a name has no usable
 * extension or there are more than three kinds. It keeps two downloads of
 * different formats in the same minute from getting the same ZIP name.
 */
export function zipFormatTag(names: string[]): string {
  const exts: string[] = [];
  for (const n of names) {
    const ext = splitExtension(n).ext.toLowerCase();
    if (!/^[a-z0-9]{1,8}$/.test(ext)) return '';
    if (!exts.includes(ext)) exts.push(ext);
  }
  return exts.length <= 3 ? exts.join('-') : '';
}

/** `<portable stem>_<YYYY-MM-DD_HHMM>[_<tag>].zip`, local time, via export-names. */
export function downloadZipName(stem: string, at: Date = new Date(), tag = ''): string {
  return `${exportRootName(stem, at, /^[a-z0-9-]{1,26}$/.test(tag) ? tag : '')}.zip`;
}

/** Portable, case-insensitively unique names for the ZIP's top level, in order. */
export function zipEntryNames(names: string[]): string[] {
  const dir = new DirectoryNames();
  return names.map((n) => dir.claim(sanitizeFileName(n), true));
}

/** The ZIP as a Blob (`application/zip`). */
export async function buildDownloadZip(files: ZipDownloadFile[], at: Date = new Date()): Promise<Blob> {
  if (!files.length) throw new Error('nothing to download');
  const { default: JSZip } = await import('jszip');
  const zip = new JSZip();
  const names = zipEntryNames(files.map((f) => f.name));
  files.forEach((f, i) => {
    const name = names[i]!;
    zip.file(name, f.data, { date: at, compression: zipCompressionFor(name) });
  });
  return zip.generateAsync({
    type: 'blob',
    mimeType: 'application/zip',
    compression: 'DEFLATE',
    compressionOptions: { level: 6 },
  });
}

/**
 * Pack `files` into `<stem>_<date>_<format>.zip` and hand it to `downloadBlob`
 * (the system save dialog where there is one, else a download). Resolves
 * with the ZIP's suggested file name once it was saved or handed to the
 * browser, or null when the user cancelled the save dialog.
 */
export async function downloadAsZip(stem: string, files: ZipDownloadFile[], at: Date = new Date()): Promise<string | null> {
  const blob = await buildDownloadZip(files, at);
  const fileName = downloadZipName(stem, at, zipFormatTag(files.map((f) => f.name)));
  const outcome = await downloadBlob(blob, fileName, 'application/zip');
  return outcome === 'cancelled' ? null : fileName;
}
