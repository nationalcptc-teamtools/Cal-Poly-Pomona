// Type surface of zip-stream.mjs for the TypeScript side (tests + tsc).
// Keep in sync with the .mjs; the runtime has no build step.

export const MAX_CENTRAL_DIR_BYTES: number;
export function crc32(buf: Uint8Array, prev?: number): number;
export function safeEntryName(name: unknown): string | null;

export interface AddedEntry {
  name: string;
  bytes: number;
  sha256: string;
  crc32: number;
}

export class ZipWriter {
  static create(filePath: string, opts?: { mode?: number; date?: Date }): Promise<ZipWriter>;
  addIterable(name: string, chunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>, opts?: { sizeHint?: number }): Promise<AddedEntry>;
  addBuffer(name: string, buf: Uint8Array): Promise<AddedEntry>;
  addFile(name: string, src: string): Promise<AddedEntry>;
  readonly bytes: number;
  finish(): Promise<number>;
  abort(): Promise<void>;
}

export interface ZipEntry {
  name: string;
  method: number;
  crc32: number;
  compressedSize: number;
  size: number;
  offset: number;
  isDir: boolean;
}

export interface OpenZip {
  entries: ZipEntry[];
  entry(name: string): ZipEntry | null;
  openStream(entry: ZipEntry): Promise<NodeJS.ReadableStream>;
  readEntry(entry: ZipEntry, max?: number): Promise<Buffer>;
  close(): Promise<void>;
}

export function openZip(filePath: string): Promise<OpenZip>;
export function extractEntryTo(zip: OpenZip, entry: ZipEntry, dest: string, opts?: { mode?: number }): Promise<{ bytes: number; sha256: string }>;
export function hashEntry(zip: OpenZip, entry: ZipEntry): Promise<{ bytes: number; sha256: string }>;
/** True when the bytes start with a ZIP signature (PK 03 04, PK 05 06 or PK 07 08). */
export function startsWithZipSignature(head: Uint8Array | null | undefined): boolean;
