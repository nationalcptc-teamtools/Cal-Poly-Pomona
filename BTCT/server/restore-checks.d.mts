// Type surface of restore-checks.mjs for the TypeScript side (tests + tsc).

/** null when the update decodes and reads back to its own state vector, else a reason. */
export function checkYjsUpdate(Y: any, update: Uint8Array): string | null;

export interface SqliteLike {
  run(sql: string): unknown;
  query(sql: string): { get(): any };
  close(): void;
}

export function checkSqliteSnapshot(opts: {
  /** Path of the .gz file; ignored when `gz` is given. */
  gzPath?: string;
  /** The gzipped bytes themselves. */
  gz?: Uint8Array;
  tmpDir: string;
  Database: new (file: string, opts?: { readwrite?: boolean }) => SqliteLike;
  fs: typeof import('node:fs');
  zlib: typeof import('node:zlib');
}): string | null;

export function checkBackupPayloads(opts: {
  /** Folder run to read from when `read` is not given. */
  dir?: string;
  /** Returns a member's bytes by its manifest path (a ZIP reader for a .zip run). */
  read?: (rel: string) => Uint8Array | Promise<Uint8Array>;
  manifest: { files?: Array<{ path: string }>; docs?: Array<{ name: string }> };
  Y: any;
  Database: new (file: string, opts?: { readwrite?: boolean }) => SqliteLike;
  fs: typeof import('node:fs');
  zlib: typeof import('node:zlib');
  tmpDir: string;
}): Promise<string[]>;

/** `read` for checkBackupPayloads over an archive from zip-stream's openZip. */
export function zipMemberReader(zip: {
  entry(name: string): { size: number } | null;
  readEntry(entry: any, max?: number): Promise<Uint8Array>;
}): (rel: string) => Promise<Uint8Array>;

/** fcntl(F_GETLK) probe; null when the platform cannot ask. */
export function createPosixLockProbe(deps: {
  fs: typeof import('node:fs');
  ffi: any;
  platform?: string;
  arch?: string;
}): ((file: string) => { locked: boolean; pid: number }) | null;
