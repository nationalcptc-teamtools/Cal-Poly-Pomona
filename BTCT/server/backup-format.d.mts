// Type surface of backup-format.mjs for the TypeScript side (tests + tsc).
// Keep in sync with the .mjs; the runtime has no build step.

export interface BackupIncludes {
  sqlite: boolean;
  yjsShared: boolean;
  yjsPages: boolean;
  assets: boolean;
  history: boolean;
}

export interface BackupConfig {
  enabled: boolean;
  fullIntervalMin: number;
  includes: BackupIncludes;
}

export interface ManifestFile {
  path: string;
  bytes: number;
  sha256: string;
}

export interface ManifestDoc {
  name: string;
  bytes: number;
  /** Written by builds before 2026-10-12; never read. */
  stateVector?: string;
}

export interface ManifestFailedDoc {
  name: string;
  error: string;
}

export interface ManifestAsset {
  id: string;
  filename?: string;
  mime?: string;
  size?: number;
  workspaceId?: string;
  kind?: string;
  present?: boolean;
}

export interface ManifestHistory {
  pageId: string;
  bytes: number;
}

export interface BackupManifest {
  schemaVersion: number;
  format: 'btct-backup';
  instanceId: string;
  createdAt: string;
  trigger: string;
  app: Record<string, unknown>;
  includes: BackupIncludes;
  /** dataVersion was written by builds before 2026-10-12; never read. */
  sqlite: { dataVersion?: number; rawBytes?: number } | null;
  docs: ManifestDoc[];
  failedDocs?: ManifestFailedDoc[];
  assets: ManifestAsset[];
  history?: ManifestHistory[];
  files: ManifestFile[];
  totalBytes: number;
  linkedBytes?: number;
}

export const BACKUP_SCHEMA_VERSION: number;
export const BACKUP_NAME_PREFIX: string;
export const MANIFEST_FILE: string;
export const ZIP_EXT: string;
export const MAX_MANIFEST_BYTES: number;
export const FULL_INTERVAL_MIN_FLOOR: number;
export const FULL_INTERVAL_MIN_CEIL: number;
export const FULL_INTERVAL_MIN_DEFAULT: number;
export const INCLUDE_KEYS: readonly string[];
export const DEFAULT_BACKUP_CONFIG: Readonly<BackupConfig>;

export function normalizeIncludes(raw: unknown): BackupIncludes;
export function normalizeBackupConfig(raw: unknown): BackupConfig;
export function backupName(date?: Date): string;
export function isBackupName(name: unknown): boolean;
export function backupNameTime(name: string): number | null;
export interface BackupEntryName {
  base: string;
  kind: 'zip' | 'dir';
  partial: boolean;
}
export function parseBackupEntryName(name: unknown): BackupEntryName | null;
export function isBackupEntryName(name: unknown): boolean;
export function sha256File(absPath: string): Promise<string>;
export function buildManifest(input: {
  instanceId: string;
  createdAt?: string;
  trigger?: string;
  includes: Partial<BackupIncludes> | BackupIncludes;
  files: ManifestFile[];
  docs?: ManifestDoc[];
  failedDocs?: ManifestFailedDoc[];
  sqlite?: { dataVersion?: number; rawBytes?: number } | null;
  assets?: ManifestAsset[];
  history?: ManifestHistory[];
  linkedBytes?: number;
  app?: Record<string, unknown>;
}): BackupManifest;
type ManifestResult = { manifest: BackupManifest; error?: undefined } | { error: string; manifest?: undefined };
export function parseManifest(text: string): ManifestResult;
export function readManifest(dir: string): ManifestResult;
export function readZipManifest(zip: import('./zip-stream.mjs').OpenZip): Promise<ManifestResult>;
/** `unreadable`: this process may not read the copy (EACCES/EPERM); not a verdict on the backup. */
export interface VerifyResult { ok: boolean; errors: string[]; manifest: BackupManifest | null; unreadable?: boolean }
export function isAccessError(e: unknown): boolean;
export function verifyBackupDir(dir: string): Promise<VerifyResult>;
export function verifyBackupZip(zipPath: string): Promise<VerifyResult>;
export function verifyBackup(p: string): Promise<VerifyResult>;
export function formatBytes(n: number): string;

export const ENTRY_ID_RE: RegExp;
export function validateManifestEntries(m: unknown): string[];
export interface RestorePlan {
  restore: BackupIncludes;
  excluded: string[];
  absent: string[];
}
export function restorePlan(includes: unknown): RestorePlan;

export const KEEP_LAST_MAX: number;
export const KEEP_LAST_DEFAULT: number;
export function normalizeKeepLast(v: unknown): number;
export function runsToPrune(names: string[], keepLast: unknown, protect?: string | null): string[];
export function isStaleTmpRun(name: string, mtimeMs: number, now?: number, maxAgeMs?: number): boolean;
export function fileIndex(manifest: { files?: ManifestFile[] } | null | undefined): Map<string, { bytes: number; sha256: string }>;
export function estimateRunBytes(input: {
  prevManifest?: { files?: ManifestFile[]; totalBytes?: number } | null;
  assets?: Array<{ id: string; size: number }>;
  fallbackBytes?: number;
  scratchBytes?: number;
}): number;
export function withTimeout<T>(promise: Promise<T> | T, ms: number, label?: string): Promise<T>;

export function sameStateVector(a: Map<number, number> | null | undefined, b: Map<number, number> | null | undefined): boolean;
export const BACKUP_RUN_HISTORY_KEYS: readonly string[];
export function mergeBackupSettings(
  restored: Map<string, string>,
  current: Map<string, string> | null,
): { set: Array<[string, string]>; del: string[] };
export function chooseRestoreEpoch(input: {
  restoresRooms: boolean;
  keepCaches: boolean;
  currentEpoch: string | null;
  backupEpoch: string | null;
  newEpoch: string;
}): string | null;
export function restoreSpaceNeeded(
  manifest: { files?: ManifestFile[]; docs?: Array<{ bytes?: number }>; sqlite?: { rawBytes?: number } | null },
  plan: RestorePlan,
  opts?: { currentYjsBytes?: number },
): number;
