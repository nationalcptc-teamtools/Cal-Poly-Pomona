// Type surface of relay-persistence.mjs for the TypeScript side (tests + tsc).

export interface PersistenceStatus {
  failing: boolean;
  /** A seal of the LevelDB log (after a failure) is running. */
  sealing: boolean;
  failures: number;
  readFailures: number;
  lastError: string | null;
  lastFailureAt: number;
  lastSuccessAt: number;
  writes: number;
  compactions: number;
  openRooms: number;
  loadingRooms: number;
  pendingRooms: number;
  pendingBytes: number;
  unsavedClosedRooms: number;
  inflight: number;
}

/** The subset of y-leveldb's LeveldbPersistence the binding uses. */
export interface LdbLike {
  getYDoc(name: string): Promise<any>;
  storeUpdate(name: string, update: Uint8Array): Promise<number | null>;
  flushDocument(name: string): Promise<unknown>;
  tr?: Promise<unknown>;
  destroy?(): Promise<unknown>;
}

export interface RelayPersistenceOptions {
  ldb: LdbLike;
  Y: any;
  flushMs?: number;
  maxPendingBytes?: number;
  /** Flush once this many updates are buffered (default 2000). */
  maxPendingUpdates?: number;
  retryMs?: number;
  compactMs?: number;
  compactMinWrites?: number;
  log?: Pick<Console, 'error' | 'warn'>;
  /**
   * Seals the store's write-ahead log after a failure (createLevelDbLogSealer).
   * When set, the binding stays failing until a seal with no failure since
   * it started has succeeded.
   */
  sealLog?: (() => Promise<boolean>) | null;
}

export interface RelayPersistence {
  provider: LdbLike;
  bindState(name: string, doc: any): void;
  writeState(name: string, doc: any): Promise<void>;
  drain(): Promise<boolean>;
  status(): PersistenceStatus;
  compactOpenRooms(): Promise<void>;
  close(): Promise<void>;
}

/** Merge updates in groups so the cost stays near linear in their number. */
export function mergeUpdatesBounded(Y: any, updates: Uint8Array[], group?: number): Uint8Array | null;
/** Seals y-leveldb's write-ahead log (memtable to a table, new log, old log gone). */
export function createLevelDbLogSealer(ldb: any, dir: string, fs: typeof import('node:fs')): () => Promise<boolean>;
export function createRelayPersistence(opts: RelayPersistenceOptions): RelayPersistence;
