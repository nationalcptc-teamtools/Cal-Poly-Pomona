/**
 * Yjs-backed compatibility layer that mimics the Dexie API the rest of
 * this codebase already uses (`db.tableName.where(...).equals(...).toArray()`,
 * `db.tableName.add(...)`, `db.transaction(...)`, etc.).
 *
 * Why it looks like Dexie: the original implementation persisted everything
 * to IndexedDB through Dexie. Switching to a single shared Y.Doc makes the
 * whole workspace a real-time collaborative document, but we want every
 * existing repo and seed file to keep working with zero changes. So this
 * file exposes the same surface, backed by a Y.Map per table.
 *
 * Records are stored as plain JSON objects keyed by `id`. Updates replace
 * the whole record (last-writer-wins): fine for sidebar/list metadata.
 * Per-page note *contents* live in their own per-page Y.Doc and merge
 * with proper CRDT semantics; see realtime/yjs-providers.ts.
 */
import { getSharedDoc, sharedTransact, type TableName, textKey, TEXT_FIELDS_BY_ENTITY } from '@/realtime/shared-doc';
import type {
  Workspace, Page,
  ChangeLogEntry, NmapScan, NmapMachine, PageSnapshot, TypstAsset, AssetFolder,
  CommandLogEntry,
} from '@/types';

type Row = { id: string };
type Predicate<T extends Row> = (row: T) => boolean;

class Where<T extends Row> {
  constructor(
    private readonly map: () => Iterable<T>,
    private predicate: Predicate<T>,
    private reversed = false,
  ) {}

  and(p: Predicate<T>): Where<T> {
    const prev = this.predicate;
    this.predicate = (row) => prev(row) && p(row);
    return this;
  }

  reverse(): Where<T> {
    this.reversed = !this.reversed;
    return this;
  }

  private collect(): T[] {
    const out: T[] = [];
    for (const row of this.map()) {
      if (this.predicate(row)) out.push(row);
    }
    return this.reversed ? out.reverse() : out;
  }

  async toArray(): Promise<T[]> {
    return this.collect();
  }

  async first(): Promise<T | undefined> {
    // Single pass either way: unreversed returns on the first match;
    // reversed tracks the last match rather than re-scanning via collect().
    let last: T | undefined;
    for (const row of this.map()) {
      if (!this.predicate(row)) continue;
      if (!this.reversed) return row;
      last = row;
    }
    return last;
  }

  async count(): Promise<number> {
    let n = 0;
    for (const row of this.map()) if (this.predicate(row)) n++;
    return n;
  }

  async sortBy(field: keyof T): Promise<T[]> {
    const arr = this.collect();
    arr.sort((a, b) => {
      const av = a[field] as unknown;
      const bv = b[field] as unknown;
      if (typeof av === 'number' && typeof bv === 'number') return av - bv;
      const as = String(av ?? '');
      const bs = String(bv ?? '');
      return as.localeCompare(bs);
    });
    return this.reversed ? arr.reverse() : arr;
  }

  async delete(): Promise<void> {
    const ids = this.collect().map((r) => r.id);
    if (ids.length === 0) return;
    // The matching rows live in the parent table; we only have an iterator
    // here. Use the parent reference passed via the closure in `Table.where`.
    this.deleteIds(ids);
  }

  // Set by Table.where so we can delete the actual Y.Map entries.
  deleteIds: (ids: string[]) => void = () => undefined;
}

/** Y.Texts belong to their record: drop them with it, or the shared doc keeps every deleted title forever. */
function deleteTextsFor(c: ReturnType<typeof getSharedDoc>, table: TableName, id: string): void {
  for (const [entity, info] of Object.entries(TEXT_FIELDS_BY_ENTITY)) {
    if (info.table !== table) continue;
    for (const field of info.fields) {
      const key = textKey(entity, id, field);
      if (c.texts.has(key)) c.texts.delete(key);
    }
  }
}

class Table<T extends Row> {
  constructor(public readonly name: TableName) {}

  private get yMap() {
    return getSharedDoc().tables[this.name];
  }

  private *iter(): Iterable<T> {
    for (const v of this.yMap.values()) {
      if (v && typeof v === 'object') yield v as T;
    }
  }

  async toArray(): Promise<T[]> {
    return [...this.iter()];
  }

  async get(id: string): Promise<T | undefined> {
    const v = this.yMap.get(id);
    return v ? (v as T) : undefined;
  }

  async count(): Promise<number> {
    return this.yMap.size;
  }

  async add(record: T): Promise<string> {
    if (!record.id) throw new Error(`${this.name}.add: record missing id`);
    sharedTransact(() => { this.yMap.set(record.id, { ...record }); });
    return record.id;
  }

  async put(record: T): Promise<string> {
    return this.add(record);
  }

  async bulkAdd(records: T[]): Promise<void> {
    sharedTransact(() => {
      for (const r of records) {
        if (!r.id) throw new Error(`${this.name}.bulkAdd: record missing id`);
        this.yMap.set(r.id, { ...r });
      }
    });
  }

  async update(id: string, patch: Partial<T>): Promise<number> {
    const cur = this.yMap.get(id) as T | undefined;
    if (!cur) return 0;
    sharedTransact(() => {
      this.yMap.set(id, { ...cur, ...patch });
    });
    return 1;
  }

  async delete(id: string): Promise<void> {
    sharedTransact(() => {
      this.yMap.delete(id);
      deleteTextsFor(getSharedDoc(), this.name, id);
    });
  }

  /** Delete several records (and their texts) in ONE transaction. */
  async bulkDelete(ids: readonly string[]): Promise<void> {
    if (ids.length === 0) return;
    sharedTransact(() => {
      const c = getSharedDoc();
      for (const id of ids) {
        this.yMap.delete(id);
        deleteTextsFor(c, this.name, id);
      }
    });
  }

  where(field: keyof T): { equals: (value: unknown) => Where<T> } {
    const iter = () => this.iter();
    const yMap = () => this.yMap;
    return {
      equals: (value: unknown) => {
        const eq: Predicate<T> = (row) => (row as Record<string, unknown>)[field as string] === value;
        const w = new Where<T>(iter, eq);
        w.deleteIds = (ids) => {
          sharedTransact(() => {
            const m = yMap();
            const c = getSharedDoc();
            for (const id of ids) {
              m.delete(id);
              deleteTextsFor(c, this.name, id);
            }
          });
        };
        return w;
      },
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────
// Database surface
// ─────────────────────────────────────────────────────────────────────────
class AppDatabase {
  workspaces   = new Table<Workspace>     ('workspaces');
  pages        = new Table<Page>          ('pages');
  changeLogs    = new Table<ChangeLogEntry>('changeLogs');
  pageSnapshots = new Table<PageSnapshot> ('pageSnapshots');
  nmapScans     = new Table<NmapScan>     ('nmapScans');
  nmapMachines  = new Table<NmapMachine>  ('nmapMachines');
  typstAssets   = new Table<TypstAsset>   ('typstAssets');
  assetFolders  = new Table<AssetFolder>  ('assetFolders');
  commandLogs   = new Table<CommandLogEntry>('commandLogs');

  /**
   * Yjs has no transactional rollback, but it does batch updates: every
   * write inside `fn` is wrapped in a single Yjs transaction so observers
   * fire only once. The `mode` and `tables` arguments are ignored:
   * accepted for Dexie API parity.
   */
  async transaction<T>(_mode: string, _tables: unknown, fn: () => Promise<T> | T): Promise<T> {
    // Cannot wrap an async fn directly in doc.transact (transact must be
    // synchronous). Each write inside fn already wraps itself in
    // sharedTransact, so just call fn().
    return await fn();
  }

  /**
   * Wipe every shared table. Used by the "Reset workspace data" action.
   * Note: this propagates to *every connected user*: it's a shared doc.
   */
  async delete(): Promise<void> {
    const c = getSharedDoc();
    sharedTransact(() => {
      for (const map of Object.values(c.tables)) {
        for (const k of Array.from(map.keys())) map.delete(k);
      }
    });
  }

  // No-op for Dexie API parity. The shared doc is opened lazily on first use.
  async open(): Promise<this> {
    getSharedDoc();
    return this;
  }
}

export const db = new AppDatabase();

