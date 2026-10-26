/**
 * Single shared Yjs document containing all workspace metadata
 * (workspaces, pages, nmap scans, nmap machines, assets, command logs,
 * change logs, page snapshots).
 *
 * Real-time editing model
 * ───────────────────────
 * This is the source of truth for the entire app state visible in the
 * sidebar AND for every collaboratively-edited text field.
 *
 *   • Sidebar/list metadata (icons, types, parents, timestamps, …) lives
 *     in Y.Map<id, JSON-record> per table. These rows are coarse-grained
 *     last-writer-wins, which is correct for non-textual fields.
 *
 *   • Every collaboratively-edited text field (page title, page slug,
 *     nmap scan name, nmap hostname, etc.) lives as
 *     a Y.Text inside the `texts` Y.Map keyed `<entity>:<id>:<field>`.
 *     The UI binds inputs to these Y.Texts using diff-based deltas
 *     (insert / delete) so two users can type into the same field at
 *     the same time without losing characters, exactly how Google Docs,
 *     Notion, Linear, etc. handle text. A central observer (see
 *     `mirrorTextsToRecords`) writes the resulting string back into the
 *     JSON record snapshot so read-only consumers (sidebar, tab title,
 *     search) keep working without changes.
 *
 *   • Long-form note bodies (Milkdown markdown) use a *separate* per-page
 *     Y.Doc with the existing collab plugin. See realtime/yjs-providers.ts.
 *
 * Networking:
 *   - WebsocketProvider connects to the Bun collab server, room name
 *     "btct-shared". Auth token is sent as a query param so the server
 *     can reject unauthenticated clients.
 *   - IndexedDB persistence keeps a local cache so the UI can render
 *     instantly while the WS catches up.
 */
import * as Y from 'yjs';
import { IndexeddbPersistence } from 'y-indexeddb';
import { WebsocketProvider } from 'y-websocket';
import { probeSession, useAuthStore, WS_URL } from '@/auth/auth-store';
import { checkRestoreEpochNow, restoreEpochParams } from './restore-epoch';
import { bindConnectionStatus, markIdbUnavailable, resetConnectionStatus, useConnectionStore } from './connection-status';
import { whenIdbLoaded } from './idb-ready';

export const TABLE_NAMES = [
  'workspaces',
  'pages',
  'changeLogs',
  'pageSnapshots',
  'nmapScans',
  'nmapMachines',
  'typstAssets',
  'assetFolders',
  'commandLogs',
  // Server-written mirror of the public settings (admin theme policy), so
  // clients re-theme live. Read by theme-store via shared-bindings; never
  // written by clients.
  'settingsPublic',
] as const;
export type TableName = (typeof TABLE_NAMES)[number];

const SHARED_ROOM = 'btct-shared';

export interface SharedDocContext {
  doc: Y.Doc;
  persistence: IndexeddbPersistence;
  provider: WebsocketProvider;
  tables: Record<TableName, Y.Map<unknown>>;
  /** Y.Map<key, Y.Text>: collaborative text fields. Key is `<entity>:<id>:<field>`. */
  texts: Y.Map<Y.Text>;
  whenReady: Promise<void>;
}

let ctx: SharedDocContext | null = null;
let unbindStatus: (() => void) | null = null;

export function getSharedDoc(): SharedDocContext {
  if (ctx) return ctx;

  const doc = new Y.Doc();
  const persistence = new IndexeddbPersistence(`btct-${SHARED_ROOM}`, doc);

  const tables = {} as Record<TableName, Y.Map<unknown>>;
  for (const name of TABLE_NAMES) {
    tables[name] = doc.getMap(name);
  }
  const texts = doc.getMap<Y.Text>('texts');

  const token = useAuthStore.getState().token ?? '';
  const provider = new WebsocketProvider(`${WS_URL}/yjs`, SHARED_ROOM, doc, {
    params: { token, ...restoreEpochParams() },
    connect: true,
  });

  resetConnectionStatus();
  unbindStatus = bindConnectionStatus(provider, probeSession, () => {
    // The token is dead: stop hammering the server with upgrades it will
    // refuse. The banner offers a fresh login, which rebuilds every
    // provider; IndexedDB keeps whatever was edited meanwhile.
    try { provider.disconnect(); } catch { /* already gone */ }
  });
  // A connect that fails may be the relay's 409 for a stale restore epoch,
  // which the browser cannot read: ask for the epoch now (rate-limited), so
  // the tab reloads in seconds rather than at the next 30 s poll.
  const onConnectFailed = () => {
    if (useConnectionStore.getState().status !== 'connected') void checkRestoreEpochNow();
  };
  provider.on('connection-close', onConnectFailed);
  provider.on('connection-error', onConnectFailed);

  // "Ready" = local IndexedDB has loaded its cached state into the doc
  // AND the websocket has finished its initial sync with the server (or
  // we've waited a short grace period for the server to respond). An
  // IndexedDB that cannot open counts as loaded-with-nothing: the app runs
  // from memory and the server, and the banner says the offline cache is off.
  const whenIdb = whenIdbLoaded(persistence, markIdbUnavailable).then(() => undefined);
  const whenWs = new Promise<void>((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      resolve();
    };
    provider.on('sync', (synced: boolean) => { if (synced) finish(); });
    provider.on('status', (e: { status: string }) => {
      // If we connect but never receive a sync event (e.g. server has no
      // state for this room), treat "connected" as ready after a moment.
      if (e.status === 'connected') setTimeout(finish, 250);
    });
    // Hard cap so a broken/missing server doesn't block the UI forever.
    setTimeout(finish, 4000);
  });

  const whenReady = Promise.all([whenIdb, whenWs]).then(() => undefined);

  ctx = { doc, persistence, provider, tables, texts, whenReady };

  // Wire the Y.Text -> JSON snapshot mirror so sidebar/tab labels/search
  // see authoritative text values without each consumer having to know
  // about Y.Text. Done lazily after `ctx` is assigned so the helper can
  // safely call getSharedDoc().
  mirrorTextsToRecords();

  // Once the doc has fully synced (IDB + WS), seed any missing Y.Texts
  // for records that were created before the Y.Text registry existed
  // (or by clients that didn't pre-seed). Without this, those records'
  // text fields silently fall back to last-writer-wins on the JSON map
  // and concurrent edits drop characters.
  // Gated on a real provider sync, never on whenReady (invariant 1).
  const c = ctx;
  const migrate = () => {
    void whenIdb.then(() => {
      if (ctx !== c) return;
      seedMissingYTexts(c);
      scrubEmojiIcons(c);
    });
  };
  if (provider.synced) migrate();
  else {
    const onSync = (synced: boolean) => {
      if (!synced) return;
      provider.off('sync', onSync);
      migrate();
    };
    provider.on('sync', onSync);
  }
  scheduleMirrorReconcile(ctx);

  return ctx;
}

/**
 * One-shot migration: walks every page in the shared doc and clears the
 * `icon` field if it contains any character outside ASCII (the regex is
 * /[^\x00-\x7F]/, so Latin-1 letters go too). Pages created by legacy seed data shipped with emoji
 * icons (clipboard, magnifier, bug, etc.); the current theme has no
 * place for them. Runs each time the doc loads and is idempotent: once every
 * record has icon === '' nothing further happens. It also clears emoji
 * icons that come back from a backup, an older ZIP or the API, in every
 * workspace: a product decision (README invariant 57), not a defect.
 *
 * Safe across clients: writes go through the shared Yjs map, so every
 * connected peer converges on the cleared state via standard CRDT
 * merge. Single-character ASCII icons (e.g. an explicit 'H') are
 * preserved.
 */
function scrubEmojiIcons(c: SharedDocContext): void {
  const pageMap = c.tables['pages'];
  const NON_ASCII = /[^\x00-\x7F]/;
  c.doc.transact(() => {
    for (const [id, raw] of pageMap.entries()) {
      if (!raw || typeof raw !== 'object') continue;
      const rec = raw as Record<string, unknown>;
      const icon = rec['icon'];
      if (typeof icon === 'string' && icon.length > 0 && NON_ASCII.test(icon)) {
        pageMap.set(id, { ...rec, icon: '' });
      }
    }
  });
}

/**
 * Tear down the shared Y.Doc and its providers. Call this on logout (and
 * defensively on login) so the next session rebuilds everything with the
 * current auth token. Without this, the WebsocketProvider keeps the old
 * token baked into its query string and the new session's edits never
 * propagate to other peers.
 */
export function disposeSharedDoc(): void {
  if (!ctx) return;
  const c = ctx;
  ctx = null;
  mirrorBound = false;
  unbindStatus?.();
  unbindStatus = null;
  try { c.provider.disconnect(); } catch { /* ignore */ }
  try { c.provider.destroy(); } catch { /* ignore */ }
  try { c.persistence.destroy(); } catch { /* ignore */ }
  try { c.doc.destroy(); } catch { /* ignore */ }
}

// ─────────────────────────────────────────────────────────────────────────
// Y.Text registry
// ─────────────────────────────────────────────────────────────────────────

/**
 * Build the canonical key for a collaborative text field. We use a flat
 * namespace (`page:<id>:title`) rather than nested Y.Maps so it's cheap
 * to enumerate and reason about, and so individual Y.Texts can be created
 * lazily without restructuring the parent record.
 */
export function textKey(entity: string, id: string, field: string): string {
  return `${entity}:${id}:${field}`;
}

/**
 * Get-or-create the Y.Text for a given key. If the Y.Text doesn't exist
 * yet, it's seeded with `initial`. The init is wrapped in a transaction
 * and double-checks the map to avoid the common "two clients race to
 * create" footgun (last-writer wins on the map slot, but at least the
 * losing client's reference is then re-read so its observers fire on
 * the surviving Y.Text).
 */
export function getOrInitYText(key: string, initial: string): Y.Text {
  const c = getSharedDoc();
  let t = c.texts.get(key);
  if (t) return t;
  sharedTransact(() => {
    t = c.texts.get(key);
    if (!t) {
      t = new Y.Text();
      if (initial) t.insert(0, initial);
      c.texts.set(key, t);
    }
  });
  // After the transaction, re-fetch: another peer may have set a
  // different Y.Text into the slot.
  return c.texts.get(key) ?? t!;
}

/**
 * Programmatically set a collaborative text field to `value`.
 *
 * Repos MUST call this (not just `db.table.update`) whenever they change a
 * field that is registered as a Y.Text in `TEXT_FIELDS_BY_ENTITY`. The mirror
 * observer treats the Y.Text as the source of truth and copies it back into the
 * JSON record, so a record-only write is silently reverted on the next sync
 * (e.g. a hard reload). This keeps the two in agreement.
 *
 * The write is a **minimal common-prefix/suffix splice**, never a
 * clear-and-reinsert (invariant #3b), so a concurrent typist in the same field
 * keeps their caret and the edit stays mergeable.
 */
export function setYTextValue(entity: string, id: string, field: string, value: string): void {
  const t = getOrInitYText(textKey(entity, id, field), value);
  const cur = t.toString();
  if (cur === value) return;
  let start = 0;
  const min = Math.min(cur.length, value.length);
  while (start < min && cur.charCodeAt(start) === value.charCodeAt(start)) start++;
  let curEnd = cur.length;
  let valEnd = value.length;
  while (curEnd > start && valEnd > start && cur.charCodeAt(curEnd - 1) === value.charCodeAt(valEnd - 1)) {
    curEnd--;
    valEnd--;
  }
  sharedTransact(() => {
    if (curEnd - start > 0) t.delete(start, curEnd - start);
    if (valEnd - start > 0) t.insert(start, value.slice(start, valEnd));
  });
}

/**
 * Subscribe to remote changes on a specific table. The callback fires
 * whenever the Y.Map changes (local or remote). Returns an unsubscribe
 * function.
 */
/**
 * What a table observer learns about one change burst: which record ids
 * changed (with the delete's old value) and a reader for their current
 * state. Lets a subscriber scope its reload instead of rescanning
 * everything (see the nmapMachines binding).
 */
export interface TableEvent {
  keys: Map<string, { action: 'add' | 'update' | 'delete'; oldValue?: unknown }>;
  current: (key: string) => unknown;
}

export function subscribeTable(name: TableName, fn: (e: TableEvent) => void): () => void {
  const c = getSharedDoc();
  const map = c.tables[name];
  const handler = (event: Y.YMapEvent<unknown>) => fn({
    keys: event.changes.keys as TableEvent['keys'],
    current: (key) => map.get(key),
  });
  map.observe(handler);
  return () => map.unobserve(handler);
}

/**
 * Wrap a series of writes in a Yjs transaction so observers fire once.
 */
export function sharedTransact<T>(fn: () => T): T {
  const c = getSharedDoc();
  let result: T;
  c.doc.transact(() => { result = fn(); });
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  return result!;
}

// ─────────────────────────────────────────────────────────────────────────
// Y.Text -> JSON record mirror
// ─────────────────────────────────────────────────────────────────────────

/**
 * Maps "<entity>:<id>:<field>" → which JSON table the snapshot lives in.
 * Add new collaborative text fields here.
 */
const TEXT_FIELD_TO_TABLE: Record<string, TableName> = {
  page: 'pages',
  workspace: 'workspaces',
  nmapScan: 'nmapScans',
  nmapMachine: 'nmapMachines',
};

let mirrorBound = false;

/**
 * Watch every Y.Text in the `texts` map (deeply, so we catch insert/delete
 * deltas too) and write the resulting plain string back into the matching
 * JSON record snapshot. This keeps `pages.title`, `graphNodes.label`,
 * `nmapMachines.hostname`, etc. consistent with the authoritative Y.Text
 * for any code that just reads those strings (sidebar tree, tab labels,
 * search index, exports).
 */
function mirrorTextsToRecords() {
  if (mirrorBound) return;
  mirrorBound = true;
  const c = ctx;
  if (!c) return;

  const writeBack = (key: string) => { writeTextToRecord(c, key); };

  // Each keystroke used to rewrite the whole record (content markdown
  // included) straight away, so a title edit re-broadcast the page body per
  // character; the Y.Text already drives the input, so the JSON mirror can
  // trail by a beat. One trailing timer per key coalesces a typing burst.
  const pending = new Map<string, number>();
  const schedule = (key: string) => {
    if (pending.has(key)) return;
    pending.set(key, window.setTimeout(() => {
      pending.delete(key);
      writeBack(key);
    }, 150));
  };

  // observeDeep fires for any nested Y.Text change (insert/delete) AND
  // for additions/removals of Y.Texts in the parent map.
  //
  // Only the client whose transaction changed the text writes the record.
  // A bystander used to write it too, from its own copy of the record, and
  // when that copy predated the typist's latest body save and the
  // bystander's client id won the merge, record.content went back to the
  // older body for everyone (and N bystanders meant N whole-record
  // broadcasts per rename).
  c.texts.observeDeep((events, transaction) => {
    if (!transaction.local) return;
    for (const key of touchedTextKeys(events)) schedule(key);
  });
}

/** The `texts` keys a batch of observeDeep events touched. */
export function touchedTextKeys(events: Array<Y.YEvent<Y.AbstractType<unknown>>>): Set<string> {
  const touched = new Set<string>();
  for (const ev of events) {
    // For changes inside a Y.Text, ev.target is that Y.Text; its key in
    // the parent map is `ev.path[0]`.
    const path = ev.path;
    if (path.length > 0 && typeof path[0] === 'string') {
      touched.add(path[0]);
    }
    // For top-level adds/removes on the texts map, ev.changes.keys has the keys.
    if (path.length === 0 && 'keys' in ev.changes) {
      for (const k of ev.changes.keys.keys()) touched.add(k);
    }
  }
  return touched;
}

/**
 * Copy one Y.Text into its record's field, and only that field, if they
 * differ. Returns true when it wrote.
 */
export function writeTextToRecord(c: Pick<SharedDocContext, 'texts' | 'tables' | 'doc'>, key: string): boolean {
  const t = c.texts.get(key);
  if (!t) return false;
  const [entity, id, field] = key.split(':');
  if (!entity || !id || !field) return false;
  const table = TEXT_FIELD_TO_TABLE[entity];
  if (!table) return false;
  const map = c.tables[table];
  const cur = map.get(id) as Record<string, unknown> | undefined;
  if (!cur) return false;
  const value = t.toString();
  if (cur[field] === value) return false;
  c.doc.transact(() => {
    map.set(id, { ...cur, [field]: value, updatedAt: Date.now() });
  });
  return true;
}

/**
 * Once after the first real sync, mend records whose text field disagrees
 * with its Y.Text. With write-back limited to the typing client, a typist
 * who closed the tab inside the 150 ms window would otherwise leave the
 * record's title stale until the next edit. Waits a moment past the sync so
 * write-backs already in flight from other clients land first, and only
 * touches fields that still disagree then.
 */
const RECONCILE_DELAY_MS = 3000;
function scheduleMirrorReconcile(c: SharedDocContext): void {
  const run = () => {
    window.setTimeout(() => {
      if (ctx !== c) return;
      for (const key of Array.from(c.texts.keys())) writeTextToRecord(c, key);
    }, RECONCILE_DELAY_MS);
  };
  if (c.provider.synced) { run(); return; }
  const onSync = (synced: boolean) => {
    if (!synced) return;
    c.provider.off('sync', onSync);
    run();
  };
  c.provider.on('sync', onSync);
}

// ─────────────────────────────────────────────────────────────────────────
// Y.Text migration / pre-seeding
// ─────────────────────────────────────────────────────────────────────────

/**
 * Which JSON fields on each table are collaborative Y.Texts. This drives
 * both create-time pre-seeding (in repos) and the post-sync migration
 * pass below.
 */
export const TEXT_FIELDS_BY_ENTITY: Record<string, { table: TableName; fields: string[] }> = {
  page:        { table: 'pages',        fields: ['title', 'slug'] },
  workspace:   { table: 'workspaces',   fields: ['name'] },
  nmapScan:    { table: 'nmapScans',    fields: ['name'] },
  nmapMachine: { table: 'nmapMachines', fields: ['hostname'] },
};

/**
 * Walk every record in every table and create a Y.Text for any missing
 * `<entity>:<id>:<field>` slot, seeding it from the JSON snapshot. This
 * runs once per session after the initial sync completes, ensuring that
 * records created in older releases (when Y.Text fields didn't exist
 * yet) get migrated lazily without requiring a server-side rewrite.
 */
export function seedMissingYTexts(c: SharedDocContext): void {
  c.doc.transact(() => {
    for (const [entity, info] of Object.entries(TEXT_FIELDS_BY_ENTITY)) {
      const map = c.tables[info.table];
      for (const [id, raw] of map.entries()) {
        if (!raw || typeof raw !== 'object') continue;
        const rec = raw as Record<string, unknown>;
        for (const field of info.fields) {
          const key = textKey(entity, String(id), field);
          if (c.texts.has(key)) continue;
          const val = rec[field];
          const t = new Y.Text();
          if (typeof val === 'string' && val.length > 0) t.insert(0, val);
          c.texts.set(key, t);
        }
      }
    }
  });
}
