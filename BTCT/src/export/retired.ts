import { getSharedDoc } from '@/realtime/shared-doc';

/**
 * Archive compatibility for features that were removed from the app.
 *
 * Nothing here is a live feature: there is no UI, no repo, no observer and
 * no entry in `TABLE_NAMES`, so these maps cost the running app nothing.
 * They exist so a workspace ZIP exported from this build still carries the
 * records an older build wrote (web recon site maps, attack-narrative
 * graphs and their nodes/edges, attack chains, quick-add timeline events),
 * and so importing such a ZIP puts them back where a future archive export
 * can find them again.
 */
export interface RetiredRecord {
  id: string;
  workspaceId?: string;
  siteMapId?: string;
  graphId?: string;
  sourceNodeId?: string;
  targetNodeId?: string;
  linkedPageId?: string | null;
  nodeIds?: string[];
  [key: string]: unknown;
}

export type RetiredTable =
  | 'siteMaps' | 'siteMapNodes' | 'siteMapEdges'
  | 'graphs' | 'graphNodes' | 'graphEdges'
  | 'attackChains' | 'timelineEvents';

export type RetiredData = Record<RetiredTable, RetiredRecord[]>;

/** Every retired table, and how a row is tied back to a workspace. */
const TABLES: Array<{
  name: RetiredTable;
  /** Direct: the row carries `workspaceId`. Parent: it points at a parent row. */
  parent?: { table: RetiredTable; field: 'siteMapId' | 'graphId' };
}> = [
  { name: 'siteMaps' },
  { name: 'siteMapNodes', parent: { table: 'siteMaps', field: 'siteMapId' } },
  { name: 'siteMapEdges', parent: { table: 'siteMaps', field: 'siteMapId' } },
  { name: 'graphs' },
  { name: 'graphNodes', parent: { table: 'graphs', field: 'graphId' } },
  { name: 'graphEdges', parent: { table: 'graphs', field: 'graphId' } },
  { name: 'attackChains' },
  { name: 'timelineEvents' },
];

/** Id-valued fields that must be remapped on import, per table. */
const ID_FIELDS = ['siteMapId', 'graphId', 'sourceNodeId', 'targetNodeId', 'linkedPageId'] as const;

export const RETIRED_TABLES: RetiredTable[] = TABLES.map((t) => t.name);

export function emptyRetired(): RetiredData {
  return Object.fromEntries(RETIRED_TABLES.map((t) => [t, []])) as unknown as RetiredData;
}

export function collectRetired(workspaceId: string): RetiredData {
  const { doc } = getSharedDoc();
  const out = emptyRetired();
  const idsByTable = new Map<RetiredTable, Set<string>>();

  for (const { name, parent } of TABLES) {
    const rows = [...doc.getMap<RetiredRecord>(name).values()];
    const kept = parent
      ? rows.filter((r) => {
          const ref = r[parent.field];
          return typeof ref === 'string' && (idsByTable.get(parent.table)?.has(ref) ?? false);
        })
      : rows.filter((r) => r.workspaceId === workspaceId);
    out[name] = kept;
    idsByTable.set(name, new Set(kept.map((r) => r.id)));
  }
  return out;
}

/**
 * The rows `data` puts back into `workspaceId`, with every id and id-valued
 * field passed through `remap`. Pure, so an importer can write them in
 * chunks of its own choosing.
 */
export function remapRetiredRows(
  data: Partial<RetiredData> | undefined,
  workspaceId: string,
  remap: (id: string) => string,
): Array<{ table: RetiredTable; row: RetiredRecord }> {
  const out: Array<{ table: RetiredTable; row: RetiredRecord }> = [];
  if (!data) return out;
  for (const { name, parent } of TABLES) {
    const rows = data[name];
    if (!rows?.length) continue;
    for (const record of rows) {
      if (!record || typeof record.id !== 'string') continue;
      const copy: RetiredRecord = { ...record, id: remap(record.id) };
      if (!parent) copy.workspaceId = workspaceId;
      for (const field of ID_FIELDS) {
        const value = record[field];
        if (typeof value === 'string') copy[field] = remap(value);
      }
      if (Array.isArray(record.nodeIds)) copy.nodeIds = record.nodeIds.map((v) => (typeof v === 'string' ? remap(v) : v));
      out.push({ table: name, row: copy });
    }
  }
  return out;
}

export function restoreRetired(
  data: Partial<RetiredData> | undefined,
  workspaceId: string,
  remap: (id: string) => string,
): void {
  const rows = remapRetiredRows(data, workspaceId, remap);
  if (!rows.length) return;
  const { doc } = getSharedDoc();
  doc.transact(() => {
    for (const { table, row } of rows) doc.getMap<RetiredRecord>(table).set(row.id, row);
  });
}
