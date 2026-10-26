// Whether one shared-doc asset record may be read off the disk at all.
//
// A `typstAssets` record is plain JSON in the shared doc, so any authenticated
// account can write one, including its `id`. `assetPath(id)` joins that field
// onto ASSETS_DIR, and `path.join('/data/assets', '../data.sqlite')` is the
// database. A record claiming `kind: 'font'` used to skip the reference filter
// and the bake as well, so the file landed verbatim in the compile root where
// `#raw(read("/fonts/x"))` puts it in the document the caller downloads.
//
// Three independent guards, because each covers a different mistake:
//   1. the id has to look exactly like a server-generated one,
//   2. the resolved path has to sit directly inside the asset store,
//   3. the server's own inventory has to have a row for it, and `kind` comes
//      from that row, so "font" means "uploaded as a font", not "claimed as
//      a font". The record stays the source for `filename`, `crop` and
//      `blurs`, which are what the app lets people edit.
//
// Pure: no fs, no db, so src/test covers it through the .d.mts beside this file.
import path from 'node:path';

// server/assets.mjs names every blob with `crypto.randomUUID()`.
const ASSET_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * @param record the `typstAssets` record from the shared doc
 * @param row the `assets` row from server/db.mjs, or null when there is none
 * @param workspaceId the workspace being exported
 * @param assetsDir ASSETS_DIR
 * @returns `{ ok: true, from, kind, name }` or `{ ok: false, reason }`
 */
export function vetAssetRecord(record, row, workspaceId, assetsDir) {
  const id = record && typeof record.id === 'string' ? record.id : '';
  if (!ASSET_ID.test(id)) return { ok: false, reason: 'the id is not a server-generated asset id' };
  if (!row) return { ok: false, reason: 'no such asset in the server inventory' };
  if (row.workspaceId !== workspaceId) return { ok: false, reason: 'the asset belongs to another workspace' };

  // Belt and braces: the regex already rules out a separator, so this can only
  // fire if the regex is ever loosened.
  const dir = path.resolve(assetsDir);
  const from = path.resolve(dir, id);
  if (path.dirname(from) !== dir) return { ok: false, reason: 'the id resolves outside the asset store' };

  const name = path.basename(String(record?.filename ?? row.filename ?? '').replace(/\\/g, '/'));
  if (!name || name === '.' || name === '..' || !name.trim()) {
    return { ok: false, reason: 'the filename does not reduce to a usable name' };
  }
  return { ok: true, from, kind: row.kind === 'font' ? 'font' : 'image', name };
}
