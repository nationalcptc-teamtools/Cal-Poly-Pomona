/**
 * Repo for image-asset *metadata*. The bytes are never touched here: they
 * live on the server and are fetched/cached by `lib/typst-assets.ts`.
 *
 * Unlike most repos in this directory there are no Y.Text fields to pre-seed.
 * A filename and a crop rectangle are not prose: two people typing into the
 * same filename simultaneously is not a workflow worth supporting, so these
 * stay plain last-writer-wins JSON records and the Y.Text invariant doesn't
 * apply. (See CLAUDE.md "Critical invariants" #1.)
 */
import { db } from './database';
import type { BlurRegion, CropRect, ID, TypstAsset, TypstAssetKind } from '@/types';

export const typstAssetRepo = {
  async getByWorkspace(workspaceId: ID): Promise<TypstAsset[]> {
    const all = await db.typstAssets.where('workspaceId').equals(workspaceId).toArray();
    return all.sort((a, b) => a.createdAt - b.createdAt);
  },

  async getById(id: ID): Promise<TypstAsset | undefined> {
    return db.typstAssets.get(id);
  },

  /**
   * Record an asset that the server has already accepted. `id` comes from
   * the upload response so the record and the blob always agree: we never
   * mint an id client-side for something the server is storing.
   */
  async create(data: {
    id: ID;
    workspaceId: ID;
    kind: TypstAssetKind;
    filename: string;
    mime: string;
    size: number;
    width?: number | null;
    height?: number | null;
    fontFamily?: string | null;
    folderId?: ID | null;
  }): Promise<TypstAsset> {
    const now = Date.now();
    const asset: TypstAsset = {
      id: data.id,
      workspaceId: data.workspaceId,
      kind: data.kind,
      filename: data.filename,
      mime: data.mime,
      size: data.size,
      width: data.width ?? null,
      height: data.height ?? null,
      crop: null,
      blurs: null,
      fontFamily: data.fontFamily ?? null,
      folderId: data.folderId ?? null,
      createdAt: now,
      updatedAt: now,
    };
    await db.typstAssets.add(asset);
    return asset;
  },

  /**
   * Set (or clear, with null) the render-time framing: the crop rectangle
   * and the blurred regions. Both are render-time transforms; the uploaded
   * bytes are never touched.
   */
  async setFraming(
    id: ID,
    framing: { crop: CropRect | null; blurs: BlurRegion[] | null },
  ): Promise<void> {
    await db.typstAssets.update(id, { ...framing, updatedAt: Date.now() });
  },

  async rename(id: ID, filename: string): Promise<void> {
    await db.typstAssets.update(id, { filename, updatedAt: Date.now() });
  },

  /** Move the asset into a folder (null = root). Purely organizational. */
  async setFolder(id: ID, folderId: ID | null): Promise<void> {
    await db.typstAssets.update(id, { folderId, updatedAt: Date.now() });
  },

  /** Soft-delete: hide from the manager but keep the bytes for the retention window. */
  async retire(id: ID): Promise<void> {
    await db.typstAssets.update(id, { deletedAt: Date.now(), updatedAt: Date.now() });
  },

  /** Undo a retire: the asset is referenced by a note again. True if it was retired. */
  async unretire(id: ID): Promise<boolean> {
    const cur = await db.typstAssets.get(id);
    if (!cur || !cur.deletedAt) return false;
    await db.typstAssets.update(id, { deletedAt: null, updatedAt: Date.now() });
    return true;
  },

  async remove(id: ID): Promise<void> {
    await db.typstAssets.delete(id);
  },

  /**
   * True if `filename` is already taken in this workspace by a different
   * asset. Two assets sharing a name would collide on one path,
   * with the second silently shadowing the first.
   */
  async filenameTaken(workspaceId: ID, filename: string, exceptId?: ID): Promise<boolean> {
    return takenFilenames(await db.typstAssets.where('workspaceId').equals(workspaceId).toArray(), exceptId)
      .has(filename.toLowerCase());
  },

  /**
   * Append `-2`, `-3`, … to `filename` until it's free in this workspace.
   * Called before create so dropping two screenshots both named
   * `Screenshot.png` yields `Screenshot.png` and `Screenshot-2.png` rather
   * than one overwriting the other's VFS slot.
   *
   * One scan of the workspace builds the set of taken names; every candidate
   * is then a set lookup. Checking each candidate with its own scan and sort
   * made the 500th clipboard paste named `image.png` cost 500 scans.
   */
  async uniqueFilename(workspaceId: ID, filename: string): Promise<string> {
    const taken = takenFilenames(await db.typstAssets.where('workspaceId').equals(workspaceId).toArray());
    return pickUniqueFilename(taken, filename);
  },
};

/** Lower-cased filenames of `assets`, leaving out `exceptId`. */
export function takenFilenames(assets: Iterable<Pick<TypstAsset, 'id' | 'filename'>>, exceptId?: ID): Set<string> {
  const out = new Set<string>();
  for (const a of assets) {
    if (a.id !== exceptId && typeof a.filename === 'string') out.add(a.filename.toLowerCase());
  }
  return out;
}

/** The first of `name`, `stem-2.ext`, `stem-3.ext`, … not in `taken` (lower-cased names). */
export function pickUniqueFilename(taken: ReadonlySet<string>, filename: string): string {
  if (!taken.has(filename.toLowerCase())) return filename;
  const dot = filename.lastIndexOf('.');
  const stem = dot > 0 ? filename.slice(0, dot) : filename;
  const ext = dot > 0 ? filename.slice(dot) : '';
  for (let n = 2; n < 1000; n++) {
    const candidate = `${stem}-${n}${ext}`;
    if (!taken.has(candidate.toLowerCase())) return candidate;
  }
  return `${stem}-${Date.now()}${ext}`;
}
