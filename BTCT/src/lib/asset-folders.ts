// ─────────────────────────────────────────────────────────────────────────
// Pure helpers for the asset folder hierarchy.
//
// Folders are organizational only: an asset keeps its flat `/assets/<name>`
// path in the compiler's virtual filesystem no matter where it sits in the
// tree, so moving or renaming folders can never break a document reference.
// Records are plain LWW JSON (no Y.Text fields), like `typstAssets`.
//
// Also home to the preview-to-panel matching: the rendered SVG embeds each
// image as a base64 data URI of exactly the bytes we mounted, so comparing
// the first few dozen bytes identifies which asset a clicked figure shows.
//
// DOM-free and side-effect-free so everything here unit-tests directly.
// ─────────────────────────────────────────────────────────────────────────

import type { AssetFolder, ID, TypstAsset } from '@/types';

/** Stable display order: by name (case-insensitive), ties by creation time. */
export function sortFolders(folders: AssetFolder[]): AssetFolder[] {
  return [...folders].sort((a, b) => {
    const byName = a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
    return byName !== 0 ? byName : a.createdAt - b.createdAt;
  });
}

/** Direct children of `parentId` (null = root), sorted for display. */
export function childFolders(folders: AssetFolder[], parentId: ID | null): AssetFolder[] {
  return sortFolders(folders.filter((f) => (f.parentId ?? null) === (parentId ?? null)));
}

/**
 * True when `folderId` sits inside `ancestorId`'s subtree (or is it).
 * Used as the cycle guard before re-parenting: a folder may never be moved
 * into itself or one of its descendants. Bounded by the folder count so a
 * corrupt parent cycle in synced data can't loop forever.
 */
export function isDescendantFolder(
  folders: AssetFolder[],
  folderId: ID,
  ancestorId: ID,
): boolean {
  const byId = new Map(folders.map((f) => [f.id, f]));
  let current: ID | null | undefined = folderId;
  for (let hops = 0; hops <= folders.length; hops++) {
    if (current == null) return false;
    if (current === ancestorId) return true;
    current = byId.get(current)?.parentId;
  }
  return false; // parent cycle: treat as unrelated rather than spinning
}

/** Root-to-folder trail for breadcrumbs. Empty for null/unknown ids. */
export function folderTrail(folders: AssetFolder[], folderId: ID | null): AssetFolder[] {
  if (folderId == null) return [];
  const byId = new Map(folders.map((f) => [f.id, f]));
  const trail: AssetFolder[] = [];
  let current: ID | null | undefined = folderId;
  for (let hops = 0; hops <= folders.length; hops++) {
    if (current == null) break;
    const f = byId.get(current);
    if (!f) break;
    trail.push(f);
    current = f.parentId;
  }
  return trail.reverse();
}

/** Assets sitting directly in `folderId` (null = root). Order preserved. */
export function assetsInFolder<T extends Pick<TypstAsset, 'folderId'>>(
  assets: T[],
  folderId: ID | null,
): T[] {
  return assets.filter((a) => (a.folderId ?? null) === (folderId ?? null));
}

/** Direct asset count per folder id ('' = root), for the tree badges. */
export function assetCountByFolder(
  assets: Array<Pick<TypstAsset, 'folderId'>>,
): Map<string, number> {
  const counts = new Map<string, number>();
  for (const a of assets) {
    const key = a.folderId ?? '';
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

// ── Preview click → asset matching ───────────────────────────────────────

/** Bytes to compare. 48 encodes to exactly 64 base64 chars (no padding). */
const HEAD_BYTES = 48;

/** Base64 of the first `HEAD_BYTES` bytes, for prefix comparison. */
export function base64Head(bytes: Uint8Array): string {
  const head = bytes.subarray(0, HEAD_BYTES);
  let bin = '';
  for (let i = 0; i < head.length; i++) bin += String.fromCharCode(head[i]!);
  return btoa(bin);
}

/** The base64 payload head of a data URI, or null for anything else. */
export function dataUriHead(href: string): string | null {
  if (!href.startsWith('data:')) return null;
  const comma = href.indexOf(',');
  if (comma === -1 || !href.slice(0, comma).includes('base64')) return null;
  // One base64 char short of the head length so a shorter-than-HEAD_BYTES
  // payload still compares on equal footing.
  return href.slice(comma + 1, comma + 1 + 64);
}

/**
 * Which asset a rendered `<image>`'s data URI shows. `resolve` is injected
 * (lib/typst-assets `resolveAssetBytes`, which caches) so this stays pure
 * and testable. Compares the first bytes of each candidate's *rendered*
 * bytes, which are exactly what the compiler embedded into the SVG.
 */
export async function matchAssetByHref<T extends TypstAsset>(
  href: string,
  assets: T[],
  resolve: (asset: T) => Promise<Uint8Array>,
): Promise<T | null> {
  const head = dataUriHead(href);
  if (!head || head.length < 16) return null;
  for (const asset of assets) {
    try {
      const mine = base64Head(await resolve(asset));
      const n = Math.min(mine.length, head.length);
      if (n >= 16 && mine.slice(0, n) === head.slice(0, n)) return asset;
    } catch {
      // Missing bytes: this asset simply can't match.
    }
  }
  return null;
}
