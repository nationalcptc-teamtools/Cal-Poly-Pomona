import { describe, it, expect } from 'vitest';
import {
  assetCountByFolder,
  assetsInFolder,
  base64Head,
  childFolders,
  dataUriHead,
  folderTrail,
  isDescendantFolder,
  matchAssetByHref,
  sortFolders,
} from '@/lib/asset-folders';
import type { AssetFolder, TypstAsset } from '@/types';

function folder(id: string, name: string, parentId: string | null = null): AssetFolder {
  return { id, name, parentId, workspaceId: 'ws', createdAt: Number(id.replace(/\D/g, '') || 0), updatedAt: 0 };
}

const TREE: AssetFolder[] = [
  folder('f1', 'Findings'),
  folder('f2', 'Auth bypass', 'f1'),
  folder('f3', 'SQLi', 'f1'),
  folder('f4', 'Appendix'),
  folder('f5', 'Screens', 'f2'),
];

describe('folder tree helpers', () => {
  it('sorts by name then creation time', () => {
    expect(sortFolders([folder('f2', 'b'), folder('f1', 'A'), folder('f3', 'b')]).map((f) => f.id))
      .toEqual(['f1', 'f2', 'f3']);
  });

  it('lists direct children only', () => {
    expect(childFolders(TREE, null).map((f) => f.name)).toEqual(['Appendix', 'Findings']);
    expect(childFolders(TREE, 'f1').map((f) => f.name)).toEqual(['Auth bypass', 'SQLi']);
    expect(childFolders(TREE, 'f5')).toEqual([]);
  });

  it('detects descendants including self, and never loops on a parent cycle', () => {
    expect(isDescendantFolder(TREE, 'f5', 'f1')).toBe(true);
    expect(isDescendantFolder(TREE, 'f5', 'f5')).toBe(true);
    expect(isDescendantFolder(TREE, 'f1', 'f5')).toBe(false);
    expect(isDescendantFolder(TREE, 'f4', 'f1')).toBe(false);
    const cyclic = [folder('a', 'a', 'b'), folder('b', 'b', 'a')];
    expect(isDescendantFolder(cyclic, 'a', 'zzz')).toBe(false);
  });

  it('builds the breadcrumb trail root-first', () => {
    expect(folderTrail(TREE, 'f5').map((f) => f.name)).toEqual(['Findings', 'Auth bypass', 'Screens']);
    expect(folderTrail(TREE, null)).toEqual([]);
    expect(folderTrail(TREE, 'ghost')).toEqual([]);
  });

  it('filters assets by folder, treating absent folderId as root', () => {
    const assets = [
      { folderId: 'f1' }, { folderId: null }, {}, { folderId: 'f1' },
    ] as Array<Pick<TypstAsset, 'folderId'>>;
    expect(assetsInFolder(assets, 'f1').length).toBe(2);
    expect(assetsInFolder(assets, null).length).toBe(2);
    const counts = assetCountByFolder(assets);
    expect(counts.get('f1')).toBe(2);
    expect(counts.get('')).toBe(2);
  });
});

describe('preview image matching', () => {
  const bytesA = new Uint8Array(64).map((_, i) => i);
  const bytesB = new Uint8Array(64).map((_, i) => 255 - i);
  const asset = (id: string): TypstAsset => ({
    id, workspaceId: 'ws', kind: 'image', filename: `${id}.png`, mime: 'image/png',
    size: 64, createdAt: 0, updatedAt: 0,
  });

  it('base64Head matches the head of a full data URI payload', () => {
    let bin = '';
    for (const b of bytesA) bin += String.fromCharCode(b);
    const uri = `data:image/png;base64,${btoa(bin)}`;
    expect(dataUriHead(uri)).toBe(btoa(bin).slice(0, 64));
    expect(dataUriHead(uri)!.startsWith(base64Head(bytesA).slice(0, 60))).toBe(true);
    expect(dataUriHead('https://x/y.png')).toBeNull();
  });

  it('resolves the clicked image to the right asset', async () => {
    let bin = '';
    for (const b of bytesB) bin += String.fromCharCode(b);
    const href = `data:image/png;base64,${btoa(bin)}`;
    const resolve = async (a: TypstAsset) => (a.id === 'b' ? bytesB : bytesA);
    const hit = await matchAssetByHref(href, [asset('a'), asset('b')], resolve);
    expect(hit?.id).toBe('b');
    const miss = await matchAssetByHref('data:image/png;base64,QUJDRA==', [asset('a')], resolve);
    expect(miss).toBeNull();
  });
});
