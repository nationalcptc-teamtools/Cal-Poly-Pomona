import { describe, it, expect, vi, beforeEach } from 'vitest';
import JSZip from 'jszip';
import type { TypstAsset } from '@/types';

const rendered = vi.fn(async (a: TypstAsset) => Uint8Array.from(new TextEncoder().encode(`rendered:${a.id}`)));
const original = vi.fn(async (id: string) => Uint8Array.from(new TextEncoder().encode(`original:${id}`)));
const saved: { blob: Blob; name: string }[] = [];

vi.mock('@/lib/assets', () => ({
  resolveAssetBytes: (a: TypstAsset) => rendered(a),
  fetchAssetBytesUncached: (id: string) => original(id),
}));
vi.mock('@/lib/download', () => ({
  downloadBlob: async (blob: Blob, name: string) => { saved.push({ blob, name }); return 'downloaded'; },
}));

const { exportReport } = await import('@/components/typst/report-bundle-io');

function asset(over: Partial<TypstAsset>): TypstAsset {
  return {
    id: 'a', workspaceId: 'w', kind: 'image', filename: 'x.png', mime: 'image/png', size: 1,
    width: null, height: null, crop: null, blurs: null, fontFamily: null, folderId: null,
    createdAt: 0, updatedAt: 0, ...over,
  } as TypstAsset;
}

async function blobBuffer(b: Blob): Promise<ArrayBuffer> {
  return typeof b.arrayBuffer === 'function' ? b.arrayBuffer() : new Response(b).arrayBuffer();
}

describe('exportReport', () => {
  beforeEach(() => { saved.length = 0; rendered.mockClear(); original.mockClear(); });

  it('writes the template layout with rendered images and every font', async () => {
    const at = new Date(2026, 9, 20, 9, 5);
    const source = '#let cover = "assets/cover.png"\n#image("/assets/shot.png")\n#image("/assets/gone.png")';
    const assets = [
      asset({ id: 'c', filename: 'cover.png' }),
      asset({ id: 's', filename: 'shot.png', blurs: [{ x: 0, y: 0, w: 1, h: 1 }] as TypstAsset['blurs'] }),
      asset({ id: 'u', filename: 'unused.png' }),
      asset({ id: 'f', kind: 'font', filename: 'Poppins-Bold.ttf', mime: 'font/ttf' }),
    ];
    const res = await exportReport(source, assets, 'Team 3', at);
    expect(res).toMatchObject({ fileName: 'Team 3_2026-10-20_0905_report.zip', images: 2, fonts: 1, missing: ['gone.png'] });
    const zip = await JSZip.loadAsync(await blobBuffer(saved[0]!.blob));
    const root = 'Team 3_2026-10-20_0905_report';
    expect(Object.keys(zip.files).filter((n) => !zip.files[n]!.dir).sort()).toEqual([
      `${root}/assets/cover.png`, `${root}/assets/shot.png`, `${root}/fonts/Poppins-Bold.ttf`, `${root}/main.typ`,
    ]);
    expect(await zip.file(`${root}/main.typ`)!.async('string')).toBe(source);
    // Redactions travel baked: the image bytes are the render, never the upload.
    expect(await zip.file(`${root}/assets/shot.png`)!.async('string')).toBe('rendered:s');
    expect(original).toHaveBeenCalledTimes(1);
    expect(original).toHaveBeenCalledWith('f');
  });

  it('refuses to fall back to the original when a render fails', async () => {
    rendered.mockRejectedValueOnce(new Error('decode failed'));
    await expect(exportReport('"assets/x.png"', [asset({})], 'W')).rejects.toThrow(/nothing was exported/);
    expect(saved).toHaveLength(0);
  });
});
