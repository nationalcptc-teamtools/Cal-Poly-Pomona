import { describe, it, expect } from 'vitest';
import {
  assetLink,
  findAssetLinks,
  parseAssetLinkList,
  extractAssetLinks,
  assetTypstSnippet,
} from '@/lib/asset-link';
import { findScreenshotSlots } from '@/lib/typst-placeholders';

const A = '0f8fad5b-d9cb-469f-a165-70867728950e';
const B = '7c9e6679-7425-40de-944b-e07fc1f90ae7';

describe('asset links', () => {
  it('formats a link from the asset id', () => {
    expect(assetLink(A)).toBe(`btct-asset:${A}`);
  });

  it('finds links inside text', () => {
    const text = `see btct-asset:${A} and btct-asset:${B}.`;
    expect(findAssetLinks(text).map((l) => l.id)).toEqual([A, B]);
    expect(text.slice(findAssetLinks(text)[0]!.start, findAssetLinks(text)[0]!.end)).toBe(assetLink(A));
  });

  it('recognises a paste that is only links', () => {
    expect(parseAssetLinkList(`  btct-asset:${A}\n`)).toEqual([A]);
    expect(parseAssetLinkList(`btct-asset:${A}, btct-asset:${B}`)).toEqual([A, B]);
    expect(parseAssetLinkList(`look at btct-asset:${A}`)).toBeNull();
    expect(parseAssetLinkList('plain text')).toBeNull();
    expect(parseAssetLinkList('btct-asset:')).toBeNull();
  });

  it('extracts known links and leaves unknown ones in the text', () => {
    const known = (id: string) => id === A;
    const out = extractAssetLinks(`Logged in. btct-asset:${A} Then btct-asset:${B}`, known);
    expect(out.ids).toEqual([A]);
    expect(out.text).toBe(`Logged in. Then btct-asset:${B}`);
    expect(extractAssetLinks('nothing here', known)).toEqual({ text: 'nothing here', ids: [] });
  });

  it('builds a filled figure slot the report already understands', () => {
    const snippet = assetTypstSnippet({ filename: 'admin "panel".png' });
    expect(snippet).toBe('#image-placeholder("admin \\"panel\\"", path: "/assets/admin \\"panel\\".png")');
    const slot = findScreenshotSlots(snippet)[0]!;
    expect(slot.caption).toBe('admin "panel"');
    expect(slot.path).toBe('/assets/admin "panel".png');
  });
});
