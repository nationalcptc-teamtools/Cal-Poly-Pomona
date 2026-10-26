// "Copy image with blur" on a note image's right-click menu, and the two
// halves of the plain-http path: the HTML form copyImage writes there, and
// the note paste that turns that HTML back into an uploaded image.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';
import { useAppStore } from '@/stores';
import { AssetImageEditor } from '@/components/editor/AssetImageEditor';
import { copyImage } from '@/lib/clipboard';
import { dataImageFileFrom } from '@/lib/note-image-paste';
import type { TypstAsset } from '@/types';

const PNG_B64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

function imageAsset(id: string, kind: TypstAsset['kind'] = 'image'): TypstAsset {
  return { id, kind, filename: `${id}.png` } as unknown as TypstAsset;
}

beforeEach(() => {
  cleanup();
  useAppStore.setState({ imageMenu: null, editingAssetId: null, typstAssets: [] });
});

describe('the note image menu', () => {
  it('offers Copy image with blur for an image asset', () => {
    useAppStore.setState({ typstAssets: [imageAsset('a1')], imageMenu: { x: 1, y: 2, assetId: 'a1' } });
    render(<AssetImageEditor />);
    expect(screen.getByText('Copy image with blur')).toBeInTheDocument();
  });

  it('leaves it out while the asset record is unknown', () => {
    useAppStore.setState({ typstAssets: [], imageMenu: { x: 1, y: 2, assetId: 'gone' } });
    render(<AssetImageEditor />);
    expect(screen.queryByText('Copy image with blur')).toBeNull();
    expect(screen.getByText('Blur / edit image')).toBeInTheDocument();
  });
});

describe('copyImage over plain http', () => {
  let written: Record<string, string> = {};
  beforeEach(() => {
    written = {};
    Object.defineProperty(window, 'isSecureContext', { value: false, configurable: true });
    (document as unknown as { execCommand: (c: string) => boolean }).execCommand = vi.fn(() => {
      const ev = new Event('copy', { cancelable: true }) as ClipboardEvent;
      Object.defineProperty(ev, 'clipboardData', { value: { setData: (t: string, v: string) => { written[t] = v; } } });
      document.dispatchEvent(ev);
      return true;
    });
  });
  afterEach(() => {
    delete (document as unknown as { execCommand?: unknown }).execCommand;
  });

  it('writes the picture as an HTML data: image and says so', async () => {
    const png = new Blob([Uint8Array.from(atob(PNG_B64), (c) => c.charCodeAt(0))], { type: 'image/png' });
    expect(await copyImage(png, 'shot "1".png')).toBe('html');
    expect(written['text/html']).toMatch(/^<img src="data:image\/png;base64,[A-Za-z0-9+/=]+" alt="shot &quot;1&quot;.png">$/);
  });

  it('reports false when the copy event never fires', async () => {
    (document as unknown as { execCommand: () => boolean }).execCommand = () => false;
    expect(await copyImage(new Blob(['x'], { type: 'image/png' }))).toBe(false);
  });
});

describe('pasting a copied HTML image into a note', () => {
  it('turns a lone data: image into a file to upload', () => {
    const f = dataImageFileFrom(`<meta charset="utf-8"><img src="data:image/png;base64,${PNG_B64}" alt="x">`);
    expect(f?.type).toBe('image/png');
    expect(f?.name).toBe('pasted-image.png');
    expect(f?.size).toBeGreaterThan(60);
  });

  it('leaves rich text with an image in it to the normal paste', () => {
    expect(dataImageFileFrom(`<p>See this</p><img src="data:image/png;base64,${PNG_B64}">`)).toBeNull();
  });

  it('ignores remote images and SVG data', () => {
    expect(dataImageFileFrom('<img src="https://example.com/a.png">')).toBeNull();
    expect(dataImageFileFrom('<img src="data:image/svg+xml;base64,PHN2Zz4=">')).toBeNull();
  });
});
