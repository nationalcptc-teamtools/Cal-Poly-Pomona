import { describe, it, expect } from 'vitest';
import {
  ENCODABLE_FORMATS,
  extensionForFormat,
  formatFromFilename,
  formatFromMime,
  mimeForFormat,
  reencodeTargetFor,
  sniffImageFormat,
} from '@/lib/image-format';

const bytes = (...parts: (number[] | string)[]): Uint8Array => {
  const out: number[] = [];
  for (const p of parts) {
    if (typeof p === 'string') out.push(...[...p].map((c) => c.charCodeAt(0)));
    else out.push(...p);
  }
  return new Uint8Array(out);
};

const PNG = bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], [0, 0, 0, 0]);
const JPEG = bytes([0xff, 0xd8, 0xff, 0xe0], 'JFIF');
const GIF = bytes('GIF89a', [0, 0, 0, 0]);
const WEBP = bytes('RIFF', [0, 0, 0, 0], 'WEBP', [0, 0, 0, 0]);
const SVG_XML = bytes('<?xml version="1.0"?><svg></svg>');
const SVG_BARE = bytes('   <svg xmlns="http://www.w3.org/2000/svg"></svg>');
const SVG_BOM = bytes([0xef, 0xbb, 0xbf], '<svg></svg>');

describe('sniffImageFormat', () => {
  it('identifies each supported format by magic number', () => {
    expect(sniffImageFormat(PNG)).toBe('png');
    expect(sniffImageFormat(JPEG)).toBe('jpeg');
    expect(sniffImageFormat(GIF)).toBe('gif');
    expect(sniffImageFormat(WEBP)).toBe('webp');
  });

  it('recognizes SVG with an xml declaration, bare, or behind a BOM', () => {
    expect(sniffImageFormat(SVG_XML)).toBe('svg');
    expect(sniffImageFormat(SVG_BARE)).toBe('svg');
    expect(sniffImageFormat(SVG_BOM)).toBe('svg');
  });

  it('does not mistake a bare RIFF container for WebP', () => {
    expect(sniffImageFormat(bytes('RIFF', [0, 0, 0, 0], 'WAVE', [0, 0, 0, 0]))).toBeNull();
  });

  it('returns null for unrecognized or truncated data', () => {
    expect(sniffImageFormat(bytes('not an image at all'))).toBeNull();
    expect(sniffImageFormat(bytes([1, 2]))).toBeNull();
    expect(sniffImageFormat(new Uint8Array(0))).toBeNull();
  });
});

describe('filename and mime mapping', () => {
  it('maps both jpeg spellings, case-insensitively', () => {
    expect(formatFromFilename('a.jpg')).toBe('jpeg');
    expect(formatFromFilename('a.jpeg')).toBe('jpeg');
    expect(formatFromFilename('a.JPEG')).toBe('jpeg');
  });

  it('maps the remaining extensions', () => {
    expect(formatFromFilename('shot.png')).toBe('png');
    expect(formatFromFilename('anim.gif')).toBe('gif');
    expect(formatFromFilename('pic.webp')).toBe('webp');
    expect(formatFromFilename('logo.svg')).toBe('svg');
  });

  it('returns null when there is no usable extension', () => {
    expect(formatFromFilename('noextension')).toBeNull();
    expect(formatFromFilename('archive.zip')).toBeNull();
  });

  it('round-trips format → mime → format', () => {
    for (const f of ['png', 'jpeg', 'gif', 'webp', 'svg'] as const) {
      expect(formatFromMime(mimeForFormat(f))).toBe(f);
    }
  });

  it('tolerates the non-standard image/jpg', () => {
    expect(formatFromMime('image/jpg')).toBe('jpeg');
  });

  it('round-trips format → extension → format', () => {
    for (const f of ['png', 'jpeg', 'gif', 'webp', 'svg'] as const) {
      expect(formatFromFilename(`x${extensionForFormat(f)}`)).toBe(f);
    }
  });

  it('excludes formats a canvas cannot produce', () => {
    expect(ENCODABLE_FORMATS.has('gif')).toBe(false);
    expect(ENCODABLE_FORMATS.has('svg')).toBe(false);
    expect(ENCODABLE_FORMATS.has('png')).toBe(true);
    expect(ENCODABLE_FORMATS.has('jpeg')).toBe(true);
    expect(ENCODABLE_FORMATS.has('webp')).toBe(true);
  });
});

describe('reencodeTargetFor', () => {
  // The regression this whole module exists for: cropping re-encoded to PNG
  // but mounted the result at the original `.jpg` path, and Typst picks its
  // decoder from the extension, producing "Illegal start bytes: 8950"
  // (0x8950 being the PNG magic number) at compile time.
  it('demands a jpeg re-encode for PNG bytes at a .jpg path', () => {
    expect(reencodeTargetFor('screenshot.jpg', 'png')).toBe('jpeg');
  });

  it('demands a png re-encode for JPEG bytes at a .png path', () => {
    expect(reencodeTargetFor('screenshot.png', 'jpeg')).toBe('png');
  });

  it('leaves bytes alone when they already match the extension', () => {
    expect(reencodeTargetFor('a.png', 'png')).toBeNull();
    expect(reencodeTargetFor('a.jpg', 'jpeg')).toBeNull();
    expect(reencodeTargetFor('a.jpeg', 'jpeg')).toBeNull();
    expect(reencodeTargetFor('a.webp', 'webp')).toBeNull();
  });

  it('leaves formats a canvas cannot produce alone, even when mismatched', () => {
    expect(reencodeTargetFor('anim.gif', 'png')).toBeNull();
    expect(reencodeTargetFor('logo.svg', 'png')).toBeNull();
  });

  it('leaves unidentifiable bytes alone rather than guessing', () => {
    expect(reencodeTargetFor('mystery.gif', null)).toBeNull();
  });

  it('still targets the extension when the contents are unreadable but encodable', () => {
    // A corrupt upload named .png: re-encoding will fail loudly at decode
    // time, which is better than silently mounting bytes Typst can't read.
    expect(reencodeTargetFor('broken.png', null)).toBe('png');
  });

  it('returns null for a file with no extension at all', () => {
    expect(reencodeTargetFor('noextension', 'png')).toBeNull();
  });
});
