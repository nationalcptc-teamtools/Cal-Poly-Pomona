import { describe, it, expect } from 'vitest';
import { imageSize, looksLikeSvg, svgRefusal } from '../../server/typst/image-size.mjs';

// Dimensions have to come from the header, because the number this guards
// against is the DECODED size: a 6000x6000 PNG encodes to under a megabyte
// and costs gigabytes of RSS to decode.

function png(width: number, height: number, { bitDepth = 8, truncate = 0 } = {}): Uint8Array {
  const buf = new Uint8Array(33 - truncate);
  buf.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 0);
  const view = new DataView(buf.buffer);
  if (buf.length >= 16) {
    view.setUint32(8, 13); // IHDR length
    buf.set([0x49, 0x48, 0x44, 0x52], 12); // "IHDR"
  }
  if (buf.length >= 24) {
    view.setUint32(16, width);
    view.setUint32(20, height);
  }
  if (buf.length >= 25) buf[24] = bitDepth;
  return buf;
}

function jpeg(width: number, height: number, marker = 0xc0): Uint8Array {
  // SOI, a JFIF APP0 to skip over, then the SOFn that carries the size.
  const parts = [0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x00, 0x00, 0xff, marker, 0x00, 0x11, 0x08];
  parts.push((height >> 8) & 0xff, height & 0xff, (width >> 8) & 0xff, width & 0xff);
  return new Uint8Array(parts);
}

// WebP is the format that made this necessary in the first place: a
// 5560-byte 12000x12000 lossless file took typst to a 958 MB working set,
// and the format allows 16383x16383.
function riff(fourcc: string, payload: number): Uint8Array {
  const b = new Uint8Array(20 + payload);
  const put = (at: number, text: string) => { for (let i = 0; i < text.length; i += 1) b[at + i] = text.charCodeAt(i); };
  const le32 = (at: number, v: number) => { b[at] = v & 0xff; b[at + 1] = (v >>> 8) & 0xff; b[at + 2] = (v >>> 16) & 0xff; b[at + 3] = (v >>> 24) & 0xff; };
  put(0, 'RIFF');
  le32(4, b.length - 8);
  put(8, 'WEBP');
  put(12, fourcc);
  le32(16, payload);
  return b;
}

function webpVP8X(width: number, height: number, truncate = 0): Uint8Array {
  const b = riff('VP8X', 10);
  b[20] = 0x10;
  const le24 = (at: number, v: number) => { b[at] = v & 0xff; b[at + 1] = (v >>> 8) & 0xff; b[at + 2] = (v >>> 16) & 0xff; };
  le24(24, width - 1);
  le24(27, height - 1);
  return truncate ? b.slice(0, b.length - truncate) : b;
}

function webpVP8L(width: number, height: number, truncate = 0): Uint8Array {
  const b = riff('VP8L', 9);
  b[20] = 0x2f;
  const packed = (((height - 1) << 14) | (width - 1)) >>> 0;
  b[21] = packed & 0xff;
  b[22] = (packed >>> 8) & 0xff;
  b[23] = (packed >>> 16) & 0xff;
  b[24] = (packed >>> 24) & 0xff;
  return truncate ? b.slice(0, b.length - truncate) : b;
}

function webpVP8(width: number, height: number, truncate = 0): Uint8Array {
  const b = riff('VP8 ', 10);
  b[20] = 0x30; b[21] = 0x01; b[22] = 0x00; // frame tag
  b[23] = 0x9d; b[24] = 0x01; b[25] = 0x2a; // start code
  const le16 = (at: number, v: number) => { b[at] = v & 0xff; b[at + 1] = (v >>> 8) & 0xff; };
  le16(26, width);
  le16(28, height);
  return truncate ? b.slice(0, b.length - truncate) : b;
}

describe('imageSize', () => {
  it('reads a PNG IHDR', () => {
    expect(imageSize(png(6000, 4000))).toEqual({ width: 6000, height: 4000 });
    expect(imageSize(png(1, 1))).toEqual({ width: 1, height: 1 });
  });

  it('reads a JPEG SOF0 past an APP0 segment', () => {
    expect(imageSize(jpeg(1920, 1080))).toEqual({ width: 1920, height: 1080 });
  });

  it('reads the progressive and arithmetic SOF markers too', () => {
    for (const marker of [0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]) {
      expect(imageSize(jpeg(800, 600, marker)), marker.toString(16)).toEqual({ width: 800, height: 600 });
    }
  });

  it('is not fooled by the JPEG markers that are not frame headers', () => {
    // 0xc4 is a Huffman table, 0xc8 is reserved, 0xcc is arithmetic coding.
    for (const marker of [0xc4, 0xc8, 0xcc]) {
      expect(imageSize(jpeg(800, 600, marker)), marker.toString(16)).toBeNull();
    }
  });

  it('reads a GIF logical screen descriptor', () => {
    const gif = new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x40, 0x01, 0xf0, 0x00, 0x00, 0x00, 0x00]);
    expect(imageSize(gif)).toEqual({ width: 320, height: 240 });
  });

  it('returns null for a truncated header', () => {
    expect(imageSize(png(6000, 4000, { truncate: 12 }))).toBeNull();
    expect(imageSize(new Uint8Array([0xff, 0xd8, 0xff]))).toBeNull();
    expect(imageSize(new Uint8Array())).toBeNull();
  });

  it('reads an extended WebP canvas', () => {
    expect(imageSize(webpVP8X(12000, 12000))).toEqual({ width: 12000, height: 12000 });
    expect(imageSize(webpVP8X(16383, 16383))).toEqual({ width: 16383, height: 16383 });
    expect(imageSize(webpVP8X(1, 1))).toEqual({ width: 1, height: 1 });
  });

  it('reads a lossless WebP', () => {
    expect(imageSize(webpVP8L(12000, 12000))).toEqual({ width: 12000, height: 12000 });
    expect(imageSize(webpVP8L(16383, 16383))).toEqual({ width: 16383, height: 16383 });
    expect(imageSize(webpVP8L(640, 480))).toEqual({ width: 640, height: 480 });
  });

  it('reads a lossy WebP keyframe', () => {
    expect(imageSize(webpVP8(1920, 1080))).toEqual({ width: 1920, height: 1080 });
    expect(imageSize(webpVP8(16383, 16383))).toEqual({ width: 16383, height: 16383 });
  });

  it('returns null for a truncated or unknown WebP chunk', () => {
    expect(imageSize(webpVP8X(12000, 12000, 4))).toBeNull();
    expect(imageSize(webpVP8L(12000, 12000, 6))).toBeNull(); // cuts into the packed size field
    expect(imageSize(webpVP8(1920, 1080, 3))).toBeNull();
    expect(imageSize(riff('ALPH', 8))).toBeNull(); // a chunk that carries no size
    expect(imageSize(new Uint8Array([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50]))).toBeNull();
  });

  it('does not take a lossy WebP without its start code', () => {
    const b = webpVP8(1920, 1080);
    b[24] = 0x00; // break the 9d 01 2a start code
    expect(imageSize(b)).toBeNull();
  });

  it('returns null for something that is not an image', () => {
    expect(imageSize(new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31]))).toBeNull(); // %PDF-1
    expect(imageSize(new Uint8Array([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x4f, 0x4b, 0x21, 0x21]))).toBeNull(); // RIFF, not WEBP
  });

  it('returns null rather than zero for a zero dimension', () => {
    expect(imageSize(png(0, 100))).toBeNull();
    expect(imageSize(png(100, 0))).toBeNull();
  });
});

// SVG has no pixel dimensions to read and no decode bomb to bound, so it is
// the one format staged unsized. That exemption is only safe if a file has
// to look like SVG to get it.
describe('looksLikeSvg', () => {
  const bytes = (text: string, prefix: number[] = []) =>
    new Uint8Array([...prefix, ...[...text].map((c) => c.charCodeAt(0))]);

  it('accepts the shapes a real SVG starts with', () => {
    expect(looksLikeSvg(bytes('<svg xmlns="http://www.w3.org/2000/svg"/>'))).toBe(true);
    expect(looksLikeSvg(bytes('<?xml version="1.0"?><svg/>'))).toBe(true);
    expect(looksLikeSvg(bytes('\n\n   <SVG width="10"/>'))).toBe(true);
    expect(looksLikeSvg(bytes('<svg/>', [0xef, 0xbb, 0xbf]))).toBe(true); // UTF-8 BOM
    // Inkscape and friends write both of these ahead of the tag.
    expect(looksLikeSvg(bytes('<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "x.dtd">\n<svg/>'))).toBe(true);
    expect(looksLikeSvg(bytes('<!-- Generator: Some Editor -->\n<svg width="2"/>'))).toBe(true);
  });

  it('refuses anything else, including a raster wearing the name', () => {
    expect(looksLikeSvg(png(10, 10))).toBe(false);
    expect(looksLikeSvg(webpVP8L(10, 10))).toBe(false);
    expect(looksLikeSvg(bytes('<html><body>'))).toBe(false);
    expect(looksLikeSvg(bytes('<?xml version="1.0"?>'))).toBe(false); // XML, but no svg tag
    expect(looksLikeSvg(bytes('   '))).toBe(false);
    expect(looksLikeSvg(new Uint8Array())).toBe(false);
  });

  it('will not hunt past the first kilobyte for the tag', () => {
    expect(looksLikeSvg(bytes(`<!--${'x'.repeat(1100)}--><svg/>`))).toBe(false);
  });
});

// SVG is staged without dimensions, so the pixel cap never sees it. Typst's
// SVG loader refuses http and file hrefs and out-of-root paths, but an
// embedded data URI is a raster the loader decodes: a 596 KB SVG carrying a
// 12000x12000 PNG took the typst child to a 431 MB peak.
describe('svgRefusal', () => {
  const utf8 = (text: string, prefix: number[] = []) =>
    new Uint8Array([...prefix, ...new TextEncoder().encode(text)]);

  const LOGO = '<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M2 2h20v20H2z" fill="#036"/><text>image of a logo</text></svg>';

  it('passes a clean logo', () => {
    expect(svgRefusal(utf8(LOGO), 'logo.svg')).toBeNull();
  });

  it('passes a plain doctype, which has no internal subset', () => {
    expect(svgRefusal(utf8('<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n<svg/>'), 'logo.svg')).toBeNull();
  });

  it('refuses an embedded bitmap, whatever the case or namespace', () => {
    for (const body of [
      '<svg><image href="data:image/png;base64,iVBORw0KGgo="/></svg>',
      '<svg><IMAGE xlink:href="data:image/png;base64,iVBORw0KGgo="/></svg>',
      '<svg xmlns:svg="http://www.w3.org/2000/svg"><svg:image xlink:href="data:image/png;base64,AAAA"/></svg>',
      '<svg>\n  <image\n    href="x.png"/>\n</svg>',
    ]) {
      const out = svgRefusal(utf8(body), 'shot.svg');
      expect(out, body.slice(0, 40)).toBe('shot.svg: this SVG embeds a bitmap, which the server cannot size. Export the PDF from the browser instead.');
    }
  });

  it('does not trip over a tag that merely starts with image', () => {
    expect(svgRefusal(utf8('<svg><imageinary x="1"/><images/></svg>'), 'logo.svg')).toBeNull();
    expect(svgRefusal(utf8('<svg><text>an image of a server</text></svg>'), 'logo.svg')).toBeNull();
  });

  it('refuses feImage, the other element that loads a raster', () => {
    // A filter primitive rather than a drawing element, and the worse of the
    // two: the same 144 MP PNG behind an feImage took the typst child to
    // 994 MB, against 431 MB for an ordinary image tag.
    for (const body of [
      '<svg><filter id="f"><feImage xlink:href="data:image/png;base64,AAAA"/></filter></svg>',
      '<svg><filter id="f"><feImage href="data:image/png;base64,AAAA"/></filter></svg>',
      '<svg xmlns:svg="http://www.w3.org/2000/svg"><filter id="f"><svg:feImage href="x.png"/></filter></svg>',
    ]) {
      expect(svgRefusal(utf8(body), 'shot.svg'), body.slice(0, 50))
        .toBe('shot.svg: this SVG embeds a bitmap, which the server cannot size. Export the PDF from the browser instead.');
    }
  });

  it('refuses a data URI anywhere else, since typst blocks every other href', () => {
    const message = 'shot.svg: this SVG embeds data (a data: URI), which the server cannot check. Export the PDF from the browser instead.';
    expect(svgRefusal(utf8('<svg><pattern id="p"><rect fill="url(data:image/png;base64,AAAA)"/></pattern></svg>'), 'shot.svg')).toBe(message);
    expect(svgRefusal(utf8('<svg><style>@import url("data:text/css,%2a%7b%7d");</style></svg>'), 'shot.svg')).toBe(message);
  });

  it('passes the filters and gradients a real drawing uses', () => {
    const body = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
      + '<defs><linearGradient id="g"><stop offset="0" stop-color="#036"/><stop offset="1" stop-color="#69c"/></linearGradient>'
      + '<filter id="f"><feGaussianBlur stdDeviation="2"/><feMerge><feMergeNode/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>'
      + '<rect width="24" height="24" fill="url(#g)" filter="url(#f)"/></svg>';
    expect(svgRefusal(utf8(body), 'logo.svg')).toBeNull();
  });

  it('does not read metadata: or an xmlns:data declaration as a data URI', () => {
    // No word boundary inside "metadata", and the namespace declaration
    // itself is followed by an equals sign rather than a colon. Using that
    // prefix on an attribute (`data:role="x"`) would be refused, which is
    // the same accepted cost as a stray `inkscape:export-data:` string.
    expect(svgRefusal(utf8('<svg><metadata:rdf/><text>metadata: none</text></svg>'), 'logo.svg')).toBeNull();
    expect(svgRefusal(utf8('<svg xmlns:data="http://example.com/ns"><rect width="1" height="1"/></svg>'), 'logo.svg')).toBeNull();
  });

  it('refuses a UTF-16 file, which the check cannot read', () => {
    const message = 'wide.svg: this SVG is not UTF-8, so the server cannot check it.';
    expect(svgRefusal(utf8('<svg/>', [0xff, 0xfe]), 'wide.svg')).toBe(message);
    expect(svgRefusal(utf8('<svg/>', [0xfe, 0xff]), 'wide.svg')).toBe(message);
  });

  it('refuses a declared entity, which is how a tag would be smuggled', () => {
    const body = '<!DOCTYPE svg [<!ENTITY hidden "<image href=\'data:image/png;base64,AAAA\'/>">]>\n<svg>&hidden;</svg>';
    expect(svgRefusal(utf8(body), 'sneaky.svg'))
      .toBe('sneaky.svg: this SVG declares XML entities, so the server cannot check it. Export the PDF from the browser instead.');
  });

  it('refuses anything over two megabytes', () => {
    const big = new Uint8Array(2 * 1024 * 1024 + 1);
    big.set(new TextEncoder().encode('<svg/>'), 0);
    expect(svgRefusal(big, 'huge.svg')).toBe('huge.svg: this SVG is too large to export from the server (2.0 MB). Export the PDF from the browser instead.');
    const justUnder = new Uint8Array(2 * 1024 * 1024);
    justUnder.set(new TextEncoder().encode('<svg/>'), 0);
    expect(svgRefusal(justUnder, 'huge.svg')).toBeNull();
  });
});
