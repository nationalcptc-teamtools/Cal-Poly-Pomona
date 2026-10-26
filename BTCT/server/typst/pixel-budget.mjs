// How many pixels one export may stage in total.
//
// The per-image cap (10 MP, in stage.mjs) guards jimp, which costs about
// 50 MB of peak per megapixel while it bakes one picture. This is the other
// half: typst holds every decoded bitmap at once while it writes the PDF's
// image streams, roughly 3 bytes per pixel, so the cost of a report is the
// sum of its screenshots whether or not anything redacts them. Measured with
// `typst compile -j 1` on 3500x2820 PNGs of 34 KB each: 8 of them took the
// child to 242 MB, 32 of them to 922 MB. Forty placed screenshots is an
// ordinary report, not an attack, and file bytes say nothing about it,
// because a screenshot compresses.
//
// 120 MP at 3 bytes per pixel is about 360 MB in the child, which leaves the
// 1 GB box room for the relay and for one bake. A machine with more memory
// can say so with TYPST_EXPORT_MAX_TOTAL_MP.
//
// Pure: no fs, no env read at call time, so src/test covers it through the
// .d.mts beside this file.

export const DEFAULT_MAX_TOTAL_MP = 120;
export const MAX_TOTAL_MP_RANGE = [10, 2000];

/** The configured total, or the default for anything missing or out of range. */
export function parseMaxTotalMegapixels(raw) {
  const text = typeof raw === 'string' ? raw.trim() : raw;
  if (text === '' || text === null || text === undefined) return DEFAULT_MAX_TOTAL_MP;
  const value = Number(text);
  const [min, max] = MAX_TOTAL_MP_RANGE;
  if (!Number.isFinite(value) || value < min || value > max) return DEFAULT_MAX_TOTAL_MP;
  return value;
}

// Read once, at load, the way the CLI paths are read from the environment:
// this is deployment configuration, not something a request may change.
export const MAX_TOTAL_MP = parseMaxTotalMegapixels(process.env.TYPST_EXPORT_MAX_TOTAL_MP);

/**
 * Accumulates staged images and says when the report has asked for too much.
 *
 * `add` takes the dimensions of one image, or null for an image with none
 * (an SVG), which costs nothing here because typst rasterizes it at the size
 * the layout asks for rather than at a size the file carries.
 */
export function createPixelBudget(maxMegapixels = MAX_TOTAL_MP) {
  const limit = maxMegapixels * 1_000_000;
  let pixels = 0;
  return {
    /** The refusal message once the total is past the budget, else null. */
    add(dims) {
      const width = Number(dims?.width);
      const height = Number(dims?.height);
      if (Number.isFinite(width) && Number.isFinite(height) && width > 0 && height > 0) {
        pixels += width * height;
      }
      if (pixels <= limit) return null;
      return `This report places about ${Math.round(pixels / 1_000_000)} MP of screenshots and the server exports up to ${maxMegapixels} MP at once. Export the PDF from the browser instead, or raise TYPST_EXPORT_MAX_TOTAL_MP on a server with more memory.`;
    },
    megapixels: () => pixels / 1_000_000,
  };
}
