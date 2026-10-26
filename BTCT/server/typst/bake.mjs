import { Jimp, ResizeStrategy } from 'jimp';
import { blurParams, effectiveStyle, hasBlurs, pixelParams } from '../../src/lib/blur-math.ts';
import { cropToPixels, isFullFrame, normalizeCrop, outputSize } from '../../src/lib/crop-math.ts';
import { formatFromFilename } from '../../src/lib/image-format.ts';

const GAP_FILL = 0xf5f5f5ff; // luma(245), the placeholder grey, same as the browser
const BAKEABLE = new Set(['png', 'jpeg']);

function bakeBlurs(img, blurs) {
  const natW = img.bitmap.width, natH = img.bitmap.height;
  for (const region of blurs) {
    const sx = Math.round(region.x * natW), sy = Math.round(region.y * natH);
    const sw = Math.max(1, Math.min(natW - sx, Math.round(region.w * natW)));
    const sh = Math.max(1, Math.min(natH - sy, Math.round(region.h * natH)));
    if (sw <= 0 || sh <= 0) continue;
    const piece = img.clone().crop({ x: sx, y: sy, w: sw, h: sh });
    if (effectiveStyle(region) === 'pixelate') {
      const { blockPx } = pixelParams(region, natW, natH);
      const smallW = Math.max(1, Math.round(sw / blockPx)), smallH = Math.max(1, Math.round(sh / blockPx));
      piece.resize({ w: smallW, h: smallH, mode: ResizeStrategy.BILINEAR });
      piece.resize({ w: sw, h: sh, mode: ResizeStrategy.NEAREST_NEIGHBOR });
    } else {
      const { radiusPx, downscale } = blurParams(region, natW, natH);
      const smallW = Math.max(1, Math.round(sw * downscale)), smallH = Math.max(1, Math.round(sh * downscale));
      piece.resize({ w: smallW, h: smallH, mode: ResizeStrategy.BILINEAR });
      piece.resize({ w: sw, h: sh, mode: ResizeStrategy.BILINEAR });
      piece.blur(Math.max(1, Math.round(radiusPx / 2)));
    }
    img.composite(piece, sx, sy);
  }
}

/**
 * Apply the framing in `meta` to `bytes`. Returns null when there is nothing
 * to apply (no crop, no blurs). Throws for a format that cannot be re-encoded
 * (gif/webp/svg), because writing an unredacted original would be worse.
 */
export async function bakeImage(bytes, meta, filename) {
  const wantsCrop = !!meta.crop && !isFullFrame(meta.crop);
  const wantsBlur = hasBlurs(meta.blurs);
  if (!wantsCrop && !wantsBlur) return null;
  const fmt = formatFromFilename(filename);
  if (!fmt || !BAKEABLE.has(fmt)) throw new Error(`${filename}: ${fmt ?? 'unknown'} images with crop or blur cannot be baked server-side; export from the app instead`);
  const img = await Jimp.read(Buffer.from(bytes));
  if (wantsBlur) bakeBlurs(img, meta.blurs);
  const mime = fmt === 'jpeg' ? 'image/jpeg' : 'image/png';
  if (!wantsCrop) return new Uint8Array(await img.getBuffer(mime));

  const natW = img.bitmap.width, natH = img.bitmap.height;
  const rect = normalizeCrop(meta.crop);
  const { sx, sy, sw, sh } = cropToPixels(rect, natW, natH);
  const size = outputSize(rect, natW, natH);
  const canvas = new Jimp({ width: size.width, height: size.height, color: GAP_FILL });
  // Intersect the source rect with the image; scale the visible part into place.
  const ix0 = Math.max(0, sx), iy0 = Math.max(0, sy), ix1 = Math.min(natW, sx + sw), iy1 = Math.min(natH, sy + sh);
  if (ix1 > ix0 && iy1 > iy0) {
    const scaleX = size.width / sw, scaleY = size.height / sh;
    const visible = img.clone().crop({ x: ix0, y: iy0, w: ix1 - ix0, h: iy1 - iy0 });
    visible.resize({ w: Math.max(1, Math.round((ix1 - ix0) * scaleX)), h: Math.max(1, Math.round((iy1 - iy0) * scaleY)), mode: ResizeStrategy.BILINEAR });
    canvas.composite(visible, Math.round((ix0 - sx) * scaleX), Math.round((iy0 - sy) * scaleY));
  }
  return new Uint8Array(await canvas.getBuffer(mime));
}
