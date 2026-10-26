// Thumbnail hooks shared by the Assets panel and the Report tab's asset
// picker: a lazily fetched, downscaled preview of an asset's rendered bytes
// (crop and blur applied), loaded only once its card nears the viewport.

import { useEffect, useState } from 'react';
import type { TypstAsset } from '@/types';
import { blursKey } from '@/lib/blur-math';
import { resolveAssetThumbnail } from '@/lib/assets';

/**
 * Object URL for a downscaled preview of an asset's *rendered* bytes (crop
 * and blur applied), fetched only once the card has scrolled near the
 * viewport (`visible`). Revokes on change so a long session doesn't leak
 * blob URLs. A 500-screenshot folder used to fetch, decode and keep a
 * full-resolution blob per card the moment the tab opened.
 */
export function useAssetPreview(asset: TypstAsset, visible: boolean): { url: string | null; error: boolean } {
  const [url, setUrl] = useState<string | null>(null);
  const [error, setError] = useState(false);
  // Depend on the crop/blur *values*, not identity, so a re-render with
  // equal framing doesn't rebuild the blob.
  const cropKey = asset.crop
    ? `${asset.crop.x},${asset.crop.y},${asset.crop.w},${asset.crop.h}`
    : '';
  const blurKey = blursKey(asset.blurs);

  useEffect(() => {
    if (asset.kind !== 'image' || !visible) return;
    let cancelled = false;
    let objUrl: string | null = null;
    setError(false);
    resolveAssetThumbnail(asset)
      .then((blob) => {
        if (cancelled) return;
        objUrl = URL.createObjectURL(blob);
        setUrl(objUrl);
      })
      .catch(() => { if (!cancelled) setError(true); });
    return () => {
      cancelled = true;
      if (objUrl) URL.revokeObjectURL(objUrl);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [asset.id, asset.kind, asset.mime, asset.filename, cropKey, blurKey, visible]);

  return { url, error };
}

/** True once `ref`'s element has come within 300 px of the viewport (and stays true). */
export function useNearViewport(ref: React.RefObject<HTMLElement | null>): boolean {
  const [near, setNear] = useState(() => typeof IntersectionObserver === 'undefined');
  useEffect(() => {
    if (near) return;
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) {
        setNear(true);
        io.disconnect();
      }
    }, { rootMargin: '300px' });
    io.observe(el);
    return () => io.disconnect();
  }, [near, ref]);
  return near;
}

