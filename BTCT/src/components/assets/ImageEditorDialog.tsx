// ─────────────────────────────────────────────────────────────────────────
// Crop-and-redact window for a shared image asset.
//
// The frame is a **viewport**: the image is panned and scaled behind it, so
// the stored `CropRect` always carries the frame's aspect ratio. The frame
// starts at the image's own shape, so an untouched asset is the identity
// crop. Its edge handles crop: drag one in and, on release, the frame takes
// the shape of what is left. Scale the image past the border and it is
// clipped there; scale it smaller and grey shows through, exactly as it will
// render in a note. Reset goes back to the whole image.
//
// Nothing here touches the uploaded bytes. Both the crop and the redaction
// rectangles are render-time metadata on the record, so either can be
// removed later and the original is always recoverable.
// ─────────────────────────────────────────────────────────────────────────

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Dialog } from '@/components/ui/Dialog';
import { Button, IconButton } from '@/components/ui/Button';
import { Input } from '@/components/ui/Field';
import { Banner } from '@/components/ui/Banner';
import {
  Crop, EyeOff, Loader2, Maximize2, Minimize2, Pencil,
  RotateCcw, Wand2, X, ZoomIn, ZoomOut,
} from 'lucide-react';
import type { BlurRegion, BlurStyle, CropRect, TypstAsset } from '@/types';
import {
  blursKey,
  DEFAULT_BLUR_STYLE,
  effectiveStrength,
  effectiveStyle,
  MAX_STRENGTH,
  MIN_STRENGTH,
} from '@/lib/blur-math';
import { ENCODABLE_FORMATS, formatFromFilename } from '@/lib/image-format';
import {
  blurredPreviewBytes,
  detectContentBounds,
  fetchAssetBytes,
} from '@/lib/assets';
import {
  constrainToAspect,
  cropAspect,
  fitCropToBox,
  FULL_FRAME,
  isFullFrame,
  zoomCrop,
  zoomPercent,
} from '@/lib/crop-math';
import { FigureViewport } from './FigureViewport';
import { useAuthStore } from '@/auth/auth-store';
import { useThemeStore } from '@/stores/theme-store';
import { resolveBlurStrengthPolicy, resolvePrefs } from '@/lib/editor-prefs';

/**
 * Frame shape when the asset has no recorded pixel size yet (the record is
 * written before the image is measured). 4:3 is a safe middle: the first
 * `fill` re-fits the crop against the real dimensions the moment they land.
 */
const FALLBACK_ASPECT = 4 / 3;

/**
 * Editable file name.
 *
 * Only the stem is editable: the extension is shown but fixed. It drives the
 * decoder choice and the byte normalization, so letting someone rename
 * `shot.png` to `shot.jpg` would reintroduce a decode failure on read.
 */
function AssetNameField({
  asset,
  onRename,
}: {
  asset: TypstAsset;
  onRename: (stem: string) => void;
}) {
  const dot = asset.filename.lastIndexOf('.');
  const currentStem = dot > 0 ? asset.filename.slice(0, dot) : asset.filename;
  const ext = dot > 0 ? asset.filename.slice(dot) : '';

  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(currentStem);

  useEffect(() => { if (!editing) setDraft(currentStem); }, [currentStem, editing]);

  const commit = () => {
    setEditing(false);
    const next = draft.trim();
    if (next && next !== currentStem) onRename(next);
    else setDraft(currentStem);
  };

  if (!editing) {
    return (
      <Button
        variant="ghost"
        size="sm"
        onClick={() => setEditing(true)}
        title="Click to rename: references in the document are updated automatically"
        className="group min-w-0 px-1.5 py-0.5 font-mono text-meta"
      >
        <span className="truncate">{asset.filename}</span>
        <Pencil size={10} className="shrink-0 opacity-0 transition-opacity group-hover:opacity-60" />
      </Button>
    );
  }

  return (
    <span className="flex min-w-0 items-center gap-0.5 font-mono text-meta">
      <Input
        autoFocus
        mono
        aria-label="File name"
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          // Keep Enter/Escape from reaching the dialog's own shortcuts, which
          // would place the image or close the window mid-rename.
          e.stopPropagation();
          if (e.key === 'Enter') { e.preventDefault(); commit(); }
          if (e.key === 'Escape') { e.preventDefault(); setDraft(currentStem); setEditing(false); }
        }}
        className="min-w-0 max-w-[22rem] flex-1 border-primary px-1.5 py-0.5 text-meta"
      />
      <span className="shrink-0 text-muted-foreground">{ext}</span>
    </span>
  );
}

export function ImageEditorDialog({
  asset,
  onApply,
  onRename,
  onClose,
}: {
  asset: TypstAsset;
  /** Commit the framing and the redaction rectangles. */
  onApply: (crop: CropRect | null, blurs: BlurRegion[] | null) => void;
  /** Rename the asset's file stem. */
  onRename: (stem: string) => void;
  onClose: () => void;
}) {
  const [imgUrl, setImgUrl] = useState<string | null>(null);
  const [bytes, setBytes] = useState<Uint8Array | null>(null);
  const [natural, setNatural] = useState<{ w: number; h: number } | null>(
    asset.width && asset.height ? { w: asset.width, h: asset.height } : null,
  );
  const [error, setError] = useState<string | null>(null);
  const [detecting, setDetecting] = useState(false);
  const [autoNote, setAutoNote] = useState<string | null>(null);

  // The frame takes the image's own shape, so an asset that has never been
  // cropped opens as the identity crop rather than an arbitrary letterbox.
  // A stored crop wins: re-opening the editor must show what is saved. The
  // crop handles change it from there.
  const [boxAspect, setBoxAspect] = useState(() => {
    if (asset.crop && asset.crop.h > 0) {
      const w = (asset.width ?? 0) * asset.crop.w;
      const h = (asset.height ?? 0) * asset.crop.h;
      if (w > 0 && h > 0) return w / h;
    }
    if (asset.width && asset.height) return asset.width / asset.height;
    return FALLBACK_ASPECT;
  });

  // A record written before the image was measured opens at the fallback
  // shape; adopt the real one once it is known, unless a crop set it.
  useEffect(() => {
    if (!natural || asset.crop || asset.width) return;
    setBoxAspect(natural.w / natural.h);
  }, [natural, asset.crop, asset.width]);

  const [crop, setCrop] = useState<CropRect | null>(asset.crop ?? null);

  // ── blur (redaction) regions ───────────────────────────────────────────
  const [blurs, setBlurs] = useState<BlurRegion[]>(asset.blurs ?? []);
  const [blurMode, setBlurMode] = useState(false);
  // Formats a canvas can't re-encode (GIF, SVG) can't be blurred either.
  const canBlur = (() => {
    const f = formatFromFilename(asset.filename);
    return !!f && ENCODABLE_FORMATS.has(f);
  })();

  // The style/strength controls edit the selected region when there is one,
  // and otherwise set what the next drawn region gets. New regions start at
  // the account's default strength (or the admin's workspace default).
  const adminBlur = useThemeStore((s) => s.blurDefaults);
  const authUser = useAuthStore((s) => s.user);
  const defaultStrengths = useMemo(
    () => resolveBlurStrengthPolicy(adminBlur, resolvePrefs(authUser).blurDefaults),
    [adminBlur, authUser],
  );
  const [selectedBlur, setSelectedBlur] = useState<number | null>(null);
  // Pixelate by default: a mosaic reads unambiguously as "redacted" in a
  // report, where a gaussian can look like a focus artefact.
  const [blurStyle, setBlurStyle] = useState<BlurStyle>(DEFAULT_BLUR_STYLE);
  const [blurStrength, setBlurStrength] = useState(() => defaultStrengths[DEFAULT_BLUR_STYLE]);

  const patchSelected = useCallback((patch: Partial<BlurRegion>) => {
    if (selectedBlur === null) return;
    setBlurs((b) => b.map((r, i) => (i === selectedBlur ? { ...r, ...patch } : r)));
  }, [selectedBlur]);

  const applyBlurStyle = useCallback((style: BlurStyle) => {
    setBlurStyle(style);
    // With no region selected the controls set up the NEXT region, so
    // switching style loads that style's default strength.
    if (selectedBlur === null) setBlurStrength(defaultStrengths[style]);
    patchSelected({ style });
  }, [patchSelected, selectedBlur, defaultStrengths]);

  const applyBlurStrength = useCallback((strength: number) => {
    setBlurStrength(strength);
    patchSelected({ strength });
  }, [patchSelected]);

  const addBlur = useCallback((r: BlurRegion) => {
    const region = { ...r, style: blurStyle, strength: blurStrength };
    setBlurs((b) => [...b, region]);
    // Select what was just drawn so the controls adjust it immediately.
    setSelectedBlur(blurs.length);
  }, [blurs.length, blurStyle, blurStrength]);

  const selectBlur = useCallback((i: number | null) => {
    setSelectedBlur(i);
    if (i === null) return;
    const r = blurs[i];
    if (r) {
      // Reflect the selected region in the controls.
      setBlurStyle(effectiveStyle(r));
      setBlurStrength(effectiveStrength(r));
    }
  }, [blurs]);

  const removeBlur = useCallback((i: number) => {
    setBlurs((b) => b.filter((_, j) => j !== i));
    setSelectedBlur((sel) =>
      sel === null ? null : sel === i ? null : sel > i ? sel - 1 : sel);
  }, []);

  const exitBlurMode = useCallback(() => {
    setBlurMode(false);
    setSelectedBlur(null);
  }, []);

  // Load the bytes and, if the record didn't carry them, the real dimensions.
  useEffect(() => {
    let cancelled = false;
    let url: string | null = null;
    setError(null);
    fetchAssetBytes(asset.id)
      .then((b) => {
        if (cancelled) return;
        setBytes(b);
        url = URL.createObjectURL(new Blob([b.slice().buffer as ArrayBuffer], { type: asset.mime }));
        setImgUrl(url);
        if (!asset.width || !asset.height) {
          const probe = new Image();
          probe.onload = () => {
            if (!cancelled) setNatural({ w: probe.naturalWidth, h: probe.naturalHeight });
          };
          probe.src = url;
        }
      })
      .catch((e) => { if (!cancelled) setError(e instanceof Error ? e.message : String(e)); });
    return () => {
      cancelled = true;
      if (url) URL.revokeObjectURL(url);
    };
  }, [asset.id, asset.mime, asset.width, asset.height]);

  // Viewport image with the blur regions baked through the real pipeline,
  // so the frame previews exactly the bytes the compiler will receive. The
  // in-flight drag gets a cheap CSS preview inside FigureViewport instead;
  // this only re-bakes when a region is committed or removed.
  const [blurredUrl, setBlurredUrl] = useState<string | null>(null);
  const blursDep = blursKey(blurs);
  useEffect(() => {
    if (!bytes || blurs.length === 0 || !canBlur) {
      setBlurredUrl(null);
      return;
    }
    let cancelled = false;
    let url: string | null = null;
    // Debounced: dragging the strength slider changes the regions many times
    // a second, and each bake re-encodes the image at full resolution.
    const timer = setTimeout(() => {
      blurredPreviewBytes(bytes, asset.mime, blurs)
        .then((out) => {
          if (cancelled) return;
          url = URL.createObjectURL(
            new Blob([out.slice().buffer as ArrayBuffer], { type: 'image/png' }),
          );
          setBlurredUrl(url);
        })
        .catch(() => { if (!cancelled) setBlurredUrl(null); });
    }, 120);
    return () => {
      cancelled = true;
      clearTimeout(timer);
      if (url) URL.revokeObjectURL(url);
    };
    // Depend on the regions' value, not the array identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bytes, asset.mime, canBlur, blursDep]);

  // First placement: fill the frame, centred.
  const seeded = useRef(false);
  useEffect(() => {
    if (seeded.current || !natural) return;
    seeded.current = true;
    if (asset.crop) {
      // An existing crop was stored against whatever box it was made for;
      // re-fit it to this one so the frame and the rect always agree.
      setCrop(constrainToAspect(asset.crop, natural.w, natural.h, boxAspect));
    } else {
      setCrop(fitCropToBox(natural.w, natural.h, boxAspect, 'cover'));
    }
  }, [natural, asset.crop, boxAspect]);

  // Re-fit whenever the box shape changes (height control, different slot).
  const lastAspect = useRef(boxAspect);
  useEffect(() => {
    if (!natural || !crop) return;
    if (Math.abs(lastAspect.current - boxAspect) < 1e-9) return;
    lastAspect.current = boxAspect;
    setCrop(constrainToAspect(crop, natural.w, natural.h, boxAspect));
  }, [boxAspect, natural, crop]);

  const runAutoDetect = useCallback(
    async (data: Uint8Array, silent: boolean) => {
      if (!natural) return;
      setDetecting(true);
      try {
        const found = await detectContentBounds(data, asset.mime);
        if (found) {
          // Trim the borders; the frame takes the trimmed shape.
          setBoxAspect(cropAspect(found, natural.w, natural.h));
          setCrop(found);
          setAutoNote('Trimmed the border.');
        } else if (!silent) {
          setAutoNote('No uniform border found to trim.');
        }
      } catch {
        if (!silent) setAutoNote('Auto-detect failed on this image.');
      } finally {
        setDetecting(false);
      }
    },
    [asset.mime, natural],
  );

  const fill = useCallback(() => {
    if (!natural) return;
    setCrop(fitCropToBox(natural.w, natural.h, boxAspect, 'cover'));
    setAutoNote(null);
  }, [natural, boxAspect]);

  const fitWhole = useCallback(() => {
    if (!natural) return;
    setCrop(fitCropToBox(natural.w, natural.h, boxAspect, 'contain'));
    setAutoNote(null);
  }, [natural, boxAspect]);

  const nudgeZoom = useCallback((factor: number) => {
    setCrop((c) => (c ? zoomCrop(c, factor) : c));
  }, []);

  // A handle drag: keep what is left inside the handles, at its own shape.
  const cropTo = useCallback((next: CropRect) => {
    if (!natural) return;
    setBoxAspect(cropAspect(next, natural.w, natural.h));
    setCrop(next);
    setAutoNote(null);
  }, [natural]);

  const reset = useCallback(() => {
    if (!natural) return;
    setBoxAspect(natural.w / natural.h);
    setCrop(FULL_FRAME);
    setAutoNote(null);
  }, [natural]);

  const cropValue = crop && !isFullFrame(crop) ? crop : crop;
  const blursValue = blurs.length > 0 ? blurs : null;
  const save = useCallback(() => {
    onApply(cropValue, blursValue);
  }, [onApply, cropValue, blursValue]);

  // Esc steps out of blur-drawing before the Dialog's own Escape closes the
  // window: capture phase, so this runs first and marks the event handled.
  useEffect(() => {
    if (!blurMode) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !e.defaultPrevented) { e.preventDefault(); exitBlurMode(); }
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [blurMode, exitBlurMode]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Enter' && !e.defaultPrevented) save(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [save]);

  return (
    <Dialog
      title={'Edit image'}
      ariaLabel={'Edit image'}
      hideHeader
      onClose={onClose}
      size="full"
      className="rounded-xl bg-card"
      bodyClassName="flex flex-col overflow-hidden"
    >
        {/* Header */}
        <div className="flex shrink-0 items-center justify-between gap-3 border-b border-border px-4 py-2.5">
          <div className="flex min-w-0 flex-1 items-center gap-2">
            <Crop size={14} className="shrink-0 text-status-purple" />
            <span className="shrink-0 text-meta font-bold uppercase tracking-widest">
              Edit image
            </span>
            <span className="shrink-0 text-muted-foreground">·</span>
            <AssetNameField asset={asset} onRename={onRename} />
          </div>
          <IconButton label="Close" title="Close (Esc)" data-dialog-close="true" onClick={onClose}>
            <X size={14} />
          </IconButton>
        </div>

        <div className="flex min-h-0 flex-1">
          {/* Viewport */}
          <div className="flex min-h-0 min-w-0 flex-1 flex-col bg-muted/40">
            <div className="min-h-0 flex-1">
              {error ? (
                <div className="flex h-full items-center justify-center text-xs text-status-red">
                  {error}
                </div>
              ) : !imgUrl || !crop ? (
                <div className="flex h-full items-center justify-center gap-2 text-xs text-muted-foreground">
                  <Loader2 size={14} className="animate-spin" /> Loading image…
                </div>
              ) : (
                <FigureViewport
                  imageUrl={blurredUrl ?? imgUrl}
                  crop={crop}
                  boxAspect={boxAspect}
                  onCropChange={(next) => { setCrop(next); setAutoNote(null); }}
                  onCropResize={cropTo}
                  blurMode={blurMode && canBlur}
                  blurs={blurs}
                  onAddBlur={addBlur}
                  onRemoveBlur={removeBlur}
                  selectedBlur={selectedBlur}
                  onSelectBlur={selectBlur}
                />
              )}
            </div>

            {/* Framing controls */}
            <div className="flex shrink-0 flex-wrap items-center gap-1 border-t border-border bg-card px-3 py-2">
              <Button variant="ghost" size="xs" icon={<Maximize2 size={12} />} onClick={fill} title="Scale so the image fills the figure, cropping the overflow">
                Fill
              </Button>
              <Button variant="ghost" size="xs" icon={<Minimize2 size={12} />} onClick={fitWhole} title="Scale so the whole image is inside the figure">
                Fit all
              </Button>
              <Button
                variant="ghost"
                size="xs"
                icon={detecting ? <Loader2 size={12} className="animate-spin" /> : <Wand2 size={12} />}
                onClick={() => bytes && void runAutoDetect(bytes, false)}
                disabled={!bytes || detecting || asset.mime === 'image/svg+xml'}
                title="Trim uniform borders, then re-frame"
              >
                Auto
              </Button>

              <div className="mx-1 h-4 w-px bg-border" />

              <Button
                variant="ghost"
                size="xs"
                icon={<EyeOff size={12} />}
                aria-pressed={blurMode}
                onClick={() => (blurMode ? exitBlurMode() : setBlurMode(true))}
                disabled={!canBlur}
                title={canBlur
                  ? 'Draw rectangles over sensitive content; they render blurred'
                  : 'This format cannot be blurred'}
                className={blurMode ? 'bg-status-purple/15 text-status-purple hover:bg-status-purple/20' : undefined}
              >
                Blur{blurs.length > 0 ? ` (${blurs.length})` : ''}
              </Button>

              {blurMode && (
                <>
                  {/* Style + strength: edit the selected region, or set what
                      the next drawn region gets. */}
                  <div role="group" aria-label="Blur style" className="flex overflow-hidden rounded border border-border">
                    {(['gaussian', 'pixelate'] as const).map((style) => (
                      <button
                        key={style}
                        type="button"
                        aria-pressed={blurStyle === style}
                        onClick={() => applyBlurStyle(style)}
                        title={style === 'gaussian'
                          ? 'Smooth gaussian blur'
                          : 'Hard mosaic blocks'}
                        className={`px-1.5 py-0.5 text-micro uppercase tracking-wide ${
                          blurStyle === style
                            ? 'bg-primary text-primary-foreground'
                            : 'text-muted-foreground hover:bg-accent'
                        }`}
                      >
                        {style === 'gaussian' ? 'Blur' : 'Pixels'}
                      </button>
                    ))}
                  </div>
                  <input
                    type="range"
                    min={MIN_STRENGTH}
                    max={MAX_STRENGTH}
                    step={0.05}
                    value={blurStrength}
                    aria-label="Blur strength"
                    onChange={(e) => applyBlurStrength(Number(e.target.value))}
                    title={selectedBlur !== null
                      ? 'Strength of the selected region'
                      : 'Strength for the next drawn region'}
                    className="w-20 accent-status-purple"
                  />
                  <span className="min-w-[30px] font-mono text-micro text-muted-foreground">
                    {Math.round(blurStrength * 100)}%
                  </span>
                </>
              )}
              {blurs.length > 0 && (
                <Button variant="ghost" size="xs" className="text-muted-foreground hover:text-foreground" onClick={() => { setBlurs([]); setSelectedBlur(null); }} title="Remove every blur region">
                  Clear
                </Button>
              )}

              <div className="mx-1 h-4 w-px bg-border" />

              <IconButton label="Zoom out" onClick={() => nudgeZoom(1.15)}>
                <ZoomOut size={13} />
              </IconButton>
              <span className="min-w-[46px] text-center font-mono text-caption text-muted-foreground">
                {crop ? `${zoomPercent(crop)}%` : 'none'}
              </span>
              <IconButton label="Zoom in" onClick={() => nudgeZoom(1 / 1.15)}>
                <ZoomIn size={13} />
              </IconButton>

              <span className="ml-2 text-caption text-muted-foreground">
                {blurMode
                  ? 'drag to draw · click to select · × removes · Esc exits'
                  : 'drag the handles to crop · drag to reposition · scroll to zoom'}
              </span>
            </div>
          </div>

        </div>

        {/* Footer */}
        <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-t border-border px-4 py-2.5">
          <div className="flex min-w-0 flex-col gap-0.5">
            <span className="font-mono text-caption text-muted-foreground">
              {natural ? `source ${natural.w} × ${natural.h} px` : 'measuring…'}
              {natural && crop && !isFullFrame(crop)
                ? ` · cropped to ${Math.round(crop.w * natural.w)} × ${Math.round(crop.h * natural.h)} px`
                : ''}
            </span>
            {autoNote && (
              <span className="truncate text-caption text-status-purple">{autoNote}</span>
            )}
          </div>

          <div className="flex items-center gap-1">
            <Button variant="ghost" size="xs" icon={<RotateCcw size={12} />} onClick={reset} title="Back to the whole image, uncropped">
              Reset
            </Button>
            <div className="mx-1 h-4 w-px bg-border" />
            <Button variant="primary" size="md" onClick={save} title="Save the crop and the redactions (the original image is never changed)">
              Save
            </Button>
          </div>
        </div>

        {error && (
          <Banner tone="red" flush className="shrink-0 border-t">
            {error}
          </Banner>
        )}
    </Dialog>
  );
}
