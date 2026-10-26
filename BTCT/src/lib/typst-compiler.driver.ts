// ─────────────────────────────────────────────────────────────────────────
// The wasm-facing half of the local Typst compiler.
//
// Wraps @myriaddreamin/typst.ts so documents render fully offline. This
// module runs inside the compiler Web Worker (typst-compiler.worker.ts) and,
// when Workers are unavailable, inline on the main thread. Either way there
// is exactly one instance per page: the compiler and renderer are built
// once and live for the session.
//
// Fonts used to be supplied only at init, which forced a full rebuild of
// the 28 MB wasm module (plus re-parsing every default font) whenever a
// workspace with its own fonts was opened, and leaked the old instance.
// typst.ts can swap fonts on a live compiler through `setFonts`, so that is
// what `setFonts` below does: build a font resolver from the cached default
// faces plus the workspace's, install it, and drop the compiler's font cache.
// ─────────────────────────────────────────────────────────────────────────

// `?url` yields the asset URL (a string); Vite emits the wasm as a hashed file
// and serves it locally. typst.ts fetches it lazily via `getModule`.
import compilerWasmUrl from '@myriaddreamin/typst-ts-web-compiler/pkg/typst_ts_web_compiler_bg.wasm?url';
import rendererWasmUrl from '@myriaddreamin/typst-ts-renderer/pkg/typst_ts_renderer_bg.wasm?url';
import { DEFAULT_FONT_FILES, DEFAULT_FONT_URL_PREFIX } from './typst-default-fonts';
import type {
  DriverCommand, PdfOutput, SvgOutput, TypstDiagnostic, TypstFontInfo, TypstShadowFile,
} from './typst-compiler-types';

// typst.ts's `format` discriminator (see CompileFormatEnum).
const FORMAT_VECTOR = 0;
const FORMAT_PDF = 1;

// typst.ts has no exported types we depend on here; treat the instances as
// structurally `any` to avoid coupling to its (less-stable) public surface.
/* eslint-disable @typescript-eslint/no-explicit-any */
type AnyCompiler = any;
type AnyRenderer = any;

export interface TypstDriver {
  /** Replace the workspace fonts. The default faces are always included. */
  setFonts(fonts: Uint8Array[]): Promise<void>;
  /** Replace the files mounted into the compiler's virtual filesystem. */
  setShadow(files: TypstShadowFile[]): Promise<void>;
  svg(source: string, mainPath: string): Promise<SvgOutput>;
  pdf(source: string, mainPath: string): Promise<PdfOutput>;
  fontInfo(bytes: Uint8Array): Promise<TypstFontInfo | null>;
}

export function createTypstDriver(): TypstDriver {
  let defaultFonts: Promise<Uint8Array[]> | null = null;
  let instance: Promise<{ compiler: AnyCompiler; renderer: AnyRenderer }> | null = null;
  let customFonts: Uint8Array[] = [];
  let shadow: TypstShadowFile[] = [];
  let shadowApplied = false;

  /** The 17 default faces, fetched once from the app's own /fonts/ folder. */
  const loadDefaultFonts = (): Promise<Uint8Array[]> => {
    if (!defaultFonts) {
      defaultFonts = Promise.all(DEFAULT_FONT_FILES.map(async (name) => {
        const res = await fetch(DEFAULT_FONT_URL_PREFIX + name);
        if (!res.ok) throw new Error(`default font ${name}: HTTP ${res.status}`);
        return new Uint8Array(await res.arrayBuffer());
      }));
      // Don't cache a failure: a transient blip must not break the session.
      defaultFonts.catch(() => { defaultFonts = null; });
    }
    return defaultFonts;
  };

  /** Build (once) the compiler + renderer with the fonts known at that moment. */
  const getInstance = () => {
    if (!instance) {
      instance = (async () => {
        const { createTypstCompiler, createTypstRenderer, loadFonts } = await import('@myriaddreamin/typst.ts');
        const fonts = await loadDefaultFonts();
        const compiler = createTypstCompiler();
        // `assets: false`: we hand over the default faces ourselves, so
        // typst.ts must not try to fetch its own copy from the CDN.
        await compiler.init({
          getModule: () => compilerWasmUrl,
          beforeBuild: [loadFonts([...fonts, ...customFonts] as unknown as Uint8Array[], { assets: false })],
        });
        const renderer = createTypstRenderer();
        await renderer.init({ getModule: () => rendererWasmUrl });
        shadowApplied = false;
        return { compiler, renderer };
      })();
      // If init throws (e.g. wasm failed to load), let the next call retry.
      instance.catch(() => { instance = null; });
    }
    return instance;
  };

  /** Push the current shadow set into the compiler if it's out of date. */
  const syncShadow = (compiler: AnyCompiler): void => {
    if (shadowApplied) return;
    // resetShadow clears every mapped file, so removals take effect too.
    compiler.resetShadow();
    for (const f of shadow) compiler.mapShadow(f.path, f.bytes);
    shadowApplied = true;
  };

  const compile = async (source: string, mainPath: string, format: number) => {
    const { compiler, renderer } = await getInstance();
    syncShadow(compiler);
    // Map the latest source, then reset + compile (matches typst.ts's own
    // ordering in TypstSnippet.vector()).
    compiler.addSource(mainPath, source);
    await compiler.reset();
    const res = await compiler.compile({ mainFilePath: mainPath, format, diagnostics: 'full' });
    const diagnostics: TypstDiagnostic[] = (res?.diagnostics ?? []) as TypstDiagnostic[];
    return { res, diagnostics, renderer };
  };

  return {
    async setFonts(fonts) {
      customFonts = fonts;
      // Not built yet: the fonts go in at init, nothing else to do.
      if (!instance) return;
      const { compiler } = await getInstance();
      const { createTypstFontBuilder } = await import('@myriaddreamin/typst.ts');
      const builder = createTypstFontBuilder();
      await builder.init({ getModule: () => compilerWasmUrl });
      for (const bytes of [...(await loadDefaultFonts()), ...fonts]) {
        try {
          await builder.addFontData(bytes);
        } catch (err) {
          // One unreadable upload must not take the whole set down.
          console.warn('[typst] skipping a font the compiler cannot parse', err);
        }
      }
      // `build` frees the resolver after the callback; the compiler keeps
      // its own reference (typst.ts: "multiple compilers can share fonts").
      await builder.build(async (resolver: unknown) => { compiler.setFonts(resolver); });
      // Drop the font cache so the new set is what the next compile sees.
      await compiler.reset();
    },

    async setShadow(files) {
      shadow = files;
      shadowApplied = false;
    },

    async svg(source, mainPath) {
      const { res, diagnostics, renderer } = await compile(source, mainPath, FORMAT_VECTOR);
      if (!res?.result) return { diagnostics };
      const svg: string = await renderer.runWithSession(async (session: unknown) => {
        renderer.manipulateData({ renderSession: session, action: 'reset', data: res.result });
        return renderer.renderSvg({ renderSession: session });
      });
      return { svg, diagnostics };
    },

    async pdf(source, mainPath) {
      const { res, diagnostics } = await compile(source, mainPath, FORMAT_PDF);
      if (!res?.result) return { diagnostics };
      return { pdf: res.result as Uint8Array, diagnostics };
    },

    async fontInfo(bytes) {
      const { createTypstFontBuilder } = await import('@myriaddreamin/typst.ts');
      const fb = createTypstFontBuilder();
      await fb.init({ getModule: () => compilerWasmUrl });
      const info: any = await fb.getFontInfo(bytes);
      if (!info) return null;
      // typst.ts returns `{ info: [ { family, variant, … } ], conditions }`; read the first entry.
      const face: any = Array.isArray(info?.info) ? info.info[0] : info;
      // The wasm returns a struct whose family field has varied across
      // versions; accept the known spellings rather than pinning to one.
      const family = face?.family ?? face?.family_name ?? face?.familyName ?? null;
      return family ? { family: String(family) } : null;
    },
  };
}

/** Route one command to the driver method it names. Shared by the worker and the inline fallback. */
export function dispatch(driver: TypstDriver, cmd: DriverCommand): Promise<unknown> {
  switch (cmd.op) {
    case 'setFonts': return driver.setFonts(cmd.fonts);
    case 'setShadow': return driver.setShadow(cmd.files);
    case 'svg': return driver.svg(cmd.source, cmd.mainPath);
    case 'pdf': return driver.pdf(cmd.source, cmd.mainPath);
    case 'fontInfo': return driver.fontInfo(cmd.bytes);
  }
}
