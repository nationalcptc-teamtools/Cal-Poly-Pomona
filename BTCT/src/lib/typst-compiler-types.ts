// Types shared by the compiler client (main thread), the worker and the
// driver. Kept dependency-free so the client never pulls the wasm code in.

/** A single Typst diagnostic (error/warning) from the compiler. */
export interface TypstDiagnostic {
  severity: string; // 'error' | 'warning' | …
  message: string;
  range?: string;
  path?: string;
}

export interface TypstSvgResult {
  svg?: string;
  diagnostics: TypstDiagnostic[];
  /**
   * True when a newer preview compile was requested before this one reached
   * the front of the queue, so it returned without doing any work. Callers
   * should ignore the result entirely rather than treating the absent `svg`
   * as "the document produced nothing".
   */
  superseded?: boolean;
}

/** A file mounted into the compiler's in-memory filesystem. */
export interface TypstShadowFile {
  /** Absolute virtual path, e.g. `/assets/screenshot.png`. */
  path: string;
  bytes: Uint8Array;
}

export interface TypstFontInfo { family: string }

/** What the driver returns for a preview compile. */
export interface SvgOutput { svg?: string; diagnostics: TypstDiagnostic[] }
/** What the driver returns for a PDF compile. `pdf` is absent on errors. */
export interface PdfOutput { pdf?: Uint8Array; diagnostics: TypstDiagnostic[] }

/** One request to the driver, without the correlation id. */
export type DriverCommand =
  | { op: 'setFonts'; fonts: Uint8Array[] }
  | { op: 'setShadow'; files: TypstShadowFile[] }
  | { op: 'svg'; source: string; mainPath: string }
  | { op: 'pdf'; source: string; mainPath: string }
  | { op: 'fontInfo'; bytes: Uint8Array };

export type DriverRequest = DriverCommand & { id: number };

export type DriverResponse =
  | { id: number; ok: true; value: unknown }
  | { id: number; ok: false; error: string };
