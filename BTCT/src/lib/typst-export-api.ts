// Client side of the server Typst export (server/typst/index.mjs).
//
// This module is Typst code for invariant #17's purposes (it is named
// `typst-export-api.ts`, matching the `lib/typst-` exemption), so it may only
// be imported from `src/components/typst/` or another `lib/typst-*` module,
// never from anything the entry bundle loads unconditionally.
import { API_URL, useAuthStore } from '@/auth/auth-store';

export interface ExportCapabilities { pdf: boolean; docx: boolean }

export interface ServerExportResult {
  blob: Blob;
  baked: number;
  warnings: string[];
}

function authHeaders(): Record<string, string> {
  const token = useAuthStore.getState().token;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

const NO_CAPABILITIES: ExportCapabilities = { pdf: false, docx: false };

/**
 * One capability probe. `retry` is true when the answer says nothing about
 * the server (no response, a 5xx other than 501, 408, 429, a body that is not
 * JSON): the first probe on a fresh box waits for a Python import of
 * pdf2docx (about a second, much longer on a loaded host), and one lost
 * answer used to hide both server export buttons until the tab was reopened.
 * A 404 or 501 (no export routes) and a 401/403 are answers, not retried.
 */
export async function probeExportCapabilities(): Promise<{ caps: ExportCapabilities; retry: boolean }> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}/api/typst/capabilities`, { headers: authHeaders() });
  } catch {
    return { caps: NO_CAPABILITIES, retry: true };
  }
  if (!res.ok) {
    const transient = (res.status >= 500 && res.status !== 501) || res.status === 408 || res.status === 429;
    return { caps: NO_CAPABILITIES, retry: transient };
  }
  try {
    const data = (await res.json()) as Partial<ExportCapabilities> | null;
    return { caps: { pdf: data?.pdf === true, docx: data?.docx === true }, retry: false };
  } catch {
    return { caps: NO_CAPABILITIES, retry: true };
  }
}

/** What the server can export. All false when the routes do not exist. */
export async function fetchExportCapabilities(): Promise<ExportCapabilities> {
  return (await probeExportCapabilities()).caps;
}

/** Waits between capability probes after one that said nothing (then it gives up). */
export const CAPABILITY_RETRY_DELAYS_MS = [1500, 3000, 6000, 12000] as const;

/**
 * Probe the capabilities, retrying a probe that said nothing on
 * CAPABILITY_RETRY_DELAYS_MS, and call `onCaps` with every answer (the
 * all-false one included, so the buttons stay hidden while it retries).
 * Returns a cancel function for an unmount; nothing is called after it.
 */
export function loadExportCapabilities(
  onCaps: (caps: ExportCapabilities) => void,
  opts: {
    probe?: () => Promise<{ caps: ExportCapabilities; retry: boolean }>;
    delays?: readonly number[];
    setTimer?: (fn: () => void, ms: number) => unknown;
    clearTimer?: (handle: unknown) => void;
  } = {},
): () => void {
  const probe = opts.probe ?? probeExportCapabilities;
  const delays = opts.delays ?? CAPABILITY_RETRY_DELAYS_MS;
  const setTimer = opts.setTimer ?? ((fn: () => void, ms: number) => setTimeout(fn, ms));
  const clearTimer = opts.clearTimer ?? ((h: unknown) => clearTimeout(h as ReturnType<typeof setTimeout>));
  let cancelled = false;
  let timer: unknown = null;
  const attempt = (n: number) => {
    void probe().then(({ caps, retry }) => {
      if (cancelled) return;
      onCaps(caps);
      const wait = retry ? delays[n] : undefined;
      if (wait !== undefined) timer = setTimer(() => { timer = null; attempt(n + 1); }, wait);
    });
  };
  attempt(0);
  return () => {
    cancelled = true;
    if (timer !== null) clearTimer(timer);
  };
}

/**
 * Decode the `X-Export-Warnings` header (see `server/typst/index.mjs`'s
 * `encodeWarnings`): `encodeURIComponent(JSON.stringify(string[]))`, or
 * absent when there is nothing to report.
 *
 * A header only ever comes from this server, but it still travels through a
 * proxy and a browser's header parser before it gets here, so a malformed
 * value (a broken percent-escape, valid JSON that is not a string array)
 * is swallowed rather than thrown: the export already succeeded, and losing
 * the warnings is far better than losing the download over them.
 */
function decodeWarningsHeader(header: string | null): string[] {
  if (!header) return [];
  try {
    const parsed: unknown = JSON.parse(decodeURIComponent(header));
    if (Array.isArray(parsed) && parsed.every((w) => typeof w === 'string')) return parsed;
    return [];
  } catch {
    return [];
  }
}

/**
 * The banner after a server export, or null when there is nothing to say.
 *
 * `X-Baked-Images` is the only thing that tells whoever clicked the button
 * that the crops and redactions really did go into the file they just
 * downloaded, so it leads. Warnings follow in the wording the tab already
 * used. Nothing baked and nothing to warn about stays silent, as before.
 */
export function serverExportNotice(baked: number, warnings: string[]): string | null {
  const redacted = baked > 0 ? `${baked} image(s) had their redactions baked in.` : null;
  if (warnings.length === 0) return redacted === null ? null : `Exported. ${redacted}`;
  return [
    ...(redacted === null ? [] : [redacted]),
    `Exported, with ${warnings.length} note(s):`,
    ...warnings,
  ].join('\n');
}

export async function exportOnServer(workspaceId: string, format: 'pdf' | 'docx'): Promise<ServerExportResult> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}/api/typst/${encodeURIComponent(workspaceId)}/export?format=${format}`, {
      method: 'POST',
      headers: authHeaders(),
    });
  } catch {
    throw new Error('Could not reach the server.');
  }
  if (!res.ok) {
    const data = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(data.error || `export failed (${res.status})`);
  }
  return {
    blob: await res.blob(),
    baked: Number(res.headers.get('X-Baked-Images') ?? 0),
    warnings: decodeWarningsHeader(res.headers.get('X-Export-Warnings')),
  };
}
