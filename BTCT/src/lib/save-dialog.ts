// ─────────────────────────────────────────────────────────────────────────
// "Save as" with the operating system's own dialog.
//
// Where the browser has the File System Access API's `showSaveFilePicker`
// (Chrome and Edge on Windows and Linux), a download can open the native
// Explorer or GTK save dialog, so the user picks the folder and the name.
// Firefox (Kali's ESR included) and Safari do not implement it; there every
// download keeps going straight to the browser's Downloads folder.
//
// `pickSaveTarget` opens the dialog and hands back a target that can take a
// Blob or a stream (a 200 MB backup ZIP is piped from the response, never
// held in memory). A cancelled dialog is a quiet 'cancelled'; any other
// failure of the API is 'unavailable', and the caller falls back to the
// plain download. The dialog needs a user gesture: when the work before it
// took longer than the browser's activation window (a workspace export, a
// server-side PDF), a small "ready, Save…" bar asks for one more click.
//
// The preference "Ask where to save each export" is per device
// (localStorage `btct.askWhereToSave`, default on), like the interface zoom:
// whether a dialog exists at all depends on the browser.
//
// Imports nothing, so `download.ts` stays cheap for the shell.
// ─────────────────────────────────────────────────────────────────────────

export type SaveOutcome = 'saved' | 'downloaded' | 'cancelled';

interface PickerWritable extends WritableStream<Uint8Array> {
  write(data: Blob | BufferSource | string): Promise<void>;
  close(): Promise<void>;
  abort(reason?: unknown): Promise<void>;
}

interface PickerHandle {
  name?: string;
  createWritable(): Promise<PickerWritable>;
  remove?(): Promise<void>;
}

interface PickerOptions {
  suggestedName: string;
  types?: Array<{ description: string; accept: Record<string, string[]> }>;
  id?: string;
  startIn?: string;
}

type PickerFn = (opts: PickerOptions) => Promise<PickerHandle>;

const PREF_KEY = 'btct.askWhereToSave';
/** The dialog remembers its last folder under this id, apart from other sites' pickers. */
export const PICKER_ID = 'btct-exports';

const prefListeners = new Set<(on: boolean) => void>();

function pickerFn(): PickerFn | null {
  if (typeof window === 'undefined') return null;
  const fn = (window as unknown as { showSaveFilePicker?: PickerFn }).showSaveFilePicker;
  return typeof fn === 'function' ? fn.bind(window) : null;
}

/** True when this browser can open the system save dialog. */
export function saveDialogSupported(): boolean {
  return pickerFn() !== null;
}

/** The "Ask where to save each export" preference on this device (default on). */
export function getAskWhereToSave(): boolean {
  try { return localStorage.getItem(PREF_KEY) !== '0'; } catch { return true; }
}

export function setAskWhereToSave(on: boolean): void {
  try { localStorage.setItem(PREF_KEY, on ? '1' : '0'); } catch { /* storage blocked: session only */ }
  for (const fn of prefListeners) fn(on);
}

export function onAskWhereToSaveChange(fn: (on: boolean) => void): () => void {
  prefListeners.add(fn);
  return () => { prefListeners.delete(fn); };
}

/** True when a download should open the system save dialog. */
export function usesSaveDialog(): boolean {
  return saveDialogSupported() && getAskWhereToSave();
}

/** The `types` filter for a file: ZIP gets its own label, anything else its extension. */
export function pickerTypes(filename: string, mime: string): PickerOptions['types'] {
  const ext = /\.([A-Za-z0-9]{1,10})$/.exec(filename)?.[1]?.toLowerCase();
  const type = (mime || '').split(';')[0]!.trim().toLowerCase();
  if (!ext || !/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(type)) return undefined;
  if (ext === 'zip') return [{ description: 'ZIP archive', accept: { 'application/zip': ['.zip'] } }];
  return [{ description: `${ext.toUpperCase()} file`, accept: { [type]: [`.${ext}`] } }];
}

function errorName(e: unknown): string {
  return e && typeof e === 'object' && 'name' in e ? String((e as { name: unknown }).name) : '';
}

/** A file the user picked in the save dialog. */
export interface SaveTarget {
  /** The name the user chose (may differ from the suggestion). */
  name: string;
  writeBlob(blob: Blob): Promise<void>;
  /** Pipe `body` into the file; `onProgress` gets the bytes written so far. */
  writeStream(body: ReadableStream<Uint8Array>, onProgress?: (bytes: number) => void, signal?: AbortSignal): Promise<void>;
  /** Remove the (empty) file the dialog created, when nothing will be written. */
  discard(): Promise<void>;
}

function toTarget(handle: PickerHandle, fallbackName: string): SaveTarget {
  return {
    name: handle.name || fallbackName,
    async writeBlob(blob) {
      const w = await handle.createWritable();
      try {
        await w.write(blob);
        await w.close();
      } catch (e) {
        await w.abort(e).catch(() => {});
        throw e;
      }
    },
    async writeStream(body, onProgress, signal) {
      const w = await handle.createWritable();
      let written = 0;
      const counter = new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, ctl) {
          written += chunk.byteLength;
          onProgress?.(written);
          ctl.enqueue(chunk);
        },
      });
      // pipeTo closes the file on success and aborts it (keeping the old
      // contents, or none) on any error or abort.
      await body.pipeThrough(counter).pipeTo(w, signal ? { signal } : undefined);
    },
    async discard() {
      try { await handle.remove?.(); } catch { /* nothing to remove, or not allowed */ }
    },
  };
}

/**
 * The "file is ready" bar: one click on Save… is the user gesture the
 * dialog needs. Plain DOM in the app's theme variables, so non-React code
 * (the paste handler) can use it too.
 */
function promptForGesture(filename: string, open: () => Promise<PickerHandle>): Promise<PickerHandle | 'cancelled'> {
  return new Promise((resolve, reject) => {
    const bar = document.createElement('div');
    bar.setAttribute('role', 'alertdialog');
    bar.setAttribute('aria-label', 'Save file');
    bar.dataset.btctSavePrompt = '';
    bar.style.cssText = [
      'position:fixed', 'right:16px', 'bottom:16px', 'z-index:2147483000', 'max-width:min(420px,calc(100vw - 32px))',
      'display:flex', 'align-items:center', 'gap:8px', 'padding:8px 10px', 'font-size:12px',
      'background:hsl(var(--popover))', 'color:hsl(var(--popover-foreground, var(--foreground)))',
      'border:1px solid hsl(var(--border))', 'box-shadow:var(--pane-shadow)',
    ].join(';');
    const text = document.createElement('span');
    text.style.cssText = 'flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
    text.textContent = `${filename} is ready.`;
    text.title = filename;
    const btn = (label: string, primary: boolean) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = label;
      b.style.cssText = `padding:3px 10px;border:1px solid hsl(var(--border));cursor:pointer;${primary
        ? 'background:hsl(var(--primary));color:hsl(var(--primary-foreground))'
        : 'background:transparent;color:inherit'}`;
      return b;
    };
    const save = btn('Save…', true);
    const cancel = btn('Cancel', false);
    const done = () => bar.remove();
    save.addEventListener('click', () => {
      done();
      // Called inside the click, while the gesture is live.
      open().then(resolve, reject);
    });
    cancel.addEventListener('click', () => { done(); resolve('cancelled'); });
    bar.append(text, save, cancel);
    document.body.appendChild(bar);
    save.focus();
  });
}

/**
 * Open the system save dialog for `suggestedName`. Resolves with the picked
 * target, 'cancelled' when the user closed the dialog (or the ready bar), or
 * 'unavailable' when there is no dialog to show (no API, preference off, or
 * the API failed): the caller then downloads the plain way.
 *
 * Call it straight from a click handler where possible; the picker call
 * itself happens before the first await.
 */
export async function pickSaveTarget(suggestedName: string, mime: string): Promise<SaveTarget | 'cancelled' | 'unavailable'> {
  const picker = usesSaveDialog() ? pickerFn() : null;
  if (!picker) return 'unavailable';
  const types = pickerTypes(suggestedName, mime);
  const open = () => picker({ suggestedName, ...(types ? { types } : {}), id: PICKER_ID, startIn: 'downloads' });
  const activation = typeof navigator !== 'undefined'
    ? (navigator as unknown as { userActivation?: { isActive: boolean } }).userActivation
    : undefined;
  let handle: PickerHandle | 'cancelled';
  try {
    handle = activation && !activation.isActive ? await promptForGesture(suggestedName, open) : await open();
  } catch (e) {
    const name = errorName(e);
    if (name === 'AbortError') return 'cancelled';
    if (name === 'SecurityError' || name === 'NotAllowedError') {
      // The gesture ran out between the click and here: ask for a fresh one.
      try {
        handle = await promptForGesture(suggestedName, open);
      } catch (e2) {
        return errorName(e2) === 'AbortError' ? 'cancelled' : 'unavailable';
      }
    } else {
      return 'unavailable';
    }
  }
  return handle === 'cancelled' ? 'cancelled' : toTarget(handle, suggestedName);
}
