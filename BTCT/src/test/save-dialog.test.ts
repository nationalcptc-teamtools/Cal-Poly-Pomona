import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import JSZip from 'jszip';
import { downloadBlob } from '@/lib/download';
import { downloadAsZip } from '@/lib/download-zip';
import { PICKER_ID, getAskWhereToSave, pickSaveTarget, pickerTypes, setAskWhereToSave, usesSaveDialog } from '@/lib/save-dialog';

type PickerOpts = { suggestedName: string; types?: unknown; id?: string; startIn?: string };

/** An in-memory stand-in for the File System Access API's save picker. */
function installPicker(behaviour: 'ok' | 'abort' | 'security' | 'type' = 'ok') {
  const calls: PickerOpts[] = [];
  const written: Uint8Array[] = [];
  const state = { closed: false, aborted: false, removed: false };
  const picker = vi.fn(async (opts: PickerOpts) => {
    calls.push(opts);
    if (behaviour === 'abort') throw new DOMException('The user aborted a request.', 'AbortError');
    if (behaviour === 'security') throw new DOMException('Must be handling a user gesture.', 'SecurityError');
    if (behaviour === 'type') throw new TypeError('bad accept');
    return {
      name: opts.suggestedName,
      async createWritable() {
        const ws = new WritableStream<Uint8Array>({
          write(chunk) { written.push(new Uint8Array(chunk)); },
          close() { state.closed = true; },
          abort() { state.aborted = true; },
        });
        return Object.assign(ws, {
          async write(data: Blob | BufferSource | string) {
            const buf = data instanceof Blob ? new Uint8Array(await data.arrayBuffer())
              : typeof data === 'string' ? new TextEncoder().encode(data)
                : new Uint8Array(data instanceof ArrayBuffer ? data : (data as ArrayBufferView).buffer);
            written.push(buf);
          },
          async close() { state.closed = true; },
          async abort() { state.aborted = true; },
        });
      },
      async remove() { state.removed = true; },
    };
  });
  (window as unknown as { showSaveFilePicker?: unknown }).showSaveFilePicker = picker;
  const bytes = () => {
    const out = new Uint8Array(written.reduce((n, c) => n + c.byteLength, 0));
    let o = 0;
    for (const c of written) { out.set(c, o); o += c.byteLength; }
    return out;
  };
  return { picker, calls, bytes, state };
}

describe('downloadBlob and the system save dialog', () => {
  let clicks: string[] = [];
  const origClick = HTMLAnchorElement.prototype.click;
  beforeEach(() => {
    clicks = [];
    localStorage.clear();
    URL.createObjectURL = (() => 'blob:test/1') as typeof URL.createObjectURL;
    URL.revokeObjectURL = (() => {}) as typeof URL.revokeObjectURL;
    HTMLAnchorElement.prototype.click = function click(this: HTMLAnchorElement) { clicks.push(this.download); };
  });
  afterEach(() => {
    HTMLAnchorElement.prototype.click = origClick;
    delete (window as unknown as { showSaveFilePicker?: unknown }).showSaveFilePicker;
    document.querySelectorAll('[data-btct-save-prompt]').forEach((n) => n.remove());
  });

  it('opens the picker with the suggested name, ZIP filter and id, and writes the bytes', async () => {
    const { calls, bytes, state } = installPicker();
    const outcome = await downloadBlob(new Blob(['PK-bytes'], { type: 'application/zip' }), 'w_2026-10-15_1200.zip', 'application/zip');
    expect(outcome).toBe('saved');
    expect(calls).toEqual([{
      suggestedName: 'w_2026-10-15_1200.zip',
      types: [{ description: 'ZIP archive', accept: { 'application/zip': ['.zip'] } }],
      id: PICKER_ID,
      startIn: 'downloads',
    }]);
    expect(new TextDecoder().decode(bytes())).toBe('PK-bytes');
    expect(state.closed).toBe(true);
    expect(clicks).toEqual([]);
  });

  it('a cancelled dialog downloads nothing and says so', async () => {
    installPicker('abort');
    const outcome = await downloadBlob(new Blob(['x']), 'a.zip', 'application/zip');
    expect(outcome).toBe('cancelled');
    expect(clicks).toEqual([]);
  });

  it('falls back to the anchor download when the picker is missing (Firefox)', async () => {
    expect(usesSaveDialog()).toBe(false);
    const p = downloadBlob(new Blob(['x']), 'a.zip', 'application/zip');
    // The anchor click is synchronous, before the promise is awaited.
    expect(clicks).toEqual(['a.zip']);
    expect(await p).toBe('downloaded');
  });

  it('with the preference off, a browser that has the picker downloads straight away', async () => {
    const { picker } = installPicker();
    setAskWhereToSave(false);
    expect(getAskWhereToSave()).toBe(false);
    expect(await downloadBlob(new Blob(['x']), 'a.zip', 'application/zip')).toBe('downloaded');
    expect(picker).not.toHaveBeenCalled();
    expect(clicks).toEqual(['a.zip']);
    setAskWhereToSave(true);
    expect(localStorage.getItem('btct.askWhereToSave')).toBe('1');
  });

  it('a picker that fails for another reason falls back to the download', async () => {
    installPicker('type');
    expect(await downloadBlob(new Blob(['x']), 'a.zip', 'application/zip')).toBe('downloaded');
    expect(clicks).toEqual(['a.zip']);
  });

  it('an expired gesture asks for one more click before opening the dialog', async () => {
    const { picker, bytes } = installPicker();
    Object.defineProperty(navigator, 'userActivation', { configurable: true, value: { isActive: false } });
    try {
      const p = downloadBlob(new Blob(['late']), 'late.zip', 'application/zip');
      await Promise.resolve();
      expect(picker).not.toHaveBeenCalled();
      const bar = document.querySelector('[data-btct-save-prompt]')!;
      expect(bar.textContent).toContain('late.zip is ready.');
      (bar.querySelector('button') as HTMLButtonElement).click();
      expect(await p).toBe('saved');
      expect(new TextDecoder().decode(bytes())).toBe('late');
    } finally {
      delete (navigator as unknown as { userActivation?: unknown }).userActivation;
    }
  });

  it('the ready bar can be dismissed: nothing is saved or downloaded', async () => {
    const { picker } = installPicker();
    Object.defineProperty(navigator, 'userActivation', { configurable: true, value: { isActive: false } });
    try {
      const p = downloadBlob(new Blob(['x']), 'x.zip', 'application/zip');
      await Promise.resolve();
      const buttons = document.querySelectorAll('[data-btct-save-prompt] button');
      (buttons[1] as HTMLButtonElement).click();
      expect(await p).toBe('cancelled');
      expect(picker).not.toHaveBeenCalled();
      expect(clicks).toEqual([]);
    } finally {
      delete (navigator as unknown as { userActivation?: unknown }).userActivation;
    }
  });

  it('downloadAsZip writes a valid ZIP through the picker and resolves null on cancel', async () => {
    const at = new Date(2026, 9, 15, 12, 0);
    const { calls, bytes } = installPicker();
    const name = await downloadAsZip('command-log', [{ name: 'command-log.csv', data: 'a,b\n1,2\n' }], at);
    expect(name).toBe('command-log_2026-10-15_1200_csv.zip');
    expect(calls[0]!.suggestedName).toBe(name);
    const zip = await JSZip.loadAsync(bytes());
    expect(await zip.file('command-log.csv')!.async('string')).toBe('a,b\n1,2\n');

    installPicker('abort');
    expect(await downloadAsZip('command-log', [{ name: 'command-log.csv', data: 'x' }], at)).toBeNull();
    expect(clicks).toEqual([]);
  });

  it('pickSaveTarget streams into the file and discard removes it', async () => {
    const { bytes, state } = installPicker();
    const t = await pickSaveTarget('btct-backup-20261015-120000.zip', 'application/zip');
    if (typeof t === 'string') throw new Error(`expected a target, got ${t}`);
    const seen: number[] = [];
    const body = new ReadableStream<Uint8Array>({
      start(ctl) {
        for (let i = 0; i < 7; i++) ctl.enqueue(new Uint8Array(10_000).fill(7));
        ctl.close();
      },
    });
    await t.writeStream(body, (n) => seen.push(n));
    expect(bytes().byteLength).toBe(70_000);
    expect(seen.at(-1)).toBe(70_000);
    expect(state.closed).toBe(true);
    await t.discard();
    expect(state.removed).toBe(true);
  });
});

describe('pickerTypes', () => {
  it('labels ZIP, uses the extension otherwise, and drops what Chrome would reject', () => {
    expect(pickerTypes('a.zip', 'application/zip')).toEqual([{ description: 'ZIP archive', accept: { 'application/zip': ['.zip'] } }]);
    expect(pickerTypes('a.txt', 'text/plain; charset=utf-8')).toEqual([{ description: 'TXT file', accept: { 'text/plain': ['.txt'] } }]);
    expect(pickerTypes('noext', 'text/plain')).toBeUndefined();
    expect(pickerTypes('a.bin', '')).toBeUndefined();
  });
});
