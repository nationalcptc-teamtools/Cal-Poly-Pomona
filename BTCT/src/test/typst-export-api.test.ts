// Client side of the server Typst export (server/typst/index.mjs). Covers
// the capability probe, the export call's blob/warnings decoding, and the
// pure warning rewrite used for display.
import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  exportOnServer,
  fetchExportCapabilities,
  loadExportCapabilities,
  probeExportCapabilities,
  serverExportNotice,
  type ExportCapabilities,
} from '@/lib/typst-export-api';

afterEach(() => vi.unstubAllGlobals());

describe('typst export api', () => {
  it('reports no capabilities when the route is missing (flag off)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 404 })));
    expect(await fetchExportCapabilities()).toEqual({ pdf: false, docx: false });
  });

  it('returns the blob and the baked count', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new Uint8Array([1, 2, 3]), {
      status: 200,
      headers: { 'X-Baked-Images': '2' },
    })));
    const out = await exportOnServer('w1', 'docx');
    expect(out.baked).toBe(2);
    expect(out.blob.size).toBe(3);
    expect(out.warnings).toEqual([]);
  });

  it('surfaces the server error message', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'Typst error at main.typ:3: boom' }), { status: 422 })));
    await expect(exportOnServer('w1', 'pdf')).rejects.toThrow('Typst error at main.typ:3: boom');
  });

  it('decodes a well-formed warnings header into an array', async () => {
    const encoded = encodeURIComponent(JSON.stringify(['No repeating header or footer was found, so the Word file has none.']));
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new Uint8Array([1]), {
      status: 200,
      headers: { 'X-Baked-Images': '0', 'X-Export-Warnings': encoded },
    })));
    const out = await exportOnServer('w1', 'docx');
    expect(out.warnings).toEqual(['No repeating header or footer was found, so the Word file has none.']);
  });

  it('never throws on a malformed warnings header (bad percent-escape)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new Uint8Array([1]), {
      status: 200,
      headers: { 'X-Baked-Images': '0', 'X-Export-Warnings': '%E0%A4%A' },
    })));
    const out = await exportOnServer('w1', 'docx');
    expect(out.warnings).toEqual([]);
  });

  it('never throws on a malformed warnings header (valid escape, not JSON)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new Uint8Array([1]), {
      status: 200,
      headers: { 'X-Baked-Images': '0', 'X-Export-Warnings': encodeURIComponent('not json') },
    })));
    const out = await exportOnServer('w1', 'docx');
    expect(out.warnings).toEqual([]);
  });

  it('rejects with the server sentence on a 429', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ error: 'Another export is already queued. Try again in a moment.' }),
      { status: 429 },
    )));
    await expect(exportOnServer('w1', 'pdf')).rejects.toThrow('Another export is already queued. Try again in a moment.');
  });

  it('reports a network failure as "Could not reach the server."', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network down'); }));
    await expect(exportOnServer('w1', 'pdf')).rejects.toThrow('Could not reach the server.');
  });

  describe('serverExportNotice', () => {
    // X-Baked-Images is the only thing that tells an operator the redactions
    // actually went into the file they just downloaded, and it was returned
    // and never shown.
    it('says nothing when nothing was baked and nothing went wrong', () => {
      expect(serverExportNotice(0, [])).toBeNull();
    });

    it('reports the redaction count on a clean export', () => {
      expect(serverExportNotice(3, [])).toBe('Exported. 3 image(s) had their redactions baked in.');
    });

    it('leads with the redaction count and then the notes', () => {
      // Warnings reach the banner in the server's own wording: the converter
      // writes them for an operator and nothing here rewords them.
      expect(serverExportNotice(1, ['27 table-of-contents entries were rebuilt.']))
        .toBe([
          '1 image(s) had their redactions baked in.',
          'Exported, with 1 note(s):',
          '27 table-of-contents entries were rebuilt.',
        ].join('\n'));
    });

    it('keeps the notes-only wording when nothing was baked', () => {
      expect(serverExportNotice(0, ['Two assets are named a.png; only the first was used.']))
        .toBe('Exported, with 1 note(s):\nTwo assets are named a.png; only the first was used.');
    });
  });
});

describe('capability probe', () => {
  const answer = (status: number, body = '{"pdf":true,"docx":true}') =>
    vi.stubGlobal('fetch', vi.fn(async () => new Response(body, { status })));

  it('takes a 200 as the answer', async () => {
    answer(200);
    expect(await probeExportCapabilities()).toEqual({ caps: { pdf: true, docx: true }, retry: false });
  });

  it('does not retry an answer that means no export (404, 501, 401)', async () => {
    for (const status of [404, 501, 401, 403]) {
      answer(status);
      expect((await probeExportCapabilities()).retry).toBe(false);
    }
  });

  it('retries a probe that said nothing (network error, 5xx, 429, a body that is not JSON)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch'); }));
    expect(await probeExportCapabilities()).toEqual({ caps: { pdf: false, docx: false }, retry: true });
    for (const status of [500, 502, 503, 504, 408, 429]) {
      answer(status);
      expect((await probeExportCapabilities()).retry).toBe(true);
    }
    answer(200, '<html>proxy</html>');
    expect((await probeExportCapabilities()).retry).toBe(true);
  });

  function manualTimers() {
    const queue: { fn: () => void; ms: number; id: number }[] = [];
    let next = 1;
    return {
      queue,
      setTimer: (fn: () => void, ms: number) => { const id = next++; queue.push({ fn, ms, id }); return id; },
      clearTimer: (h: unknown) => { const i = queue.findIndex((t) => t.id === h); if (i >= 0) queue.splice(i, 1); },
      fire: async () => { const t = queue.shift(); t?.fn(); await new Promise((r) => setTimeout(r, 0)); },
    };
  }
  const flush = () => new Promise((r) => setTimeout(r, 0));

  it('shows the buttons once a retried probe answers', async () => {
    const results = [
      { caps: { pdf: false, docx: false }, retry: true },
      { caps: { pdf: false, docx: false }, retry: true },
      { caps: { pdf: true, docx: true }, retry: false },
    ];
    const probe = vi.fn(async () => results.shift()!);
    const seen: ExportCapabilities[] = [];
    const t = manualTimers();
    loadExportCapabilities((c) => seen.push(c), { probe, delays: [10, 20, 40], setTimer: t.setTimer, clearTimer: t.clearTimer });
    await flush();
    expect(t.queue.map((q) => q.ms)).toEqual([10]);
    await t.fire();
    expect(t.queue.map((q) => q.ms)).toEqual([20]);
    await t.fire();
    expect(probe).toHaveBeenCalledTimes(3);
    expect(seen.at(-1)).toEqual({ pdf: true, docx: true });
    expect(t.queue).toEqual([]);
  });

  it('gives up after the last delay', async () => {
    const probe = vi.fn(async () => ({ caps: { pdf: false, docx: false }, retry: true }));
    const t = manualTimers();
    loadExportCapabilities(() => {}, { probe, delays: [1, 2], setTimer: t.setTimer, clearTimer: t.clearTimer });
    await flush();
    await t.fire();
    await t.fire();
    expect(probe).toHaveBeenCalledTimes(3);
    expect(t.queue).toEqual([]);
  });

  it('calls nothing and probes no more after cancel', async () => {
    const probe = vi.fn(async () => ({ caps: { pdf: true, docx: true }, retry: true }));
    const onCaps = vi.fn();
    const t = manualTimers();
    const cancel = loadExportCapabilities(onCaps, { probe, delays: [5], setTimer: t.setTimer, clearTimer: t.clearTimer });
    await flush();
    expect(onCaps).toHaveBeenCalledTimes(1);
    cancel();
    expect(t.queue).toEqual([]);
    const cancelEarly = loadExportCapabilities(onCaps, { probe, delays: [5], setTimer: t.setTimer, clearTimer: t.clearTimer });
    cancelEarly();
    await flush();
    expect(onCaps).toHaveBeenCalledTimes(1);
    expect(probe).toHaveBeenCalledTimes(2);
  });
});
