import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import JSZip from 'jszip';
import { buildDownloadZip, downloadAsZip, downloadZipName, zipCompressionFor, zipEntryNames, zipFormatTag } from '@/lib/download-zip';
import { isZipBytes, readUploadText } from '@/lib/zip-upload';
import { pagesMarkdownArchive } from '@/export/pages-markdown';
import { openZip } from '../../server/zip-stream.mjs';
import type { Page } from '@/types';

const at = new Date(2026, 9, 12, 22, 48, 30); // local time, like the names

async function blobBuffer(b: Blob): Promise<Buffer> {
  return Buffer.from(await b.arrayBuffer());
}

describe('download ZIP names', () => {
  it('is <portable stem>_<YYYY-MM-DD_HHMM>.zip', () => {
    expect(downloadZipName('command-log', at)).toBe('command-log_2026-10-12_2248.zip');
    expect(downloadZipName('CPTC: Team 5 / report?', at)).toBe('CPTC_ Team 5 _ report__2026-10-12_2248.zip');
    expect(downloadZipName('', at)).toBe('Untitled_2026-10-12_2248.zip');
    expect(downloadZipName('con', at)).toBe('con__2026-10-12_2248.zip');
  });

  it('adds the format tag after the stamp, and keeps the name within one segment', () => {
    expect(downloadZipName('Alpha Corp CPTC', at, 'pdf')).toBe('Alpha Corp CPTC_2026-10-12_2248_pdf.zip');
    expect(downloadZipName('Alpha Corp CPTC', at, 'docx')).not.toBe(downloadZipName('Alpha Corp CPTC', at, 'pdf'));
    expect(downloadZipName('x', at, '../evil')).toBe('x_2026-10-12_2248.zip');
    const long = downloadZipName('W'.repeat(200), at, 'svg');
    expect(new TextEncoder().encode(long.replace(/\.zip$/, '')).length).toBeLessThanOrEqual(60);
    expect(long.endsWith('_2026-10-12_2248_svg.zip')).toBe(true);
  });

  it('derives the tag from the files: one per extension, in order', () => {
    expect(zipFormatTag(['document.pdf'])).toBe('pdf');
    expect(zipFormatTag(['command-log-1.CSV'])).toBe('csv');
    expect(zipFormatTag(['a.png', 'b.png', 'c.jpg'])).toBe('png-jpg');
    expect(zipFormatTag(['noext'])).toBe('');
    expect(zipFormatTag(['a.a', 'b.b', 'c.c', 'd.d'])).toBe('');
  });
  it('keeps entry names, made portable and unique ignoring case', () => {
    expect(zipEntryNames(['document.pdf'])).toEqual(['document.pdf']);
    expect(zipEntryNames(['a.json', 'A.json', 'b/c.txt'])).toEqual(['a.json', 'A-2.json', 'b_c.txt']);
  });
  it('stores compressed formats and deflates text', () => {
    for (const n of ['x.png', 'x.JPG', 'r.pdf', 'r.docx', 'a.zip', 'f.woff2']) expect(zipCompressionFor(n)).toBe('STORE');
    for (const n of ['x.csv', 'x.json', 'x.md', 'x.svg', 'x.txt', 'noext']) expect(zipCompressionFor(n)).toBe('DEFLATE');
  });
});

describe('buildDownloadZip', () => {
  const dirs: string[] = [];
  afterEach(() => { for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true }); });

  it('holds the original files under their names, text deflated and PDF stored', async () => {
    const pdf = new Uint8Array(2000).fill(0x25);
    const csv = 'a,b\n'.repeat(500);
    const blob = await buildDownloadZip([{ name: 'command-log-1.csv', data: csv }, { name: 'document.pdf', data: pdf }], at);
    expect(blob.type).toBe('application/zip');
    const buf = await blobBuffer(blob);
    expect(isZipBytes(buf.subarray(0, 4))).toBe(true);
    const j = await JSZip.loadAsync(buf);
    expect(Object.keys(j.files)).toEqual(['command-log-1.csv', 'document.pdf']);
    expect(await j.file('command-log-1.csv')!.async('string')).toBe(csv);
    expect(Buffer.from(await j.file('document.pdf')!.async('uint8array')).equals(Buffer.from(pdf))).toBe(true);
    // The compression method as written in the archive, read by the server's reader.
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'btct-dz-'));
    dirs.push(d);
    fs.writeFileSync(path.join(d, 'z.zip'), buf);
    const z = await openZip(path.join(d, 'z.zip'));
    expect(z.entry('command-log-1.csv')!.method).toBe(8);
    expect(z.entry('document.pdf')!.method).toBe(0);
    await z.close();
  });

  it('refuses an empty list', async () => {
    await expect(buildDownloadZip([], at)).rejects.toThrow(/nothing/);
  });
});

describe('downloadAsZip', () => {
  const created: Blob[] = [];
  let clicks: string[] = [];
  const origClick = HTMLAnchorElement.prototype.click;
  beforeEach(() => {
    created.length = 0;
    clicks = [];
    URL.createObjectURL = ((b: Blob) => { created.push(b); return `blob:test/${created.length}`; }) as typeof URL.createObjectURL;
    URL.revokeObjectURL = (() => {}) as typeof URL.revokeObjectURL;
    HTMLAnchorElement.prototype.click = function click(this: HTMLAnchorElement) { clicks.push(this.download); };
  });
  afterEach(() => { HTMLAnchorElement.prototype.click = origClick; vi.useRealTimers(); });

  it('hands one .zip to downloadBlob and resolves with its name', async () => {
    const name = await downloadAsZip('btct-prefs-alice', [{ name: 'btct-prefs-alice.json', data: '{"format":"btct-prefs"}' }], at);
    expect(name).toBe('btct-prefs-alice_2026-10-12_2248_json.zip');
    expect(clicks).toEqual([name]);
    expect(created[0]!.type).toBe('application/zip');
    const j = await JSZip.loadAsync(await blobBuffer(created[0]!));
    expect(await j.file('btct-prefs-alice.json')!.async('string')).toBe('{"format":"btct-prefs"}');
  });
});

describe('pagesMarkdownArchive', () => {
  it('wraps a single page in <Title>_<date>_md.zip holding <Title>.md', async () => {
    const page = { id: 'p1', workspaceId: 'w', title: 'Recon notes', content: '# Hi', tags: [], parentId: null, sortOrder: 0 } as unknown as Page;
    const { blob, fileName, files } = await pagesMarkdownArchive([page], { id: 'w', name: 'WS' }, at);
    expect(files).toBe(1);
    expect(fileName).toBe('Recon notes_2026-10-12_2248_md.zip');
    const j = await JSZip.loadAsync(await blobBuffer(blob));
    expect(Object.keys(j.files)).toEqual(['Recon notes.md']);
  });
});

describe('readUploadText', () => {
  const opts = { pick: (n: string) => n.endsWith('.json'), maxBytes: 1000, what: 'settings export' };
  const asFile = (data: string | Uint8Array, name: string) => Object.assign(new Blob([data as BlobPart]), { name });

  it('reads a bare file as it is (exports from older builds)', async () => {
    const r = await readUploadText(asFile('{"a":1}', 'btct-prefs-x.json'), opts);
    expect(r).toEqual({ name: 'btct-prefs-x.json', text: '{"a":1}', fromZip: false });
  });

  it('reads the first matching member of a ZIP, recognised by its signature', async () => {
    const z = new JSZip();
    z.file('readme.txt', 'skip me');
    z.file('btct-prefs-x.json', '{"a":2}');
    const buf = await z.generateAsync({ type: 'uint8array', compression: 'DEFLATE' });
    const r = await readUploadText(asFile(buf, 'renamed.bin'), opts);
    expect(r).toEqual({ name: 'btct-prefs-x.json', text: '{"a":2}', fromZip: true });
  });

  it('refuses a ZIP without a matching member, an oversize member and an oversize file', async () => {
    const z = new JSZip();
    z.file('a.txt', 'x');
    await expect(readUploadText(asFile(await z.generateAsync({ type: 'uint8array' }), 'a.zip'), opts)).rejects.toThrow(/holds no settings export/);
    const big = new JSZip();
    big.file('big.json', 'x'.repeat(50_000));
    const bigZip = await big.generateAsync({ type: 'uint8array', compression: 'DEFLATE' });
    expect(bigZip.length).toBeLessThan(1000);
    await expect(readUploadText(asFile(bigZip, 'b.zip'), opts)).rejects.toThrow(/too large/);
    await expect(readUploadText(asFile('x'.repeat(2000), 'c.json'), opts)).rejects.toThrow(/too large/);
  });

  it('says so when the ZIP is damaged', async () => {
    const bad = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 1, 2, 3, 4, 5]);
    await expect(readUploadText(asFile(bad, 'd.zip'), opts)).rejects.toThrow(/not a readable ZIP/);
  });
});
