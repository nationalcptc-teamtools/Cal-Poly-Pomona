import { describe, it, expect, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import JSZip from 'jszip';
import {
  ZipWriter,
  openZip,
  crc32,
  safeEntryName,
  extractEntryTo,
  hashEntry,
  startsWithZipSignature,
} from '../../server/zip-stream.mjs';
import { buildManifest, normalizeIncludes, verifyBackupZip, verifyBackup } from '../../server/backup-format.mjs';

const dirs: string[] = [];
const tmp = () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'btct-zip-'));
  dirs.push(d);
  return d;
};
afterEach(() => { for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true }); });

const sha = (b: Uint8Array) => crypto.createHash('sha256').update(b).digest('hex');

async function* chunked(buf: Buffer, size: number) {
  for (let i = 0; i < buf.length; i += size) yield buf.subarray(i, i + size);
}

describe('crc32 and names', () => {
  it('matches the standard check value', () => {
    expect(crc32(Buffer.from('123456789'))).toBe(0xcbf43926);
    const a = Buffer.from('hello ');
    const b = Buffer.from('world');
    expect(crc32(b, crc32(a))).toBe(crc32(Buffer.concat([a, b])));
  });
  it('refuses names that could leave a folder', () => {
    for (const bad of ['', '/etc/passwd', '../x', 'a/../b', 'a/./b', 'C:/x', 'c:x', 'a\\b', 'a\u0000b', 'a//b', '.', '..']) {
      expect(safeEntryName(bad)).toBeNull();
    }
    for (const ok of ['manifest.json', 'assets/abc-123', 'yjs/btct-shared.yupdate.gz', 'dir/']) {
      expect(safeEntryName(ok)).toBe(ok);
    }
  });
});

describe('ZipWriter and openZip', () => {
  it('round-trips buffers, files and streams, with sha256 and CRC32 checked', async () => {
    const d = tmp();
    const src = path.join(d, 'blob.bin');
    const blob = crypto.randomBytes(3 * 1024 * 1024 + 17);
    fs.writeFileSync(src, blob);
    const big = crypto.randomBytes(700_000);
    const zipPath = path.join(d, 'out.zip');
    const w = await ZipWriter.create(zipPath);
    await w.addBuffer('manifest.json', Buffer.from('{"a":1}'));
    const r2 = await w.addFile('assets/blob', src);
    // No size hint: the writer reserves a ZIP64 extra in the local header.
    const r3 = await w.addIterable('sqlite/data.sqlite.gz', chunked(big, 4096));
    const r4 = await w.addBuffer('empty', Buffer.alloc(0));
    const total = await w.finish();
    expect(total).toBe(fs.statSync(zipPath).size);
    expect(fs.statSync(zipPath).mode & 0o777).toBe(0o600);
    expect(r2).toMatchObject({ bytes: blob.length, sha256: sha(blob) });
    expect(r3).toMatchObject({ bytes: big.length, sha256: sha(big) });

    const z = await openZip(zipPath);
    try {
      expect(z.entries.map((e) => e.name)).toEqual(['manifest.json', 'assets/blob', 'sqlite/data.sqlite.gz', 'empty']);
      expect((await z.readEntry(z.entry('manifest.json')!)).toString()).toBe('{"a":1}');
      expect(await hashEntry(z, z.entry('assets/blob')!)).toEqual({ bytes: blob.length, sha256: r2.sha256 });
      expect(await hashEntry(z, z.entry('sqlite/data.sqlite.gz')!)).toEqual({ bytes: big.length, sha256: r3.sha256 });
      expect(await hashEntry(z, z.entry('empty')!)).toEqual({ bytes: 0, sha256: r4.sha256 });
      const dest = path.join(d, 'x', 'blob');
      expect(await extractEntryTo(z, z.entry('assets/blob')!, dest)).toEqual({ bytes: blob.length, sha256: r2.sha256 });
      expect(fs.readFileSync(dest).equals(blob)).toBe(true);
      // Never overwrites.
      await expect(extractEntryTo(z, z.entry('assets/blob')!, dest)).rejects.toThrow();
    } finally {
      await z.close();
    }

    // A second implementation reads it too (local headers included).
    const j = await JSZip.loadAsync(fs.readFileSync(zipPath));
    expect(Buffer.from(await j.file('assets/blob')!.async('uint8array')).equals(blob)).toBe(true);
    expect(Buffer.from(await j.file('sqlite/data.sqlite.gz')!.async('uint8array')).equals(big)).toBe(true);
  });

  it('refuses duplicate and unsafe names, and a file that already exists', async () => {
    const d = tmp();
    const zipPath = path.join(d, 'a.zip');
    const w = await ZipWriter.create(zipPath);
    await w.addBuffer('a', Buffer.from('1'));
    await expect(w.addBuffer('a', Buffer.from('2'))).rejects.toThrow(/duplicate/);
    await expect(w.addBuffer('../a', Buffer.from('2'))).rejects.toThrow(/unsafe/);
    await expect(w.addFile('b', path.join(d, 'missing'))).rejects.toMatchObject({ code: 'ENOENT' });
    await w.finish();
    await expect(ZipWriter.create(zipPath)).rejects.toThrow();
    const z = await openZip(zipPath);
    expect(z.entries.map((e) => e.name)).toEqual(['a']);
    await z.close();
  });

  it('refuses an archive with a traversal name, and one that is not a zip', async () => {
    const d = tmp();
    const j = new JSZip();
    j.file('ok.txt', 'fine');
    j.file('../evil.txt', 'planted');
    const p = path.join(d, 'evil.zip');
    fs.writeFileSync(p, await j.generateAsync({ type: 'nodebuffer' }));
    await expect(openZip(p)).rejects.toMatchObject({ code: 'BAD_ZIP' });
    const q = path.join(d, 'junk.zip');
    fs.writeFileSync(q, 'not a zip at all, just text that is long enough');
    await expect(openZip(q)).rejects.toMatchObject({ code: 'BAD_ZIP' });
  });

  it('reads DEFLATE entries written by another tool', async () => {
    const d = tmp();
    const j = new JSZip();
    const text = 'line\n'.repeat(10_000);
    j.file('a.txt', text);
    const p = path.join(d, 'deflate.zip');
    fs.writeFileSync(p, await j.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' }));
    const z = await openZip(p);
    expect(z.entry('a.txt')!.method).toBe(8);
    expect((await z.readEntry(z.entry('a.txt')!)).toString()).toBe(text);
    await z.close();
  });

  it('detects a flipped byte through the CRC32', async () => {
    const d = tmp();
    const p = path.join(d, 'c.zip');
    const w = await ZipWriter.create(p);
    await w.addBuffer('data', Buffer.alloc(1000, 7));
    await w.finish();
    const buf = fs.readFileSync(p);
    const at = 30 + 'data'.length + 500;
    buf[at] = buf[at]! ^ 0xff;
    fs.writeFileSync(p, buf);
    const z = await openZip(p);
    await expect(hashEntry(z, z.entry('data')!)).rejects.toThrow(/CRC/);
    await z.close();
  });

  it('writes ZIP64 records past 65535 entries', async () => {
    const d = tmp();
    const p = path.join(d, 'many.zip');
    const w = await ZipWriter.create(p);
    const n = 65_600;
    for (let i = 0; i < n; i++) await w.addBuffer(`e/${i}`, Buffer.from([i & 0xff]));
    await w.finish();
    const z = await openZip(p);
    expect(z.entries.length).toBe(n);
    expect((await z.readEntry(z.entry('e/65599')!))[0]).toBe(65_599 & 0xff);
    await z.close();
  }, 120_000);

  it('writes ZIP64 offsets past 4 GiB (sparse file)', async () => {
    const d = tmp();
    const p = path.join(d, 'far.zip');
    const w = await ZipWriter.create(p);
    await w.addBuffer('first', Buffer.from('a'));
    // Skip ahead without writing: the file is sparse, so this costs no disk.
    (w as unknown as { pos: number }).pos = 5 * 2 ** 30;
    await w.addBuffer('far', Buffer.from('beyond 4 GiB'));
    await w.finish();
    const z = await openZip(p);
    expect(z.entry('far')!.offset).toBe(5 * 2 ** 30);
    expect((await z.readEntry(z.entry('far')!)).toString()).toBe('beyond 4 GiB');
    expect((await z.readEntry(z.entry('first')!)).toString()).toBe('a');
    await z.close();
  }, 60_000);
});

describe('verifyBackupZip', () => {
  async function makeZip(d: string, mutate?: (files: Array<{ path: string; bytes: number; sha256: string }>, m: ReturnType<typeof buildManifest>) => void) {
    const p = path.join(d, 'btct-backup-20261012-100000.zip');
    const w = await ZipWriter.create(p);
    const files = [];
    for (const [name, body] of [['yjs/btct-shared.yupdate.gz', 'hello'], ['sqlite/data.sqlite.gz', 'world'], ['assets/a1', 'png']] as const) {
      const r = await w.addBuffer(name, Buffer.from(body));
      files.push({ path: r.name, bytes: r.bytes, sha256: r.sha256 });
    }
    const m = buildManifest({
      instanceId: 'i', includes: normalizeIncludes({ history: false }), files,
      docs: [{ name: 'btct-shared', bytes: 5 }], sqlite: { rawBytes: 10 },
      assets: [{ id: 'a1', present: true }],
    });
    mutate?.(files, m);
    await w.addBuffer('manifest.json', Buffer.from(JSON.stringify(m)));
    await w.finish();
    return p;
  }

  it('accepts a matching archive, through verifyBackup too', async () => {
    const d = tmp();
    const p = await makeZip(d);
    const v = await verifyBackupZip(p);
    expect(v).toMatchObject({ ok: true, errors: [] });
    expect(v.manifest?.files.length).toBe(3);
    expect((await verifyBackup(p)).ok).toBe(true);
  });

  it('reports a hash that does not match', async () => {
    const d = tmp();
    const p = await makeZip(d, (_files, m) => { m.files[1]!.sha256 = '0'.repeat(64); });
    const v = await verifyBackupZip(p);
    expect(v.ok).toBe(false);
    expect(v.errors).toEqual(['checksum mismatch: sqlite/data.sqlite.gz']);
  });

  it('reports a listed file the archive lacks, and an unsafe asset id', async () => {
    const d = tmp();
    const p = await makeZip(d, (_files, m) => { m.files.push({ path: 'assets/a2', bytes: 1, sha256: 'x' }); m.assets.push({ id: 'a2', present: true }); });
    expect((await verifyBackupZip(p)).errors).toEqual(['missing: assets/a2']);
    const d2 = tmp();
    const q = await makeZip(d2, (_files, m) => { m.assets = [{ id: '../x', present: true }]; });
    const v = await verifyBackupZip(q);
    expect(v.ok).toBe(false);
    expect(v.errors[0]).toMatch(/unsafe id/);
  });

  it('fails cleanly on a zip without a manifest and on a missing path', async () => {
    const d = tmp();
    const p = path.join(d, 'x.zip');
    const w = await ZipWriter.create(p);
    await w.addBuffer('a', Buffer.from('1'));
    await w.finish();
    expect((await verifyBackupZip(p)).errors[0]).toMatch(/manifest/);
    expect((await verifyBackup(path.join(d, 'nope.zip'))).errors[0]).toMatch(/no such backup/);
  });
});

describe('startsWithZipSignature', () => {
  it('knows a JSZip archive, an empty archive and the spanned marker', async () => {
    const zip = new JSZip();
    zip.file('command-log.json', '[]');
    const bytes = await zip.generateAsync({ type: 'uint8array' });
    expect(startsWithZipSignature(bytes)).toBe(true);
    expect(startsWithZipSignature(await new JSZip().generateAsync({ type: 'uint8array' }))).toBe(true);
    expect(startsWithZipSignature(Buffer.from([0x50, 0x4b, 0x07, 0x08]))).toBe(true);
  });

  it('refuses JSON, short input and other PK bytes', () => {
    expect(startsWithZipSignature(Buffer.from('{"workspaceId":"w","logs":[]}'))).toBe(false);
    expect(startsWithZipSignature(Buffer.from('PK'))).toBe(false);
    expect(startsWithZipSignature(Buffer.from('PKZZ'))).toBe(false);
    expect(startsWithZipSignature(null)).toBe(false);
  });
});
