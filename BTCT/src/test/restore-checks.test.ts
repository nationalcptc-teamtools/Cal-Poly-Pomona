// @vitest-environment node
import { describe, it, expect, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import * as Y from 'yjs';
import { checkYjsUpdate, checkBackupPayloads, createPosixLockProbe, zipMemberReader } from '../../server/restore-checks.mjs';
import { ZipWriter, openZip } from '../../server/zip-stream.mjs';

// restore.mjs --verify used to check only sizes and hashes, so a run whose
// SQLite snapshot or a room's update could not be decoded passed it and the
// restore then failed while staging. These checks decode what staging does.

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true }); });
const tmp = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'btct-rc-')); dirs.push(d); return d; };

function roomUpdate(text: string) {
  const d = new Y.Doc();
  d.getText('t').insert(0, text);
  d.getMap('m').set('k', 1);
  const u = Y.encodeStateAsUpdate(d);
  d.destroy();
  return u;
}

describe('checkYjsUpdate', () => {
  it('accepts a whole document update', () => {
    expect(checkYjsUpdate(Y, roomUpdate('hello'))).toBeNull();
    expect(checkYjsUpdate(Y, Y.encodeStateAsUpdate(new Y.Doc()))).toBeNull();
  });

  it('refuses random bytes and a truncated update', () => {
    const noise = new Uint8Array(crypto.randomBytes(2048));
    expect(checkYjsUpdate(Y, noise)).not.toBeNull();
    const u = roomUpdate('a long enough body to cut in half '.repeat(20));
    expect(checkYjsUpdate(Y, u.subarray(0, Math.floor(u.length / 2)))).not.toBeNull();
  });

  it('refuses an update that depends on changes it does not hold', () => {
    const d = new Y.Doc();
    d.getText('t').insert(0, 'base');
    const sv = Y.encodeStateVector(d);
    d.getText('t').insert(4, ' more');
    const tail = Y.encodeStateAsUpdate(d, sv);
    expect(checkYjsUpdate(Y, tail)).toMatch(/incomplete|read back/);
  });
});

describe('checkBackupPayloads', () => {
  function backup(rooms: Record<string, Uint8Array>, sqlite?: Buffer) {
    const dir = tmp();
    fs.mkdirSync(path.join(dir, 'yjs'));
    const files: Array<{ path: string }> = [];
    for (const [name, u] of Object.entries(rooms)) {
      fs.writeFileSync(path.join(dir, 'yjs', `${name}.yupdate.gz`), zlib.gzipSync(u));
      files.push({ path: `yjs/${name}.yupdate.gz` });
    }
    if (sqlite) {
      fs.mkdirSync(path.join(dir, 'sqlite'));
      fs.writeFileSync(path.join(dir, 'sqlite', 'data.sqlite.gz'), zlib.gzipSync(sqlite));
      files.push({ path: 'sqlite/data.sqlite.gz' });
    }
    return { dir, manifest: { files, docs: Object.keys(rooms).map((name) => ({ name })) } };
  }

  // A stand-in for bun:sqlite: the real one is checked in the Bun child below.
  class FakeDb {
    static verdict = 'ok';
    constructor(_file: string) {}
    run() {}
    query() { return { get: () => ({ quick_check: FakeDb.verdict }) }; }
    close() {}
  }
  const header = () => {
    const b = Buffer.alloc(4096);
    b.write('SQLite format 3\u0000', 0, 'latin1');
    return b;
  };

  it('passes a backup whose payloads decode', async () => {
    FakeDb.verdict = 'ok';
    const { dir, manifest } = backup({ 'btct-shared': roomUpdate('s'), 'page-1': roomUpdate('p') }, header());
    expect(await checkBackupPayloads({ dir, manifest, Y, Database: FakeDb, fs, zlib, tmpDir: tmp() })).toEqual([]);
  });

  it('names every payload that does not decode', async () => {
    FakeDb.verdict = 'ok';
    const { dir, manifest } = backup({ 'btct-shared': roomUpdate('s'), 'page-bad': new Uint8Array(crypto.randomBytes(2048)) }, Buffer.from(crypto.randomBytes(4096)));
    const errors = await checkBackupPayloads({ dir, manifest, Y, Database: FakeDb, fs, zlib, tmpDir: tmp() });
    expect(errors.length).toBe(2);
    expect(errors[0]).toMatch(/^sqlite\/data\.sqlite\.gz: not an SQLite database/);
    expect(errors[1]).toMatch(/^yjs\/page-bad\.yupdate\.gz: /);
  });

  it('reports a snapshot that fails quick_check and leaves no temp file', async () => {
    FakeDb.verdict = '*** in database main ***';
    const work = tmp();
    const { dir, manifest } = backup({}, header());
    const errors = await checkBackupPayloads({ dir, manifest, Y, Database: FakeDb, fs, zlib, tmpDir: work });
    expect(errors).toEqual(['sqlite/data.sqlite.gz: fails quick_check: *** in database main ***']);
    expect(fs.readdirSync(work)).toEqual([]);
  });

  it('skips a room the manifest does not list as a file', async () => {
    const { dir } = backup({ 'page-1': roomUpdate('p') });
    const manifest = { files: [], docs: [{ name: 'page-1' }] };
    expect(await checkBackupPayloads({ dir, manifest, Y, Database: FakeDb, fs, zlib, tmpDir: tmp() })).toEqual([]);
  });
});

describe('checkBackupPayloads on a .zip run', () => {
  // restore.mjs --verify does not unpack a ZIP, so the payloads are read
  // straight from the archive through zipMemberReader.
  class OkDb {
    constructor(_file: string) {}
    run() {}
    query() { return { get: () => ({ quick_check: 'ok' }) }; }
    close() {}
  }
  async function zipRun(rooms: Record<string, Uint8Array>, sqlite?: Buffer) {
    const zipPath = path.join(tmp(), 'run.zip');
    const w = await ZipWriter.create(zipPath);
    const files: Array<{ path: string }> = [];
    if (sqlite) {
      await w.addBuffer('sqlite/data.sqlite.gz', zlib.gzipSync(sqlite));
      files.push({ path: 'sqlite/data.sqlite.gz' });
    }
    for (const [name, u] of Object.entries(rooms)) {
      await w.addBuffer(`yjs/${name}.yupdate.gz`, zlib.gzipSync(u));
      files.push({ path: `yjs/${name}.yupdate.gz` });
    }
    await w.finish();
    return { zipPath, manifest: { files, docs: Object.keys(rooms).map((name) => ({ name })) } };
  }
  const header = () => {
    const b = Buffer.alloc(4096);
    b.write('SQLite format 3\u0000', 0, 'latin1');
    return b;
  };

  it('decodes good members in place', async () => {
    const { zipPath, manifest } = await zipRun({ 'btct-shared': roomUpdate('s'), 'page-1': roomUpdate('p') }, header());
    const zip = await openZip(zipPath);
    try {
      expect(await checkBackupPayloads({ read: zipMemberReader(zip), manifest, Y, Database: OkDb, fs, zlib, tmpDir: tmp() })).toEqual([]);
    } finally {
      await zip.close();
    }
  });

  it('names undecodable members and one the archive lacks', async () => {
    const { zipPath, manifest } = await zipRun({ 'page-bad': new Uint8Array(crypto.randomBytes(1024)) }, Buffer.from(crypto.randomBytes(4096)));
    manifest.files.push({ path: 'yjs/page-gone.yupdate.gz' });
    manifest.docs.push({ name: 'page-gone' });
    const zip = await openZip(zipPath);
    try {
      const errors = await checkBackupPayloads({ read: zipMemberReader(zip), manifest, Y, Database: OkDb, fs, zlib, tmpDir: tmp() });
      expect(errors.length).toBe(3);
      expect(errors[0]).toMatch(/^sqlite\/data\.sqlite\.gz: not an SQLite database/);
      expect(errors[1]).toMatch(/^yjs\/page-bad\.yupdate\.gz: /);
      expect(errors[2]).toMatch(/^yjs\/page-gone\.yupdate\.gz: .*missing from the archive/);
    } finally {
      await zip.close();
    }
  });
});

describe('createPosixLockProbe', () => {
  it('is null where it cannot ask', () => {
    expect(createPosixLockProbe({ fs, ffi: null })).toBeNull();
    expect(createPosixLockProbe({ fs, ffi: { dlopen: () => { throw new Error('no libc'); }, FFIType: {} }, platform: 'linux', arch: 'x64' })).toBeNull();
    expect(createPosixLockProbe({ fs, ffi: { dlopen: () => ({}) }, platform: 'win32' })).toBeNull();
  });

  // Real SQLite, real LevelDB, real fcntl: Bun only, in a child process.
  it.skipIf(!process.versions.bun)('finds a real holder of SQLite and LevelDB without changing a file, and checks a real snapshot', () => {
    const child = path.join(__dirname, 'fixtures', 'restore-checks-child.mjs');
    const r = spawnSync(process.execPath, [child], { cwd: process.cwd(), encoding: 'utf8', timeout: 60_000 });
    const out = JSON.parse((r.stdout || '').trim().split('\n').pop() || '{}');
    expect(out.error).toBeUndefined();
    expect(out.good).toBeNull();
    expect(out.garbage).toMatch(/bad header/);
    expect(out.broken).not.toBeNull();
    expect(out.notGzip).toMatch(/gunzip/);
    expect(out.tempLeft).toBe(0);
    expect(out.offPlatform).toBeNull();
    if (process.platform === 'linux' && (process.arch === 'x64' || process.arch === 'arm64')) {
      expect(out.probeAvailable).toBe(true);
      expect(out.missing).toBe(false);
      expect(out.sqliteIdle).toBe(false);
      expect(out.sqliteHeld).toBe(true);
      expect(out.shmHeld).toBe(true);
      expect(out.unchangedByProbe).toBe(true);
      expect(out.sqliteAfter).toBe(false);
      expect(out.leveldbHeld).toBe(true);
      expect(out.leveldbUnchanged).toBe(true);
      expect(out.leveldbAfter).toBe(false);
    }
  }, 90_000);
});
