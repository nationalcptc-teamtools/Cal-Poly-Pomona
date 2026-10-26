// Child process for src/test/restore-checks.test.ts (Bun only): checks a
// real SQLite snapshot and the fcntl lock probe against real holders, and
// prints one JSON line.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { Database } from 'bun:sqlite';
import * as ffi from 'bun:ffi';
import { checkSqliteSnapshot, createPosixLockProbe } from '../../../server/restore-checks.mjs';

const out = {};
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'btct-rc-'));
const md5 = (f) => crypto.createHash('md5').update(fs.readFileSync(f)).digest('hex');
const listing = (dir) => fs.readdirSync(dir).sort().map((f) => `${f}:${md5(path.join(dir, f))}`).join(',');

/** Start a child that holds `code`'s handle open until stdin closes. */
function holdOpen(code) {
  return new Promise((resolve, reject) => {
    const c = spawn(process.execPath, ['-e', code], { cwd: process.cwd(), stdio: ['pipe', 'pipe', 'inherit'] });
    c.stdout.on('data', (b) => { if (String(b).includes('ready')) resolve(c); });
    c.on('error', reject);
    c.on('exit', (code) => reject(new Error(`holder exited ${code}`)));
  });
}
const release = (c) => new Promise((r) => { c.removeAllListeners('exit'); c.on('exit', r); c.stdin.end(); });

try {
  // ── SQLite snapshot checks ──
  const dbFile = path.join(root, 'src.sqlite');
  const d = new Database(dbFile, { create: true });
  d.run('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
  d.run('CREATE TABLE filler (id INTEGER PRIMARY KEY, body TEXT)');
  const ins = d.query('INSERT INTO filler (body) VALUES (?)');
  for (let i = 0; i < 400; i++) ins.run('x'.repeat(200) + i);
  d.close();
  const good = path.join(root, 'good.sqlite.gz');
  fs.writeFileSync(good, zlib.gzipSync(fs.readFileSync(dbFile)));
  const deps = { tmpDir: root, Database, fs, zlib };
  out.good = checkSqliteSnapshot({ gzPath: good, ...deps });
  const garbage = path.join(root, 'garbage.sqlite.gz');
  fs.writeFileSync(garbage, zlib.gzipSync(crypto.randomBytes(4096)));
  out.garbage = checkSqliteSnapshot({ gzPath: garbage, ...deps });
  const raw = fs.readFileSync(dbFile);
  // Keep the header, overwrite every page after the first with noise.
  crypto.randomFillSync(raw, 4096);
  const broken = path.join(root, 'broken.sqlite.gz');
  fs.writeFileSync(broken, zlib.gzipSync(raw));
  out.broken = checkSqliteSnapshot({ gzPath: broken, ...deps });
  out.notGzip = checkSqliteSnapshot({ gzPath: dbFile, ...deps });
  out.tempLeft = fs.readdirSync(root).filter((f) => f.startsWith('btct-verify-')).length;

  // ── Lock probe ──
  const holder = createPosixLockProbe({ fs, ffi });
  out.probeAvailable = !!holder;
  if (holder) {
    const live = path.join(root, 'live');
    fs.mkdirSync(live);
    const liveDb = path.join(live, 'data.sqlite');
    const s = new Database(liveDb, { create: true });
    s.run('PRAGMA journal_mode = WAL');
    s.run('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
    s.run("INSERT INTO settings VALUES ('a', 'b')");
    s.close();
    out.missing = holder(path.join(live, 'nope')).locked;
    out.sqliteIdle = holder(liveDb).locked;
    const sq = await holdOpen(`const { Database } = require('bun:sqlite'); const d = new Database(${JSON.stringify(liveDb)}); d.run('PRAGMA journal_mode = WAL'); d.query('SELECT * FROM settings').all(); console.log('ready'); process.stdin.on('data', () => {}); process.stdin.on('end', () => { d.close(); process.exit(0); });`);
    const before = listing(live);
    out.sqliteHeld = holder(liveDb).locked;
    out.shmHeld = holder(`${liveDb}-shm`).locked;
    out.unchangedByProbe = listing(live) === before;
    await release(sq);
    out.sqliteAfter = holder(liveDb).locked;

    const ldbDir = path.join(root, 'yjs');
    const lv = await holdOpen(`const { LeveldbPersistence } = require('y-leveldb'); const l = new LeveldbPersistence(${JSON.stringify(ldbDir)}); l.getYDoc('x').then(() => { console.log('ready'); }); process.stdin.on('data', () => {}); process.stdin.on('end', () => { l.destroy().then(() => process.exit(0)); });`);
    const ldbBefore = listing(ldbDir);
    out.leveldbHeld = holder(path.join(ldbDir, 'LOCK')).locked;
    out.leveldbUnchanged = listing(ldbDir) === ldbBefore;
    await release(lv);
    out.leveldbAfter = holder(path.join(ldbDir, 'LOCK')).locked;
  }
  out.offPlatform = createPosixLockProbe({ fs, ffi, platform: 'darwin' });
} catch (err) {
  out.error = String(err?.stack || err);
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
process.stdout.write(JSON.stringify(out) + '\n');
process.exit(0);
