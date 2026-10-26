// Child process for src/test/leveldb-log-seal.test.ts: drives a real
// LevelDB (y-leveldb over leveldown) and prints one JSON line. It runs in
// its own process so a crash in the native binding fails the test instead
// of taking the vitest worker down: leveldown's compactRange on a handle
// still opening dereferenced a null pointer (step 3 seals a database right
// after opening it, which the sealer now waits for).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as Y from 'yjs';
import { LeveldbPersistence } from 'y-leveldb';
import { createLevelDbLogSealer } from '../../../server/relay-persistence.mjs';

const update = (text) => {
  const d = new Y.Doc();
  d.getText('t').insert(0, text);
  const u = Y.encodeStateAsUpdate(d);
  d.destroy();
  return u;
};
const walFiles = (dir) => fs.readdirSync(dir).filter((f) => /^\d+\.log$/.test(f));
const loseLogs = (dir) => { for (const f of walFiles(dir)) fs.unlinkSync(path.join(dir, f)); };
async function textAfterReopen(dir, room) {
  const ldb = new LeveldbPersistence(dir);
  const doc = await ldb.getYDoc(room);
  const s = doc.getText('t').toString();
  doc.destroy();
  await ldb.destroy();
  return s;
}

const out = {};
const dirs = [];
const tmp = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'btct-seal-')); dirs.push(d); return d; };
try {
  // 1. No seal: a write lives only in the log until LevelDB flushes.
  {
    const dir = tmp();
    const ldb = new LeveldbPersistence(dir);
    await ldb.storeUpdate('room', update('in the log only'));
    await ldb.destroy();
    loseLogs(dir);
    out.noSeal = await textAfterReopen(dir, 'room');
  }
  // 2. Seal: everything before it is in a table file, the old log is gone.
  {
    const dir = tmp();
    const ldb = new LeveldbPersistence(dir);
    const seal = createLevelDbLogSealer(ldb, dir, fs);
    await ldb.storeUpdate('room', update('before the seal'));
    await ldb.storeUpdate('other', update('also before'));
    const before = walFiles(dir);
    out.logsBefore = before.length;
    out.sealed = await seal();
    out.oldLogLeft = walFiles(dir).some((f) => before.includes(f));
    await ldb.storeUpdate('late', update('after the seal'));
    const live = await ldb.getYDoc('room');
    out.liveAfterSeal = live.getText('t').toString();
    live.destroy();
    await ldb.destroy();
    loseLogs(dir);
    out.room = await textAfterReopen(dir, 'room');
    out.other = await textAfterReopen(dir, 'other');
    out.late = await textAfterReopen(dir, 'late');
  }
  // 3. Sealing an empty database twice, then writing and reopening.
  {
    const dir = tmp();
    const ldb = new LeveldbPersistence(dir);
    const seal = createLevelDbLogSealer(ldb, dir, fs);
    out.emptySeals = [await seal(), await seal()];
    await ldb.storeUpdate('room', update('x'));
    await ldb.destroy();
    out.afterEmptySeals = await textAfterReopen(dir, 'room');
  }
} catch (err) {
  out.error = String(err?.stack || err);
} finally {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
}
process.stdout.write(JSON.stringify(out) + '\n');
process.exit(0);
