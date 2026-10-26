// ─────────────────────────────────────────────────────────────────────────
// Payload checks for restore.mjs (--verify and before a restore).
//
// verifyBackup (backup-format.mjs, a folder or a .zip) checks sizes and
// hashes against the manifest. A run that is internally consistent but cannot be decoded (a
// writer bug, or a manifest rewritten along with its payload) passed that,
// and the restore then failed while staging with exit 1. These checks do
// what staging does with each payload, without writing anywhere but a
// temporary directory:
//   • the SQLite snapshot: gunzip to a temp file, check the header, switch
//     the copy out of WAL and run quick_check (finishStagedSqlite does the
//     same to the staged copy);
//   • every Yjs room: gunzip, apply the update to an empty doc, and compare
//     the doc's state vector with the update's (stageRooms reads every room
//     back from LevelDB the same way).
// Asset blobs and history twins are copied as bytes by a restore, so their
// hashes are all a restore relies on.
//
// Dependencies are injected (Y, a bun:sqlite-like Database class, fs, zlib)
// so src/test can drive it.
// ─────────────────────────────────────────────────────────────────────────
import path from 'node:path';

const SQLITE_HEADER = 'SQLite format 3\u0000';

/** Same comparison as backup-format's sameStateVector, on decoded maps. */
function sameSV(a, b) {
  if (a.size !== b.size) return false;
  for (const [k, v] of a) if (b.get(k) !== v) return false;
  return true;
}

/**
 * Decode one room's update the way a restore reads it back. Returns null
 * when it is fine, else a short reason.
 */
export function checkYjsUpdate(Y, update) {
  let expected;
  try {
    expected = Y.decodeStateVector(Y.encodeStateVectorFromUpdate(update));
  } catch (err) {
    return `not a Yjs update (${err?.message || err})`;
  }
  const doc = new Y.Doc();
  try {
    Y.applyUpdate(doc, update);
    if (doc.store.pendingStructs) return 'the update is incomplete (it depends on changes it does not hold)';
    const got = Y.decodeStateVector(Y.encodeStateVector(doc));
    if (!sameSV(got, expected)) return 'the update does not read back to its own state vector';
    return null;
  } catch (err) {
    return `the update cannot be applied (${err?.message || err})`;
  } finally {
    doc.destroy();
  }
}

/**
 * Check a gzipped SQLite snapshot, read from `gzPath` or passed as the
 * bytes `gz`. `tmpDir` gets one temporary file, which is removed again. Returns null when it is fine, else a short reason.
 */
export function checkSqliteSnapshot({ gzPath, gz, tmpDir, Database, fs, zlib }) {
  let raw;
  try {
    raw = zlib.gunzipSync(gz ?? fs.readFileSync(gzPath));
  } catch (err) {
    return `cannot gunzip (${err?.message || err})`;
  }
  if (raw.length < 100 || raw.subarray(0, 16).toString('latin1') !== SQLITE_HEADER) {
    return 'not an SQLite database (bad header)';
  }
  const work = fs.mkdtempSync(path.join(tmpDir, 'btct-verify-'));
  const file = path.join(work, 'data.sqlite');
  let d = null;
  try {
    fs.writeFileSync(file, raw);
    raw = null;
    d = new Database(file, { readwrite: true });
    d.run('PRAGMA journal_mode = DELETE');
    const check = d.query('PRAGMA quick_check').get();
    const verdict = check ? Object.values(check)[0] : 'no answer';
    if (verdict !== 'ok') return `fails quick_check: ${verdict}`;
    return null;
  } catch (err) {
    return `cannot be opened (${err?.message || err})`;
  } finally {
    try { d?.close(); } catch { /* ignore */ }
    try { fs.rmSync(work, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

/**
 * Decode every payload a restore would decode. `manifest` has passed
 * verifyBackup, so every path below is listed and hashed. `read(rel)`
 * returns a member's bytes (a Buffer, or a promise of one); it defaults to
 * reading `<dir>/<rel>` for a folder run, and restore.mjs passes a ZIP
 * reader for a .zip run, so --verify decodes the members in place without
 * unpacking anything. Resolves with a list of problems (empty when the
 * backup can be restored).
 */
export async function checkBackupPayloads({ dir, read, manifest, Y, Database, fs, zlib, tmpDir }) {
  const readRel = read || ((rel) => fs.readFileSync(path.join(dir, ...rel.split('/'))));
  const errors = [];
  const listed = new Set((manifest.files || []).map((f) => f.path));
  if (listed.has('sqlite/data.sqlite.gz')) {
    let gz = null;
    try {
      gz = await readRel('sqlite/data.sqlite.gz');
    } catch (err) {
      errors.push(`sqlite/data.sqlite.gz: cannot be read (${err?.message || err})`);
    }
    if (gz) {
      const why = checkSqliteSnapshot({ gz, tmpDir, Database, fs, zlib });
      if (why) errors.push(`sqlite/data.sqlite.gz: ${why}`);
    }
  }
  for (const d of manifest.docs || []) {
    const rel = `yjs/${d.name}.yupdate.gz`;
    if (!listed.has(rel)) continue;
    let update;
    try {
      update = new Uint8Array(zlib.gunzipSync(await readRel(rel)));
    } catch (err) {
      errors.push(`${rel}: cannot gunzip (${err?.message || err})`);
      continue;
    }
    const why = checkYjsUpdate(Y, update);
    if (why) errors.push(`${rel}: ${why}`);
  }
  return errors;
}

/**
 * `read` for checkBackupPayloads over an archive opened with zip-stream's
 * openZip: a member's bytes by its manifest path, CRC32 and size checked
 * by the reader. A member the archive does not hold is an error.
 */
export function zipMemberReader(zip) {
  return async (rel) => {
    const entry = zip.entry(rel);
    if (!entry) throw new Error('missing from the archive');
    return zip.readEntry(entry, entry.size);
  };
}

// ── Is another process using the data? (read-only) ─────────────────────
// The restore must refuse while the server runs. It used to find out by
// opening LevelDB (which replays and compacts its log) and SQLite with an
// exclusive lock (which checkpoints and deletes the -wal on close), so even
// a refused run rewrote files under /data. fcntl(F_GETLK) asks the kernel
// whether a lock would conflict without taking one or writing anything, and
// works across containers (the kernel's lock table is per inode). LevelDB
// holds a write lock on its LOCK file; an open SQLite connection in WAL mode
// holds read locks on the database file and its -shm.

const F_GETLK = 5; // x86_64 and aarch64 Linux
const F_WRLCK = 1;
const F_UNLCK = 2;

/**
 * Returns `holder(file)` -> { locked, pid } (pid 0 when the holder is in
 * another pid namespace), or null when this platform cannot ask (not Linux
 * on x64/arm64, or no libc to load). A missing file is never locked.
 *
 * @param {{ fs: typeof import('node:fs'), ffi: any, platform?: string, arch?: string }} deps
 */
export function createPosixLockProbe({ fs, ffi, platform = process.platform, arch = process.arch }) {
  if (platform !== 'linux' || (arch !== 'x64' && arch !== 'arm64') || !ffi?.dlopen) return null;
  let fcntl;
  try {
    const lib = ffi.dlopen('libc.so.6', { fcntl: { args: [ffi.FFIType.i32, ffi.FFIType.i32, ffi.FFIType.ptr], returns: ffi.FFIType.i32 } });
    fcntl = lib.symbols.fcntl;
  } catch {
    return null;
  }
  return function holder(file) {
    let fd;
    try {
      fd = fs.openSync(file, 'r');
    } catch (err) {
      if (err?.code === 'ENOENT') return { locked: false, pid: 0 };
      throw err;
    }
    try {
      // struct flock { short l_type; short l_whence; off_t l_start; off_t l_len; pid_t l_pid; }
      const bytes = new Uint8Array(32);
      const v = new DataView(bytes.buffer);
      v.setInt16(0, F_WRLCK, true);
      v.setInt16(2, 0, true); // SEEK_SET
      v.setBigInt64(8, 0n, true);
      v.setBigInt64(16, 0n, true); // to the end of the file
      const r = fcntl(fd, F_GETLK, ffi.ptr(bytes));
      if (r !== 0) throw new Error(`fcntl(F_GETLK) failed on ${file}`);
      const type = v.getInt16(0, true);
      return { locked: type !== F_UNLCK, pid: v.getInt32(24, true) };
    } finally {
      fs.closeSync(fd);
    }
  };
}
