// ─────────────────────────────────────────────────────────────────────────
// A small streaming ZIP writer and reader for the backup engine.
//
// Why not a library: the server has no build step and a 1 GB box, and a
// backup run can be several hundred MB, so the archive is never held in
// memory. The writer streams each entry straight into a file handle and
// patches the entry's local header afterwards (CRC32 and sizes are known
// only then), so there are no data descriptors and every unzip tool reads
// the result. Entries are STORED: the members that compress well are
// already gzipped by the engine, and images are compressed by nature.
// ZIP64 records are written only when a size, an offset or the entry count
// needs them, so an ordinary run is a plain ZIP.
//
// The reader parses the central directory (ZIP64 included), refuses any
// entry name that could escape a directory, and streams an entry back with
// its CRC32 and size checked. STORE and DEFLATE are accepted; encryption is
// refused. Node APIs only, so vitest loads it too.
// ─────────────────────────────────────────────────────────────────────────
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_EOCD = 0x06064b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const U32 = 0xffffffff;
const U16 = 0xffff;
const FLAG_UTF8 = 0x0800;
const FLAG_ENCRYPTED = 0x0001;
// Unix, spec 4.5 (ZIP64): what "version made by" says.
const MADE_BY = (3 << 8) | 45;
const LOCAL_HEADER = 30;
const CENTRAL_HEADER = 46;
const EOCD_SIZE = 22;
const ZIP64_LOCAL_EXTRA = 20; // id, size, usize(8), csize(8)
const WRITE_BUFFER_BYTES = 1024 * 1024;
/** Largest central directory the reader accepts (a few hundred bytes per entry). */
export const MAX_CENTRAL_DIR_BYTES = 64 * 1024 * 1024;

// ── CRC32 ────────────────────────────────────────────────────────────────

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32Js(buf, prev = 0) {
  let c = (prev ^ U32) >>> 0;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ U32) >>> 0;
}

/** CRC32 of `buf`, continuing from `prev` (zlib.crc32 when the runtime has it). */
export const crc32 = typeof zlib.crc32 === 'function'
  ? (buf, prev = 0) => zlib.crc32(buf, prev) >>> 0
  : crc32Js;

// ── Names ────────────────────────────────────────────────────────────────

/**
 * A member name that is safe to turn into a path below a directory, or null.
 * Refused: empty, absolute, a drive letter, a backslash, NUL or another
 * control character, and any `.` or `..` segment.
 */
export function safeEntryName(name) {
  if (typeof name !== 'string' || !name || name.length > 1024) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(name)) return null;
  if (name.startsWith('/') || /^[A-Za-z]:/.test(name)) return null;
  const segs = name.split('/');
  const last = segs[segs.length - 1] === '' ? segs.length - 1 : segs.length;
  for (let i = 0; i < last; i++) {
    const s = segs[i];
    if (!s || s === '.' || s === '..') return null;
  }
  return name;
}

function dosDateTime(date) {
  const d = date instanceof Date && !Number.isNaN(date.getTime()) ? date : new Date();
  const year = Math.max(1980, Math.min(2107, d.getFullYear()));
  const time = (d.getHours() << 11) | (d.getMinutes() << 5) | Math.floor(d.getSeconds() / 2);
  const day = ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  return { time, day };
}

/** Read an open file from the start to its end, 1 MiB at a time. */
async function* readChunks(fh, chunkSize = 1024 * 1024) {
  let pos = 0;
  for (;;) {
    const buf = Buffer.allocUnsafe(chunkSize);
    const { bytesRead } = await fh.read(buf, 0, chunkSize, pos);
    if (!bytesRead) return;
    pos += bytesRead;
    yield buf.subarray(0, bytesRead);
  }
}

// ── Writer ───────────────────────────────────────────────────────────────

/**
 * Streams entries into `filePath` (created with `mode`, refused when it
 * exists). Call `add*` one at a time, then `finish()` (central directory,
 * fsync, close) or `abort()` (close; the caller removes the file).
 */
export class ZipWriter {
  static async create(filePath, { mode = 0o600, date = new Date() } = {}) {
    const fh = await fsp.open(filePath, 'wx', mode);
    return new ZipWriter(fh, filePath, date);
  }

  constructor(fh, filePath, date) {
    this.fh = fh;
    this.filePath = filePath;
    this.pos = 0;
    this.entries = [];
    this.names = new Set();
    this.stamp = dosDateTime(date);
    this.busy = false;
    this.closed = false;
    // Small appends (headers, small entries) are gathered here and written
    // in one call: one positional write per header cost about 1.5 ms per
    // entry, so 65,000 small entries took 100 s.
    this.pending = Buffer.allocUnsafe(WRITE_BUFFER_BYTES);
    this.pendingAt = 0; // file offset of pending[0]
    this.pendingLen = 0;
  }

  async #writeAt(buf, position) {
    let off = 0;
    while (off < buf.length) {
      const { bytesWritten } = await this.fh.write(buf, off, buf.length - off, position + off);
      off += bytesWritten;
    }
  }

  async #flush() {
    if (!this.pendingLen) return;
    await this.#writeAt(this.pending.subarray(0, this.pendingLen), this.pendingAt);
    this.pendingAt += this.pendingLen;
    this.pendingLen = 0;
  }

  /** Append at the end (the default), or patch bytes already written at `position`. */
  async #write(buf, position = this.pos) {
    if (position !== this.pos) {
      const end = position + buf.length;
      if (position >= this.pendingAt && end <= this.pendingAt + this.pendingLen) {
        buf.copy(this.pending, position - this.pendingAt);
      } else if (end <= this.pendingAt) {
        await this.#writeAt(buf, position);
      } else {
        await this.#flush();
        await this.#writeAt(buf, position);
      }
      return;
    }
    if (this.pendingAt + this.pendingLen !== this.pos) {
      // `pos` was moved (tests skip ahead to reach ZIP64 offsets).
      await this.#flush();
      this.pendingAt = this.pos;
    }
    if (buf.length >= WRITE_BUFFER_BYTES / 4) {
      await this.#flush();
      await this.#writeAt(buf, this.pos);
      this.pendingAt = this.pos + buf.length;
    } else {
      if (this.pendingLen + buf.length > WRITE_BUFFER_BYTES) await this.#flush();
      buf.copy(this.pending, this.pendingLen);
      this.pendingLen += buf.length;
    }
    this.pos += buf.length;
  }

  #localHeader(nameBuf, { crc = 0, size = 0, zip64 = false }) {
    const h = Buffer.alloc(LOCAL_HEADER + nameBuf.length + (zip64 ? ZIP64_LOCAL_EXTRA : 0));
    h.writeUInt32LE(SIG_LOCAL, 0);
    h.writeUInt16LE(zip64 ? 45 : 20, 4);
    h.writeUInt16LE(FLAG_UTF8, 6);
    h.writeUInt16LE(0, 8); // STORE
    h.writeUInt16LE(this.stamp.time, 10);
    h.writeUInt16LE(this.stamp.day, 12);
    h.writeUInt32LE(crc >>> 0, 14);
    h.writeUInt32LE(zip64 ? U32 : size, 18);
    h.writeUInt32LE(zip64 ? U32 : size, 22);
    h.writeUInt16LE(nameBuf.length, 26);
    h.writeUInt16LE(zip64 ? ZIP64_LOCAL_EXTRA : 0, 28);
    nameBuf.copy(h, LOCAL_HEADER);
    if (zip64) {
      const x = LOCAL_HEADER + nameBuf.length;
      h.writeUInt16LE(0x0001, x);
      h.writeUInt16LE(16, x + 2);
      h.writeBigUInt64LE(BigInt(size), x + 4);
      h.writeBigUInt64LE(BigInt(size), x + 12);
    }
    return h;
  }

  /**
   * Add one entry from an async iterable of Buffers/Uint8Arrays (a readable
   * stream, or an array). `sizeHint` is an upper bound on the entry's size;
   * without one, room for a ZIP64 size is reserved. Resolves with
   * `{ name, bytes, sha256, crc32 }`.
   */
  async addIterable(name, chunks, { sizeHint } = {}) {
    if (this.closed) throw new Error('zip already finished');
    if (this.busy) throw new Error('one entry at a time');
    if (!safeEntryName(name) || name.endsWith('/')) throw new Error(`unsafe zip entry name: ${name}`);
    if (this.names.has(name)) throw new Error(`duplicate zip entry: ${name}`);
    this.busy = true;
    try {
      const nameBuf = Buffer.from(name, 'utf8');
      // Reserve ZIP64 room when the entry may reach 4 GiB (1% headroom for gzip).
      const zip64 = !(Number.isFinite(sizeHint) && sizeHint >= 0 && sizeHint * 1.01 + 1024 * 1024 < U32);
      const headerAt = this.pos;
      await this.#write(this.#localHeader(nameBuf, { zip64 }));
      const hash = crypto.createHash('sha256');
      let crc = 0;
      let size = 0;
      for await (const chunk of chunks) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
        if (!buf.length) continue;
        crc = crc32(buf, crc);
        hash.update(buf);
        size += buf.length;
        await this.#write(buf);
      }
      if (!zip64 && size >= U32) throw new Error(`zip entry ${name} grew past its size hint`);
      await this.#write(this.#localHeader(nameBuf, { crc, size, zip64 }), headerAt);
      this.names.add(name);
      this.entries.push({ nameBuf, crc, size, offset: headerAt });
      return { name, bytes: size, sha256: hash.digest('hex'), crc32: crc };
    } finally {
      this.busy = false;
    }
  }

  /** Add `buf` as one entry. */
  addBuffer(name, buf) {
    const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
    return this.addIterable(name, [b], { sizeHint: b.length });
  }

  /**
   * Stream the file at `src` in as one entry (its size is the hint). The file
   * is opened before anything is written, so a missing file rejects with
   * ENOENT and leaves the archive untouched; one deleted after that is still
   * read whole (an open file outlives its name).
   */
  async addFile(name, src) {
    const fh = await fsp.open(src, 'r');
    try {
      const { size } = await fh.stat();
      return await this.addIterable(name, readChunks(fh), { sizeHint: size });
    } finally {
      await fh.close().catch(() => {});
    }
  }

  /** Bytes written so far. */
  get bytes() {
    return this.pos;
  }

  /** Write the central directory, fsync and close. Resolves with the archive size. */
  async finish() {
    if (this.closed) throw new Error('zip already finished');
    const cdStart = this.pos;
    const parts = [];
    let cdSize = 0;
    for (const e of this.entries) {
      const extra = [];
      if (e.size >= U32) extra.push(BigInt(e.size), BigInt(e.size));
      if (e.offset >= U32) extra.push(BigInt(e.offset));
      const extraLen = extra.length ? 4 + extra.length * 8 : 0;
      const h = Buffer.alloc(CENTRAL_HEADER + e.nameBuf.length + extraLen);
      h.writeUInt32LE(SIG_CENTRAL, 0);
      h.writeUInt16LE(MADE_BY, 4);
      h.writeUInt16LE(extra.length ? 45 : 20, 6);
      h.writeUInt16LE(FLAG_UTF8, 8);
      h.writeUInt16LE(0, 10);
      h.writeUInt16LE(this.stamp.time, 12);
      h.writeUInt16LE(this.stamp.day, 14);
      h.writeUInt32LE(e.crc >>> 0, 16);
      h.writeUInt32LE(e.size >= U32 ? U32 : e.size, 20);
      h.writeUInt32LE(e.size >= U32 ? U32 : e.size, 24);
      h.writeUInt16LE(e.nameBuf.length, 28);
      h.writeUInt16LE(extraLen, 30);
      h.writeUInt16LE(0, 32); // comment
      h.writeUInt16LE(0, 34); // disk
      h.writeUInt16LE(0, 36); // internal attrs
      h.writeUInt32LE(((0o100600 << 16) >>> 0), 38); // regular file, 0600
      h.writeUInt32LE(e.offset >= U32 ? U32 : e.offset, 42);
      e.nameBuf.copy(h, CENTRAL_HEADER);
      if (extraLen) {
        let x = CENTRAL_HEADER + e.nameBuf.length;
        h.writeUInt16LE(0x0001, x);
        h.writeUInt16LE(extra.length * 8, x + 2);
        x += 4;
        for (const v of extra) { h.writeBigUInt64LE(v, x); x += 8; }
      }
      parts.push(h);
      cdSize += h.length;
      if (cdSize > 4 * 1024 * 1024) { await this.#write(Buffer.concat(parts)); parts.length = 0; cdSize = 0; }
    }
    if (parts.length) await this.#write(Buffer.concat(parts));
    const cdLen = this.pos - cdStart;
    const count = this.entries.length;
    const needZip64 = count >= U16 || cdStart >= U32 || cdLen >= U32;
    if (needZip64) {
      const z = Buffer.alloc(56 + 20);
      const at = this.pos;
      z.writeUInt32LE(SIG_ZIP64_EOCD, 0);
      z.writeBigUInt64LE(44n, 4);
      z.writeUInt16LE(MADE_BY, 12);
      z.writeUInt16LE(45, 14);
      z.writeUInt32LE(0, 16);
      z.writeUInt32LE(0, 20);
      z.writeBigUInt64LE(BigInt(count), 24);
      z.writeBigUInt64LE(BigInt(count), 32);
      z.writeBigUInt64LE(BigInt(cdLen), 40);
      z.writeBigUInt64LE(BigInt(cdStart), 48);
      z.writeUInt32LE(SIG_ZIP64_LOCATOR, 56);
      z.writeUInt32LE(0, 60);
      z.writeBigUInt64LE(BigInt(at), 64);
      z.writeUInt32LE(1, 72);
      await this.#write(z);
    }
    const end = Buffer.alloc(EOCD_SIZE);
    end.writeUInt32LE(SIG_EOCD, 0);
    end.writeUInt16LE(0, 4);
    end.writeUInt16LE(0, 6);
    end.writeUInt16LE(Math.min(count, U16), 8);
    end.writeUInt16LE(Math.min(count, U16), 10);
    end.writeUInt32LE(cdLen >= U32 ? U32 : cdLen, 12);
    end.writeUInt32LE(cdStart >= U32 ? U32 : cdStart, 16);
    end.writeUInt16LE(0, 20);
    await this.#write(end);
    await this.#flush();
    await this.fh.sync();
    await this.fh.close();
    this.closed = true;
    return this.pos;
  }

  /** Close without finishing. The caller removes the file. */
  async abort() {
    if (this.closed) return;
    this.closed = true;
    try { await this.fh.close(); } catch { /* already closed */ }
  }
}

// ── Reader ───────────────────────────────────────────────────────────────

async function readAt(fh, position, length) {
  const buf = Buffer.alloc(length);
  let off = 0;
  while (off < length) {
    const { bytesRead } = await fh.read(buf, off, length - off, position + off);
    if (!bytesRead) throw new Error('unexpected end of zip file');
    off += bytesRead;
  }
  return buf;
}

function bad(msg) {
  const e = new Error(`not a usable zip: ${msg}`);
  e.code = 'BAD_ZIP';
  return e;
}

/**
 * Open a ZIP and read its central directory. Resolves with
 * `{ entries, entry(name), openStream(entry), readEntry(entry, max), close() }`.
 * Every entry has `{ name, method, crc32, compressedSize, size, offset, isDir }`;
 * a name `safeEntryName` refuses, a duplicate name or an encrypted entry
 * makes the whole archive refused.
 */
/**
 * True when `head` (the first bytes of a body or file) starts with a ZIP
 * signature: a local file header, an empty archive's end record, or a
 * spanned archive's marker. Used to tell a ZIP sent under any Content-Type.
 */
export function startsWithZipSignature(head) {
  if (!head || head.length < 4) return false;
  if (head[0] !== 0x50 || head[1] !== 0x4b) return false;
  const sig = (head[2] << 8) | head[3];
  return sig === 0x0304 || sig === 0x0506 || sig === 0x0708;
}

export async function openZip(filePath) {
  const fh = await fsp.open(filePath, 'r');
  try {
    const { size: fileSize } = await fh.stat();
    if (fileSize < EOCD_SIZE) throw bad('too short');
    const tailLen = Math.min(fileSize, EOCD_SIZE + 0xffff);
    const tail = await readAt(fh, fileSize - tailLen, tailLen);
    let eocd = -1;
    for (let i = tail.length - EOCD_SIZE; i >= 0; i--) {
      if (tail.readUInt32LE(i) === SIG_EOCD) { eocd = i; break; }
    }
    if (eocd < 0) throw bad('no end of central directory');
    let count = tail.readUInt16LE(eocd + 10);
    let cdLen = tail.readUInt32LE(eocd + 12);
    let cdStart = tail.readUInt32LE(eocd + 16);
    const eocdAbs = fileSize - tailLen + eocd;
    if (count === U16 || cdLen === U32 || cdStart === U32) {
      if (eocdAbs < 20) throw bad('ZIP64 locator missing');
      const loc = await readAt(fh, eocdAbs - 20, 20);
      if (loc.readUInt32LE(0) !== SIG_ZIP64_LOCATOR) throw bad('ZIP64 locator missing');
      const z64At = Number(loc.readBigUInt64LE(8));
      const z = await readAt(fh, z64At, 56);
      if (z.readUInt32LE(0) !== SIG_ZIP64_EOCD) throw bad('ZIP64 end record missing');
      count = Number(z.readBigUInt64LE(32));
      cdLen = Number(z.readBigUInt64LE(40));
      cdStart = Number(z.readBigUInt64LE(48));
    }
    if (cdLen > MAX_CENTRAL_DIR_BYTES) throw bad(`central directory of ${cdLen} bytes`);
    if (cdStart + cdLen > fileSize) throw bad('central directory outside the file');
    const cd = await readAt(fh, cdStart, cdLen);
    const entries = [];
    const byName = new Map();
    let p = 0;
    for (let i = 0; i < count; i++) {
      if (p + CENTRAL_HEADER > cd.length || cd.readUInt32LE(p) !== SIG_CENTRAL) throw bad('damaged central directory');
      const flags = cd.readUInt16LE(p + 8);
      const method = cd.readUInt16LE(p + 10);
      const crc = cd.readUInt32LE(p + 16);
      let csize = cd.readUInt32LE(p + 20);
      let usize = cd.readUInt32LE(p + 24);
      const nameLen = cd.readUInt16LE(p + 28);
      const extraLen = cd.readUInt16LE(p + 30);
      const commentLen = cd.readUInt16LE(p + 32);
      let offset = cd.readUInt32LE(p + 42);
      const nameEnd = p + CENTRAL_HEADER + nameLen;
      if (nameEnd + extraLen + commentLen > cd.length) throw bad('damaged central directory');
      const name = cd.toString('utf8', p + CENTRAL_HEADER, nameEnd);
      // ZIP64 extended information: only the fields that overflowed, in order.
      let x = nameEnd;
      const xEnd = nameEnd + extraLen;
      while (x + 4 <= xEnd) {
        const id = cd.readUInt16LE(x);
        const len = cd.readUInt16LE(x + 2);
        if (id === 0x0001) {
          let q = x + 4;
          if (usize === U32 && q + 8 <= x + 4 + len) { usize = Number(cd.readBigUInt64LE(q)); q += 8; }
          if (csize === U32 && q + 8 <= x + 4 + len) { csize = Number(cd.readBigUInt64LE(q)); q += 8; }
          if (offset === U32 && q + 8 <= x + 4 + len) { offset = Number(cd.readBigUInt64LE(q)); q += 8; }
        }
        x += 4 + len;
      }
      p = xEnd + commentLen;
      if (flags & FLAG_ENCRYPTED) throw bad(`encrypted entry ${name}`);
      if (!safeEntryName(name)) throw bad(`unsafe entry name ${JSON.stringify(name).slice(0, 120)}`);
      if (byName.has(name)) throw bad(`duplicate entry ${name}`);
      const isDir = name.endsWith('/');
      if (!isDir && method !== 0 && method !== 8) throw bad(`entry ${name} uses compression method ${method}`);
      if (offset + LOCAL_HEADER > fileSize || offset + csize > fileSize) throw bad(`entry ${name} points outside the file`);
      const entry = { name, method, crc32: crc, compressedSize: csize, size: usize, offset, isDir };
      entries.push(entry);
      byName.set(name, entry);
    }

    const dataStart = async (entry) => {
      const h = await readAt(fh, entry.offset, LOCAL_HEADER);
      if (h.readUInt32LE(0) !== SIG_LOCAL) throw bad(`no local header for ${entry.name}`);
      const start = entry.offset + LOCAL_HEADER + h.readUInt16LE(26) + h.readUInt16LE(28);
      if (start + entry.compressedSize > fileSize) throw bad(`entry ${entry.name} runs past the end`);
      return start;
    };

    /** A readable of the entry's bytes; it errors when the CRC or the size is wrong. */
    const openStream = async (entry) => {
      const start = await dataStart(entry);
      const raw = entry.compressedSize
        ? fs.createReadStream(filePath, { start, end: start + entry.compressedSize - 1, highWaterMark: 1024 * 1024 })
        : Readable.from([]);
      let crc = 0;
      let n = 0;
      const check = new Transform({
        transform(chunk, _enc, cb) {
          n += chunk.length;
          if (n > entry.size) return cb(bad(`entry ${entry.name} is longer than its header says`));
          crc = crc32(chunk, crc);
          cb(null, chunk);
        },
        flush(cb) {
          if (n !== entry.size) return cb(bad(`entry ${entry.name} is ${n} bytes, header says ${entry.size}`));
          if (crc !== entry.crc32) return cb(bad(`CRC mismatch in ${entry.name}`));
          cb();
        },
      });
      const onErr = (e) => check.destroy(e);
      raw.on('error', onErr);
      if (entry.method === 8) {
        const inflate = zlib.createInflateRaw();
        inflate.on('error', onErr);
        return raw.pipe(inflate).pipe(check);
      }
      return raw.pipe(check);
    };

    return {
      entries,
      entry: (name) => byName.get(name) || null,
      openStream,
      /** The whole entry as a Buffer; refused past `max` bytes. */
      async readEntry(entry, max = 64 * 1024 * 1024) {
        if (entry.size > max) throw bad(`entry ${entry.name} is ${entry.size} bytes, more than ${max}`);
        const chunks = [];
        for await (const c of await openStream(entry)) chunks.push(c);
        return Buffer.concat(chunks);
      },
      close: () => fh.close().catch(() => {}),
    };
  } catch (e) {
    await fh.close().catch(() => {});
    throw e;
  }
}

/**
 * Stream one entry to `dest` (created with `mode`, refused when it exists),
 * hashing it on the way. Resolves with `{ bytes, sha256 }`.
 */
export async function extractEntryTo(zip, entry, dest, { mode = 0o600 } = {}) {
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  const tap = new Transform({
    transform(chunk, _enc, cb) { hash.update(chunk); bytes += chunk.length; cb(null, chunk); },
  });
  await fsp.mkdir(path.dirname(dest), { recursive: true });
  await pipeline(await zip.openStream(entry), tap, fs.createWriteStream(dest, { flags: 'wx', mode }));
  return { bytes, sha256: hash.digest('hex') };
}

/** Hash one entry without writing it anywhere. Resolves with `{ bytes, sha256 }`. */
export async function hashEntry(zip, entry) {
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  for await (const c of await zip.openStream(entry)) { hash.update(c); bytes += c.length; }
  return { bytes, sha256: hash.digest('hex') };
}
