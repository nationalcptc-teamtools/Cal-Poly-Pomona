// @vitest-environment node
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createLevelDbLogSealer } from '../../server/relay-persistence.mjs';

// A log append that fails half way (ENOSPC) leaves a torn record; LevelDB
// keeps appending after it and serves reads from memory, and the next open
// drops everything from the torn record on. LevelDB writes its log at its
// own file offset, so the tear cannot be faked from outside the process.
// These tests show what the seal guarantees instead: once it has run,
// nothing written before it depends on the log, so losing the log (which is
// what a torn record amounts to) loses nothing. The tear itself was
// reproduced on a full tmpfs (docs/competition-fixes-2026-10-12/bugs.md).

const child = path.join(__dirname, 'fixtures', 'leveldb-seal-child.mjs');

describe('LevelDB log seal (real LevelDB, in a child process)', () => {
  it('moves every write into a table file, replaces the log and keeps working', () => {
    const r = spawnSync(process.execPath, [child], { cwd: process.cwd(), encoding: 'utf8', timeout: 60_000 });
    const line = (r.stdout || '').trim().split('\n').pop() || '{}';
    const out = JSON.parse(line);
    expect(out.error).toBeUndefined();
    // Without a seal the write was only in the log.
    expect(out.noSeal).toBe('');
    expect(out.logsBefore).toBe(1);
    expect(out.sealed).toBe(true);
    expect(out.oldLogLeft).toBe(false);
    expect(out.liveAfterSeal).toBe('before the seal');
    expect(out.room).toBe('before the seal');
    expect(out.other).toBe('also before');
    // Written after the seal: in the new log only, like any write.
    expect(out.late).toBe('');
    expect(out.emptySeals).toEqual([true, true]);
    expect(out.afterEmptySeals).toBe('x');
  }, 90_000);

  it('reports false, not success, when the handle has no compactRange', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'btct-seal-'));
    try {
      const fake = { _transact: async (f: (db: unknown) => Promise<unknown>) => { try { return await f({}); } catch { return null; } } };
      const seal = createLevelDbLogSealer(fake, dir, fs);
      expect(await seal()).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
