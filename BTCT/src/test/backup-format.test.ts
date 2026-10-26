import { describe, it, expect, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  DEFAULT_BACKUP_CONFIG,
  FULL_INTERVAL_MIN_FLOOR,
  FULL_INTERVAL_MIN_CEIL,
  normalizeIncludes,
  normalizeBackupConfig,
  backupName,
  isBackupName,
  buildManifest,
  verifyBackupDir,
  sha256File,
  formatBytes,
  validateManifestEntries,
  restorePlan,
  normalizeKeepLast,
  KEEP_LAST_DEFAULT,
  parseBackupEntryName,
  isBackupEntryName,
  runsToPrune,
  isStaleTmpRun,
  estimateRunBytes,
  withTimeout,
  sameStateVector,
  mergeBackupSettings,
  BACKUP_RUN_HISTORY_KEYS,
  chooseRestoreEpoch,
  restoreSpaceNeeded,
} from '../../server/backup-format.mjs';

describe('normalizeIncludes', () => {
  it('defaults every category to true', () => {
    expect(normalizeIncludes(undefined)).toEqual({ sqlite: true, yjsShared: true, yjsPages: true, assets: true, history: true });
    expect(normalizeIncludes(null)).toEqual({ sqlite: true, yjsShared: true, yjsPages: true, assets: true, history: true });
  });

  it('keeps explicit booleans and ignores anything else', () => {
    expect(normalizeIncludes({ sqlite: false, assets: 'no', extra: true })).toEqual({
      sqlite: false, yjsShared: true, yjsPages: true, assets: true, history: true,
    });
  });
});

describe('normalizeBackupConfig', () => {
  it('has sane defaults', () => {
    expect(normalizeBackupConfig(undefined)).toEqual(DEFAULT_BACKUP_CONFIG);
    expect(DEFAULT_BACKUP_CONFIG.enabled).toBe(false);
    expect(DEFAULT_BACKUP_CONFIG.fullIntervalMin).toBe(60);
  });

  it('accepts the string forms the settings table stores', () => {
    const c = normalizeBackupConfig({ enabled: '1', fullIntervalMin: '15', includes: '{"assets":false}' });
    expect(c.enabled).toBe(true);
    expect(c.fullIntervalMin).toBe(15);
    expect(c.includes.assets).toBe(false);
  });

  it('clamps the interval to the floor and ceiling and falls back on garbage', () => {
    expect(normalizeBackupConfig({ fullIntervalMin: 0 }).fullIntervalMin).toBe(FULL_INTERVAL_MIN_FLOOR);
    expect(normalizeBackupConfig({ fullIntervalMin: -5 }).fullIntervalMin).toBe(FULL_INTERVAL_MIN_FLOOR);
    expect(normalizeBackupConfig({ fullIntervalMin: 1e9 }).fullIntervalMin).toBe(FULL_INTERVAL_MIN_CEIL);
    expect(normalizeBackupConfig({ fullIntervalMin: 'abc' }).fullIntervalMin).toBe(60);
    expect(normalizeBackupConfig({ fullIntervalMin: 2.7 }).fullIntervalMin).toBe(2);
  });
});

describe('backup names', () => {
  it('formats a UTC timestamp and round-trips through isBackupName', () => {
    const name = backupName(new Date(Date.UTC(2026, 7, 23, 10, 15, 0)));
    expect(name).toBe('btct-backup-20260823-101500');
    expect(isBackupName(name)).toBe(true);
  });

  it('rejects anything that is not a plain backup directory name', () => {
    for (const bad of ['../x', 'btct-backup-2026', 'btct-backup-20260823-101500.tmp', 'btct-backup-20260823-101500/..', '']) {
      expect(isBackupName(bad)).toBe(false);
    }
  });
});

describe('manifest round trip', () => {
  const dirs: string[] = [];
  const tmp = () => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'btct-bk-'));
    dirs.push(d);
    return d;
  };
  afterEach(() => { for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true }); });

  async function makeBackup(dir: string) {
    fs.mkdirSync(path.join(dir, 'yjs'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'yjs', 'btct-shared.yupdate.gz'), Buffer.from('hello'));
    fs.mkdirSync(path.join(dir, 'sqlite'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'sqlite', 'data.sqlite.gz'), Buffer.from('world'));
    const files = [];
    for (const rel of ['yjs/btct-shared.yupdate.gz', 'sqlite/data.sqlite.gz']) {
      const abs = path.join(dir, rel);
      files.push({ path: rel, bytes: fs.statSync(abs).size, sha256: await sha256File(abs) });
    }
    const manifest = buildManifest({
      instanceId: 'inst-1',
      createdAt: '2026-08-23T10:15:00.000Z',
      trigger: 'manual',
      includes: normalizeIncludes({ assets: false }),
      files,
      // stateVector and dataVersion are no longer written; manifests from
      // older builds still carry them and must keep verifying.
      docs: [{ name: 'btct-shared', bytes: 5, stateVector: 'AA==' }],
      sqlite: { dataVersion: 7, rawBytes: 4096 },
      app: { version: '0.5.0' },
    });
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2));
    return manifest;
  }

  it('verifies a backup whose files match the manifest', async () => {
    const dir = tmp();
    const m = await makeBackup(dir);
    expect(m.schemaVersion).toBe(1);
    expect(m.files.length).toBe(2);
    const v = await verifyBackupDir(dir);
    expect(v.ok).toBe(true);
    expect(v.errors).toEqual([]);
    expect(v.manifest?.instanceId).toBe('inst-1');
  });

  it('reports a tampered or missing file by path', async () => {
    const dir = tmp();
    await makeBackup(dir);
    fs.writeFileSync(path.join(dir, 'sqlite', 'data.sqlite.gz'), Buffer.from('w0rld'));
    fs.unlinkSync(path.join(dir, 'yjs', 'btct-shared.yupdate.gz'));
    const v = await verifyBackupDir(dir);
    expect(v.ok).toBe(false);
    expect(v.errors.some((e) => e.includes('data.sqlite.gz'))).toBe(true);
    expect(v.errors.some((e) => e.includes('btct-shared.yupdate.gz'))).toBe(true);
  });

  it('refuses a manifest whose asset id escapes its folder, even when the file hashes', async () => {
    const dir = tmp();
    const m = await makeBackup(dir);
    fs.writeFileSync(path.join(dir, 'escaped.txt'), 'planted');
    m.assets = [{ id: '../escaped.txt', present: true }];
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(m));
    const v = await verifyBackupDir(dir);
    expect(v.ok).toBe(false);
    expect(v.errors[0]).toMatch(/unsafe id/);
  });

  it('refuses an entry whose file is not listed (so never hashed)', async () => {
    const dir = tmp();
    const m = await makeBackup(dir);
    fs.mkdirSync(path.join(dir, 'history'));
    fs.writeFileSync(path.join(dir, 'history', 'p1.ydoc'), 'x');
    m.history = [{ pageId: 'p1', bytes: 1 }];
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(m));
    const v = await verifyBackupDir(dir);
    expect(v.ok).toBe(false);
    expect(v.errors[0]).toMatch(/history\/p1\.ydoc/);
  });

  it('fails cleanly without a manifest', async () => {
    const dir = tmp();
    const v = await verifyBackupDir(dir);
    expect(v.ok).toBe(false);
    expect(v.errors[0]).toMatch(/manifest/i);
  });
});

describe('formatBytes', () => {
  it('picks a readable unit', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MB');
    expect(formatBytes(3 * 1024 ** 3)).toBe('3.0 GB');
  });
});

describe('validateManifestEntries', () => {
  const files = [
    { path: 'yjs/btct-shared.yupdate.gz', bytes: 1, sha256: 'a' },
    { path: 'assets/abc-1', bytes: 1, sha256: 'b' },
    { path: 'history/p_1.ydoc', bytes: 1, sha256: 'c' },
  ];
  it('accepts plain ids whose files are listed, and absent assets without a file', () => {
    expect(validateManifestEntries({
      files,
      docs: [{ name: 'btct-shared' }],
      assets: [{ id: 'abc-1', present: true }, { id: 'gone', present: false }],
      history: [{ pageId: 'p_1' }],
    })).toEqual([]);
  });
  it('flags traversal, slashes and non-strings in every list', () => {
    const errs = validateManifestEntries({
      files,
      docs: [{ name: '../yjs' }],
      assets: [{ id: 'a/b', present: true }],
      history: [{ pageId: 7 }],
    });
    expect(errs).toHaveLength(3);
  });
  it('requires the sqlite file when the manifest includes sqlite', () => {
    expect(validateManifestEntries({ files, includes: { sqlite: true } })[0]).toMatch(/sqlite/);
  });
});

describe('restorePlan', () => {
  it('treats keys an older manifest never had as absent, not excluded', () => {
    const p = restorePlan({ sqlite: true, yjsShared: true, yjsPages: true, assets: true });
    expect(p.excluded).toEqual([]);
    expect(p.absent).toEqual(['history']);
    expect(p.restore.history).toBe(false);
    expect(p.restore.sqlite).toBe(true);
  });
  it('lists explicit exclusions (these need --partial)', () => {
    const p = restorePlan({ sqlite: true, yjsShared: false, yjsPages: true, assets: false, history: true });
    expect(p.excluded).toEqual(['yjsShared', 'assets']);
  });
});

describe('retention helpers', () => {
  const names = ['btct-backup-20261012-100000', 'btct-backup-20261012-110000', 'btct-backup-20261012-120000', 'btct-backup-20261012-130000'];
  it('keep-last defaults to KEEP_LAST_DEFAULT when unset, 0 keeps all, and is clamped', () => {
    expect(normalizeKeepLast(undefined)).toBe(KEEP_LAST_DEFAULT);
    expect(normalizeKeepLast('')).toBe(KEEP_LAST_DEFAULT);
    expect(normalizeKeepLast('0')).toBe(0);
    expect(normalizeKeepLast(0)).toBe(0);
    expect(normalizeKeepLast('3')).toBe(3);
    expect(normalizeKeepLast(-2)).toBe(0);
    expect(normalizeKeepLast(1e9)).toBe(1000);
  });
  it('prunes the oldest runs beyond N and never the run just written', () => {
    expect(runsToPrune(names, 0)).toEqual([]);
    expect(runsToPrune(names, 2)).toEqual(['btct-backup-20261012-110000', 'btct-backup-20261012-100000']);
    expect(runsToPrune(names, 1, 'btct-backup-20261012-100000')).toEqual(['btct-backup-20261012-120000', 'btct-backup-20261012-110000']);
    expect(runsToPrune([...names, 'junk', 'btct-backup-20261012-140000.tmp'], 3)).toEqual(['btct-backup-20261012-100000']);
  });
  it('orders ZIP runs and older folder runs by the time in the name', () => {
    const mixed = ['btct-backup-20261012-100000', 'btct-backup-20261012-110000.zip', 'btct-backup-20261012-120000', 'btct-backup-20261012-130000.zip'];
    expect(runsToPrune(mixed, 2)).toEqual(['btct-backup-20261012-110000.zip', 'btct-backup-20261012-100000']);
    expect(runsToPrune([...mixed, 'btct-backup-20261012-140000.zip.tmp', 'x.zip'], 4)).toEqual([]);
    expect(runsToPrune(mixed, 1, 'btct-backup-20261012-110000.zip')).toEqual(['btct-backup-20261012-120000', 'btct-backup-20261012-100000']);
  });
  it('parses backup entry names', () => {
    expect(parseBackupEntryName('btct-backup-20261012-100000.zip')).toEqual({ base: 'btct-backup-20261012-100000', kind: 'zip', partial: false });
    expect(parseBackupEntryName('btct-backup-20261012-100000.zip.tmp')).toEqual({ base: 'btct-backup-20261012-100000', kind: 'zip', partial: true });
    expect(parseBackupEntryName('btct-backup-20261012-100000')).toEqual({ base: 'btct-backup-20261012-100000', kind: 'dir', partial: false });
    expect(parseBackupEntryName('btct-backup-20261012-100000.tmp')).toEqual({ base: 'btct-backup-20261012-100000', kind: 'dir', partial: true });
    for (const bad of ['../btct-backup-20261012-100000.zip', 'btct-backup-20261012-100000.zip/x', 'x.zip', 'btct-backup-2026.zip', '', null]) {
      expect(parseBackupEntryName(bad)).toBeNull();
      expect(isBackupEntryName(bad)).toBe(false);
    }
  });
  it('treats only hour-old .tmp runs as stale', () => {
    const now = 10 * 3600_000;
    expect(isStaleTmpRun('btct-backup-20261012-100000.tmp', now - 2 * 3600_000, now)).toBe(true);
    expect(isStaleTmpRun('btct-backup-20261012-100000.tmp', now - 60_000, now)).toBe(false);
    expect(isStaleTmpRun('btct-backup-20261012-100000', now - 2 * 3600_000, now)).toBe(false);
    expect(isStaleTmpRun('../x.tmp', 0, now)).toBe(false);
    expect(isStaleTmpRun('btct-backup-20261012-100000.zip.tmp', now - 2 * 3600_000, now)).toBe(true);
    expect(isStaleTmpRun('btct-backup-20261012-100000.zip.tmp', now - 60_000, now)).toBe(false);
    expect(isStaleTmpRun('btct-backup-20261012-100000.zip', now - 2 * 3600_000, now)).toBe(false);
  });
});

describe('estimateRunBytes', () => {
  const prev = {
    totalBytes: 1000 + 300,
    files: [
      { path: 'sqlite/data.sqlite.gz', bytes: 1000, sha256: 'x' },
      { path: 'assets/a', bytes: 100, sha256: 'y' },
      { path: 'assets/b', bytes: 200, sha256: 'z' },
    ],
  };
  // Every ZIP is a full copy: all assets count, whatever the previous run held.
  it('counts every asset plus the previous non-asset bytes and 20%', () => {
    expect(estimateRunBytes({ prevManifest: prev, assets: [{ id: 'a', size: 100 }, { id: 'b', size: 200 }, { id: 'c', size: 50 }] }))
      .toBe(1200 + 350 + (3 + 3 + 1) * 200);
  });
  it('adds the scratch bytes of the raw SQLite snapshot', () => {
    expect(estimateRunBytes({ prevManifest: prev, assets: [], scratchBytes: 5000 })).toBe(1200 + 5000 + (3 + 0 + 1) * 200);
  });
  it('without a previous run, uses the fallback plus every asset', () => {
    expect(estimateRunBytes({ assets: [{ id: 'a', size: 10 }], fallbackBytes: 100 })).toBe(120 + 10 + 2 * 200);
  });
});

describe('withTimeout', () => {
  it('passes a result through and rejects a slow promise', async () => {
    expect(await withTimeout(Promise.resolve(5), 1000)).toBe(5);
    await expect(withTimeout(new Promise(() => {}), 10, 'room x')).rejects.toThrow(/room x timed out/);
    expect(await withTimeout(Promise.resolve(1), 0)).toBe(1);
  });
});

describe('restore helpers', () => {
  it('compares state vectors by content, not encoding order', () => {
    expect(sameStateVector(new Map([[1, 5], [2, 3]]), new Map([[2, 3], [1, 5]]))).toBe(true);
    expect(sameStateVector(new Map([[1, 5]]), new Map([[1, 4]]))).toBe(false);
    expect(sameStateVector(new Map([[1, 5]]), new Map([[1, 5], [2, 1]]))).toBe(false);
  });

  it("keeps this box's backup settings over the backup's", () => {
    const restored = new Map([['backup_enabled', '0'], ['backup_token', 'old'], ['backup_old_key', 'x']]);
    const current = new Map([['backup_enabled', '1'], ['backup_token', 'new'], ['backup_keep_last', '5']]);
    const r = mergeBackupSettings(restored, current);
    expect(r.del).toEqual(['backup_old_key']);
    expect(new Map(r.set)).toEqual(current);
  });

  it("on a fresh box keeps the backup's config but drops its last result", () => {
    const restored = new Map([['backup_enabled', '1'], ['backup_last_result', '{}']]);
    expect(mergeBackupSettings(restored, null)).toEqual({ set: [], del: ['backup_last_result'] });
  });

  it("on a fresh box drops the source box's whole run history, keeps token and instance id", () => {
    const restored = new Map([
      ['backup_enabled', '1'], ['backup_token', 'tok'], ['backup_instance_id', 'id-a'],
      ['backup_last_result', '{}'], ['backup_last_good', '{"name":"btct-backup-20261013-071439.zip"}'],
      ['backup_last_run_at', '1792000000000'],
    ]);
    const r = mergeBackupSettings(restored, null);
    expect(r.set).toEqual([]);
    expect([...r.del].sort()).toEqual([...BACKUP_RUN_HISTORY_KEYS].sort());
    for (const k of ['backup_enabled', 'backup_token', 'backup_instance_id']) expect(r.del).not.toContain(k);
  });

  it('picks a new epoch only when rooms roll back', () => {
    const base = { currentEpoch: 'cur', backupEpoch: 'bak', newEpoch: 'new' };
    expect(chooseRestoreEpoch({ ...base, restoresRooms: true, keepCaches: false })).toBe('new');
    expect(chooseRestoreEpoch({ ...base, restoresRooms: true, keepCaches: true })).toBe('cur');
    expect(chooseRestoreEpoch({ ...base, restoresRooms: false, keepCaches: false })).toBe('cur');
    expect(chooseRestoreEpoch({ ...base, currentEpoch: null, restoresRooms: false, keepCaches: false })).toBe('bak');
    expect(chooseRestoreEpoch({ newEpoch: 'n', currentEpoch: null, backupEpoch: null, restoresRooms: false, keepCaches: false })).toBeNull();
  });

  it('sizes the staging area from the manifest', () => {
    const m = {
      sqlite: { rawBytes: 4000 },
      docs: [{ bytes: 10 }, { bytes: 20 }],
      files: [
        { path: 'sqlite/data.sqlite.gz', bytes: 400, sha256: '' },
        { path: 'assets/a', bytes: 500, sha256: '' },
        { path: 'history/p.ydoc', bytes: 60, sha256: '' },
      ],
    };
    expect(restoreSpaceNeeded(m, restorePlan({ sqlite: true, yjsShared: true, yjsPages: true, assets: true, history: true }))).toBe(4000 + 90 + 500 + 60);
    expect(restoreSpaceNeeded(m, restorePlan({ sqlite: false, yjsShared: true, yjsPages: false, assets: false, history: false }), { currentYjsBytes: 1000 })).toBe(90 + 1000);
  });
});
