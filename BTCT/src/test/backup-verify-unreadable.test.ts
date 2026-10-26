// A backup copy this process may not read (EACCES/EPERM) is reported as
// unreadable, not as a backup that failed verification. Tests run as root
// in the container, where chmod does not block a read, so the denial is
// simulated by spying on the fs calls the verifier makes.
import { describe, it, expect, afterEach, vi } from 'vitest';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { verifyBackup, verifyBackupDir, isAccessError, MANIFEST_FILE } from '../../server/backup-format.mjs';

function denied(code = 'EACCES') {
  return Object.assign(new Error(`${code}: permission denied`), { code });
}

const tmp: string[] = [];
function tmpDir() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'btct-verify-'));
  tmp.push(d);
  return d;
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const d of tmp.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

describe('isAccessError', () => {
  it('matches EACCES and EPERM only', () => {
    expect(isAccessError(denied('EACCES'))).toBe(true);
    expect(isAccessError(denied('EPERM'))).toBe(true);
    expect(isAccessError(Object.assign(new Error('x'), { code: 'ENOENT' }))).toBe(false);
    expect(isAccessError(null)).toBe(false);
  });
});

describe('verifyBackup on a copy it cannot read', () => {
  it('flags a ZIP whose open is denied as unreadable', async () => {
    const d = tmpDir();
    const zip = path.join(d, 'btct-backup-20261013-080000.zip');
    fs.writeFileSync(zip, 'PK');
    vi.spyOn(fsp, 'open').mockRejectedValue(denied());
    const v = await verifyBackup(zip);
    expect(v.ok).toBe(false);
    expect(v.unreadable).toBe(true);
    expect(v.errors[0]).toContain('cannot read');
    expect(v.errors[0]).toContain('EACCES');
  });

  it('keeps a damaged but readable ZIP a verification failure', async () => {
    const d = tmpDir();
    const zip = path.join(d, 'btct-backup-20261013-080000.zip');
    fs.writeFileSync(zip, 'not a zip at all, but long enough to read a tail from');
    const v = await verifyBackup(zip);
    expect(v.ok).toBe(false);
    expect(v.unreadable).toBeFalsy();
  });

  it('flags a path whose stat is denied as unreadable, not missing', async () => {
    vi.spyOn(fs, 'statSync').mockImplementation(() => { throw denied('EPERM'); });
    const v = await verifyBackup('/backups/locked/btct-backup-20261013-080000.zip');
    expect(v.unreadable).toBe(true);
    expect(v.errors[0]).not.toContain('no such backup');
  });

  it('flags a folder run whose manifest is denied as unreadable', async () => {
    const d = tmpDir();
    fs.writeFileSync(path.join(d, MANIFEST_FILE), '{}');
    vi.spyOn(fs, 'accessSync').mockImplementation(() => { throw denied(); });
    const v = await verifyBackupDir(d);
    expect(v.unreadable).toBe(true);
  });

  it('still reports a missing folder manifest as a bad backup', async () => {
    const v = await verifyBackupDir(tmpDir());
    expect(v.ok).toBe(false);
    expect(v.unreadable).toBeFalsy();
    expect(v.errors[0]).toContain(MANIFEST_FILE);
  });
});
