import path from 'node:path';
import { describe, it, expect } from 'vitest';
import { vetAssetRecord } from '../../server/typst/vet-asset.mjs';

// The threat this module exists for: a `typstAssets` record is plain JSON in
// the shared doc, and any authenticated account can write one. Before the
// staging code touches the filesystem with a field off that record, the
// record has to earn it.

const DIR = path.resolve('/data/assets');
const ID = '7d2f1b90-4c3a-4d5e-8f01-2a3b4c5d6e7f';
const WS = 'ws-1';

const row = (over = {}) => ({
  id: ID, workspaceId: WS, kind: 'image', filename: 'shot.png',
  mime: 'image/png', size: 10, uploadedBy: 1, createdAt: 0, ...over,
});
const record = (over = {}) => ({ id: ID, workspaceId: WS, kind: 'image', filename: 'shot.png', ...over });

describe('vetAssetRecord', () => {
  it('accepts a record whose id is a real upload and whose row matches', () => {
    const out = vetAssetRecord(record(), row(), WS, DIR);
    expect(out).toEqual({ ok: true, from: path.join(DIR, ID), kind: 'image', name: 'shot.png' });
  });

  it('refuses an id that climbs out of the asset store', () => {
    for (const id of ['../data.sqlite', '../../proc/self/environ', '..\\..\\data.sqlite']) {
      const out = vetAssetRecord(record({ id }), row({ id }), WS, DIR);
      expect(out.ok, id).toBe(false);
    }
  });

  it('refuses an absolute id, on either path flavour', () => {
    for (const id of ['/etc/passwd', 'C:\\Windows\\win.ini', 'C:/Windows/win.ini', '\\\\host\\share\\x']) {
      expect(vetAssetRecord(record({ id }), row({ id }), WS, DIR).ok, id).toBe(false);
    }
  });

  it('refuses anything that is not exactly a uuid', () => {
    for (const id of ['', 'shot.png', `${ID}.png`, ` ${ID}`, `${ID}/x`, 'zzzzzzzz-4c3a-4d5e-8f01-2a3b4c5d6e7f', 42, null, undefined]) {
      expect(vetAssetRecord(record({ id }), row({ id }), WS, DIR).ok, String(id)).toBe(false);
    }
  });

  it('refuses a uuid with no row in the server inventory', () => {
    expect(vetAssetRecord(record(), null, WS, DIR).ok).toBe(false);
  });

  it('refuses a row that belongs to another workspace', () => {
    expect(vetAssetRecord(record(), row({ workspaceId: 'ws-2' }), WS, DIR).ok).toBe(false);
  });

  it('takes kind from the inventory row, never from the record', () => {
    // The whole point: claiming kind 'font' in the CRDT must not skip the
    // reference filter and the bake for a file uploaded as an image.
    expect(vetAssetRecord(record({ kind: 'font' }), row({ kind: 'image' }), WS, DIR))
      .toMatchObject({ ok: true, kind: 'image' });
    expect(vetAssetRecord(record({ kind: 'image' }), row({ kind: 'font' }), WS, DIR))
      .toMatchObject({ ok: true, kind: 'font' });
  });

  it('reduces the record filename to a bare name', () => {
    expect(vetAssetRecord(record({ filename: '../../evil.png' }), row(), WS, DIR))
      .toMatchObject({ ok: true, name: 'evil.png' });
    expect(vetAssetRecord(record({ filename: 'C:/Windows/win.ini' }), row(), WS, DIR))
      .toMatchObject({ ok: true, name: 'win.ini' });
  });

  it('refuses a filename that reduces to nothing usable', () => {
    for (const filename of ['', '.', '..', '/', '   ']) {
      expect(vetAssetRecord(record({ filename }), row(), WS, DIR).ok, JSON.stringify(filename)).toBe(false);
    }
  });

  it('falls back to the inventory filename when the record has none', () => {
    // The row's name went through sanitizeFilename at upload, so it is always
    // usable; a record with no filename at all is worth staging, not skipping.
    for (const filename of [null, undefined]) {
      expect(vetAssetRecord(record({ filename }), row(), WS, DIR)).toMatchObject({ ok: true, name: 'shot.png' });
    }
  });

  it('gives a reason for every refusal', () => {
    const out = vetAssetRecord(record({ id: '../x' }), null, WS, DIR);
    if (out.ok) throw new Error('expected this record to be refused');
    expect(typeof out.reason).toBe('string');
    expect(out.reason.length).toBeGreaterThan(0);
  });
});
