// @vitest-environment node
// Retention prune must never unlink a path outside ASSETS_DIR, whatever key a
// client wrote into the shared typstAssets map (the relay validates no schema).
import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'harden-ret-'));
const assetsDir = path.join(root, 'assets');

vi.mock('../../server/db.mjs', () => ({
  getSetting: (k: string) => (k === 'retention_days' ? '1' : null),
  setSetting: () => {},
  countPageVersionsBefore: () => 0,
  deletePageVersionsBefore: () => 0,
  deletePageVersionsInRange: () => 0,
  deleteAssetRow: () => {},
}));
vi.mock('../../server/assets.mjs', () => ({ ASSETS_DIR: path.join(fs.realpathSync(os.tmpdir()), path.basename(root), 'assets') }));

// Resolve y-websocket from server/, as retention.mjs does: a checkout with its
// own server/node_modules would otherwise hand the test a second copy.
const require = createRequire(new URL('../../server/retention.mjs', import.meta.url));
const { getYDoc } = require('y-websocket/bin/utils');

describe('retention prune asset ids', () => {
  beforeAll(() => { fs.mkdirSync(assetsDir, { recursive: true }); });
  afterAll(() => { fs.rmSync(root, { recursive: true, force: true }); });

  it('does not delete a file outside ASSETS_DIR for a traversal key', async () => {
    const victim = path.join(root, 'victim.txt');
    fs.writeFileSync(victim, 'keep me');
    const inside = path.join(assetsDir, '0123abcd-0123-4abc-8def-0123456789ab');
    fs.writeFileSync(inside, 'old bytes');
    const assets = getYDoc('btct-shared').getMap('typstAssets');
    assets.set('../victim.txt', { deletedAt: 1 });
    assets.set('0123abcd-0123-4abc-8def-0123456789ab', { deletedAt: 1 });
    // retention.mjs ships no .d.mts; a non-literal specifier keeps tsc out of it.
    const RETENTION = new URL('../../server/retention.mjs', import.meta.url).href;
    const { pruneNow } = (await import(/* @vite-ignore */ RETENTION)) as {
      pruneNow: () => Promise<{ ran: boolean }>;
    };
    const out = await pruneNow();
    expect(out.ran).toBe(true);
    expect(fs.existsSync(inside)).toBe(false); // a real retired asset is still pruned
    expect(fs.existsSync(victim)).toBe(true);
  });
});
