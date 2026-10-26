// @vitest-environment node
// A junk (null) value written into the shared commandLogs map by any client
// must not break the live-window prune: the window stays bounded.
import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { getYDoc } = require('y-websocket/bin/utils');
const CAP = 500;
// yjs-data.mjs ships no .d.mts; a non-literal specifier keeps tsc out of it.
const YJS_DATA = new URL('../../server/yjs-data.mjs', import.meta.url).href;

describe('command log live window', () => {
  it('stays bounded when the map holds a null record', async () => {
    const { appendCommandLogs } = (await import(/* @vite-ignore */ YJS_DATA)) as {
      appendCommandLogs: (records: object[]) => Promise<void>;
    };
    const map = getYDoc('btct-shared').getMap('commandLogs');
    map.set('junk', null);
    let n = 0;
    const batch = () => Array.from({ length: 400 }, () => {
      n++;
      return { id: `c${n}`, workspaceId: 'w1', startedAt: n, command: 'id' };
    });
    for (let i = 0; i < 3; i++) await expect(appendCommandLogs(batch())).resolves.toBeUndefined();
    const live = [...map.values()].filter((r) => r && (r as { workspaceId?: string }).workspaceId === 'w1');
    expect(live.length).toBeLessThanOrEqual(CAP);
  });
});
