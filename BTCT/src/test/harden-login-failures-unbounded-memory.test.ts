// @vitest-environment node
// The failed-login map in server/index.mjs promises "the map is pruned so it
// can't grow unbounded". index.mjs starts the server on import, so this test
// lifts the throttle block out of the real source and runs it in isolation.
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

function loadThrottle() {
  const src = fs.readFileSync(path.resolve(__dirname, '../../server/index.mjs'), 'utf8');
  const start = src.indexOf('const LOGIN_MAX_FAILURES');
  const end = src.indexOf('async function ensureSeedAccounts');
  expect(start).toBeGreaterThan(-1);
  expect(end).toBeGreaterThan(start);
  const block = src.slice(start, end);
  return new Function(`${block}\nreturn { loginFailures, recordLoginFailure, loginThrottled };`)() as {
    loginFailures: Map<string, unknown>;
    recordLoginFailure: (k: string) => void;
  };
}

describe('login failure throttle map', () => {
  it('stays under a hard cap for many distinct keys inside one window', () => {
    const { loginFailures, recordLoginFailure } = loadThrottle();
    for (let i = 0; i < 5000; i++) recordLoginFailure(`u${i}${'x'.repeat(7000)}|1.2.3.4`);
    expect(loginFailures.size).toBeLessThanOrEqual(1001);
    let bytes = 0;
    for (const k of loginFailures.keys()) bytes += k.length;
    expect(bytes).toBeLessThan(1024 * 1024);
  });
});
