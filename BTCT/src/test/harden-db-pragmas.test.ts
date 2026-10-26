// @vitest-environment node
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

describe('db.mjs pragmas', () => {
  it('sets busy_timeout and journal_size_limit', () => {
    const src = fs.readFileSync(path.resolve(__dirname, '../../server/db.mjs'), 'utf8');
    expect(src).toContain('PRAGMA busy_timeout = 5000');
    expect(src).toContain('PRAGMA journal_size_limit');
  });
});
