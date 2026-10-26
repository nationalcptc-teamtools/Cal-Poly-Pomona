import { afterEach, describe, expect, it, vi } from 'vitest';
import { ByteLru } from '@/lib/byte-lru';
import { thumbnailSize } from '@/lib/assets';

// CLI-10 / C2: the rendered-bytes cache is capped by size and keeps
// in-flight work; thumbnails are downscaled, never upscaled.
const MB = 1024 * 1024;
const flush = () => new Promise((r) => setTimeout(r, 0));
afterEach(() => vi.restoreAllMocks());

describe('ByteLru', () => {
  it('200 resolves of 1 MB stay at or under a 64 MB cap, newest kept', async () => {
    const lru = new ByteLru<Uint8Array>(64 * MB, (b) => b.byteLength);
    for (let i = 0; i < 200; i++) lru.set(`a${i}`, Promise.resolve(new Uint8Array(MB)));
    await flush();
    expect(lru.bytes).toBeLessThanOrEqual(64 * MB);
    expect(lru.has('a199')).toBe(true);
    expect(lru.has('a0')).toBe(false);
  });

  it('never evicts an entry still in flight, and counts it once it lands', async () => {
    const lru = new ByteLru<Uint8Array>(2 * MB, (b) => b.byteLength);
    let land!: (v: Uint8Array) => void;
    lru.set('slow', new Promise((r) => { land = r; }));
    for (let i = 0; i < 5; i++) lru.set(`f${i}`, Promise.resolve(new Uint8Array(MB)));
    await flush();
    expect(lru.has('slow')).toBe(true);
    land(new Uint8Array(MB));
    await flush();
    expect(lru.bytes).toBeLessThanOrEqual(2 * MB);
    expect(lru.has('slow')).toBe(true);
  });

  it('refreshes recency on get and forgets rejections', async () => {
    const lru = new ByteLru<Uint8Array>(2 * MB, (b) => b.byteLength);
    lru.set('a', Promise.resolve(new Uint8Array(MB)));
    lru.set('b', Promise.resolve(new Uint8Array(MB)));
    await flush();
    void lru.get('a');
    lru.set('c', Promise.resolve(new Uint8Array(MB)));
    await flush();
    expect(lru.has('a')).toBe(true);
    expect(lru.has('b')).toBe(false);
    const bad = Promise.reject(new Error('404'));
    bad.catch(() => undefined);
    lru.set('bad', bad);
    await flush();
    expect(lru.has('bad')).toBe(false);
  });

  it('a single entry over the cap is kept (its caller holds it anyway)', async () => {
    const lru = new ByteLru<Uint8Array>(MB, (b) => b.byteLength);
    lru.set('big', Promise.resolve(new Uint8Array(3 * MB)));
    await flush();
    expect(lru.has('big')).toBe(true);
  });
});

describe('thumbnailSize', () => {
  it('scales the longest side to the limit and never upscales', () => {
    expect(thumbnailSize(1920, 1080, 320)).toEqual({ width: 320, height: 180 });
    expect(thumbnailSize(1080, 1920, 320)).toEqual({ width: 180, height: 320 });
    expect(thumbnailSize(200, 100, 320)).toEqual({ width: 200, height: 100 });
  });
});
