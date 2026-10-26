import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { REVOKE_DELAY_MS, downloadBlob, downloadText } from '@/lib/download';

describe('downloadBlob', () => {
  const created: Blob[] = [];
  const revoked: string[] = [];
  let clicks: Array<{ connected: boolean; download: string; href: string }> = [];
  const origClick = HTMLAnchorElement.prototype.click;

  beforeEach(() => {
    vi.useFakeTimers();
    created.length = 0;
    revoked.length = 0;
    clicks = [];
    URL.createObjectURL = ((b: Blob) => { created.push(b); return `blob:test/${created.length}`; }) as typeof URL.createObjectURL;
    URL.revokeObjectURL = ((u: string) => { revoked.push(u); }) as typeof URL.revokeObjectURL;
    HTMLAnchorElement.prototype.click = function click(this: HTMLAnchorElement) {
      clicks.push({ connected: this.isConnected, download: this.download, href: this.href });
    };
  });
  afterEach(() => {
    HTMLAnchorElement.prototype.click = origClick;
    vi.useRealTimers();
  });

  it('clicks an attached anchor, removes it, and revokes only after the delay', () => {
    downloadBlob(new Blob(['x'], { type: 'text/plain' }), 'a.txt', 'text/plain');
    expect(clicks).toEqual([{ connected: true, download: 'a.txt', href: 'blob:test/1' }]);
    expect(document.querySelectorAll('a').length).toBe(0);
    expect(revoked).toEqual([]);
    vi.advanceTimersByTime(REVOKE_DELAY_MS - 1);
    expect(revoked).toEqual([]);
    vi.advanceTimersByTime(1);
    expect(revoked).toEqual(['blob:test/1']);
    expect(REVOKE_DELAY_MS).toBe(60_000);
  });

  it('does not copy a Blob that already has the right type', () => {
    const blob = new Blob(['zip'], { type: 'application/zip' });
    downloadBlob(blob, 'w.zip', 'application/zip');
    expect(created[0]).toBe(blob);
  });

  it('wraps text in a typed Blob', async () => {
    downloadText('{"a":1}', 'p.json', 'application/json');
    expect(created[0]!.type).toBe('application/json');
    expect(await created[0]!.text()).toBe('{"a":1}');
  });
});
