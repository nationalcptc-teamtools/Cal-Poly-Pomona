import { afterEach, describe, expect, it, vi } from 'vitest';
import { pollWhileVisible } from '@/lib/visible-poll';

afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });
describe('visible polling', () => {
  it('pauses while hidden, refreshes on return, and stops at cleanup', async () => {
    vi.useFakeTimers();
    const hidden = vi.spyOn(document, 'hidden', 'get').mockReturnValue(false);
    const task = vi.fn();
    const stop = pollWhileVisible(task, 1000);
    await vi.advanceTimersByTimeAsync(1000);
    expect(task).toHaveBeenCalledTimes(2);
    hidden.mockReturnValue(true);
    document.dispatchEvent(new Event('visibilitychange'));
    await vi.advanceTimersByTimeAsync(5000);
    expect(task).toHaveBeenCalledTimes(2);
    hidden.mockReturnValue(false);
    document.dispatchEvent(new Event('visibilitychange'));
    expect(task).toHaveBeenCalledTimes(3);
    stop();
    await vi.advanceTimersByTimeAsync(5000);
    expect(task).toHaveBeenCalledTimes(3);
  });
  it('never overlaps an in-flight request', async () => {
    vi.useFakeTimers();
    vi.spyOn(document, 'hidden', 'get').mockReturnValue(false);
    let resolve!: () => void;
    const task = vi.fn(() => new Promise<void>((done) => { resolve = done; }));
    const stop = pollWhileVisible(task, 1000);
    await vi.advanceTimersByTimeAsync(5000);
    document.dispatchEvent(new Event('visibilitychange'));
    expect(task).toHaveBeenCalledTimes(1);
    resolve();
    await vi.advanceTimersByTimeAsync(1000);
    expect(task).toHaveBeenCalledTimes(2);
    stop(); resolve();
  });
});
