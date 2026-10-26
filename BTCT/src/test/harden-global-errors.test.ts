import { describe, expect, it, vi } from 'vitest';
import { installGlobalErrorLogging } from '@/lib/global-errors';

describe('installGlobalErrorLogging', () => {
  it('logs error and unhandledrejection with a prefix, once, without preventing default', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    installGlobalErrorLogging();
    installGlobalErrorLogging();
    const ev = new Event('error', { cancelable: true });
    window.dispatchEvent(ev);
    const rej = new Event('unhandledrejection', { cancelable: true });
    Object.assign(rej, { reason: 'boom' });
    window.dispatchEvent(rej);
    expect(spy).toHaveBeenCalledTimes(2);
    expect(spy.mock.calls[0]?.[0]).toBe('[global-error]');
    expect(spy.mock.calls[1]?.[0]).toBe('[unhandled-rejection]');
    expect(ev.defaultPrevented).toBe(false);
    expect(rej.defaultPrevented).toBe(false);
    spy.mockRestore();
  });
});
