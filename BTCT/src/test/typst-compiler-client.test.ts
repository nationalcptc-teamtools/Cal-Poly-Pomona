import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { DriverCommand, DriverRequest, DriverResponse } from '@/lib/typst-compiler-types';

/**
 * Stands in for the compiler Worker: records what the client posts and
 * answers through `handler`, asynchronously like a real worker would.
 */
class FakeWorker {
  static instances: FakeWorker[] = [];
  static handler: (cmd: DriverCommand) => unknown = () => undefined;
  posted: DriverRequest[] = [];
  terminated = 0;
  onmessage: ((e: { data: DriverResponse }) => void) | null = null;
  onerror: ((e: { message: string }) => void) | null = null;
  constructor() { FakeWorker.instances.push(this); }
  postMessage(req: DriverRequest) {
    this.posted.push(req);
    void Promise.resolve().then(async () => {
      try {
        const value = await FakeWorker.handler(req);
        this.onmessage?.({ data: { id: req.id, ok: true, value } });
      } catch (err) {
        this.onmessage?.({ data: { id: req.id, ok: false, error: String(err) } });
      }
    });
  }
  terminate() { this.terminated++; }
  crash(message: string) { this.onerror?.({ message }); }
}

const ops = (w: FakeWorker) => w.posted.map((p) => p.op);
// Memoized so `bytes(1)` called twice yields the *same* array instance: the
// client tracks font/shadow changes by reference, so re-passing "the same"
// bytes must compare equal the way a caller reusing its own buffer would.
const byteCache = new Map<number, Uint8Array>();
const bytes = (n: number) => byteCache.get(n) ?? (byteCache.set(n, new Uint8Array([n])), byteCache.get(n)!);

async function loadClient() {
  vi.resetModules();
  return import('@/lib/typst-compiler');
}

describe('typst compiler client', () => {
  beforeEach(() => {
    FakeWorker.instances = [];
    FakeWorker.handler = (cmd) => (cmd.op === 'svg' ? { svg: '<svg/>', diagnostics: [] } : undefined);
    vi.stubGlobal('Worker', FakeWorker);
  });
  afterEach(() => { vi.unstubAllGlobals(); });

  it('starts one worker lazily and compiles through it', async () => {
    const c = await loadClient();
    expect(FakeWorker.instances).toHaveLength(0);
    const res = await c.compileTypstSvg('= hi', {}, '/main.typ');
    expect(res).toEqual({ svg: '<svg/>', diagnostics: [] });
    expect(FakeWorker.instances).toHaveLength(1);
    const w = FakeWorker.instances[0]!;
    expect(ops(w)).toEqual(['svg']);
    expect(w.posted[0]).toMatchObject({ op: 'svg', source: '= hi', mainPath: '/main.typ' });
  });

  it('pushes fonts and shadow files only when they change, before the compile that needs them', async () => {
    const c = await loadClient();
    expect(c.setTypstFonts([bytes(1)])).toBe(true);
    expect(c.setTypstFonts([bytes(1)])).toBe(false); // same reference: no change
    expect(c.setTypstShadowFiles([{ path: '/a.png', bytes: bytes(2) }])).toBe(true);
    await c.compileTypstSvg('a');
    await c.compileTypstSvg('b');
    const w = FakeWorker.instances[0]!;
    expect(ops(w)).toEqual(['setFonts', 'setShadow', 'svg', 'svg']);
    expect(w.posted[0]).toMatchObject({ op: 'setFonts', fonts: [bytes(1)] });
    expect(w.posted[1]).toMatchObject({ op: 'setShadow', files: [{ path: '/a.png', bytes: bytes(2) }] });
  });

  it('skips a coalesced preview that was superseded before it started', async () => {
    const c = await loadClient();
    FakeWorker.handler = (cmd) =>
      (cmd.op === 'svg' ? { svg: `<svg data-src="${cmd.source}"/>`, diagnostics: [] } : undefined);
    const a = c.compileTypstSvg('a', { coalesce: true });
    const b = c.compileTypstSvg('b', { coalesce: true });
    const d = c.compileTypstSvg('c', { coalesce: true });
    const [ra, rb, rc] = await Promise.all([a, b, d]);
    // 'a' and 'b' are both superseded before either reaches the front of the
    // queue (all three were requested in the same tick, so neither has
    // started when 'c' arrives); only the newest, 'c', actually compiles.
    expect(ra).toEqual({ diagnostics: [], superseded: true });
    expect(rb).toEqual({ diagnostics: [], superseded: true });
    expect(rc.svg).toContain('c');
    expect(ops(FakeWorker.instances[0]!)).toEqual(['svg']); // only 'c' reaches the worker
  });

  it('keeps an in-flight preview and runs only the newest of the ones queued behind it', async () => {
    const c = await loadClient();
    let releaseA!: () => void;
    const aDone = new Promise<void>((r) => { releaseA = r; });
    FakeWorker.handler = async (cmd) => {
      if (cmd.op !== 'svg') return undefined;
      if (cmd.source === 'a') await aDone;
      return { svg: `<svg data-src="${cmd.source}"/>`, diagnostics: [] };
    };
    const a = c.compileTypstSvg('a', { coalesce: true });
    // Wait for 'a' to actually reach the worker (and start hanging there)
    // before queuing 'b' and 'c' behind it.
    await vi.waitFor(() => {
      expect(FakeWorker.instances[0]?.posted.some((p) => p.op === 'svg' && p.source === 'a')).toBe(true);
    });
    const w = FakeWorker.instances[0]!;
    const b = c.compileTypstSvg('b', { coalesce: true });
    const d = c.compileTypstSvg('c', { coalesce: true });
    releaseA();
    const [ra, rb, rc] = await Promise.all([a, b, d]);
    // 'a' was already in flight, so it isn't superseded; 'b' is superseded by
    // 'c' before either gets a turn, so only 'a' and 'c' ever reach the worker.
    expect(ra.svg).toContain('a');
    expect(rb).toEqual({ diagnostics: [], superseded: true });
    expect(rc.svg).toContain('c');
    expect(ops(w)).toEqual(['svg', 'svg']);
  });

  it('turns a PDF compile with errors into a readable rejection', async () => {
    const c = await loadClient();
    FakeWorker.handler = () => ({ diagnostics: [{ severity: 'error', message: 'unknown variable: x' }] });
    await expect(c.compileTypstPdf('#x')).rejects.toThrow('Typst error: unknown variable: x');
  });

  it('recovers from a crashed worker and re-sends its state to the replacement', async () => {
    const c = await loadClient();
    c.setTypstFonts([bytes(7)]);
    await c.compileTypstSvg('a');
    const first = FakeWorker.instances[0]!;
    // Hang the next compile, then crash the worker under it.
    FakeWorker.handler = () => new Promise(() => {});
    const hung = c.compileTypstSvg('b');
    // Wait for 'b' to actually reach the worker before crashing it, so the
    // crash finds a genuinely in-flight request in `pending`.
    await vi.waitFor(() => {
      expect(first.posted.some((p) => p.op === 'svg' && p.source === 'b')).toBe(true);
    });
    first.crash('boom');
    await expect(hung).rejects.toThrow('boom');

    FakeWorker.handler = (cmd) => (cmd.op === 'svg' ? { svg: '<svg/>', diagnostics: [] } : undefined);
    await c.compileTypstSvg('c');
    expect(FakeWorker.instances).toHaveLength(2);
    const second = FakeWorker.instances[1]!;
    expect(ops(second)).toEqual(['setFonts', 'setShadow', 'svg']);
    expect(second.posted[0]).toMatchObject({ op: 'setFonts', fonts: [bytes(7)] });
  });

  // The worker keeps the instantiated wasm, the 17 default faces and a copy
  // of every workspace image alive for the life of the page. Closing the
  // Report tab schedules its release; reopening within the window cancels it,
  // because a tab switch must not re-pay wasm instantiation.
  it('releases an idle worker after the delay and starts a fresh one on the next compile', async () => {
    vi.useFakeTimers();
    try {
      const c = await loadClient();
      c.setTypstFonts([bytes(9)]);
      await c.compileTypstSvg('a');
      const first = FakeWorker.instances[0]!;

      c.scheduleTypstRelease();
      c.scheduleTypstRelease(); // scheduling twice keeps one timer
      expect(vi.getTimerCount()).toBe(1);
      expect(first.terminated).toBe(0);

      await vi.advanceTimersByTimeAsync(5 * 60_000);
      expect(first.terminated).toBe(1);
      expect(vi.getTimerCount()).toBe(0);

      await c.compileTypstSvg('b');
      expect(FakeWorker.instances).toHaveLength(2);
      // The replacement holds nothing, so fonts and shadow files are pushed
      // again before the compile that needs them.
      expect(ops(FakeWorker.instances[1]!)).toEqual(['setFonts', 'setShadow', 'svg']);
    } finally {
      vi.useRealTimers();
    }
  });

  it('keeps the worker when the release is cancelled before it fires', async () => {
    vi.useFakeTimers();
    try {
      const c = await loadClient();
      await c.compileTypstSvg('a');
      const first = FakeWorker.instances[0]!;

      c.scheduleTypstRelease();
      c.cancelTypstRelease();
      await vi.advanceTimersByTimeAsync(10 * 60_000);

      expect(first.terminated).toBe(0);
      expect(vi.getTimerCount()).toBe(0);
      await c.compileTypstSvg('b');
      expect(FakeWorker.instances).toHaveLength(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('rejects a compile that was in flight when the compiler was released', async () => {
    const c = await loadClient();
    FakeWorker.handler = () => new Promise(() => {});
    const hung = c.compileTypstSvg('a');
    await vi.waitFor(() => {
      expect(FakeWorker.instances[0]?.posted.some((p) => p.op === 'svg')).toBe(true);
    });
    c.releaseTypstCompiler();
    await expect(hung).rejects.toThrow(/released/);
    expect(FakeWorker.instances[0]!.terminated).toBe(1);
  });

  it('reads font info through the worker', async () => {
    const c = await loadClient();
    FakeWorker.handler = (cmd) => (cmd.op === 'fontInfo' ? { family: 'Poppins' } : undefined);
    expect(await c.getFontInfo(bytes(3))).toEqual({ family: 'Poppins' });
  });

  it('retries the inline compiler load after a failure', async () => {
    // No Worker: falls back to the inline transport, which runs the driver
    // directly on the main thread.
    vi.stubGlobal('Worker', undefined);
    let attempt = 0;
    const opsSeen: string[] = [];
    // Scoped to this test only: unmocked in `finally` so the other tests keep
    // using the real driver module untouched.
    vi.doMock('@/lib/typst-compiler.driver', () => ({
      createTypstDriver: () => {
        attempt++;
        // First load fails (e.g. the wasm was unreachable); this must not be
        // cached, so the next call gets a fresh attempt instead of the same
        // stale rejection forever.
        if (attempt === 1) throw new Error('wasm unreachable');
        return { svg: async () => ({ svg: '<svg/>', diagnostics: [] }) };
      },
      dispatch: (driver: { svg: () => unknown }, cmd: DriverCommand) => {
        opsSeen.push(cmd.op);
        return cmd.op === 'svg' ? driver.svg() : undefined;
      },
    }));
    try {
      const c = await loadClient();
      c.setTypstFonts([bytes(1)]);
      await expect(c.compileTypstSvg('a')).rejects.toThrow('wasm unreachable');
      await expect(c.compileTypstSvg('b')).resolves.toEqual({ svg: '<svg/>', diagnostics: [] });
      // The replacement driver started empty: fonts and shadow files are
      // re-sent to it before the retried compile runs.
      expect(opsSeen).toEqual(['setFonts', 'setShadow', 'svg']);
    } finally {
      vi.doUnmock('@/lib/typst-compiler.driver');
    }
  });
});
