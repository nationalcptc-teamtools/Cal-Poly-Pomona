import { describe, it, expect, vi, afterEach } from 'vitest';
import { computeNextRun, createJob } from '../../server/scheduler.mjs';

describe('computeNextRun', () => {
  it('waits one interval when the job has never run', () => {
    expect(computeNextRun(null, 60_000, 1_000_000)).toBe(1_060_000);
  });

  it('fires immediately when overdue (e.g. after a restart)', () => {
    expect(computeNextRun(900_000, 60_000, 1_000_000)).toBe(1_000_000);
  });

  it('anchors to the last run otherwise', () => {
    expect(computeNextRun(990_000, 60_000, 1_000_000)).toBe(1_050_000);
  });

  it('retries a failed run sooner, never later than the interval', () => {
    expect(computeNextRun(990_000, 60_000, 1_000_000, { failed: true, retryMs: 20_000 })).toBe(1_010_000);
    expect(computeNextRun(990_000, 60_000, 1_000_000, { failed: true, retryMs: 600_000 })).toBe(1_050_000);
    expect(computeNextRun(990_000, 60_000, 1_000_000, { failed: false, retryMs: 20_000 })).toBe(1_050_000);
  });
});

describe('createJob', () => {
  afterEach(() => { vi.useRealTimers(); });

  function setup(opts: Partial<Parameters<typeof createJob>[0]> = {}) {
    vi.useFakeTimers();
    vi.setSystemTime(1_000_000);
    const runs: number[] = [];
    const job = createJob({
      name: 'test',
      intervalMs: () => 1000,
      enabled: () => true,
      run: async () => { runs.push(Date.now()); },
      ...opts,
    });
    return { job, runs };
  }

  it('runs on schedule and records success', async () => {
    const { job, runs } = setup();
    job.start();
    expect(job.status().nextRunAt).toBe(1_001_000);
    await vi.advanceTimersByTimeAsync(1000);
    expect(runs).toEqual([1_001_000]);
    const s = job.status();
    expect(s.lastRunAt).toBe(1_001_000);
    expect(s.lastSuccessAt).toBe(1_001_000);
    expect(s.lastError).toBeNull();
    expect(s.nextRunAt).toBe(1_002_000);
    job.stop();
  });

  it('never overlaps: a trigger while running is reported, not queued', async () => {
    let release: () => void = () => {};
    const { job } = setup({
      run: () => new Promise<void>((resolve) => { release = resolve; }),
    });
    const first = job.trigger('manual');
    const second = await job.trigger('manual');
    expect(second).toEqual({ ran: false, reason: 'already-running' });
    expect(job.status().running).toBe(true);
    release();
    expect(await first).toMatchObject({ ran: true, error: null });
    expect(job.status().running).toBe(false);
  });

  it('records a failure and keeps scheduling', async () => {
    const { job } = setup({ run: async () => { throw new Error('disk full'); } });
    job.start();
    await vi.advanceTimersByTimeAsync(1000);
    const s = job.status();
    expect(s.lastError).toBe('disk full');
    expect(s.lastSuccessAt).toBeNull();
    expect(s.nextRunAt).toBe(1_002_000);
    job.stop();
  });

  it('retries after retryMs when the last run failed, then goes back to the interval', async () => {
    let fail = true;
    const { job } = setup({
      intervalMs: () => 10_000,
      retryMs: () => 2000,
      run: async () => { if (fail) throw new Error('no space'); },
    });
    job.start();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(job.status().lastError).toBe('no space');
    expect(job.status().nextRunAt).toBe(1_012_000);
    fail = false;
    await vi.advanceTimersByTimeAsync(2000);
    expect(job.status().lastError).toBeNull();
    expect(job.status().nextRunAt).toBe(1_022_000);
    job.stop();
  });

  it('reports when the current run started', async () => {
    let release: () => void = () => {};
    const { job } = setup({ run: () => new Promise<void>((resolve) => { release = resolve; }) });
    expect(job.status().runningSince).toBeNull();
    const p = job.trigger('manual');
    expect(job.status().runningSince).toBe(1_000_000);
    release();
    await p;
    expect(job.status().runningSince).toBeNull();
  });

  it('stays idle while disabled but still honours a manual trigger', async () => {
    const { job, runs } = setup({ enabled: () => false });
    job.start();
    expect(job.status().nextRunAt).toBeNull();
    await vi.advanceTimersByTimeAsync(5000);
    expect(runs).toEqual([]);
    expect(await job.trigger('manual')).toEqual({ ran: true, error: null, result: undefined });
    expect(runs.length).toBe(1);
    job.stop();
  });

  it('hands the run its own outcome, so a caller never reads it back from storage', async () => {
    const ok = setup({ run: async () => ({ name: 'b1', ok: true }) });
    expect(await ok.job.trigger('manual')).toEqual({ ran: true, error: null, result: { name: 'b1', ok: true } });
    const bad = setup({ run: async () => { throw new Error('database or disk is full'); } });
    const r = await bad.job.trigger('manual');
    expect(r).toEqual({ ran: true, error: 'database or disk is full', result: undefined });
    expect(bad.job.status().lastError).toBe('database or disk is full');
  });

  it('resumes from a persisted last run so an overdue job fires right away', async () => {
    const { job, runs } = setup({ initialLastRunAt: 990_000 });
    job.start();
    expect(job.status().nextRunAt).toBe(1_000_000);
    await vi.advanceTimersByTimeAsync(0);
    expect(runs.length).toBe(1);
    job.stop();
  });

  it('reschedules when the interval changes', () => {
    let interval = 1000;
    const { job } = setup({ intervalMs: () => interval });
    job.start();
    interval = 5000;
    job.reschedule();
    expect(job.status().nextRunAt).toBe(1_005_000);
    job.stop();
  });
});
