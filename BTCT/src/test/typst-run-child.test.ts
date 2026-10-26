import { describe, it, expect } from 'vitest';
import { convertLimit } from '../../server/typst/convert-limit.mjs';
import { runChild } from '../../server/typst/run-child.mjs';

// The Word converter used to be killed at 120 s, which failed any report long
// enough to need more. It now runs without a cap unless the operator sets
// DOCX_CONVERT_TIMEOUT_S, and a child whose caller has gone is killed so an
// abandoned export does not hold the queue.

describe('convertLimit', () => {
  it('has no cap and no budget when the variable is unset, empty or 0', () => {
    for (const value of [undefined, '', '0', ' 0 ']) {
      expect(convertLimit(value)).toEqual({ timeoutMs: 0, budgetSeconds: null });
    }
  });

  it('turns a positive number of seconds into a cap and a budget 15 s under it', () => {
    expect(convertLimit('120')).toEqual({ timeoutMs: 120_000, budgetSeconds: 105 });
    expect(convertLimit('900')).toEqual({ timeoutMs: 900_000, budgetSeconds: 885 });
  });

  it('never hands the converter a budget below one second', () => {
    expect(convertLimit('10')).toEqual({ timeoutMs: 10_000, budgetSeconds: 1 });
  });

  it('treats anything that is not a positive number as no cap', () => {
    for (const value of ['-5', 'abc', 'NaN', 'Infinity', '1e999']) {
      expect(convertLimit(value)).toEqual({ timeoutMs: 0, budgetSeconds: null });
    }
  });
});

describe('runChild', () => {
  const sleeper = ['-e', 'setTimeout(() => {}, 30000)'];

  it('kills the child when the signal aborts, and says so', async () => {
    const controller = new AbortController();
    const started = Date.now();
    const pending = runChild(process.execPath, sleeper, process.cwd(), { timeoutMs: 0, signal: controller.signal });
    setTimeout(() => controller.abort(), 200);
    const result = await pending;
    expect(result.aborted).toBe(true);
    expect(result.killed).toBe(false);
    expect(Date.now() - started).toBeLessThan(10_000);
  });

  it('does not start the child when the signal has already aborted', async () => {
    const controller = new AbortController();
    controller.abort();
    const result = await runChild(process.execPath, sleeper, process.cwd(), { timeoutMs: 0, signal: controller.signal });
    expect(result.aborted).toBe(true);
  });

  it('still enforces a cap when one is given', async () => {
    const result = await runChild(process.execPath, sleeper, process.cwd(), { timeoutMs: 300 });
    expect(result.killed).toBe(true);
    expect(result.aborted).toBe(false);
    expect(result.stderr).toMatch(/timed out after 0.3 s/);
  });

  // The venv's python.exe on Windows is a launcher that starts the real
  // interpreter as its own child, so killing only the direct child left the
  // converter running. The whole tree must go.
  it('kills grandchildren too, on abort and on timeout', async () => {
    const fs = await import('node:fs');
    const os = await import('node:os');
    const path = await import('node:path');
    const pidFile = path.join(os.tmpdir(), `btct-grandchild-${process.pid}-${Date.now()}.txt`);
    const parent = [
      '-e',
      `const { spawn } = require('node:child_process');
       const g = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 30000)'], { stdio: 'ignore' });
       require('node:fs').writeFileSync(${JSON.stringify(pidFile)}, String(g.pid));
       setTimeout(() => {}, 30000);`,
    ];
    const alive = (pid: number) => { try { process.kill(pid, 0); return true; } catch { return false; } };
    const waitForPid = async () => {
      for (let i = 0; i < 100; i += 1) {
        if (fs.existsSync(pidFile)) return Number(fs.readFileSync(pidFile, 'utf8'));
        await new Promise((r) => setTimeout(r, 50));
      }
      throw new Error('grandchild never started');
    };
    const settle = async (pid: number) => {
      for (let i = 0; i < 40 && alive(pid); i += 1) await new Promise((r) => setTimeout(r, 100));
    };

    const controller = new AbortController();
    const aborted = runChild(process.execPath, parent, process.cwd(), { timeoutMs: 0, signal: controller.signal });
    const first = await waitForPid();
    controller.abort();
    expect((await aborted).aborted).toBe(true);
    await settle(first);
    expect(alive(first)).toBe(false);

    fs.rmSync(pidFile, { force: true });
    const capped = runChild(process.execPath, parent, process.cwd(), { timeoutMs: 1500 });
    const second = await waitForPid();
    expect((await capped).killed).toBe(true);
    await settle(second);
    expect(alive(second)).toBe(false);
    fs.rmSync(pidFile, { force: true });
  }, 20_000);

  // The real case: the repo's Windows virtualenv launcher starting the real
  // interpreter. Skipped where that venv is absent (CI, the Docker image,
  // where the venv's python is a symlink and a single process).
  const venvPython = (() => {
    const p = `${process.cwd()}\\.venv-pdf2docx\\Scripts\\python.exe`;
    try { return process.platform === 'win32' && require('node:fs').existsSync(p) ? p : null; } catch { return null; }
  })();
  it.skipIf(!venvPython)('kills the interpreter a venv launcher started, on abort', async () => {
    const fs = await import('node:fs');
    const os = await import('node:os');
    const path = await import('node:path');
    const pidFile = path.join(os.tmpdir(), `btct-venv-${process.pid}-${Date.now()}.txt`);
    const code = `import os, time; open(${JSON.stringify(pidFile)}, 'w').write(str(os.getpid())); time.sleep(30)`;
    const controller = new AbortController();
    const pending = runChild(venvPython as string, ['-I', '-B', '-c', code], process.cwd(), { timeoutMs: 0, signal: controller.signal });
    let pid = 0;
    for (let i = 0; i < 200 && !pid; i += 1) {
      if (fs.existsSync(pidFile)) pid = Number(fs.readFileSync(pidFile, 'utf8')) || 0;
      else await new Promise((r) => setTimeout(r, 50));
    }
    expect(pid).toBeGreaterThan(0);
    controller.abort();
    expect((await pending).aborted).toBe(true);
    const alive = () => { try { process.kill(pid, 0); return true; } catch { return false; } };
    for (let i = 0; i < 50 && alive(); i += 1) await new Promise((r) => setTimeout(r, 100));
    expect(alive()).toBe(false);
    fs.rmSync(pidFile, { force: true });
  }, 30_000);

  it('runs to completion with no cap and reports the exit code', async () => {
    const result = await runChild(process.execPath, ['-e', 'process.exit(3)'], process.cwd(), { timeoutMs: 0 });
    expect(result).toMatchObject({ code: 3, killed: false, aborted: false });
  });
});
