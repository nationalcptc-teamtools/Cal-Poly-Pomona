// One child process for the report export: an argument array, never a shell
// string (a caption or a filename from the shared doc must never be parsed by
// a shell), the minimal environment from child-env.mjs, an optional time cap,
// and an optional AbortSignal that kills the child when the caller has gone.
//
// The kill on abort matters once the converter has no cap: an export whose
// browser disconnected would otherwise keep a core busy for minutes and hold
// the one-running, one-waiting export queue for nobody.
//
// Both kills take the whole process tree. On Windows a virtualenv's
// python.exe is a launcher that starts the real interpreter as its own child,
// so killing only the direct child left the converter running (measured: the
// launcher died, the interpreter kept converting). There `taskkill /T` ends
// the tree; elsewhere the child leads its own process group and the group is
// killed.
import { execFile } from 'node:child_process';
import path from 'node:path';
import { childEnv } from './child-env.mjs';

const MAX_BUFFER = 16 * 1024 * 1024;
const WINDOWS = process.platform === 'win32';

function killTree(child) {
  if (child.exitCode !== null || child.signalCode !== null || !child.pid) return;
  if (WINDOWS) {
    execFile('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true }, () => {});
    return;
  }
  try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch { /* already gone */ } }
}

export function runChild(cli, args, cwd, { timeoutMs = 0, signal = null } = {}) {
  return new Promise((resolve) => {
    if (signal?.aborted) {
      resolve({ code: 130, killed: false, aborted: true, signal: null, stderr: '' });
      return;
    }
    let aborted = false;
    let timedOut = false;
    let timer = null;
    const child = execFile(cli, args, {
      cwd, env: childEnv(), windowsHide: true, maxBuffer: MAX_BUFFER, detached: !WINDOWS,
    }, (err, _stdout, stderr) => {
      if (timer) clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      if (aborted) {
        return resolve({ code: 130, killed: false, aborted: true, signal: err?.signal ?? null, stderr: '' });
      }
      if (timedOut) {
        return resolve({ code: 124, killed: true, aborted: false, signal: err?.signal ?? 'SIGKILL', stderr: `error: ${path.basename(cli)} timed out after ${timeoutMs / 1000} s` });
      }
      // The binary was on PATH when the capabilities cache was filled and is
      // gone now. That is not something the report did, so it is a 501 like
      // any other missing CLI, not a 422 with an empty message.
      if (err && err.code === 'ENOENT') return resolve({ code: 'ENOENT', killed: false, aborted: false, signal: null, stderr: '' });
      // A signal we did not send is a death we did not cause, and its stderr
      // is the only clue to why, so it is never thrown away.
      resolve({
        code: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
        killed: false,
        aborted: false,
        signal: err?.signal ?? null,
        stderr: String(stderr ?? ''),
      });
    });
    function onAbort() {
      aborted = true;
      killTree(child);
    }
    if (timeoutMs > 0) {
      timer = setTimeout(() => { timedOut = true; killTree(child); }, timeoutMs);
    }
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}
