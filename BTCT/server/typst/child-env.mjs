// The environment every child process of an export gets.
//
// Its own module because both spawners need it and they must not import each
// other: export.mjs already imports stage.mjs, and stage.mjs spawns the bake
// worker.

/**
 * PATH and nothing else a child does not need to start.
 *
 * The server's own environment holds AUTH_SECRET and the cmdlog and backup
 * tokens, and neither CLI (nor the bake worker, which reads one image and
 * writes another) has any business reading them.
 */
export function childEnv() {
  const env = { PATH: process.env.PATH ?? '' };
  if (process.platform === 'win32') {
    // Windows binaries fail to start without these: SystemRoot resolves the
    // system DLLs, TEMP/TMP is where both CLIs write their scratch files.
    for (const key of ['SystemRoot', 'windir', 'TEMP', 'TMP', 'PATHEXT']) {
      if (process.env[key]) env[key] = process.env[key];
    }
  }
  return env;
}
