// ─────────────────────────────────────────────────────────────────────────
// Environment fix-ups that must run before any module loads y-websocket.
// server/index.mjs imports this first; ES modules evaluate their imports in
// order, so y-websocket (pulled in by yjs-data.mjs, data-export.mjs,
// history.mjs and index.mjs) reads the corrected environment.
//
// y-websocket opens LevelDB whenever YPERSISTENCE is a string, so an empty
// value (`YPERSISTENCE=` in an env file) opened LevelDB at '' and the
// process exited 1 at boot. Treat it as unset, the way restore.mjs does.
// ─────────────────────────────────────────────────────────────────────────

if (typeof process.env.YPERSISTENCE === 'string' && process.env.YPERSISTENCE.trim() === '') {
  delete process.env.YPERSISTENCE;
  console.warn('[btct-server] YPERSISTENCE is set but empty; treating it as unset');
}
if (!process.env.YPERSISTENCE) {
  console.warn('[btct-server] YPERSISTENCE is not set: Yjs rooms are memory-only and are lost when the server stops (the Docker image sets /data/yjs)');
}
