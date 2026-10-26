// ─────────────────────────────────────────────────────────────────────────
// Data retention: prune old page-version history and images.
//
// Admin-configurable and OFF by default (`retention_days = 0` = keep forever),
// so nothing is ever deleted until an admin opts in. When set to N days:
//   • page_versions older than N days are deleted;
//   • assets that were RETIRED (soft-deleted: removed from a note, so their
//     shared record carries `deletedAt`) more than N days ago have their bytes,
//     their SQLite row and their shared record permanently removed.
// Retiring instead of hard-deleting on note-image removal is what lets the
// history keep showing an image for the retention window.
//
// The job runs on boot and daily, and its last run is persisted in settings,
// so a box that was off past the deadline prunes right after it comes back up
// (createJob's `initialLastRunAt`, same pattern as backups).
// ─────────────────────────────────────────────────────────────────────────

import fs from 'node:fs';
import path from 'node:path';
import {
  getSetting, setSetting,
  countPageVersionsBefore, deletePageVersionsBefore, deletePageVersionsInRange,
  deleteAssetRow,
} from './db.mjs';
import { collectRetiredAssets, removeAssetRecords } from './yjs-data.mjs';
import { ASSETS_DIR } from './assets.mjs';
import { createJob } from './scheduler.mjs';
import { ENTRY_ID_RE } from './backup-format.mjs';

const DAY_MS = 24 * 60 * 60 * 1000;
const CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000; // re-check four times a day

function clampDays(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.min(Math.floor(n), 3650); // 0 = off, cap at ~10 years
}

/** Admin retention config. `days === 0` means retention is off. */
export function getRetentionConfig() {
  return {
    days: clampDays(getSetting('retention_days') || 0),
    lastRunAt: Number(getSetting('retention_last_run') || 0) || null,
    lastPruned: (() => {
      try { return JSON.parse(getSetting('retention_last_pruned') || 'null'); } catch { return null; }
    })(),
  };
}

let reschedule = () => {};

export function setRetentionConfig(patch) {
  if (patch && patch.days !== undefined) {
    setSetting('retention_days', String(clampDays(patch.days)));
    reschedule();
  }
  return getRetentionConfig();
}

/** Prune everything past the retention window. Returns what it removed. */
export async function pruneNow() {
  const days = clampDays(getSetting('retention_days') || 0);
  if (days <= 0) return { ran: false, days: 0, versions: 0, assets: 0 };
  const cutoff = Date.now() - days * DAY_MS;

  const versions = deletePageVersionsBefore(cutoff);

  // Retired assets: delete bytes, SQLite row, then the shared record.
  let assets = 0;
  try {
    const ids = await collectRetiredAssets(cutoff);
    const dir = path.resolve(ASSETS_DIR);
    for (const id of ids) {
      // Ids are raw client-written map keys: only a well-formed id that
      // resolves directly under ASSETS_DIR may become a path. A junk key
      // still has its shared record removed so it is not re-collected.
      const p = path.resolve(dir, String(id));
      if (!ENTRY_ID_RE.test(String(id)) || path.dirname(p) !== dir) continue;
      try { fs.unlinkSync(p); } catch { /* already gone */ }
      try { deleteAssetRow(id); } catch { /* already gone */ }
      assets++;
    }
    await removeAssetRecords(ids);
  } catch (e) {
    console.warn('[retention] asset prune failed:', e?.message || e);
  }

  const result = { ran: true, days, versions, assets, at: Date.now() };
  setSetting('retention_last_pruned', JSON.stringify(result));
  return result;
}

/** Explicitly delete edit history in a date range (admin button). */
export function pruneHistoryRange(afterMs, beforeMs) {
  const a = Number(afterMs) || 0;
  const b = Number(beforeMs) || Date.now();
  if (b < a) return { deleted: 0 };
  return { deleted: deletePageVersionsInRange(a, b) };
}

/** How many versions would today's prune remove (for the admin preview). */
export function retentionStatus() {
  const cfg = getRetentionConfig();
  const dueCount = cfg.days > 0 ? countPageVersionsBefore(Date.now() - cfg.days * DAY_MS) : 0;
  return { ...cfg, dueVersionCount: dueCount };
}

export function startRetentionScheduler() {
  const job = createJob({
    name: 'retention',
    intervalMs: () => CHECK_INTERVAL_MS,
    enabled: () => clampDays(getSetting('retention_days') || 0) > 0,
    initialLastRunAt: Number(getSetting('retention_last_run') || 0) || null,
    run: async () => { await pruneNow(); },
    onStatus: (s) => { if (s.lastRunAt) setSetting('retention_last_run', String(s.lastRunAt)); },
    log: (m) => console.warn('[retention]', m),
  });
  reschedule = () => job.reschedule();
  job.start();
  return job;
}
