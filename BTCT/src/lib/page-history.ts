// ─────────────────────────────────────────────────────────────────────────
// Pure helpers for the version-history tab (no DOM, no network). The API
// client lives in src/realtime/page-history-api.ts and the viewer in
// src/components/history/HistoryView.tsx; this file is what the unit tests
// exercise.
// ─────────────────────────────────────────────────────────────────────────
import type { PageVersion } from '@/types';

export interface VersionDayGroup {
  /** Local calendar day, `YYYY-MM-DD`. */
  dayKey: string;
  /** "Today", "Yesterday", or a long date. */
  label: string;
  /** Newest first, as received. */
  versions: PageVersion[];
}

function pad(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

export function dayKeyOf(ts: number): string {
  const d = new Date(ts);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

export function dayLabel(ts: number, now: number = Date.now()): string {
  const key = dayKeyOf(ts);
  if (key === dayKeyOf(now)) return 'Today';
  // Calendar arithmetic, not "now minus 24 h": the day after a 23-hour DST
  // day, the first hour of the morning would otherwise skip yesterday.
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  if (key === dayKeyOf(yesterday.getTime())) return 'Yesterday';
  const d = new Date(ts);
  const sameYear = d.getFullYear() === new Date(now).getFullYear();
  return d.toLocaleDateString(undefined, {
    weekday: 'long',
    month: 'long',
    day: 'numeric',
    ...(sameYear ? {} : { year: 'numeric' }),
  });
}

/** Google Docs groups the timeline by day; entries inside keep their order. */
export function groupVersionsByDay(versions: PageVersion[], now: number = Date.now()): VersionDayGroup[] {
  const groups: VersionDayGroup[] = [];
  for (const v of versions) {
    const dayKey = dayKeyOf(v.createdAt);
    const last = groups[groups.length - 1];
    if (last && last.dayKey === dayKey) last.versions.push(v);
    else groups.push({ dayKey, label: dayLabel(v.createdAt, now), versions: [v] });
  }
  return groups;
}

export function versionLabel(v: PageVersion): string {
  if (v.name) return v.name;
  switch (v.trigger) {
    case 'restore': return 'Restored version';
    case 'import': return 'Imported version';
    case 'named': return 'Named version';
    default: return 'Auto-saved';
  }
}

export function formatVersionTime(ts: number): string {
  return new Date(ts).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

export interface VersionFilter {
  namedOnly?: boolean;
  /** Keep versions this account changed or created. */
  userId?: number | null;
}

export function filterVersions(versions: PageVersion[], filter: VersionFilter): PageVersion[] {
  return versions.filter((v) => {
    if (filter.namedOnly && !v.name) return false;
    if (filter.userId != null && !(v.changedBy.includes(filter.userId) || v.createdBy === filter.userId)) return false;
    return true;
  });
}

/** The nearest older version that can be diffed against (imports cannot). */
export function previousDiffable(versions: PageVersion[], current: PageVersion): PageVersion | null {
  const idx = versions.findIndex((v) => v.id === current.id);
  if (idx === -1) return null;
  for (let i = idx + 1; i < versions.length; i++) {
    const candidate = versions[i];
    if (candidate?.diffable) return candidate;
  }
  return null;
}
