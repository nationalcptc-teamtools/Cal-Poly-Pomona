/**
 * Pure filter + export helpers for the Command Log view. Kept DOM/Yjs-free so
 * the predicate is directly unit-testable (see src/test/cmdlog-filter.test.ts),
 * matching the repo's pure-module-plus-test convention (crop-math, pane-resize).
 */
import type { CommandLogEntry } from '@/types';

export type CmdLogStatus = 'all' | 'success' | 'failed' | 'running';

export interface CmdLogFilter {
  operators: Set<string>;   // empty = all operators
  tools: Set<string>;       // empty = all tools
  host: string;             // 'all' sentinel = any host
  from: number | null;      // epoch ms, inclusive
  to: number | null;        // epoch ms, inclusive
  query: string;            // case-insensitive substring over the command text
  status: CmdLogStatus;
}

export function emptyFilter(): CmdLogFilter {
  return { operators: new Set(), tools: new Set(), host: 'all', from: null, to: null, query: '', status: 'all' };
}

/** True if `row` matches every active constraint in `f`. */
export function matchesFilter(row: CommandLogEntry, f: CmdLogFilter): boolean {
  if (f.operators.size && !f.operators.has(row.operator)) return false;
  if (f.tools.size && !f.tools.has(row.tool)) return false;
  if (f.host !== 'all' && (row.host ?? '') !== f.host) return false;
  if (f.from !== null && row.startedAt < f.from) return false;
  if (f.to !== null && row.startedAt > f.to) return false;
  if (f.status !== 'all' && statusOf(row) !== f.status) return false;
  if (f.query) {
    const q = f.query.toLowerCase();
    if (!row.command.toLowerCase().includes(q)) return false;
  }
  return true;
}

/** Filter then sort newest-first. */
export function applyCmdLogFilter(rows: CommandLogEntry[], f: CmdLogFilter): CommandLogEntry[] {
  return rows.filter((r) => matchesFilter(r, f)).sort((a, b) => b.startedAt - a.startedAt);
}

/** A command with no exit code yet is still running; 0 is success, else failed. */
export function statusOf(row: CommandLogEntry): Exclude<CmdLogStatus, 'all'> {
  if (row.exitCode === null || row.exitCode === undefined) return 'running';
  return row.exitCode === 0 ? 'success' : 'failed';
}

/** Distinct, sorted operator names present in the set (for the filter chips). */
export function distinctOperators(rows: CommandLogEntry[]): string[] {
  return [...new Set(rows.map((r) => r.operator))].sort((a, b) => a.localeCompare(b));
}

/** Distinct, sorted tool names present in the set. */
export function distinctTools(rows: CommandLogEntry[]): string[] {
  return [...new Set(rows.map((r) => r.tool))].sort((a, b) => a.localeCompare(b));
}

/** Distinct, sorted non-empty host names present in the set. */
export function distinctHosts(rows: CommandLogEntry[]): string[] {
  return [...new Set(rows.map((r) => r.host).filter((h): h is string => !!h))].sort((a, b) => a.localeCompare(b));
}

const CSV_COLS: Array<[string, (r: CommandLogEntry) => unknown]> = [
  ['startedAt', (r) => new Date(r.startedAt).toISOString()],
  ['operator', (r) => r.operator],
  ['host', (r) => r.host ?? ''],
  ['tool', (r) => r.tool],
  ['command', (r) => r.command],
  ['cwd', (r) => r.cwd ?? ''],
  ['exitCode', (r) => (r.exitCode ?? '')],
  ['durationMs', (r) => (r.durationMs ?? '')],
];

/**
 * One CSV cell. A text cell that starts with `=`, `+`, `-`, `@`, a tab or a
 * carriage return is a formula to Excel and LibreOffice, and quoting does not
 * stop that, so it gets a leading apostrophe (OWASP's CSV injection advice).
 * Numbers stay numbers: a negative exit code is not a formula.
 */
export function csvCell(v: unknown): string {
  let s = String(v ?? '');
  if (typeof v === 'string' && /^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Report-ready CSV of the given (already-filtered) rows. */
export function toCsv(rows: CommandLogEntry[]): string {
  const header = CSV_COLS.map(([h]) => h).join(',');
  const lines = rows.map((r) => CSV_COLS.map(([, get]) => csvCell(get(r))).join(','));
  return [header, ...lines].join('\n') + '\n';
}
