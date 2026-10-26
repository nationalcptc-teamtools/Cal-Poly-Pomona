import { describe, it, expect } from 'vitest';
import type { CommandLogEntry } from '@/types';
import {
  emptyFilter, matchesFilter, applyCmdLogFilter, statusOf,
  distinctOperators, distinctTools, distinctHosts, toCsv, csvCell,
} from '@/lib/cmdlog-filter';

function row(over: Partial<CommandLogEntry>): CommandLogEntry {
  return {
    id: over.id ?? Math.random().toString(36).slice(2),
    workspaceId: 'ws1',
    operator: over.operator ?? 'rob',
    command: over.command ?? 'nmap -sV 10.0.0.5',
    tool: over.tool ?? 'nmap',
    cwd: over.cwd ?? '/root',
    host: over.host ?? 'kali-rob',
    localUser: 'root',
    shellPid: 1234,
    startedAt: over.startedAt ?? 1000,
    receivedAt: over.receivedAt ?? 1000,
    exitCode: over.exitCode === undefined ? 0 : over.exitCode,
    durationMs: over.durationMs ?? 500,
    redacted: true,
    ...over,
  };
}

describe('statusOf', () => {
  it('classifies running / success / failed', () => {
    expect(statusOf(row({ exitCode: null }))).toBe('running');
    expect(statusOf(row({ exitCode: 0 }))).toBe('success');
    expect(statusOf(row({ exitCode: 1 }))).toBe('failed');
  });
  it('treats a missing exit code as running', () => {
    const r = row({}); delete (r as { exitCode?: number | null }).exitCode;
    expect(statusOf(r)).toBe('running');
  });
});

describe('matchesFilter', () => {
  const base = row({ operator: 'alice', tool: 'hydra', host: 'kali-a', startedAt: 5000, command: 'hydra -l admin ssh://x', exitCode: 1 });

  it('empty filter matches everything', () => {
    expect(matchesFilter(base, emptyFilter())).toBe(true);
  });
  it('operator set filters by membership', () => {
    expect(matchesFilter(base, { ...emptyFilter(), operators: new Set(['alice']) })).toBe(true);
    expect(matchesFilter(base, { ...emptyFilter(), operators: new Set(['rob']) })).toBe(false);
  });
  it('tool set filters by membership', () => {
    expect(matchesFilter(base, { ...emptyFilter(), tools: new Set(['nmap']) })).toBe(false);
    expect(matchesFilter(base, { ...emptyFilter(), tools: new Set(['hydra']) })).toBe(true);
  });
  it('host sentinel vs exact', () => {
    expect(matchesFilter(base, { ...emptyFilter(), host: 'all' })).toBe(true);
    expect(matchesFilter(base, { ...emptyFilter(), host: 'kali-a' })).toBe(true);
    expect(matchesFilter(base, { ...emptyFilter(), host: 'kali-b' })).toBe(false);
  });
  it('time bounds are inclusive', () => {
    expect(matchesFilter(base, { ...emptyFilter(), from: 5000, to: 5000 })).toBe(true);
    expect(matchesFilter(base, { ...emptyFilter(), from: 5001 })).toBe(false);
    expect(matchesFilter(base, { ...emptyFilter(), to: 4999 })).toBe(false);
  });
  it('query is a case-insensitive substring of the command', () => {
    expect(matchesFilter(base, { ...emptyFilter(), query: 'ADMIN' })).toBe(true);
    expect(matchesFilter(base, { ...emptyFilter(), query: 'gobuster' })).toBe(false);
  });
  it('status filters on exit code', () => {
    expect(matchesFilter(base, { ...emptyFilter(), status: 'failed' })).toBe(true);
    expect(matchesFilter(base, { ...emptyFilter(), status: 'success' })).toBe(false);
    expect(matchesFilter(row({ exitCode: null }), { ...emptyFilter(), status: 'running' })).toBe(true);
  });
});

describe('applyCmdLogFilter', () => {
  it('filters and sorts newest-first', () => {
    const rows = [row({ startedAt: 100 }), row({ startedAt: 300 }), row({ startedAt: 200 })];
    const out = applyCmdLogFilter(rows, emptyFilter());
    expect(out.map((r) => r.startedAt)).toEqual([300, 200, 100]);
  });
});

describe('distinct helpers', () => {
  const rows = [
    row({ operator: 'rob', tool: 'nmap', host: 'h1' }),
    row({ operator: 'alice', tool: 'nmap', host: 'h2' }),
    row({ operator: 'rob', tool: 'hydra', host: null }),
  ];
  it('operators/tools/hosts are distinct + sorted, hosts drop empties', () => {
    expect(distinctOperators(rows)).toEqual(['alice', 'rob']);
    expect(distinctTools(rows)).toEqual(['hydra', 'nmap']);
    expect(distinctHosts(rows)).toEqual(['h1', 'h2']);
  });
});

describe('toCsv', () => {
  it('emits a header and quotes cells with commas/quotes', () => {
    const csv = toCsv([row({ command: 'sh -c "a,b"', operator: 'rob', tool: 'sh', host: 'h', startedAt: 0, exitCode: 0, durationMs: 10 })]);
    const [header, line] = csv.split('\n');
    expect(header).toBe('startedAt,operator,host,tool,command,cwd,exitCode,durationMs');
    expect(line).toContain('"sh -c ""a,b"""');
  });
});

describe('csvCell formula guard', () => {
  it('prefixes text that a spreadsheet would run as a formula', () => {
    expect(csvCell('=HYPERLINK("http://x")')).toBe(`"'=HYPERLINK(""http://x"")"`);
    expect(csvCell('+cmd')).toBe("'+cmd");
    expect(csvCell('-rf')).toBe("'-rf");
    expect(csvCell('@SUM(A1)')).toBe("'@SUM(A1)");
    expect(csvCell('\tx')).toBe("'\tx");
    expect(csvCell('nmap -sV')).toBe('nmap -sV');
  });

  it('leaves numbers alone, negative ones included', () => {
    expect(csvCell(-1)).toBe('-1');
    expect(csvCell(0)).toBe('0');
  });

  it('ends the file with a newline so line counts match row counts', () => {
    expect(toCsv([]).endsWith('\n')).toBe(true);
  });
});
