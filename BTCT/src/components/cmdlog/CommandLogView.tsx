import { useEffect, useMemo, useRef, useState, useCallback, memo } from 'react';
import { useAppStore } from '@/stores';
import { Dialog } from '@/components/ui/Dialog';
import { Button, IconButton, ToggleChip } from '@/components/ui/Button';
import { FieldLabel, Input, Select } from '@/components/ui/Field';
import { Banner } from '@/components/ui/Banner';
import { useAuthStore } from '@/auth/auth-store';
import type { CommandLogEntry } from '@/types';
import { Terminal, Download, RefreshCw, Search, X, CircleDot, Plus } from 'lucide-react';
import { cn } from '@/lib/utils';
import { downloadAsZip } from '@/lib/download-zip';
import { countCommandLogArchive, fetchCommandLogArchive } from '@/export/cmdlog-io';
import {
  emptyFilter, applyCmdLogFilter, statusOf,
  distinctOperators, distinctTools, distinctHosts, toCsv,
  type CmdLogFilter, type CmdLogStatus,
} from '@/lib/cmdlog-filter';

const GRID = 'grid grid-cols-[136px_120px_96px_1fr_54px_72px] gap-2';

// Preset time windows for the "since" filter. `null` = all time.
const TIME_PRESETS: Array<[string, number | null]> = [
  ['All', null], ['1h', 3600_000], ['24h', 86_400_000], ['7d', 604_800_000],
];

// Deterministic hue from an operator name so each operator keeps one color
// across sessions (operators aren't BTCT users, so there's no stored color).
// Memoized: this ran twice per row per render over the whole (up to 5000-row)
// archive; the operator set is tiny, so cache the computed color by name.
const operatorColorCache = new Map<string, string>();
function operatorColor(name: string): string {
  const hit = operatorColorCache.get(name);
  if (hit) return hit;
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  const color = `hsl(${h % 360} 65% 55%)`;
  operatorColorCache.set(name, color);
  return color;
}

// Cap how many rows are put in the DOM at once. The count still reports the
// true total; "Search full archive" can return 5000 rows, and mounting all
// of them (6 cells + 2 icons each) is what made that button janky.
const MAX_RENDERED_ROWS = 400;

function fmtTime(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleString(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
function fmtDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return '';
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const m = Math.floor(ms / 60_000);
  const s = Math.round((ms % 60_000) / 1000);
  return `${m}m${s.toString().padStart(2, '0')}s`;
}

// Row caps of the two archive windows (the server clamps a query at 5000).
const RECENT_LIMIT = 1000;
const FULL_LIMIT = 5000;

// One log row. Memoized so a live-capture batch (which changes only a few
// rows) doesn't re-render the entire visible archive.
const LogRow = memo(function LogRow({ r }: { r: CommandLogEntry }) {
  const st = statusOf(r);
  const color = operatorColor(r.operator);
  return (
    <div
      style={{ borderLeft: `3px solid ${color}` }}
      className={cn(
        GRID,
        'items-start px-3 py-2 text-xs hover:bg-accent/30',
        st === 'failed' && 'bg-status-red/5',
      )}
    >
      <div className="font-mono text-caption text-muted-foreground" title={new Date(r.startedAt).toISOString()}>
        {fmtTime(r.startedAt)}
      </div>
      <div className="flex min-w-0 items-center gap-1.5">
        <CircleDot size={9} className="shrink-0" style={{ color }} />
        <span className="truncate" title={r.host ? `${r.operator} @ ${r.host}` : r.operator}>{r.operator}</span>
      </div>
      <div className="truncate font-mono text-meta text-status-green" title={r.tool}>{r.tool}</div>
      <div className="min-w-0 break-all font-mono text-meta" title={r.cwd ? `cwd: ${r.cwd}` : undefined}>
        {r.command}
      </div>
      <div className="text-center">
        {st === 'running' ? (
          <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-status-amber" title="Running…" />
        ) : (
          <span className={cn('font-mono text-meta', st === 'success' ? 'text-muted-foreground' : 'text-status-red')}>
            {r.exitCode}
          </span>
        )}
      </div>
      <div className="font-mono text-caption text-muted-foreground">{fmtDuration(r.durationMs)}</div>
    </div>
  );
});

export function CommandLogView() {
  const liveRows = useAppStore((s) => s.commandLogs);      // shared-doc live window
  const workspaceId = useAppStore((s) => s.activeWorkspaceId);
  const cmdlogQuery = useAuthStore((s) => s.cmdlogQuery);

  const [archive, setArchive] = useState<CommandLogEntry[]>([]);   // from REST
  const [loading, setLoading] = useState(true);
  const [archiveWindow, setArchiveWindow] = useState<'recent' | 'full'>('recent');
  // Set when the query returned as many rows as it asked for: the archive
  // then holds more than the view, and an export must not stop at the cap.
  const [capped, setCapped] = useState(false);
  const [archiveTotal, setArchiveTotal] = useState<number | null>(null);
  const [exportNote, setExportNote] = useState('');
  const [filter, setFilter] = useState<CmdLogFilter>(() => emptyFilter());
  const [since, setSince] = useState<number | null>(86_400_000);   // default: last 24h
  const [adding, setAdding] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  // Seed the archive from REST so history shows even on a cold shared doc.
  // `full` fetches everything; `recent` limits to the last 24h.
  const fetchArchive = useCallback(async (mode: 'recent' | 'full') => {
    if (!workspaceId) return;
    setLoading(true);
    try {
      const rows = await cmdlogQuery({
        workspaceId,
        from: mode === 'recent' ? Date.now() - 86_400_000 : undefined,
        limit: mode === 'full' ? FULL_LIMIT : RECENT_LIMIT,
      });
      setArchive(rows);
      setArchiveWindow(mode);
      const isCapped = rows.length >= (mode === 'full' ? FULL_LIMIT : RECENT_LIMIT);
      setCapped(isCapped);
      setArchiveTotal(null);
      if (isCapped) {
        countCommandLogArchive(workspaceId).then(setArchiveTotal).catch(() => setArchiveTotal(null));
      }
    } catch {
      setArchive([]);   // ingest disabled or offline: fall back to the live window only
      setCapped(false);
    } finally {
      setLoading(false);
    }
  }, [workspaceId, cmdlogQuery]);

  useEffect(() => { void fetchArchive('recent'); }, [fetchArchive]);

  // Merge REST archive with the live CRDT window, CRDT winning on id (it carries
  // the freshest exit/duration). Live rows also surface commands that arrived
  // after the last archive fetch without a re-query.
  const merged = useMemo(() => {
    const byId = new Map<string, CommandLogEntry>();
    for (const r of archive) byId.set(r.id, r);
    for (const r of liveRows) byId.set(r.id, r);
    return [...byId.values()];
  }, [archive, liveRows]);

  const operators = useMemo(() => distinctOperators(merged), [merged]);
  const tools = useMemo(() => distinctTools(merged), [merged]);
  const hosts = useMemo(() => distinctHosts(merged), [merged]);

  // A manually-added entry is written server-side to SQLite + CRDT; the CRDT
  // push refreshes liveRows on its own, but merge it into `archive` too so it
  // shows instantly regardless of the current archive window.
  const onManualAdded = useCallback((log: CommandLogEntry) => {
    setArchive((prev) => (prev.some((r) => r.id === log.id) ? prev : [log, ...prev]));
  }, []);

  // Advance the relative-time window on a coarse tick. Reading Date.now()
  // inside the memo froze the window at mount, so "last 24h" never moved;
  // recomputing it every render would instead rebuild `rows` constantly.
  // A 30s tick advances the boundary without per-render churn.
  const [nowTick, setNowTick] = useState(() => Date.now());
  useEffect(() => {
    if (since === null) return;
    const t = setInterval(() => setNowTick(Date.now()), 30_000);
    return () => clearInterval(t);
  }, [since]);

  const effectiveFilter = useMemo<CmdLogFilter>(
    () => ({ ...filter, from: since !== null ? nowTick - since : filter.from }),
    [filter, since, nowTick],
  );
  const rows = useMemo(() => applyCmdLogFilter(merged, effectiveFilter), [merged, effectiveFilter]);

  const toggleIn = (key: 'operators' | 'tools') => (value: string) => {
    setFilter((f) => {
      const next = new Set(f[key]);
      if (next.has(value)) next.delete(value); else next.add(value);
      return { ...f, [key]: next };
    });
  };
  const running = rows.filter((r) => statusOf(r) === 'running').length;

  // Export what the view shows, filters included. When the archive query hit
  // its cap the view is short, so fetch the whole archive (uncapped route)
  // and apply the same filters to it instead of exporting a silent subset.
  const exportRows = async (format: 'csv' | 'json') => {
    let data = rows;
    setExportNote('');
    if (capped && workspaceId) {
      try {
        setExportNote('Reading the whole archive…');
        const all = await fetchCommandLogArchive(workspaceId);
        const byId = new Map<string, CommandLogEntry>();
        for (const r of all) byId.set(r.id, r);
        for (const r of liveRows) byId.set(r.id, r);
        data = applyCmdLogFilter([...byId.values()], effectiveFilter);
        setExportNote('');
      } catch (e) {
        setExportNote(`Exported ${rows.length} loaded rows only: the full archive could not be read (${e instanceof Error ? e.message : String(e)}).`);
      }
    }
    // The file keeps its old name inside `command-log_<date>_csv.zip` (or `_json`).
    const stamp = Date.now();
    const file = format === 'csv'
      ? { name: `command-log-${stamp}.csv`, data: toCsv(data) }
      : { name: `command-log-${stamp}.json`, data: JSON.stringify(data, null, 2) };
    try {
      await downloadAsZip('command-log', [file]);
    } catch (e) {
      setExportNote(`Export failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  if (loading && !merged.length) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
        Loading command log…
      </div>
    );
  }

  const origin = typeof window !== 'undefined' ? window.location.origin : 'http://<btct-host>:8080';

  return (
    <div className="flex h-full flex-col overflow-y-auto">
      <div className="mx-auto w-full max-w-6xl px-4 py-5 sm:px-6">
        {/* Header */}
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h1 className="flex items-center gap-2 text-base font-semibold">
              <Terminal size={16} className="text-status-green" />
              Command Log
            </h1>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Whitelisted commands captured from every operator's shell.
              {' · '}{rows.length} command{rows.length !== 1 ? 's' : ''}
              {running > 0 ? ` · ${running} running` : ''}
              {' · '}showing {archiveWindow === 'full' ? 'full archive' : 'last 24h'} + live
              {capped ? ` · loaded ${archive.length} of ${archiveTotal ?? 'more'} archived (exports read them all)` : ''}
            </p>
            {exportNote && <p role="status" className="mt-0.5 text-xs text-status-amber">{exportNote}</p>}
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <Button variant="primary" size="sm" icon={<Plus size={12} />} onClick={() => setAdding(true)} title="Manually add a command-log entry">
              Add entry
            </Button>
            <Button variant="outline" size="sm" icon={<RefreshCw size={12} className={cn(loading && 'animate-spin')} />} onClick={() => void fetchArchive(archiveWindow === 'full' ? 'full' : 'recent')} title="Refresh from the archive">
              Refresh
            </Button>
            <Button variant="outline" size="sm" icon={<Download size={12} />} onClick={() => void exportRows('csv')} title="Export the filtered rows as CSV">
              CSV
            </Button>
            <Button variant="outline" size="sm" icon={<Download size={12} />} onClick={() => void exportRows('json')} title="Export the filtered rows as JSON">
              JSON
            </Button>
          </div>
        </div>

        {/* Filters */}
        <div role="search" aria-label="Filter the command log" className="mb-4 flex flex-col gap-2.5 rounded-md border border-border p-2.5">
          {/* Search + status + time + archive scope */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex h-7 items-center gap-1.5 rounded border border-input bg-background px-2 focus-within:border-primary">
              <Search size={12} className="text-muted-foreground" />
              <input
                ref={searchRef}
                value={filter.query}
                onChange={(e) => setFilter((f) => ({ ...f, query: e.target.value }))}
                placeholder="Search command…"
                aria-label="Search commands"
                className="w-40 bg-transparent text-meta outline-none placeholder:text-muted-foreground sm:w-48"
              />
              {filter.query && (
                <IconButton size="sm" label="Clear the search" onClick={() => setFilter((f) => ({ ...f, query: '' }))}>
                  <X size={11} />
                </IconButton>
              )}
            </div>
            <div role="group" aria-label="Status" className="flex flex-wrap items-center gap-1">
              <span className="mr-1 text-caption font-bold uppercase tracking-widest text-muted-foreground">Status</span>
              {(['all', 'success', 'failed', 'running'] as CmdLogStatus[]).map((st) => (
                <ToggleChip key={st} pressed={filter.status === st} className="capitalize" onClick={() => setFilter((f) => ({ ...f, status: st }))}>
                  {st}
                </ToggleChip>
              ))}
            </div>
            <div role="group" aria-label="Since" className="flex flex-wrap items-center gap-1">
              <span className="mr-1 text-caption font-bold uppercase tracking-widest text-muted-foreground">Since</span>
              {TIME_PRESETS.map(([label, ms]) => (
                <ToggleChip key={label} pressed={since === ms} onClick={() => setSince(ms)}>
                  {label}
                </ToggleChip>
              ))}
            </div>
            {archiveWindow !== 'full' && (
              <Button variant="ghost" size="sm" className="ml-auto text-caption text-muted-foreground hover:text-foreground" onClick={() => void fetchArchive('full')} title="Load the full archive (beyond the last 24h)">
                Search full archive
              </Button>
            )}
          </div>

          {/* Operator chips */}
          {operators.length > 0 && (
            <div role="group" aria-label="Operators" className="flex flex-wrap items-center gap-1">
              <span className="mr-1 text-caption font-bold uppercase tracking-widest text-muted-foreground">Operators</span>
              {operators.map((op) => {
                const active = filter.operators.has(op);
                return (
                  <ToggleChip key={op} pressed={active} onClick={() => toggleIn('operators')(op)}>
                    <CircleDot size={9} style={{ color: operatorColor(op) }} />
                    {op}
                  </ToggleChip>
                );
              })}
            </div>
          )}

          {/* Tool + host selects */}
          <div className="flex flex-wrap items-center gap-3">
            <div role="group" aria-label="Tools" className="flex flex-wrap items-center gap-1">
              <span className="mr-1 text-caption font-bold uppercase tracking-widest text-muted-foreground">Tools</span>
              {tools.map((t) => {
                const active = filter.tools.has(t);
                return (
                  <ToggleChip key={t} mono pressed={active} onClick={() => toggleIn('tools')(t)}>
                    {t}
                  </ToggleChip>
                );
              })}
            </div>
            {hosts.length > 1 && (
              <div className="flex items-center gap-1">
                <span className="mr-1 text-caption font-bold uppercase tracking-widest text-muted-foreground">Host</span>
                <Select
                  aria-label="Host"
                  value={filter.host}
                  onChange={(e) => setFilter((f) => ({ ...f, host: e.target.value }))}
                  className="text-meta"
                >
                  <option value="all">All hosts</option>
                  {hosts.map((h) => <option key={h} value={h}>{h}</option>)}
                </Select>
              </div>
            )}
          </div>
        </div>

        {/* Table */}
        {rows.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center text-muted-foreground">
            <Terminal size={40} className="mb-4 opacity-30" aria-hidden />
            <p className="text-sm text-foreground">No commands logged yet.</p>
            <p className="mt-1 max-w-md text-xs">
              Launch the capture agent on a Kali box, then work normally. Whitelisted commands appear here live:
            </p>
            <code className="mt-3 max-w-full overflow-x-auto whitespace-nowrap rounded-md bg-background px-3 py-1.5 font-mono text-meta text-foreground">
              python3 -m btct_agent install --server {origin} --token &lt;token&gt; --operator &lt;you&gt;
            </code>
          </div>
        ) : (
          <div className="overflow-hidden rounded-md border border-border">
            <div className="divide-y divide-border">
              {rows.slice(0, MAX_RENDERED_ROWS).map((r) => (
                <LogRow key={r.id} r={r} />
              ))}
            </div>
            {rows.length > MAX_RENDERED_ROWS && (
              <div className="border-t border-border px-3 py-2 text-center text-meta text-muted-foreground">
                Showing {MAX_RENDERED_ROWS} of {rows.length} rows. Narrow the filters or export to CSV to see the rest.
              </div>
            )}
          </div>
        )}
      </div>

      {adding && workspaceId && (
        <AddEntryDialog
          workspaceId={workspaceId}
          operators={operators}
          hosts={hosts}
          onClose={() => setAdding(false)}
          onAdded={onManualAdded}
        />
      )}
    </div>
  );
}

// Modal form to hand-enter one command-log record as a chosen operator.
function AddEntryDialog({ workspaceId, operators, hosts, onClose, onAdded }: {
  workspaceId: string;
  operators: string[];
  hosts: string[];
  onClose: () => void;
  onAdded: (log: CommandLogEntry) => void;
}) {
  const addManual = useAuthStore((s) => s.cmdlogAddManual);
  const me = useAuthStore((s) => s.user);
  const [operator, setOperator] = useState(me?.username ?? '');
  const [command, setCommand] = useState('');
  const [tool, setTool] = useState('');
  const [host, setHost] = useState('');
  const [cwd, setCwd] = useState('');
  const [exitCode, setExitCode] = useState('');
  const [durationMs, setDurationMs] = useState('');
  const [when, setWhen] = useState(() => localDatetimeValue(Date.now()));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    if (!operator.trim() || !command.trim()) { setErr('Operator and command are required.'); return; }
    setBusy(true); setErr(null);
    try {
      const log = await addManual({
        workspaceId,
        operator: operator.trim(),
        command: command,
        tool: tool.trim() || undefined,
        host: host.trim() || undefined,
        cwd: cwd.trim() || undefined,
        startedAt: when ? new Date(when).getTime() : undefined,
        exitCode: exitCode.trim() === '' ? undefined : Number(exitCode),
        durationMs: durationMs.trim() === '' ? undefined : Number(durationMs),
      });
      onAdded(log);
      onClose();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'failed to add entry');
    } finally {
      setBusy(false);
    }
  };

  const field = 'px-2.5 py-1.5';

  return (
    <Dialog
      title="Add command-log entry"
      icon={<Plus size={14} className="text-primary" />}
      onClose={onClose}
      dismissible={!busy}
      size="lg"
      className="max-w-lg"
      footer={
        <>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={() => void submit()} disabled={busy}>
            {busy ? 'Adding…' : 'Add entry'}
          </Button>
        </>
      }
    >
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel htmlFor="cl-operator">Operator *</FieldLabel>
              <Input id="cl-operator" list="cmdlog-operators" value={operator} onChange={(e) => setOperator(e.target.value)} placeholder="who ran it" className={field} autoFocus />
              <datalist id="cmdlog-operators">
                {operators.map((op) => <option key={op} value={op} />)}
              </datalist>
            </div>
            <div>
              <FieldLabel htmlFor="cl-tool">Tool</FieldLabel>
              <Input id="cl-tool" value={tool} onChange={(e) => setTool(e.target.value)} placeholder="auto from command" className={field} />
            </div>
          </div>

          <div>
            <FieldLabel htmlFor="cl-command">Command *</FieldLabel>
            <Input id="cl-command" value={command} onChange={(e) => setCommand(e.target.value)} placeholder="nmap -sV 10.0.0.5" mono className={field} />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <FieldLabel htmlFor="cl-host">Host</FieldLabel>
              <Input id="cl-host" list="cmdlog-hosts" value={host} onChange={(e) => setHost(e.target.value)} placeholder="kali-box" className={field} />
              <datalist id="cmdlog-hosts">
                {hosts.map((h) => <option key={h} value={h} />)}
              </datalist>
            </div>
            <div>
              <FieldLabel htmlFor="cl-cwd">Working dir</FieldLabel>
              <Input id="cl-cwd" value={cwd} onChange={(e) => setCwd(e.target.value)} placeholder="/root" mono className={field} />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <FieldLabel htmlFor="cl-when">Started</FieldLabel>
              <Input id="cl-when" type="datetime-local" step="1" value={when} onChange={(e) => setWhen(e.target.value)} className={field} />
            </div>
            <div>
              <FieldLabel htmlFor="cl-exit">Exit code</FieldLabel>
              <Input id="cl-exit" type="number" value={exitCode} onChange={(e) => setExitCode(e.target.value)} placeholder="blank = running" className={field} />
            </div>
            <div>
              <FieldLabel htmlFor="cl-duration">Duration (ms)</FieldLabel>
              <Input id="cl-duration" type="number" value={durationMs} onChange={(e) => setDurationMs(e.target.value)} placeholder="optional" className={field} />
            </div>
          </div>

          {err && <Banner tone="red">{err}</Banner>}
        </div>
    </Dialog>
  );
}

// Format an epoch-ms into the value a <input type="datetime-local"> expects
// (local time, `YYYY-MM-DDTHH:MM:SS`).
function localDatetimeValue(ts: number): string {
  const d = new Date(ts - new Date().getTimezoneOffset() * 60_000);
  return d.toISOString().slice(0, 19);
}
