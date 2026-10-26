import { Fragment, useState } from 'react';
import type { ToolFinding, FindingSeverity } from '@/types';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/Badge';
import { ChevronDown, ChevronRight } from 'lucide-react';

// Web/app tool findings (gobuster, sqlmap, sstimap, dalfox, openvas, nuclei,
// bbot, wpscan, nikto, gitleaks, secretfinder), uploaded through the
// scan-ingest API and attached to a host by IP. Any other tool name still
// renders with a generic count. Rendered in the
// Web Scans tab (src/components/nmap/WebScanView.tsx), grouped by tool and
// collapsed by default so a host with many hits stays readable. The nmap view
// only links here; it never renders findings inline.

export const SEV_ORDER: FindingSeverity[] = ['info', 'low', 'medium', 'high', 'critical'];
export const SEV_TONE: Record<FindingSeverity, 'neutral' | 'blue' | 'amber' | 'red'> = {
  info: 'neutral', low: 'blue', medium: 'amber', high: 'red', critical: 'red',
};
const SEV_DOT: Record<FindingSeverity, string> = {
  info: 'bg-muted-foreground', low: 'bg-status-blue', medium: 'bg-status-amber',
  high: 'bg-status-red', critical: 'bg-status-red',
};
const TOOL_LABEL: Record<string, string> = {
  gobuster: 'Gobuster', sqlmap: 'SQLMap', sstimap: 'SSTImap', dalfox: 'Dalfox',
  openvas: 'OpenVAS', nuclei: 'Nuclei', bbot: 'BBOT',
  wpscan: 'WPScan', nikto: 'Nikto', gitleaks: 'Gitleaks', secretfinder: 'SecretFinder',
};
const toolLabel = (t: string) => TOOL_LABEL[t] ?? t;

export function worstSeverity(items: ToolFinding[]): FindingSeverity {
  let idx = 0;
  for (const f of items) { const i = SEV_ORDER.indexOf(f.severity); if (i > idx) idx = i; }
  return SEV_ORDER[idx]!;
}

const dget = (f: ToolFinding, k: string): string => {
  const v = f.details?.[k];
  return v === undefined || v === null ? '' : String(v);
};
const uniq = (xs: string[]) => [...new Set(xs.filter(Boolean))];
const cut = (xs: string[], n = 4) => (xs.length > n ? [...xs.slice(0, n), `+${xs.length - n}`] : xs);

/**
 * One short line summarising a tool's results for the group header, so the
 * gist (endpoints found, injectable params, XSS sinks) reads without opening
 * every finding. Falls back to a plain count for unknown tools.
 */
function summarize(tool: string, items: ToolFinding[]): string {
  const n = items.length;
  const plural = (word: string) => `${n} ${word}${n !== 1 ? 's' : ''}`;
  if (tool === 'gobuster') {
    const dns = items.every((f) => dget(f, 'subdomain'));
    return dns && items.length ? plural('subdomain') : plural('endpoint');
  }
  if (tool === 'sqlmap') {
    const params = cut(uniq(items.map((f) => dget(f, 'parameter'))));
    const dbms = uniq(items.map((f) => dget(f, 'dbms')));
    const base = params.length ? `injectable: ${params.join(', ')}` : 'injectable';
    return dbms.length ? `${base} (${dbms.join(', ')})` : base;
  }
  if (tool === 'sstimap') {
    const params = cut(uniq(items.map((f) => dget(f, 'parameter'))));
    const eng = uniq(items.map((f) => dget(f, 'engine')));
    const base = params.length ? `SSTI: ${params.join(', ')}` : plural('SSTI hit');
    return eng.length ? `${base} (${eng.join(', ')})` : base;
  }
  if (tool === 'dalfox') {
    const params = cut(uniq(items.map((f) => dget(f, 'parameter'))));
    return params.length ? `XSS: ${params.join(', ')}` : plural('XSS');
  }
  if (tool === 'nuclei') {
    const tpl = cut(uniq(items.map((f) => dget(f, 'template') || dget(f, 'type'))));
    const base = `${n} ${n === 1 ? 'match' : 'matches'}`;
    return tpl.length ? `${base}: ${tpl.join(', ')}` : base;
  }
  if (tool === 'openvas') {
    const cves = cut(uniq(items.flatMap((f) => dget(f, 'cve').split(/[\s,]+/))));
    return cves.length ? `${plural('finding')}: ${cves.join(', ')}` : plural('finding');
  }
  if (tool === 'bbot') {
    const types = cut(uniq(items.map((f) => dget(f, 'event_type'))));
    return types.length ? `${plural('event')}: ${types.join(', ')}` : plural('event');
  }
  if (tool === 'wpscan') {
    const comps = cut(uniq(items.map((f) => dget(f, 'component') || dget(f, 'type'))));
    return comps.length ? `${plural('issue')}: ${comps.join(', ')}` : plural('issue');
  }
  if (tool === 'nikto') {
    return plural('finding');
  }
  if (tool === 'gitleaks' || tool === 'secretfinder') {
    const kinds = cut(uniq(items.map((f) => dget(f, 'rule') || dget(f, 'type'))));
    return kinds.length ? `${plural('secret')}: ${kinds.join(', ')}` : plural('secret');
  }
  return plural('result');
}

/** The grouped-by-tool finding list for one host. */
export function HostFindings({ findings }: { findings: ToolFinding[] }) {
  if (findings.length === 0) {
    return <p className="py-6 text-center text-xs text-muted-foreground">No web scans attached to this host yet.</p>;
  }
  const byTool = new Map<string, ToolFinding[]>();
  for (const f of findings) {
    const arr = byTool.get(f.tool) ?? [];
    arr.push(f);
    byTool.set(f.tool, arr);
  }
  const groups = [...byTool.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  return (
    <div className="flex flex-col gap-2">
      {groups.map(([tool, items]) => <ToolGroup key={tool} tool={tool} items={items} />)}
    </div>
  );
}

function ToolGroup({ tool, items }: { tool: string; items: ToolFinding[] }) {
  const [open, setOpen] = useState(true);
  const worst = worstSeverity(items);
  const sorted = [...items].sort(
    (a, b) => SEV_ORDER.indexOf(b.severity) - SEV_ORDER.indexOf(a.severity) || a.title.localeCompare(b.title),
  );
  return (
    <div className="overflow-hidden rounded-md border border-border">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 bg-background/40 px-3 py-2 text-left hover:bg-accent"
      >
        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        <span className="shrink-0 text-xs font-semibold">{toolLabel(tool)}</span>
        <span className="min-w-0 flex-1 truncate text-meta text-muted-foreground">{summarize(tool, items)}</span>
        <Badge tone={SEV_TONE[worst]} solid>{worst}</Badge>
      </button>
      {open && (
        <div className="divide-y divide-border border-t border-border">
          {sorted.map((f) => <FindingRow key={f.id} finding={f} />)}
        </div>
      )}
    </div>
  );
}

function FindingRow({ finding }: { finding: ToolFinding }) {
  const [open, setOpen] = useState(false);
  const details = finding.details ? Object.entries(finding.details) : [];
  const expandable = details.length > 0 || !!finding.evidence || !!finding.url;
  return (
    <div>
      <div
        className={cn('flex items-center gap-2 px-3 py-1.5 text-xs', expandable && 'cursor-pointer hover:bg-accent')}
        onClick={() => expandable && setOpen((o) => !o)}
      >
        <span className="w-3.5 shrink-0">
          {expandable && (open ? <ChevronDown size={11} /> : <ChevronRight size={11} />)}
        </span>
        <span className={cn('h-1.5 w-1.5 shrink-0 rounded-full', SEV_DOT[finding.severity])} title={finding.severity} />
        <span className="min-w-0 flex-1 truncate font-mono text-foreground">{finding.title}</span>
        {finding.port !== undefined && (
          <span className="shrink-0 font-mono text-meta text-muted-foreground">:{finding.port}</span>
        )}
      </div>
      {open && expandable && (
        <div className="space-y-2 bg-background/40 px-3 pb-2.5 pl-9">
          {finding.url && (
            <a
              href={finding.url}
              target="_blank"
              rel="noreferrer"
              className="block break-all font-mono text-meta text-status-blue hover:underline"
            >
              {finding.url}
            </a>
          )}
          {details.length > 0 && (
            <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-meta">
              {details.map(([k, v]) => (
                <Fragment key={k}>
                  <span className="font-semibold uppercase tracking-wide text-muted-foreground">{k}</span>
                  <span className="break-all font-mono text-foreground">{String(v)}</span>
                </Fragment>
              ))}
            </div>
          )}
          {finding.evidence && (
            <pre className="whitespace-pre-wrap break-all rounded bg-background p-2 font-mono text-meta text-foreground">{finding.evidence}</pre>
          )}
        </div>
      )}
    </div>
  );
}
