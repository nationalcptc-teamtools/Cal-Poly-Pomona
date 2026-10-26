import { useMemo, useState } from 'react';
import { Dialog } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';
import { useAppStore } from '@/stores';
import { useShallow } from 'zustand/react/shallow';
import { useAuthStore } from '@/auth/auth-store';
import { cn } from '@/lib/utils';
import { Upload, FileUp, CheckCircle2, AlertCircle } from 'lucide-react';

// Manual, in-app counterpart to the scan-ingest API (server/scan-ingest.mjs):
// paste or pick a scan and POST it to the same /api/scans/* routes, so a
// hand upload and a tool upload land through one code path (parse, upsert by
// IP, dedupe, broadcast). The request carries the user's session token, which
// the server accepts regardless of the optional ingest token (an app user is
// already trusted to write the workspace).

type Mode = 'nmap' | 'tool';

const TOOL_EXAMPLE = `{
  "tool": "gobuster",
  "target": { "ip": "10.10.10.5", "port": 80, "url": "http://10.10.10.5/" },
  "findings": [
    { "title": "/admin  (301)", "severity": "low",
      "url": "http://10.10.10.5/admin",
      "details": { "status": 301, "size": 312 } }
  ]
}`;

export function ScanUploadDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { workspaces, activeWorkspaceId } = useAppStore(
    useShallow((s) => ({ workspaces: s.workspaces, activeWorkspaceId: s.activeWorkspaceId })),
  );
  const token = useAuthStore((s) => s.token);

  const [mode, setMode] = useState<Mode>('nmap');
  const [workspaceId, setWorkspaceId] = useState<string>(activeWorkspaceId ?? '');
  const [scanName, setScanName] = useState('');
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Default the picker to the active workspace whenever the dialog opens.
  const ws = workspaceId || activeWorkspaceId || (workspaces[0]?.id ?? '');

  const placeholder = useMemo(
    () => (mode === 'nmap'
      ? 'Paste nmap -oX XML here, or JSON { "hosts": [...] }. Or choose a file below.'
      : TOOL_EXAMPLE),
    [mode],
  );

  const reset = () => { setText(''); setResult(null); setError(null); setScanName(''); };
  const close = () => { reset(); onClose(); };

  const pickFile = async (file: File | undefined) => {
    if (!file) return;
    setError(null);
    try { setText(await file.text()); } catch { setError('Could not read that file.'); }
  };

  const submit = async () => {
    setBusy(true);
    setResult(null);
    setError(null);
    const body = text.trim();
    if (!body) { setError('Nothing to upload. Paste a scan or choose a file.'); setBusy(false); return; }
    try {
      const headers: Record<string, string> = {};
      if (token) headers.Authorization = `Bearer ${token}`;
      let res: Response;

      if (mode === 'nmap' && body.startsWith('<')) {
        // Raw nmap XML: workspace + scan go on the query string.
        const qs = new URLSearchParams();
        if (ws) qs.set('workspace', ws);
        if (scanName.trim()) qs.set('scan', scanName.trim());
        headers['Content-Type'] = 'application/xml';
        res = await fetch(`/api/scans/nmap?${qs.toString()}`, { method: 'POST', headers, body });
      } else {
        // JSON path (nmap hosts JSON, or a tool payload): inject the chosen
        // workspace (and scan name for nmap) so the picker wins.
        let parsed: Record<string, unknown>;
        try { parsed = JSON.parse(body); } catch { setError('That is not valid JSON (and not nmap XML).'); setBusy(false); return; }
        if (ws) parsed.workspace = ws;
        if (mode === 'nmap' && scanName.trim()) parsed.scan = scanName.trim();
        headers['Content-Type'] = 'application/json';
        res = await fetch(`/api/scans/${mode}`, { method: 'POST', headers, body: JSON.stringify(parsed) });
      }

      const data = await res.json().catch(() => ({}));
      if (!res.ok) { setError(data?.error || `Upload failed (HTTP ${res.status}).`); setBusy(false); return; }
      setResult(summarize(mode, data));
      setText('');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Upload failed.');
    } finally {
      setBusy(false);
    }
  };

  const tab = (m: Mode, label: string) => (
    <button
      type="button"
      onClick={() => { setMode(m); setResult(null); setError(null); }}
      className={cn(
        'flex-1 rounded px-3 py-1.5 text-xs font-medium transition-colors',
        mode === m ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground',
      )}
    >
      {label}
    </button>
  );

  return (
    <Dialog
      open={open}
      onClose={close}
      title="Upload scan"
      icon={<Upload size={15} />}
      size="lg"
      footer={
        <div className="flex items-center justify-end gap-2">
          <Button variant="ghost" size="sm" onClick={close}>Close</Button>
          <Button size="sm" onClick={() => void submit()} disabled={busy || !ws}>
            {busy ? 'Uploading…' : 'Upload'}
          </Button>
        </div>
      }
    >
      <div className="flex flex-col gap-3">
        <div className="flex gap-1 rounded-md bg-muted p-1">
          {tab('nmap', 'Nmap')}
          {tab('tool', 'Tool findings')}
        </div>

        <p className="text-meta text-muted-foreground">
          {mode === 'nmap'
            ? 'Hosts are added to a scan group and merged by IP. Re-upload with the same scan name to add more ports to the same hosts.'
            : 'Findings attach to the host matching target.ip (a stub host is created if that IP is new).'}
        </p>

        <div className="flex flex-wrap items-end gap-3">
          <label className="flex min-w-[180px] flex-1 flex-col gap-1">
            <span className="text-caption uppercase tracking-wider text-muted-foreground">Workspace</span>
            <select
              value={ws}
              onChange={(e) => setWorkspaceId(e.target.value)}
              className="rounded border border-border bg-background px-2 py-1.5 text-xs outline-none focus:border-primary"
            >
              {workspaces.length === 0 && <option value="">No workspaces</option>}
              {workspaces.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
            </select>
          </label>
          {mode === 'nmap' && (
            <label className="flex min-w-[180px] flex-1 flex-col gap-1">
              <span className="text-caption uppercase tracking-wider text-muted-foreground">Scan name (optional)</span>
              <input
                value={scanName}
                onChange={(e) => setScanName(e.target.value)}
                placeholder="e.g. HTB Lab sweep"
                className="rounded border border-border bg-background px-2 py-1.5 text-xs outline-none focus:border-primary"
              />
            </label>
          )}
        </div>

        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={placeholder}
          spellCheck={false}
          className="h-56 w-full resize-y rounded border border-border bg-background p-2.5 font-mono text-meta outline-none focus:border-primary"
        />

        {mode === 'nmap' && (
          <label className="inline-flex w-fit cursor-pointer items-center gap-1.5 text-meta text-status-blue hover:underline">
            <FileUp size={13} />
            Choose an .xml / .json file
            <input
              type="file"
              accept=".xml,.json,application/xml,text/xml,application/json"
              className="hidden"
              onChange={(e) => { void pickFile(e.target.files?.[0]); e.target.value = ''; }}
            />
          </label>
        )}

        {error && (
          <div className="flex items-start gap-2 rounded border border-status-red/40 bg-status-red/10 p-2.5 text-meta text-status-red">
            <AlertCircle size={14} className="mt-px shrink-0" />
            <span className="break-words">{error}</span>
          </div>
        )}
        {result && (
          <div className="flex items-start gap-2 rounded border border-status-green/40 bg-status-green/10 p-2.5 text-meta text-status-green">
            <CheckCircle2 size={14} className="mt-px shrink-0" />
            <span className="break-words">{result}</span>
          </div>
        )}
      </div>
    </Dialog>
  );
}

function summarize(mode: Mode, data: Record<string, unknown>): string {
  const n = (k: string) => (typeof data[k] === 'number' ? (data[k] as number) : 0);
  if (mode === 'nmap') {
    const parts = [`${n('added')} host${n('added') !== 1 ? 's' : ''} added`, `${n('updated')} updated`];
    if (n('hostsSkipped') > 0) parts.push(`${n('hostsSkipped')} skipped`);
    return `Nmap import done: ${parts.join(', ')}.`;
  }
  const parts = [`${n('added')} added`];
  if (n('deduped') > 0) parts.push(`${n('deduped')} duplicate${n('deduped') !== 1 ? 's' : ''} skipped`);
  if (n('skipped') > 0) parts.push(`${n('skipped')} invalid`);
  const where = data.matched ? `host ${String(data.ip ?? '')}` : `a new stub for ${String(data.ip ?? '')}`;
  const hn = data.hostnameSet ? ' (hostname set)' : '';
  return `Findings attached to ${where}${hn}: ${parts.join(', ')}.`;
}
