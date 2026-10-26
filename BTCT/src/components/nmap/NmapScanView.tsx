import { useCallback, useEffect, useRef, useState } from 'react';
import { useAppStore } from '@/stores';
import { useShallow } from 'zustand/react/shallow';
import type { NmapMachine, NmapPort, MachineOS } from '@/types';
import { worstSeverity, SEV_TONE } from '@/components/nmap/web-scan-findings';
import { Upload, ArrowLeft, Monitor, Skull, ChevronDown, ChevronRight, Pencil, X, Radar, Globe } from 'lucide-react';
import { cn } from '@/lib/utils';
import { toLayoutPx } from '@/lib/ui-zoom';
import { v4 as uuidv4 } from 'uuid';
import { nmapMachineRepo } from '@/db/nmap-repo';
import { textKey, setYTextValue } from '@/realtime/shared-doc';
import { useYTextInput } from '@/realtime/use-y-text';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { MenuItem, MenuSeparator, MenuSurface } from '@/components/ui/Menu';

// ── OS icons (inline SVG for Windows / Linux / Attacker) ──

function WindowsIcon({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 5.5l7.5-1v7H3z" /><path d="M11.5 4.3L21 3v8.5h-9.5z" /><path d="M3 12.5h7.5v7L3 18.5z" /><path d="M11.5 12.5H21V21l-9.5-1.2z" />
    </svg>
  );
}

function LinuxIcon({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2C9 2 7 5 7 9c0 2 .5 3.5 1 5-1.5 1-3 2.5-3 4 0 1 1 2 3 2h8c2 0 3-1 3-2 0-1.5-1.5-3-3-4 .5-1.5 1-3 1-5 0-4-2-7-5-7z" />
      <circle cx="10" cy="8" r="1" fill="currentColor" /><circle cx="14" cy="8" r="1" fill="currentColor" />
      <path d="M10 11h4" />
    </svg>
  );
}

function AttackerIcon({ size = 18 }: { size?: number }) {
  return <Skull size={size} />;
}

function UnknownIcon({ size = 18 }: { size?: number }) {
  return <Monitor size={size} />;
}

function OSIcon({ os, size }: { os: MachineOS; size?: number }) {
  switch (os) {
    case 'windows': return <WindowsIcon size={size} />;
    case 'linux': return <LinuxIcon size={size} />;
    case 'attacker': return <AttackerIcon size={size} />;
    default: return <UnknownIcon size={size} />;
  }
}

const OS_OPTIONS: { value: MachineOS; label: string }[] = [
  { value: 'windows', label: 'Windows' },
  { value: 'linux', label: 'Linux' },
  { value: 'attacker', label: 'Attacker' },
  { value: 'unknown', label: 'Unknown' },
];

// ── Main view ──

export function NmapScanView({ scanId }: { scanId: string }) {
  const { nmapScans, nmapMachines, loadNmapScans, loadNmapMachines, importToNmapGroup, deleteNmapMachine, activeWorkspaceId, openTab, setSelectedNmapMachineId } = useAppStore(useShallow((s) => ({
    nmapScans: s.nmapScans,
    nmapMachines: s.nmapMachines,
    loadNmapScans: s.loadNmapScans,
    loadNmapMachines: s.loadNmapMachines,
    importToNmapGroup: s.importToNmapGroup,
    deleteNmapMachine: s.deleteNmapMachine,
    activeWorkspaceId: s.activeWorkspaceId,
    openTab: s.openTab,
    setSelectedNmapMachineId: s.setSelectedNmapMachineId,
  })));
  const fileRef = useRef<HTMLInputElement>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const scan = nmapScans.find((s) => s.id === scanId);

  useEffect(() => {
    if (activeWorkspaceId) void loadNmapScans();
  }, [activeWorkspaceId, loadNmapScans]);

  // Broadcast whichever host's row is expanded so a teammate following us
  // sees the same one; collapsing (or switching scans) clears it.
  useEffect(() => {
    setSelectedNmapMachineId(expandedId);
  }, [expandedId, setSelectedNmapMachineId]);
  useEffect(() => {
    setExpandedId(null);
  }, [scanId]);

  useEffect(() => {
    if (scanId) void loadNmapMachines(scanId);
  }, [scanId, loadNmapMachines]);

  const handleImport = useCallback(async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    for (let i = 0; i < files.length; i++) {
      const file = files[i]!;
      const xml = await file.text();
      await importToNmapGroup(scanId, xml);
    }
    if (fileRef.current) fileRef.current.value = '';
  }, [importToNmapGroup, scanId]);

  const handleDeleteMachine = useCallback(async (machineId: string) => {
    await deleteNmapMachine(machineId);
  }, [deleteNmapMachine]);

  const openMachineInTab = (m: NmapMachine) => {
    openTab({ id: uuidv4(), kind: 'nmap-machine', entityId: m.id, title: m.hostname || m.ip });
  };

  const openWebScanTab = (m: NmapMachine) => {
    openTab({ id: uuidv4(), kind: 'web-scan', entityId: m.id, title: `${m.hostname || m.ip} scans` });
  };

  return (
    <div className="flex h-full flex-col overflow-y-auto">
      <div className="mx-auto w-full max-w-4xl px-4 py-5 sm:px-6">
        {/* Header */}
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div className="min-w-0">
            <h1 className="flex items-center gap-2 text-base font-semibold"><Radar size={16} className="shrink-0 text-status-green" /><span className="truncate">{scan?.name ?? 'Nmap Group'}</span></h1>
            {scan && (
              <p className="mt-0.5 text-xs text-muted-foreground">
                Created {new Date(scan.importedAt).toLocaleString()} · {nmapMachines.length} host{nmapMachines.length !== 1 ? 's' : ''}
              </p>
            )}
          </div>
          <div className="flex items-center gap-2">
            <input
              ref={fileRef}
              type="file"
              accept=".xml"
              multiple
              className="hidden"
              onChange={(e) => void handleImport(e.target.files)}
            />
            <Button variant="primary" size="sm" icon={<Upload size={12} />} onClick={() => fileRef.current?.click()}>
              Import XML
            </Button>
          </div>
        </div>

        {/* Machine rows */}
        {nmapMachines.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
            <Monitor size={40} className="mb-4 opacity-30" aria-hidden />
            <p className="text-sm text-foreground">No hosts found in this scan.</p>
            <p className="mt-1 text-xs">Import an Nmap XML file to get started.</p>
          </div>
        ) : (
          <div className="flex flex-col divide-y divide-border overflow-hidden rounded-md border border-border">
            {nmapMachines.map((machine) => (
              <MachineRow
                key={machine.id}
                machine={machine}
                expanded={expandedId === machine.id}
                onToggle={() => setExpandedId((id) => (id === machine.id ? null : machine.id))}
                onOpenTab={() => openMachineInTab(machine)}
                onViewScans={() => openWebScanTab(machine)}
                onDelete={() => void handleDeleteMachine(machine.id)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Machine row (full-width, expands in place to show its ports) ──

function MachineRow({ machine, expanded, onToggle, onOpenTab, onViewScans, onDelete }: {
  machine: NmapMachine;
  expanded: boolean;
  onToggle: () => void;
  onOpenTab: () => void;
  onViewScans: () => void;
  onDelete: () => void;
}) {
  const openPortCount = machine.ports.filter((p) => p.state === 'open').length;
  const findings = machine.toolFindings ?? [];
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [renaming, setRenaming] = useState(false);

  // Close context menu on outside click
  useEffect(() => {
    if (!ctxMenu) return;
    const close = () => setCtxMenu(null);
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setCtxMenu(null); };
    window.addEventListener('click', close);
    window.addEventListener('keydown', onKey);
    return () => { window.removeEventListener('click', close); window.removeEventListener('keydown', onKey); };
  }, [ctxMenu]);

  const handleContext = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setCtxMenu({ x: e.clientX, y: e.clientY });
  };

  const handleDeleteClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    setCtxMenu(null);
    setConfirmDelete(true);
  };

  const handleConfirmDelete = () => {
    setConfirmDelete(false);
    onDelete();
  };

  const handleRenameClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    setCtxMenu(null);
    setRenaming(true);
  };

  const handleConfirmRename = (value: string) => {
    setRenaming(false);
    setYTextValue('nmapMachine', machine.id, 'hostname', value);
  };

  const handleClick = (e: React.MouseEvent) => {
    if (e.ctrlKey && e.shiftKey) {
      e.preventDefault();
      onOpenTab();
    } else {
      onToggle();
    }
  };

  return (
    <div>
      <button
        onClick={handleClick}
        onContextMenu={handleContext}
        aria-expanded={expanded}
        className="flex w-full items-center gap-3 px-3 py-2 text-left transition-colors hover:bg-accent"
      >
        <div className="w-4 shrink-0 text-muted-foreground">
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </div>
        <div className={cn(
          'flex h-6 w-6 shrink-0 items-center justify-center',
          machine.os === 'windows' && 'text-status-blue',
          machine.os === 'linux' && 'text-status-green',
          machine.os === 'attacker' && 'text-status-red',
          machine.os === 'unknown' && 'text-muted-foreground',
        )}>
          <OSIcon os={machine.os} size={16} />
        </div>
        <div className="flex min-w-0 flex-1 items-baseline gap-2">
          <span className="shrink-0 font-mono text-xs font-semibold">{machine.ip}</span>
          {machine.hostname && (
            <span className="truncate text-meta text-muted-foreground">{machine.hostname}</span>
          )}
        </div>
        <Badge tone={openPortCount > 0 ? 'green' : 'neutral'}>
          {openPortCount} open port{openPortCount !== 1 ? 's' : ''}
        </Badge>
        {findings.length > 0 && (
          <span
            role="button"
            tabIndex={0}
            title="View attached web scans"
            onClick={(e) => { e.stopPropagation(); onViewScans(); }}
            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); onViewScans(); } }}
            className="shrink-0 cursor-pointer rounded hover:opacity-80 focus:outline-none focus-visible:ring-1 focus-visible:ring-primary"
          >
            <Badge tone={SEV_TONE[worstSeverity(findings)]}>
              {findings.length} vuln{findings.length !== 1 ? 's' : ''} &rarr;
            </Badge>
          </span>
        )}
      </button>

      {expanded && (
        <div className="border-t border-border bg-background/40 px-3 py-3">
          <PortsTable machine={machine} />
        </div>
      )}

      {/* Context menu */}
      {ctxMenu && (
        <MenuSurface
          className="fixed z-50"
          style={{ left: toLayoutPx(ctxMenu.x), top: toLayoutPx(ctxMenu.y) }}
          onClick={(e) => e.stopPropagation()}
        >
          <MenuItem icon={<Pencil size={12} />} onClick={handleRenameClick}>
            {machine.hostname ? 'Rename Machine' : 'Add Name'}
          </MenuItem>
          <MenuSeparator />
          <MenuItem danger icon={<X size={12} />} onClick={handleDeleteClick}>
            Delete Machine
          </MenuItem>
        </MenuSurface>
      )}

      {/* Rename dialog */}
      {renaming && (
        <ConfirmDialog
          title={machine.hostname ? 'Rename machine' : 'Add a name'}
          message={`Name for ${machine.ip}, synced live to every teammate.`}
          confirmLabel="Save"
          input={{ initial: machine.hostname, placeholder: 'e.g. web01' }}
          onCancel={() => setRenaming(false)}
          onConfirm={handleConfirmRename}
        />
      )}

      {/* Delete confirmation dialog */}
      {confirmDelete && (
        <ConfirmDialog
          title="Delete Machine"
          destructive
          message={<>Are you sure you want to delete <span className="font-semibold text-foreground">{machine.hostname || machine.ip}</span>? This action cannot be undone.</>}
          confirmLabel="Delete"
          onConfirm={handleConfirmDelete}
          onCancel={() => setConfirmDelete(false)}
        />
      )}
    </div>
  );
}

// ── Machine detail view ──

function MachineDetail({ machine: initialMachine, onBack }: { machine: NmapMachine; onBack: (() => void) | null }) {
  const updateNmapMachine = useAppStore((s) => s.updateNmapMachine);
  const nmapMachines = useAppStore((s) => s.nmapMachines);
  const openTab = useAppStore((s) => s.openTab);

  // Get the live version of this machine from the store.
  const liveMachine = nmapMachines.find((m) => m.id === initialMachine.id) ?? initialMachine;

  const [os, setOs] = useState<MachineOS>(initialMachine.os);

  // Reset local state when the underlying machine changes (e.g. switching tabs in the same pane)
  useEffect(() => {
    setOs(initialMachine.os);
  }, [initialMachine.id]);
  useEffect(() => {
    setOs(liveMachine.os);
  }, [liveMachine.os]);

  // Hostname is a CRDT Y.Text so two users can type into it concurrently.
  const [hostnameY, setHostnameY, hostnameYRef] = useYTextInput(
    textKey('nmapMachine', initialMachine.id, 'hostname'),
    initialMachine.hostname,
  );
  const [osDropdownOpen, setOsDropdownOpen] = useState(false);
  const commitHostname = () => {
    const trimmed = hostnameY.trim();
    if (trimmed !== hostnameY) setHostnameY(trimmed);
  };

  // The OS menu is a light popover: Escape or a click elsewhere closes it.
  useEffect(() => {
    if (!osDropdownOpen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && !e.defaultPrevented) setOsDropdownOpen(false); };
    const onDown = (e: MouseEvent) => { if (!(e.target as Element | null)?.closest('[data-os-menu]')) setOsDropdownOpen(false); };
    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onDown);
    return () => { document.removeEventListener('keydown', onKey); document.removeEventListener('mousedown', onDown); };
  }, [osDropdownOpen]);

  const changeOS = (newOs: MachineOS) => {
    setOs(newOs);
    setOsDropdownOpen(false);
    void updateNmapMachine(initialMachine.id, { os: newOs });
  };

  return (
    <div className="flex h-full flex-col overflow-y-auto">
      <div className="mx-auto w-full max-w-3xl px-4 py-5 sm:px-6">
        {/* Back button */}
        {onBack && (
          <Button variant="ghost" size="sm" icon={<ArrowLeft size={12} />} onClick={onBack} className="-ml-2 mb-3 text-muted-foreground hover:text-foreground">
            Back to machines
          </Button>
        )}

        {/* Machine header */}
        <div className="mb-5 flex items-start gap-3">
          <div className={cn(
            'flex h-12 w-12 shrink-0 items-center justify-center rounded-lg bg-background',
            os === 'windows' && 'text-status-blue',
            os === 'linux' && 'text-status-green',
            os === 'attacker' && 'text-status-red',
            os === 'unknown' && 'text-muted-foreground',
          )}>
            <OSIcon os={os} size={26} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="font-mono text-base font-semibold">{initialMachine.ip}</div>
            <div className="mt-1 flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-1.5">
                <label htmlFor="nmap-hostname" className="text-caption uppercase tracking-wider text-muted-foreground">Hostname</label>
                <input
                  id="nmap-hostname"
                  ref={hostnameYRef}
                  value={hostnameY}
                  onChange={(e) => setHostnameY(e.target.value)}
                  onBlur={commitHostname}
                  onKeyDown={(e) => { if (e.key === 'Enter') commitHostname(); }}
                  placeholder="Set hostname..."
                  className="border-b border-border bg-transparent px-1 text-sm outline-none focus:border-primary"
                />
              </div>
              <div className="relative" data-os-menu>
                <Button
                  variant="outline"
                  size="xs"
                  aria-haspopup="menu"
                  aria-expanded={osDropdownOpen}
                  icon={<OSIcon os={os} size={12} />}
                  onClick={() => setOsDropdownOpen(!osDropdownOpen)}
                >
                  {OS_OPTIONS.find((o) => o.value === os)?.label ?? 'Unknown'}
                  <ChevronDown size={10} />
                </Button>
                {osDropdownOpen && (
                  <MenuSurface className="absolute left-0 top-full z-50 mt-1 min-w-[140px]">
                    {OS_OPTIONS.map((opt) => (
                      <MenuItem
                        key={opt.value}
                        icon={<OSIcon os={opt.value} size={12} />}
                        aria-current={os === opt.value || undefined}
                        className={cn(os === opt.value && 'bg-accent font-medium')}
                        onClick={() => changeOS(opt.value)}
                      >
                        {opt.label}
                      </MenuItem>
                    ))}
                  </MenuSurface>
                )}
              </div>
            </div>
          </div>
        </div>

        {(liveMachine.toolFindings?.length ?? 0) > 0 && (
          <button
            type="button"
            onClick={() => openTab({ id: uuidv4(), kind: 'web-scan', entityId: initialMachine.id, title: `${liveMachine.hostname || liveMachine.ip} scans` })}
            className="mb-4 flex w-full items-center justify-between gap-2 rounded-md border border-border bg-background/40 px-3 py-2 text-left text-xs hover:bg-accent"
          >
            <span className="flex items-center gap-2 font-medium">
              <Globe size={13} className="text-status-blue" />
              {liveMachine.toolFindings!.length} web scan finding{liveMachine.toolFindings!.length !== 1 ? 's' : ''}
            </span>
            <span className="text-meta text-muted-foreground">View scans &rarr;</span>
          </button>
        )}

        <PortsTable machine={initialMachine} />
      </div>

    </div>
  );
}

// ── Ports table (open + closed/filtered), shared by the detail view and an expanded row ──

function PortsTable({ machine }: { machine: NmapMachine }) {
  const openPorts = machine.ports.filter((p) => p.state === 'open');
  const closedPorts = machine.ports.filter((p) => p.state !== 'open');

  return (
    <>
      <div className="mb-6">
        <div className="mb-2 flex items-center justify-between border-b border-border pb-2">
          <span className="text-caption font-bold uppercase tracking-widest text-muted-foreground">
            Open Ports ({openPorts.length})
          </span>
        </div>
        {openPorts.length === 0 ? (
          <p className="py-4 text-center text-xs text-muted-foreground">No open ports detected</p>
        ) : (
          <div className="divide-y divide-border">
            {openPorts.map((p, i) => (
              <PortRow key={i} port={p} />
            ))}
          </div>
        )}
      </div>

      {closedPorts.length > 0 && (
        <div>
          <div className="mb-2 border-b border-border pb-2">
            <span className="text-caption font-bold uppercase tracking-widest text-muted-foreground">
              Closed / Filtered ({closedPorts.length})
            </span>
          </div>
          <div className="divide-y divide-border">
            {closedPorts.map((p, i) => (
              <PortRow key={i} port={p} muted />
            ))}
          </div>
        </div>
      )}
    </>
  );
}

function PortRow({ port, muted }: { port: NmapPort; muted?: boolean }) {
  const hasScripts = port.scripts && port.scripts.length > 0;
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={cn(muted && 'text-muted-foreground')}>
      <div
        className={cn(
          'flex items-center gap-3 py-1.5 text-xs sm:gap-4',
          hasScripts && 'cursor-pointer hover:bg-accent',
        )}
        onClick={() => hasScripts && setExpanded(!expanded)}
      >
        <div className="w-5 shrink-0">
          {hasScripts && (
            expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />
          )}
        </div>
        <span className={cn('w-14 shrink-0 font-mono sm:w-20', !muted && 'font-semibold text-foreground')}>{port.port}</span>
        <span className="w-10 shrink-0 uppercase sm:w-14">{port.protocol}</span>
        <span className="w-24 shrink-0 truncate sm:w-32">{port.service || 'none'}</span>
        <span className="min-w-0 flex-1 truncate text-muted-foreground">{port.version || 'none'}</span>
      </div>
      {expanded && hasScripts && (
        <div className="mb-2 ml-5 border-l-2 border-border pl-4">
          {port.scripts!.map((script, si) => (
            <div key={si} className="mb-2">
              <div className="text-caption font-bold uppercase tracking-wider text-primary">{script.id}</div>
              <pre className="mt-0.5 whitespace-pre-wrap break-all rounded bg-background p-2 font-mono text-meta text-foreground">{script.output}</pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Standalone machine view (opened as a tab) ──

export function NmapMachineView({ machineId }: { machineId: string }) {
  const [machine, setMachine] = useState<NmapMachine | null>(null);
  const [loading, setLoading] = useState(true);
  const loadNmapMachines = useAppStore((s) => s.loadNmapMachines);

  useEffect(() => {
    void nmapMachineRepo.getById(machineId).then((m) => {
      setMachine(m ?? null);
      setLoading(false);
      // Ensure machine's scan group is loaded into store so liveMachine lookup works
      if (m) void loadNmapMachines(m.scanId);
    });
  }, [machineId, loadNmapMachines]);

  if (loading) return <div className="flex h-full items-center justify-center text-xs text-muted-foreground">Loading…</div>;
  if (!machine) return <div className="flex h-full items-center justify-center text-xs text-muted-foreground">Machine not found</div>;

  return <MachineDetail key={machineId} machine={machine} onBack={null} />;
}
