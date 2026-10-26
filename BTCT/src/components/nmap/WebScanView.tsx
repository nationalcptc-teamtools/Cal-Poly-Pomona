import { useEffect, useState } from 'react';
import { useAppStore } from '@/stores';
import type { NmapMachine } from '@/types';
import { nmapMachineRepo } from '@/db/nmap-repo';
import { Badge } from '@/components/ui/Badge';
import { Globe } from 'lucide-react';
import { HostFindings, worstSeverity, SEV_TONE } from '@/components/nmap/web-scan-findings';

// The Web Scans tab: all web/app tool findings attached to one host (by IP),
// opened from the Web Scans sidebar section or the "View scans" link on an
// nmap host. Reads the live record from the store (so new uploads show as they
// arrive) and falls back to a direct fetch when the host is not in the
// in-memory list (e.g. the tab was restored on load).
export function WebScanView({ machineId }: { machineId: string }) {
  const fromStore = useAppStore(
    (s) => s.webScanHosts.find((m) => m.id === machineId) ?? s.nmapMachines.find((m) => m.id === machineId),
  );
  const loadWebScanHosts = useAppStore((s) => s.loadWebScanHosts);
  const [fetched, setFetched] = useState<NmapMachine | null>(null);

  useEffect(() => { void loadWebScanHosts(); }, [loadWebScanHosts]);
  useEffect(() => {
    if (fromStore) return;
    void nmapMachineRepo.getById(machineId).then((m) => setFetched(m ?? null));
  }, [machineId, fromStore]);

  const machine = fromStore ?? fetched;
  if (!machine) {
    return <div className="flex h-full items-center justify-center text-xs text-muted-foreground">Host not found</div>;
  }
  const findings = machine.toolFindings ?? [];
  const worst = findings.length ? worstSeverity(findings) : null;

  return (
    <div className="flex h-full flex-col overflow-y-auto">
      <div className="mx-auto w-full max-w-3xl px-4 py-5 sm:px-6">
        <div className="mb-5 flex items-start gap-3">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-lg bg-background text-status-blue">
            <Globe size={24} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="font-mono text-base font-semibold">{machine.hostname || machine.ip}</div>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-meta text-muted-foreground">
              {machine.hostname && <span className="font-mono">{machine.ip}</span>}
              <span>Web scans</span>
              {worst && (
                <Badge tone={SEV_TONE[worst]} solid>
                  {findings.length} finding{findings.length !== 1 ? 's' : ''}
                </Badge>
              )}
            </div>
          </div>
        </div>
        <HostFindings findings={findings} />
      </div>
    </div>
  );
}
