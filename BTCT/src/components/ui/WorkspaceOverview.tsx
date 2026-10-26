import { v4 as uuidv4 } from 'uuid';
import { ArrowUpRight, FileText, FileType, Images, Radar, Terminal } from 'lucide-react';
import { useShallow } from 'zustand/react/shallow';
import { useAppStore } from '@/stores';
import { useThemeStore } from '@/stores/theme-store';
import type { TabKind } from '@/types';
import { ShellLeadTools, ShellTrailTools } from './TabBar';

/** Small native-CSS landing view; no charts, polling, or extra UI libraries. */
export function WorkspaceOverview() {
  const { workspaces, activeWorkspaceId, pages, nmapScans, typstAssets, openTab } = useAppStore(useShallow((s) => ({
    workspaces: s.workspaces, activeWorkspaceId: s.activeWorkspaceId,
    pages: s.pages, nmapScans: s.nmapScans, typstAssets: s.typstAssets,
    openTab: s.openTab,
  })));
  const typstOn = useThemeStore((s) => s.features.typst);
  const workspace = workspaces.find((w) => w.id === activeWorkspaceId);
  const localPages = pages.filter((p) => p.workspaceId === activeWorkspaceId);
  const recent = [...localPages].sort((a, b) => b.updatedAt - a.updatedAt).slice(0, 6);
  const open = (kind: TabKind, entityId: string, title: string) => openTab({ id: uuidv4(), kind, entityId, title });
  return (
    <div data-ui="pane" className="pane-card flex min-h-0 min-w-0 flex-1 flex-col">
    <div data-ui="tabbar" className="flex h-8 shrink-0 items-center gap-1.5 border-b border-border px-1">
      <ShellLeadTools />
      <span className="truncate pl-1.5 text-caption font-bold uppercase tracking-widest text-muted-foreground">Overview</span>
      <span className="flex-1" />
      <ShellTrailTools />
    </div>
    <div className="op-overview"><div className="op-overview-inner">
      <div className="op-eyebrow">BTCT / Workspace overview</div>
      <h1>{workspace?.name ?? 'Your workspace'}</h1>
      <p className="op-overview-subtitle">Capture the evidence. Keep the notes. Build the report.</p>
      <div className="op-metrics">
        {[
          [localPages.length, 'Pages'],
          [nmapScans.filter((s) => s.workspaceId === activeWorkspaceId).length, 'Scan groups'],
          [typstAssets.filter((a) => a.workspaceId === activeWorkspaceId && !a.deletedAt).length, 'Assets'],
        ].map(([value, label]) => <div className="op-metric" key={label}><strong>{value}</strong><span>{label}</span></div>)}
      </div>
      <div className="op-overview-columns">
        <section>
          <h2 className="op-section-heading">Recently updated pages</h2>
          {recent.map((p) => <button className="op-recent" key={p.id} onClick={() => open('page', p.id, p.title)}>
            <FileText size={16} /><span className="truncate">{p.title || 'Untitled'}</span>
            <small>{new Date(p.updatedAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}</small><ArrowUpRight size={13} />
          </button>)}
          {!recent.length && <p className="py-6 text-muted-foreground">Create a page from the sidebar to begin documenting your work.</p>}
        </section>
        <section>
          <h2 className="op-section-heading">Workspace tools</h2>
          <div className="op-actions">
            <button className="op-action" onClick={() => open('assets', 'assets', 'Assets')}><Images size={18} /><span><strong>Manage screenshots</strong><small>Crop and redact the evidence</small></span><ArrowUpRight size={14} /></button>
            {typstOn && activeWorkspaceId && (
              <button className="op-action" onClick={() => open('typst', activeWorkspaceId, 'Report')}><FileType size={18} /><span><strong>Write the report</strong><small>Typst, with your screenshots as figures</small></span><ArrowUpRight size={14} /></button>
            )}
            <button className="op-action" onClick={() => open('cmdlog', 'cmdlog', 'Command Log')}><Terminal size={18} /><span><strong>Read the command log</strong><small>What the team actually ran</small></span><ArrowUpRight size={14} /></button>
            {nmapScans.length > 0 && nmapScans[0] && (
              <button className="op-action" onClick={() => open('nmap', nmapScans[0]!.id, nmapScans[0]!.name)}><Radar size={18} /><span><strong>Open a scan group</strong><small>Hosts, ports and NSE output</small></span><ArrowUpRight size={14} /></button>
            )}
          </div>
        </section>
      </div>
      <div className="op-footer"><span>BEEN THERE, CONQUERED THAT</span><span>Ctrl + K to find a page or command</span></div>
    </div></div>
    </div>
  );
}
