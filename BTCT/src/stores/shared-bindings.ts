/**
 * Wires the Zustand app store to Y.Map change events on the shared doc.
 *
 * Whenever another user (or this user from another tab) creates / updates
 * / deletes a workspace, page, change log, nmap scan or nmap machine,
 * the matching `load*()` action runs and
 * the UI re-renders.
 *
 * Coalesces bursts of changes via microtask debouncing so a multi-write
 * transaction (e.g. cascading delete) only triggers one reload per table.
 */
import { subscribeTable } from '@/realtime/shared-doc';
import { useAppStore } from './app-store';
import { useThemeStore, type PublicBlurSettings, type PublicThemeSettings } from './theme-store';

let bound = false;

export function bindSharedSubscriptions(): () => void {
  if (bound) return () => undefined;
  bound = true;

  const unsubs: Array<() => void> = [];

  const debounce = (fn: () => void) => {
    let queued = false;
    return () => {
      if (queued) return;
      queued = true;
      queueMicrotask(() => { queued = false; fn(); });
    };
  };

  const s = () => useAppStore.getState();

  unsubs.push(subscribeTable('workspaces',   debounce(() => { void s().loadWorkspaces(); })));
  unsubs.push(subscribeTable('pages',        debounce(() => { void s().loadPages().then(() => s().reconcileTabs()); })));
  unsubs.push(subscribeTable('changeLogs',   debounce(() => { void s().loadChangeLogs(); })));
  unsubs.push(subscribeTable('nmapScans',    debounce(() => { void s().loadNmapScans().then(() => s().reconcileTabs()); })));
  unsubs.push(subscribeTable('typstAssets',  debounce(() => { void s().loadTypstAssets(); })));
  unsubs.push(subscribeTable('assetFolders', debounce(() => { void s().loadAssetFolders(); })));
  unsubs.push(subscribeTable('commandLogs',  debounce(() => { void s().loadCommandLogs(); })));

  // Admin theme policy, mirrored into the doc by the server on every save
  // (LWW JSON): re-theme live. The store drops payloads older than the one
  // it already holds, so a stale IndexedDB replay can't undo a REST seed.
  unsubs.push(subscribeTable('settingsPublic', (e) => {
    if (e.keys.has('theme')) {
      useThemeStore.getState().applyServerTheme(e.current('theme') as PublicThemeSettings | undefined);
    }
    if (e.keys.has('blur')) {
      useThemeStore.getState().applyServerBlur(e.current('blur') as PublicBlurSettings | undefined);
    }
  }));

  // Reload only the scans whose machines actually changed: the event's
  // changed keys are machine ids, and each record (or a delete's oldValue)
  // carries its scanId. Reloading every known scan here made one port
  // toggle cost O(scans) table scans and store writes.
  const pendingScanIds = new Set<string>();
  let reloadAllScans = false;
  let machinesQueued = false;
  unsubs.push(subscribeTable('nmapMachines', (e) => {
    for (const [key, change] of e.keys) {
      const rec = (e.current(key) ?? change.oldValue) as { scanId?: string } | undefined;
      if (rec?.scanId) pendingScanIds.add(rec.scanId);
      else reloadAllScans = true; // malformed record: fall back to the old sweep
    }
    if (machinesQueued) return;
    machinesQueued = true;
    queueMicrotask(() => {
      machinesQueued = false;
      const st = s();
      const targets = reloadAllScans ? st.nmapScans.map((x) => x.id) : [...pendingScanIds];
      reloadAllScans = false;
      pendingScanIds.clear();
      for (const id of targets) void st.loadNmapMachines(id);
      // Web/app tool findings live on the machine record, so any machine
      // change may add or drop a host from the Web Scans section.
      void st.loadWebScanHosts();
    });
  }));

  return () => {
    bound = false;
    for (const u of unsubs) u();
  };
}
