import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { useAppStore } from '@/stores';
import { useShallow } from 'zustand/react/shallow';
import { ChangeLogPanel } from '@/components/sidebar/ChangeLogPanel';
import { PageHistoryPanel } from '@/components/sidebar/PageHistoryPanel';
import { LastEditedBadge } from '@/components/sidebar/LastEditedBadge';
const ExportDialog = lazy(() => import('@/components/ui/ExportDialog').then((m) => ({ default: m.ExportDialog })));
import { Portal } from '@/components/ui/Portal';
import { PanelRightClose } from 'lucide-react';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Button, IconButton } from '@/components/ui/Button';
import { PaneHeader } from '@/components/ui/Panel';
import { focusables } from '@/components/ui/Dialog';
import { cn } from '@/lib/utils';

/**
 * The properties pane (page versions, last edit, change log, export and the
 * database delete). Docked as a card right of the panes; on a narrow screen
 * (`overlay`) it slides over them with a scrim and closes on Escape.
 */
export function RightSidebar({ overlay = false }: { overlay?: boolean }) {
  const { toggleRightSidebar, activeTabId, tabs, deleteDatabase } = useAppStore(useShallow((s) => ({
    toggleRightSidebar: s.toggleRightSidebar,
    activeTabId: s.activeTabId,
    tabs: s.tabs,
    deleteDatabase: s.deleteDatabase,
  })));
  const [exportOpen, setExportOpen] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  const activeTab = tabs.find((t) => t.id === activeTabId);

  const rootRef = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!overlay) return;
    const panel = rootRef.current;
    const previous = document.activeElement as HTMLElement | null;
    if (panel) (focusables(panel)[0] ?? panel).focus({ preventScroll: true });
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || e.defaultPrevented) return;
      if (document.querySelector('[aria-modal="true"]:not([data-ui="properties"])')) return;
      e.preventDefault();
      toggleRightSidebar();
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      if (previous && previous.isConnected) previous.focus({ preventScroll: true });
    };
  }, [overlay, toggleRightSidebar]);

  return (
    <>
    {overlay && <div aria-hidden className="fixed inset-0 z-[90] bg-overlay" onMouseDown={toggleRightSidebar} />}
    <aside
      ref={rootRef}
      data-ui="properties"
      aria-label="Properties"
      role={overlay ? 'dialog' : 'complementary'}
      aria-modal={overlay || undefined}
      tabIndex={overlay ? -1 : undefined}
      className={cn(
        'pane-card flex flex-col outline-none',
        overlay
          ? 'fixed bottom-2 right-2 top-2 z-[95] w-[min(320px,calc(100*var(--vw)-16px))]'
          : 'ml-[var(--pane-gap)] h-full w-[var(--properties-width)] shrink-0',
      )}
    >
      <PaneHeader
        title="Properties"
        actions={
          <IconButton label="Close properties" onClick={toggleRightSidebar}>
            <PanelRightClose size={14} />
          </IconButton>
        }
      />

      <div className="min-h-0 flex-1 overflow-y-auto px-3 py-3">
        {activeTab && (activeTab.kind === 'page' || activeTab.kind === 'history') && (
          <>
            <LastEditedBadge target="page" targetId={activeTab.entityId} />
            <div className="mt-3 border-t border-border pt-3">
              <PageHistoryPanel pageId={activeTab.entityId} />
            </div>
          </>
        )}
        {!activeTab && (
          <p className="text-xs text-muted-foreground">Open a page to see its properties.</p>
        )}
        <div className={cn(activeTab && (activeTab.kind === 'page' || activeTab.kind === 'history') && 'mt-3 border-t border-border pt-3', !activeTab && 'mt-3')}>
          <ChangeLogPanel />
        </div>
      </div>

      <div className="flex shrink-0 flex-col gap-1 border-t border-border p-2">
        <Button variant="outline" size="sm" className="w-full" onClick={() => setExportOpen(true)}>
          Export / Import
        </Button>
        <Button variant="ghost" size="sm" className="w-full text-status-red hover:bg-status-red/10" onClick={() => setShowDeleteConfirm(true)}>
          Delete database
        </Button>
      </div>

      {exportOpen && <Suspense fallback={<Portal><div role="status" className="panel-loading">Loading export…</div></Portal>}><ExportDialog open={exportOpen} onClose={() => setExportOpen(false)} /></Suspense>}

      {showDeleteConfirm && (
        <ConfirmDialog
          title="Delete Database"
          destructive
          message={<>This will permanently delete all workspaces, pages, and data. Type <span className="font-mono font-bold text-foreground">DELETE</span> to confirm.</>}
          input={{ match: 'DELETE', placeholder: 'Type DELETE...' }}
          confirmLabel="Delete"
          onConfirm={() => { void deleteDatabase(); setShowDeleteConfirm(false); }}
          onCancel={() => setShowDeleteConfirm(false)}
        />
      )}
    </aside>
    </>
  );
}
