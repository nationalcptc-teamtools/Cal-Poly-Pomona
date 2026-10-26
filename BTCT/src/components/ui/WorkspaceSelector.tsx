import { useState, useEffect } from 'react';
import { useAppStore } from '@/stores';
import { useShallow } from 'zustand/react/shallow';
import { Briefcase, Plus, Trash2, ChevronUp } from 'lucide-react';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { IconButton } from '@/components/ui/Button';
import { Input } from '@/components/ui/Field';
import { MenuItem, MenuLabel, MenuSurface } from '@/components/ui/Menu';
import { cn } from '@/lib/utils';

export function WorkspaceSelector() {
  const { workspaces, activeWorkspaceId, setActiveWorkspace, createWorkspace, deleteWorkspace, loadPages } =
    useAppStore(useShallow((s) => ({
      workspaces: s.workspaces,
      activeWorkspaceId: s.activeWorkspaceId,
      setActiveWorkspace: s.setActiveWorkspace,
      createWorkspace: s.createWorkspace,
      deleteWorkspace: s.deleteWorkspace,
      loadPages: s.loadPages,
    })));
  const [isOpen, setIsOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [pendingDelete, setPendingDelete] = useState<{ id: string; name: string } | null>(null);

  const activeWs = workspaces.find((w) => w.id === activeWorkspaceId);

  // The dropdown is a light popover, not a dialog: Escape closes it.
  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && !e.defaultPrevented) setIsOpen(false); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [isOpen]);

  const handleSwitch = (id: string) => {
    setActiveWorkspace(id);
    void loadPages();
    setIsOpen(false);
  };

  const handleCreate = async () => {
    if (!newName.trim()) return;
    const ws = await createWorkspace(newName.trim(), '');
    setNewName('');
    handleSwitch(ws.id);
  };

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        aria-haspopup="true"
        title="Switch workspace"
        className="flex h-7 w-full items-center gap-2 rounded px-1.5 text-left hover:bg-accent"
      >
        <Briefcase size={13} className="shrink-0 text-muted-foreground" />
        <span className="min-w-0 flex-1 truncate text-xs font-medium">{activeWs?.name ?? 'No workspace'}</span>
        <ChevronUp size={12} className={cn('shrink-0 text-muted-foreground transition-transform', !isOpen && 'rotate-180')} />
      </button>

      {isOpen && (
        <MenuSurface className="absolute bottom-full left-0 right-0 z-40 mb-1.5 p-1.5" aria-label="Workspaces">
          <MenuLabel>Workspaces</MenuLabel>
          {workspaces.map((ws) => (
            <div key={ws.id} className="group flex items-center gap-0.5">
              <MenuItem
                icon={<Briefcase size={11} />}
                onClick={() => handleSwitch(ws.id)}
                aria-current={ws.id === activeWorkspaceId || undefined}
                className={cn(ws.id === activeWorkspaceId && 'bg-accent font-medium')}
              >
                {ws.name}
              </MenuItem>
              <IconButton
                label={`Delete workspace ${ws.name}`}
                title="Delete workspace"
                tone="danger"
                onClick={() => setPendingDelete({ id: ws.id, name: ws.name })}
                className="opacity-0 focus-visible:opacity-100 group-hover:opacity-100"
              >
                <Trash2 size={11} />
              </IconButton>
            </div>
          ))}
          <div className="mt-1.5 flex items-center gap-1 border-t border-border pt-1.5">
            <Input
              placeholder="New workspace..."
              aria-label="New workspace name"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') void handleCreate(); }}
              className="flex-1"
            />
            <IconButton label="Create workspace" onClick={() => void handleCreate()}>
              <Plus size={13} />
            </IconButton>
          </div>
        </MenuSurface>
      )}

      {pendingDelete && (
        <ConfirmDialog
          title="Delete Workspace"
          destructive
          message={<>This will permanently delete the workspace and all its data. Type <span className="font-mono font-bold text-foreground">{pendingDelete.name}</span> to confirm.</>}
          input={{ match: pendingDelete.name, placeholder: 'Type workspace name...' }}
          confirmLabel="Delete"
          onConfirm={() => { void deleteWorkspace(pendingDelete.id); setPendingDelete(null); }}
          onCancel={() => setPendingDelete(null)}
        />
      )}
    </div>
  );
}
