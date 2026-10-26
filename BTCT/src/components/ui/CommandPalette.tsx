import { useAppStore } from '@/stores';
import { useShallow } from 'zustand/react/shallow';
import { useThemeStore } from '@/stores/theme-store';
import { Command } from 'cmdk';
import { useRef } from 'react';
import { Dialog } from '@/components/ui/Dialog';
import { v4 as uuidv4 } from 'uuid';
import { EditorStyleCommandItem, SourceModeCommandItem } from '@/components/editor/live-preview/EditorStyleControls';
import { FileText, Plus, Settings, Users, Terminal, Images, Keyboard, FileType } from 'lucide-react';

export function CommandPalette() {
  const {
    commandPaletteOpen,
    setCommandPaletteOpen,
    pages,
    openTab,
    createPage,
    activeWorkspaceId,
    toggleDarkMode,
    setFollowPanelOpen,
  } = useAppStore(useShallow((s) => ({
    commandPaletteOpen: s.commandPaletteOpen,
    setCommandPaletteOpen: s.setCommandPaletteOpen,
    pages: s.pages,
    openTab: s.openTab,
    createPage: s.createPage,
    activeWorkspaceId: s.activeWorkspaceId,
    toggleDarkMode: s.toggleDarkMode,
    setFollowPanelOpen: s.setFollowPanelOpen,
  })));
  const typstOn = useThemeStore((s) => s.features.typst);
  const inputRef = useRef<HTMLInputElement>(null);

  if (!commandPaletteOpen) return null;

  const visiblePages = pages.filter((p) => !p.isGraphPage);

  return (
    <Dialog
      title="Command palette"
      ariaLabel="Command palette"
      hideHeader
      placement="top"
      initialFocus={inputRef}
      onClose={() => setCommandPaletteOpen(false)}
      className="w-[520px] max-w-full"
    >
        <Command label="Command palette" className="flex flex-col">
          <div className="flex items-center border-b border-border px-3">
            <Command.Input
              ref={inputRef}
              placeholder="Type a command or search..."
              className="flex-1 bg-transparent py-2.5 text-sm outline-none placeholder:text-muted-foreground"
            />
          </div>
          <Command.List className="max-h-[300px] overflow-y-auto p-1.5">
            <Command.Empty className="p-4 text-center text-sm text-muted-foreground">No results found.</Command.Empty>

            <Command.Group heading="Actions" className="mb-2 [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:pb-1 [&_[cmdk-group-heading]]:text-caption [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-muted-foreground">
              <Command.Item
                onSelect={async () => {
                  if (!activeWorkspaceId) return;
                  const page = await createPage(null, 'Untitled');
                  openTab({ id: uuidv4(), kind: 'page', entityId: page.id, title: page.title });
                  setCommandPaletteOpen(false);
                }}
                className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs aria-selected:bg-accent"
              >
                <Plus size={14} /> New Page
              </Command.Item>
              <Command.Item
                onSelect={() => { openTab({ id: uuidv4(), kind: 'cmdlog', entityId: 'cmdlog', title: 'Command Log' }); setCommandPaletteOpen(false); }}
                className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs aria-selected:bg-accent"
              >
                <Terminal size={14} /> Open Command Log
              </Command.Item>
              <Command.Item
                onSelect={() => { openTab({ id: uuidv4(), kind: 'assets', entityId: 'assets', title: 'Assets' }); setCommandPaletteOpen(false); }}
                className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs aria-selected:bg-accent"
              >
                <Images size={14} /> Open Assets Manager
              </Command.Item>
              {typstOn && (
                <Command.Item
                  onSelect={() => {
                    if (!activeWorkspaceId) return;
                    openTab({ id: uuidv4(), kind: 'typst', entityId: activeWorkspaceId, title: 'Report' });
                    setCommandPaletteOpen(false);
                  }}
                  className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs aria-selected:bg-accent"
                >
                  <FileType size={14} /> Write the Report
                </Command.Item>
              )}
              <Command.Item
                onSelect={() => { openTab({ id: uuidv4(), kind: 'shortcuts', entityId: 'shortcuts', title: 'Shortcuts' }); setCommandPaletteOpen(false); }}
                className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs aria-selected:bg-accent"
              >
                <Keyboard size={14} /> Keyboard shortcuts
              </Command.Item>
              <Command.Item
                onSelect={() => { setFollowPanelOpen(true); setCommandPaletteOpen(false); }}
                className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs aria-selected:bg-accent"
              >
                <Users size={14} /> Active Users / Follow
              </Command.Item>
              <Command.Item
                onSelect={() => { toggleDarkMode(); setCommandPaletteOpen(false); }}
                className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs aria-selected:bg-accent"
              >
                <Settings size={14} /> Toggle Light / Dark Mode
              </Command.Item>
              <EditorStyleCommandItem
                onDone={() => setCommandPaletteOpen(false)}
                className="flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-1.5 text-sm aria-selected:bg-accent"
              />
              <SourceModeCommandItem
                onDone={() => setCommandPaletteOpen(false)}
                className="flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-1.5 text-sm aria-selected:bg-accent"
              />
            </Command.Group>

            {visiblePages.length > 0 && (
              <Command.Group heading="Pages" className="mb-2 [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:pb-1 [&_[cmdk-group-heading]]:text-caption [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-muted-foreground">
                {visiblePages.map((page) => (
                  <Command.Item
                    key={page.id}
                    value={page.title}
                    onSelect={() => {
                      openTab({ id: uuidv4(), kind: 'page', entityId: page.id, title: page.title });
                      setCommandPaletteOpen(false);
                    }}
                    className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs aria-selected:bg-accent"
                  >
                    <FileText size={14} />{page.icon ? <span>{page.icon}</span> : null} {page.title}
                  </Command.Item>
                ))}
              </Command.Group>
            )}

          </Command.List>
        </Command>
    </Dialog>
  );
}
