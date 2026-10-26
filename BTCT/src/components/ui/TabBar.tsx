import { memo, useCallback, useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { useAppStore } from '@/stores';
import { X, FileText, Menu, PanelRightOpen, Radar, Monitor, Terminal, History, Images, Keyboard, FileType, Globe } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { TabItem, TabKind } from '@/types';
import { IconButton } from '@/components/ui/Button';
import { useNarrowLayout } from '@/lib/use-layout-width';
import { toLayoutPx } from '@/lib/ui-zoom';

/** Drag MIME for a tab chip (strip reorder and pane drop zones). */
export const TAB_DRAG_TYPE = 'application/x-btct-tab';

function LiveClock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    const tick = () => {
      clearTimeout(timer);
      if (document.hidden) return;
      setNow(new Date());
      timer = setTimeout(tick, 60_000 - Date.now() % 60_000);
    };
    tick();
    document.addEventListener('visibilitychange', tick);
    return () => { clearTimeout(timer); document.removeEventListener('visibilitychange', tick); };
  }, []);
  const fmt = now.toLocaleDateString('en-US', { weekday: 'short', day: '2-digit', month: 'short', year: '2-digit', timeZone: 'UTC' }).toUpperCase()
    + ', ' + now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }) + 'Z';
  return <span className="whitespace-nowrap px-1 font-mono text-caption text-muted-foreground">{fmt}</span>;
}

/** The lucide icon for a tab kind (strip chips, overview links). */
export function TabIcon({ kind, size = 12 }: { kind: TabKind; size?: number }) {
  switch (kind) {
    case 'page': return <FileText size={size} />;
    case 'nmap-machine': return <Monitor size={size} />;
    case 'nmap': return <Radar size={size} />;
    case 'cmdlog': return <Terminal size={size} />;
    case 'history': return <History size={size} />;
    case 'assets': return <Images size={size} />;
    case 'typst': return <FileType size={size} />;
    case 'web-scan': return <Globe size={size} />;
    default: return <Keyboard size={size} />;
  }
}

/** Leading shell control in the top-left pane header: the drawer toggle on a narrow screen. */
export function ShellLeadTools() {
  const narrow = useNarrowLayout();
  const open = useAppStore((s) => s.navDrawerOpen);
  const setOpen = useAppStore((s) => s.setNavDrawerOpen);
  if (!narrow) return null;
  return (
    <IconButton
      label="Open navigation"
      data-ui="drawer-toggle"
      aria-expanded={open}
      aria-controls="btct-nav"
      onClick={(e) => { e.stopPropagation(); setOpen(true); }}
      className="my-auto"
    >
      <Menu size={14} />
    </IconButton>
  );
}

/** Trailing shell controls in the top-right pane header: the UTC clock and the properties toggle. */
export function ShellTrailTools() {
  const narrow = useNarrowLayout();
  const rightOpen = useAppStore((s) => s.rightSidebarOpen);
  const toggleRight = useAppStore((s) => s.toggleRightSidebar);
  return (
    <div className="flex shrink-0 items-center gap-1 pl-1">
      {!narrow && <LiveClock />}
      {!rightOpen && (
        <IconButton label="Open properties" onClick={(e) => { e.stopPropagation(); toggleRight(); }}>
          <PanelRightOpen size={14} />
        </IconButton>
      )}
    </div>
  );
}

/**
 * Underline tab strip for one pane (theme `tabs: underline`): chips sit on
 * the 32px pane header, the active one in foreground with a 2px accent
 * underline. The strip owns drags over it (reorder, with a 2px bar where the
 * chip will land) and stops them, so the pane's drop zones stay quiet.
 */
export function TabStrip({
  tabs,
  activeId,
  onActivate,
  onClose,
  onReorder,
  onDragOverStrip,
}: {
  tabs: TabItem[];
  activeId: string | null;
  onActivate: (id: string) => void;
  onClose: (id: string) => void;
  onReorder: (draggedId: string, targetId: string, place: 'before' | 'after') => void;
  /** A tab drag entered the strip (the pane clears its drop zone). */
  onDragOverStrip?: () => void;
}) {
  return (
    <div
      role="tablist"
      aria-label="Open tabs"
      className="flex min-w-0 flex-1 items-stretch overflow-x-auto overflow-y-hidden [scrollbar-width:none]"
      onDragEnter={(e) => { if (e.dataTransfer.types.includes(TAB_DRAG_TYPE)) e.stopPropagation(); }}
      onDragLeave={(e) => e.stopPropagation()}
      onDragOver={(e) => {
        if (!e.dataTransfer.types.includes(TAB_DRAG_TYPE)) return;
        e.preventDefault();
        e.stopPropagation();
        onDragOverStrip?.();
      }}
      onDrop={(e) => {
        // Dropped on the strip itself (past the last chip): move to the end.
        const dragged = e.dataTransfer.getData(TAB_DRAG_TYPE);
        if (!dragged) return;
        e.preventDefault();
        e.stopPropagation();
        const last = tabs[tabs.length - 1];
        if (last && last.id !== dragged) onReorder(dragged, last.id, 'after');
        onDragOverStrip?.();
      }}
    >
      {tabs.map((tab) => (
        <TabChip
          key={tab.id}
          tab={tab}
          active={tab.id === activeId}
          onActivate={onActivate}
          onClose={onClose}
          onReorder={onReorder}
          onDragHover={onDragOverStrip}
        />
      ))}
    </div>
  );
}

const TabChip = memo(function TabChip({
  tab,
  active,
  onActivate,
  onClose,
  onReorder,
  onDragHover,
}: {
  tab: TabItem;
  active: boolean;
  onActivate: (id: string) => void;
  onClose: (id: string) => void;
  onReorder: (draggedId: string, targetId: string, place: 'before' | 'after') => void;
  onDragHover?: () => void;
}) {
  const [dropHint, setDropHint] = useState<'before' | 'after' | null>(null);
  // Keep the active chip in view when the strip overflows (a tab opened
  // from the sidebar lands at the end, past the visible chips).
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current;
    const strip = el?.parentElement;
    if (!active || !el || !strip) return;
    // Scroll only the strip (scrollIntoView could also move the clipped
    // pane ancestors). Rects are screen px; scrollLeft is layout px.
    const r = el.getBoundingClientRect();
    const s = strip.getBoundingClientRect();
    if (r.left < s.left) strip.scrollLeft -= toLayoutPx(s.left - r.left);
    else if (r.right > s.right) strip.scrollLeft += toLayoutPx(r.right - s.right);
  }, [active]);
  const onKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.target !== e.currentTarget) return;
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onActivate(tab.id); }
    else if (e.key === 'Delete') { e.preventDefault(); onClose(tab.id); }
  }, [onActivate, onClose, tab.id]);

  return (
    <div
      ref={ref}
      role="tab"
      aria-selected={active}
      tabIndex={0}
      title={tab.title}
      draggable
      data-tab-id={tab.id}
      onDragStart={(e) => {
        e.dataTransfer.setData(TAB_DRAG_TYPE, tab.id);
        e.dataTransfer.effectAllowed = 'move';
      }}
      onDragOver={(e) => {
        if (!e.dataTransfer.types.includes(TAB_DRAG_TYPE)) return;
        e.preventDefault();
        e.stopPropagation();
        e.dataTransfer.dropEffect = 'move';
        onDragHover?.();
        const r = e.currentTarget.getBoundingClientRect();
        setDropHint(e.clientX < r.left + r.width / 2 ? 'before' : 'after');
      }}
      onDragLeave={() => setDropHint(null)}
      onDrop={(e) => {
        const dragged = e.dataTransfer.getData(TAB_DRAG_TYPE);
        if (!dragged) return;
        e.preventDefault();
        e.stopPropagation();
        if (dropHint && dragged !== tab.id) onReorder(dragged, tab.id, dropHint);
        setDropHint(null);
      }}
      onDragEnd={() => setDropHint(null)}
      onClick={() => onActivate(tab.id)}
      onKeyDown={onKeyDown}
      className={cn(
        'group relative -mb-px flex shrink-0 cursor-grab items-center gap-1.5 border-b-2 pl-2.5 pr-1 text-xs outline-none active:cursor-grabbing focus-visible:bg-accent',
        active
          ? 'border-primary text-foreground'
          : 'border-transparent text-muted-foreground hover:bg-accent/60 hover:text-foreground',
      )}
    >
      {dropHint && (
        <span
          aria-hidden
          className={cn(
            'pointer-events-none absolute bottom-1 top-1 w-0.5 rounded-full bg-primary',
            dropHint === 'before' ? 'left-0' : 'right-0',
          )}
        />
      )}
      <span className={cn('shrink-0', active ? 'text-primary' : 'text-muted-foreground')}><TabIcon kind={tab.kind} size={12} /></span>
      <span className="max-w-[160px] truncate">{tab.title}</span>
      <button
        type="button"
        tabIndex={-1}
        aria-label={`Close ${tab.title}`}
        title={`Close ${tab.title}`}
        onClick={(e) => { e.stopPropagation(); onClose(tab.id); }}
        className="op-tab-close rounded p-0.5 hover:bg-accent hover:text-foreground"
      >
        <X size={11} />
      </button>
    </div>
  );
});
