import { AlertTriangle, Info, X } from 'lucide-react';
import { dismissNotice, useEditorNotices } from '@/lib/editor-notices';
import { cn } from '@/lib/utils';

/** The stack of editor notices (failed uploads, oversized pastes), bottom right. */
export function EditorNotices() {
  const notices = useEditorNotices((s) => s.notices);
  if (notices.length === 0) return null;
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-80 max-w-[calc(100%-2rem)] flex-col gap-2">
      {notices.map((n) => (
        <div
          key={n.id}
          role={n.tone === 'error' ? 'alert' : 'status'}
          data-testid="editor-notice"
          className={cn(
            'pointer-events-auto flex flex-col gap-2 rounded-lg border bg-card p-3 text-xs shadow-lg',
            n.tone === 'error' ? 'border-destructive/50' : 'border-border',
          )}
        >
          <div className="flex items-start gap-2">
            {n.tone === 'error'
              ? <AlertTriangle size={13} className="mt-0.5 shrink-0 text-destructive" />
              : <Info size={13} className="mt-0.5 shrink-0 text-primary" />}
            <span className="min-w-0 flex-1 break-words">{n.message}</span>
            <button type="button" aria-label="Dismiss" onClick={() => dismissNotice(n.id)}
              className="shrink-0 rounded p-0.5 text-muted-foreground hover:bg-accent">
              <X size={11} />
            </button>
          </div>
          {n.actions.length > 0 && (
            <div className="flex flex-wrap justify-end gap-1.5">
              {n.actions.map((a) => (
                <button
                  key={a.label}
                  type="button"
                  onClick={() => { dismissNotice(n.id); a.run(); }}
                  className="rounded-md border border-border px-2 py-0.5 font-medium hover:bg-accent"
                >
                  {a.label}
                </button>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
