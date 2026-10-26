import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RotateCw, X } from 'lucide-react';
import { isChunkLoadError, shouldReloadForPreloadError } from '@/lib/preload-recovery';

/**
 * Contains a render error to the part of the app that threw.
 *
 * Without one, any throw inside a tab (a malformed record, an editor error on
 * odd markdown, a lazy chunk that 404s after a redeploy) unmounted the whole
 * React tree, and the persisted tabs replayed the crash on every reload.
 * SplitContainer puts one around each pane's content, keyed on the tab, and
 * App.tsx puts one around the shell.
 */
export interface ErrorBoundaryProps {
  children: ReactNode;
  /** Where this boundary sits, for the message and the console. */
  label: string;
  /** Offer "Close this tab" (pane boundaries). */
  onClose?: () => void;
  /** Offer a second recovery action beside Reload (the root closes every tab). */
  onReset?: { label: string; run: () => void };
  /** Fill the viewport (root) instead of the pane. */
  fullScreen?: boolean;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: unknown): State {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error(`[${this.props.label}] render failed:`, error, info.componentStack);
    // A lazy view whose chunk vanished in a redeploy: reload once on our own
    // (same one-per-minute guard as the vite:preloadError handler).
    if (isChunkLoadError(error)) {
      let storage: Storage | null = null;
      try { storage = window.sessionStorage; } catch { storage = null; }
      if (shouldReloadForPreloadError(storage, Date.now())) window.location.reload();
    }
  }

  private retry = () => this.setState({ error: null });

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    const chunk = isChunkLoadError(error);
    const { label, onClose, onReset, fullScreen } = this.props;
    const btn = 'flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1 text-xs hover:bg-accent';
    return (
      <div
        role="alert"
        data-testid="error-boundary"
        className={
          fullScreen
            ? 'flex h-viewport w-viewport items-center justify-center bg-background p-6 text-foreground'
            : 'flex h-full w-full items-center justify-center p-6 text-foreground'
        }
      >
        <div className="flex max-w-md flex-col gap-3 rounded-lg border border-destructive/40 bg-card p-4 text-sm">
          <div className="flex items-center gap-2 font-semibold">
            <AlertTriangle size={14} className="shrink-0 text-destructive" />
            {chunk ? 'This view could not load' : `Something went wrong in ${label}`}
          </div>
          <p className="text-xs text-muted-foreground">
            {chunk
              ? 'The app was probably updated on the server while this page was open. Reload to pick up the new version; your notes are saved.'
              : 'The rest of the app still works, and nothing you wrote is lost: notes are saved as you type.'}
          </p>
          {!chunk && (
            <pre className="max-h-24 overflow-auto whitespace-pre-wrap rounded bg-muted p-2 text-caption text-muted-foreground">
              {error.message || String(error)}
            </pre>
          )}
          <div className="flex flex-wrap gap-2">
            <button type="button" className={btn} onClick={() => window.location.reload()}>
              <RotateCw size={12} /> Reload
            </button>
            {!chunk && !fullScreen && (
              <button type="button" className={btn} onClick={this.retry}>
                Try again
              </button>
            )}
            {onClose && (
              <button type="button" className={btn} onClick={onClose}>
                <X size={12} /> Close this tab
              </button>
            )}
            {onReset && (
              <button type="button" className={btn} onClick={() => { onReset.run(); this.retry(); }}>
                {onReset.label}
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }
}
