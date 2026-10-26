import type { ReactNode } from 'react';
import { AlertTriangle, CheckCircle2, Info, X } from 'lucide-react';
import { cn } from '@/lib/utils';

export type BannerTone = 'red' | 'amber' | 'green' | 'blue' | 'neutral';

const TONE: Record<BannerTone, string> = {
  red: 'border-status-red/40 bg-status-red/10 text-status-red',
  amber: 'border-status-amber/40 bg-status-amber/10 text-status-amber',
  green: 'border-status-green/40 bg-status-green/10 text-status-green',
  blue: 'border-status-blue/40 bg-status-blue/10 text-status-blue',
  neutral: 'border-border bg-muted/40 text-foreground',
};
const ICON: Record<BannerTone, typeof Info> = {
  red: AlertTriangle,
  amber: AlertTriangle,
  green: CheckCircle2,
  blue: Info,
  neutral: Info,
};

/**
 * Tinted inline bar, the app's feedback surface (there are no toasts):
 * 10% fill, 40% border, text in the full status colour. `flush` drops the
 * radius and side borders for a bar under a pane header.
 */
export function Banner({
  tone = 'neutral',
  children,
  actions,
  onDismiss,
  icon,
  flush,
  className,
  role,
}: {
  tone?: BannerTone;
  children: ReactNode;
  /** Buttons on the right (use Button size="sm"). */
  actions?: ReactNode;
  onDismiss?: () => void;
  /** false hides the icon; a node replaces it. */
  icon?: ReactNode | false;
  flush?: boolean;
  className?: string;
  role?: 'status' | 'alert';
}) {
  const Icon = ICON[tone];
  return (
    <div
      role={role ?? (tone === 'red' ? 'alert' : 'status')}
      className={cn(
        'flex items-start gap-2 border px-3 py-1.5 text-meta',
        flush ? 'border-x-0 border-t-0' : 'rounded-md',
        TONE[tone],
        className,
      )}
    >
      {icon !== false && <span className="mt-px shrink-0">{icon ?? <Icon size={13} />}</span>}
      <div className="min-w-0 flex-1 leading-relaxed">{children}</div>
      {actions && <div className="flex shrink-0 items-center gap-1.5">{actions}</div>}
      {onDismiss && (
        <button type="button" onClick={onDismiss} aria-label="Dismiss" title="Dismiss" className="shrink-0 rounded p-0.5 hover:bg-current/15">
          <X size={12} />
        </button>
      )}
    </div>
  );
}
