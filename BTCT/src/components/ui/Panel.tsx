import type { HTMLAttributes, ReactNode } from 'react';
import { cn } from '@/lib/utils';

/** A floating pane: card fill, pane radius and shadow (the .pane-card recipe). */
export function Panel({ className, children, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn('pane-card flex min-h-0 flex-col', className)} {...rest}>
      {children}
    </div>
  );
}

/**
 * 32px pane header: an uppercase muted title, optional status, and actions
 * on the right (IconButton or Button size="xs").
 */
export function PaneHeader({
  title,
  icon,
  status,
  actions,
  className,
}: {
  title: ReactNode;
  icon?: ReactNode;
  status?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('flex h-8 shrink-0 items-center gap-1.5 border-b border-border px-2', className)}>
      {icon && <span className="shrink-0 text-muted-foreground">{icon}</span>}
      <span className="truncate text-caption font-bold uppercase tracking-widest text-muted-foreground">{title}</span>
      {status && <span className="truncate text-caption uppercase tracking-wide text-muted-foreground">{status}</span>}
      {actions && <div className="ml-auto flex shrink-0 items-center gap-0.5">{actions}</div>}
    </div>
  );
}

/** Uppercase section heading inside a dialog or settings body. */
export function SectionHeading({ children, className }: { children: ReactNode; className?: string }) {
  return <h3 className={cn('mb-2 text-meta font-bold uppercase tracking-widest text-muted-foreground', className)}>{children}</h3>;
}
