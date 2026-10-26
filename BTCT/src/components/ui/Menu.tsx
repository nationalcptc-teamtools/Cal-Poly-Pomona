import { forwardRef, type ButtonHTMLAttributes, type HTMLAttributes, type ReactNode } from 'react';
import { cn } from '@/lib/utils';

/**
 * Menu surface for context menus and dropdowns: popover fill, pane shadow
 * instead of a border, 4px radius, 12px items. Positioning stays with the
 * caller (fixed at the pointer, or absolute under a trigger).
 */
export const MenuSurface = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(function MenuSurface(
  { className, children, ...rest },
  ref,
) {
  return (
    <div ref={ref} role="menu" className={cn('min-w-44 rounded-md bg-popover p-1 text-xs text-popover-foreground shadow-pane', className)} {...rest}>
      {children}
    </div>
  );
});

export const MenuItem = forwardRef<
  HTMLButtonElement,
  ButtonHTMLAttributes<HTMLButtonElement> & { icon?: ReactNode; danger?: boolean; hint?: ReactNode }
>(function MenuItem({ className, icon, danger, hint, children, type = 'button', ...rest }, ref) {
  return (
    <button
      ref={ref}
      type={type}
      role="menuitem"
      className={cn(
        'flex w-full items-center gap-2 rounded px-2 py-1 text-left hover:bg-accent focus-visible:bg-accent disabled:pointer-events-none disabled:opacity-40',
        danger && 'text-status-red',
        className,
      )}
      {...rest}
    >
      {icon && <span className="shrink-0 text-muted-foreground">{icon}</span>}
      <span className="min-w-0 flex-1 truncate">{children}</span>
      {hint && <span className="shrink-0 text-caption text-muted-foreground">{hint}</span>}
    </button>
  );
});

export function MenuSeparator() {
  return <div role="separator" className="my-1 h-px bg-border" />;
}

export function MenuLabel({ children }: { children: ReactNode }) {
  return <div className="px-2 pb-0.5 pt-1 text-caption uppercase tracking-wider text-muted-foreground">{children}</div>;
}
