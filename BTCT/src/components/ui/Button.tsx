import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { cn } from '@/lib/utils';

/**
 * Buttons, after the Typst Studio recipes (theme `buttons: solid`).
 *
 * variant  primary  solid accent fill, text picked by contrast (--primary-foreground)
 *          danger   solid destructive fill
 *          outline  1px border, accent-surface hover
 *          ghost    no border or fill until hover (toolbars, rows, headers)
 *          subtle   muted fill, for secondary actions inside a card
 * size     xs  compact uppercase (pane headers, dialog toolbars), 10px
 *          sm  toolbar / inline, 12px
 *          md  dialog footer, 12px medium (the default)
 */
export type ButtonVariant = 'primary' | 'danger' | 'outline' | 'ghost' | 'subtle';
export type ButtonSize = 'xs' | 'sm' | 'md';

const VARIANT: Record<ButtonVariant, string> = {
  primary: 'bg-primary text-primary-foreground hover:opacity-90',
  danger: 'bg-destructive text-destructive-foreground hover:opacity-90',
  outline: 'border border-border text-foreground hover:bg-accent',
  ghost: 'text-foreground hover:bg-accent',
  subtle: 'bg-muted text-foreground hover:bg-accent',
};
const SIZE: Record<ButtonSize, string> = {
  xs: 'gap-1 rounded px-1.5 py-0.5 text-caption uppercase tracking-wide',
  sm: 'gap-1 rounded-md px-2 py-1 text-xs',
  md: 'gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium',
};

export function buttonClass(variant: ButtonVariant = 'outline', size: ButtonSize = 'md', className?: string): string {
  return cn(
    'inline-flex shrink-0 items-center justify-center whitespace-nowrap select-none disabled:pointer-events-none disabled:opacity-40',
    VARIANT[variant],
    SIZE[size],
    className,
  );
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Leading icon (a lucide element). */
  icon?: ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'outline', size = 'md', icon, className, type = 'button', children, ...rest },
  ref,
) {
  return (
    <button ref={ref} type={type} className={buttonClass(variant, size, className)} {...rest}>
      {icon}
      {children}
    </button>
  );
});

export interface IconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'aria-label'> {
  /** Required: becomes both aria-label and the native tooltip. */
  label: string;
  size?: 'sm' | 'md';
  /** Pressed state for toggles (aria-pressed, accent fill). */
  pressed?: boolean;
  tone?: 'default' | 'danger';
}

/** Icon-only ghost button. Always labelled, so screen readers name it. */
export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { label, size = 'md', pressed, tone = 'default', className, type = 'button', title, children, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      aria-label={label}
      title={title ?? label}
      aria-pressed={pressed}
      className={cn(
        'inline-flex shrink-0 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground disabled:pointer-events-none disabled:opacity-40',
        size === 'sm' ? 'p-0.5' : 'p-1',
        pressed && 'bg-accent text-foreground',
        tone === 'danger' && 'hover:bg-status-red/15 hover:text-status-red',
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  );
});

/**
 * A filter or option chip that stays pressed (status, time window, operator,
 * tool): 1px border, accent border and tint when on. aria-pressed carries
 * the state, so a group of them reads as toggles, not links.
 */
export const ToggleChip = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement> & { pressed: boolean; mono?: boolean }>(
  function ToggleChip({ pressed, mono, className, type = 'button', children, ...rest }, ref) {
    return (
      <button
        ref={ref}
        type={type}
        aria-pressed={pressed}
        className={cn(
          'inline-flex shrink-0 items-center gap-1 rounded border px-2 py-0.5 text-caption disabled:pointer-events-none disabled:opacity-40',
          mono && 'font-mono',
          pressed
            ? 'border-primary bg-primary/15 text-foreground'
            : 'border-border text-muted-foreground hover:bg-accent hover:text-foreground',
          className,
        )}
        {...rest}
      >
        {children}
      </button>
    );
  },
);
