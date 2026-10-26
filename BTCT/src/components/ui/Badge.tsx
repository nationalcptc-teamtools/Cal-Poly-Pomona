import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

export type Tone = 'neutral' | 'primary' | 'green' | 'blue' | 'purple' | 'amber' | 'red';

const TINT: Record<Tone, string> = {
  neutral: 'bg-muted text-muted-foreground',
  // Accent tint with foreground text: any admin accent stays readable.
  primary: 'bg-primary/15 text-foreground',
  green: 'bg-status-green/12 text-status-green',
  blue: 'bg-status-blue/12 text-status-blue',
  purple: 'bg-status-purple/12 text-status-purple',
  amber: 'bg-status-amber/12 text-status-amber',
  red: 'bg-status-red/12 text-status-red',
};
const SOLID: Record<Tone, string> = {
  neutral: 'bg-muted-foreground text-card',
  primary: 'bg-primary text-primary-foreground',
  green: 'bg-status-green text-card',
  blue: 'bg-status-blue text-card',
  purple: 'bg-status-purple text-card',
  amber: 'bg-status-amber text-card',
  red: 'bg-destructive text-destructive-foreground',
};

/**
 * Small uppercase label chip ("PLACED", "ADMIN", a count). Tinted by
 * default; `solid` fills with the status colour and uses the card colour for
 * text, which reads in both modes because status hues are light in dark
 * mode and deep in light mode.
 */
export function Badge({
  tone = 'neutral',
  solid,
  children,
  className,
  title,
}: {
  tone?: Tone;
  solid?: boolean;
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        'inline-flex shrink-0 items-center gap-0.5 rounded px-1 py-px text-micro font-semibold uppercase tracking-wide',
        solid ? SOLID[tone] : TINT[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}
