import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

/**
 * A row of round colour presets. The selected one gets the focus-ring colour,
 * so it reads in both modes (the old white ring vanished on a light page).
 */
export function Swatches({
  colors,
  value,
  onPick,
  size = 'md',
  children,
  label,
}: {
  colors: readonly string[];
  /** Currently chosen hex, compared case-insensitively. */
  value: string | null | undefined;
  onPick: (hex: string) => void;
  size?: 'sm' | 'md' | 'lg';
  /** Extra controls placed first in the row (an "Auto" chip, for example). */
  children?: ReactNode;
  label?: string;
}) {
  const v = (value ?? '').toLowerCase();
  const dim = size === 'lg' ? 'h-7 w-7' : size === 'sm' ? 'h-5 w-5' : 'h-6 w-6';
  return (
    <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label={label}>
      {children}
      {colors.map((c) => {
        const on = v === c.toLowerCase();
        return (
          <button
            key={c}
            type="button"
            onClick={() => onPick(c)}
            title={c}
            aria-label={c}
            aria-pressed={on}
            className={cn(
              dim,
              'rounded-full border transition',
              on ? 'border-foreground ring-2 ring-ring' : 'border-border hover:border-muted-foreground',
            )}
            style={{ backgroundColor: c }}
          />
        );
      })}
    </div>
  );
}

/** Classes for a chip in a swatch row that is not a colour ("Auto"). */
export function swatchChipClass(on: boolean): string {
  return cn(
    'h-6 rounded-full border px-2 text-caption transition',
    on ? 'border-foreground ring-2 ring-ring' : 'border-border text-muted-foreground hover:border-muted-foreground',
  );
}
