import { useRef, type KeyboardEvent, type ReactNode } from 'react';
import { cn } from '@/lib/utils';

export interface SegmentedOption<T extends string> {
  id: T;
  label: ReactNode;
  title?: string;
}

/**
 * Segmented control (Typst Studio recipe): a bordered strip of options, the
 * chosen one filled with the accent. role=radiogroup with arrow-key
 * movement, so it reads and steers like a set of radio buttons.
 */
export function Segmented<T extends string>({
  options,
  value,
  onChange,
  label,
  size = 'sm',
  stretch,
  className,
}: {
  options: readonly SegmentedOption<T>[];
  value: T;
  onChange: (id: T) => void;
  /** Accessible name of the group. */
  label: string;
  size?: 'xs' | 'sm';
  /** Options share the full width. */
  stretch?: boolean;
  className?: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const move = (e: KeyboardEvent, i: number) => {
    const last = options.length - 1;
    const next =
      e.key === 'ArrowRight' || e.key === 'ArrowDown' ? (i === last ? 0 : i + 1)
      : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? (i === 0 ? last : i - 1)
      : -1;
    if (next < 0) return;
    e.preventDefault();
    const o = options[next];
    if (!o) return;
    onChange(o.id);
    refs.current[next]?.focus();
  };
  return (
    <div role="radiogroup" aria-label={label} className={cn('inline-flex overflow-hidden rounded-md border border-input', stretch && 'flex w-full', className)}>
      {options.map((o, i) => {
        const on = o.id === value;
        return (
          <button
            key={o.id}
            ref={(el) => { refs.current[i] = el; }}
            type="button"
            role="radio"
            aria-checked={on}
            tabIndex={on ? 0 : -1}
            title={o.title}
            onClick={() => onChange(o.id)}
            onKeyDown={(e) => move(e, i)}
            className={cn(
              'flex items-center justify-center gap-1 whitespace-nowrap',
              size === 'xs' ? 'px-1.5 py-0.5 text-micro uppercase tracking-wide' : 'px-2.5 py-1 text-caption',
              stretch && 'flex-1',
              i > 0 && 'border-l border-input',
              on ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-accent hover:text-foreground',
            )}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
