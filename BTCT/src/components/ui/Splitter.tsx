import type { KeyboardEvent, MouseEvent, PointerEvent } from 'react';
import { cn } from '@/lib/utils';

/**
 * The gap between two floating panes, which is also their resize handle
 * (Typst Studio): --pane-gap wide, nothing drawn at rest, a 2px accent bar
 * on hover and a full-strength one while dragging. role=separator with arrow
 * keys, so the handle works without a pointer too.
 *
 * Callers keep their own drag code (a DOM write per frame, one store commit
 * on release) and pass `onKeyStep` to move by a keyboard step.
 */
export function Splitter({
  orientation,
  onMouseDown,
  onPointerDown,
  onKeyStep,
  onReset,
  dragging,
  label,
  valueNow,
  valueMin,
  valueMax,
  className,
}: {
  /** 'vertical' sits between side-by-side panes (col-resize). */
  orientation: 'vertical' | 'horizontal';
  onMouseDown?: (e: MouseEvent) => void;
  /** For callers that drag with pointer events (the Report tab). */
  onPointerDown?: (e: PointerEvent) => void;
  /** -1 or +1: one keyboard step toward the start or the end. */
  onKeyStep?: (dir: -1 | 1) => void;
  /** Double-click (and Enter) resets to the default size. */
  onReset?: () => void;
  dragging?: boolean;
  label: string;
  valueNow?: number;
  valueMin?: number;
  valueMax?: number;
  className?: string;
}) {
  const vertical = orientation === 'vertical';
  const onKeyDown = (e: KeyboardEvent) => {
    const back = vertical ? 'ArrowLeft' : 'ArrowUp';
    const fwd = vertical ? 'ArrowRight' : 'ArrowDown';
    if (e.key === back || e.key === fwd) {
      if (!onKeyStep) return;
      e.preventDefault();
      onKeyStep(e.key === back ? -1 : 1);
    } else if (e.key === 'Enter' && onReset) {
      e.preventDefault();
      onReset();
    }
  };
  return (
    <div
      role="separator"
      aria-orientation={orientation}
      aria-label={label}
      aria-valuenow={valueNow === undefined ? undefined : Math.round(valueNow)}
      aria-valuemin={valueMin}
      aria-valuemax={valueMax}
      tabIndex={onKeyStep ? 0 : undefined}
      data-ui="splitter"
      data-dragging={dragging || undefined}
      onMouseDown={onMouseDown}
      onPointerDown={onPointerDown}
      onDoubleClick={onReset}
      onKeyDown={onKeyDown}
      className={cn(
        'group relative z-10 shrink-0 outline-none',
        vertical ? 'w-[var(--pane-gap)] cursor-col-resize self-stretch' : 'h-[var(--pane-gap)] cursor-row-resize',
        className,
      )}
    >
      <span
        aria-hidden
        className={cn(
          'pointer-events-none absolute rounded-full transition-colors group-hover:bg-primary/70 group-focus-visible:bg-primary group-active:bg-primary',
          vertical ? 'inset-y-0 left-1/2 w-0.5 -translate-x-1/2' : 'inset-x-0 top-1/2 h-0.5 -translate-y-1/2',
          dragging && 'bg-primary',
        )}
      />
    </div>
  );
}
