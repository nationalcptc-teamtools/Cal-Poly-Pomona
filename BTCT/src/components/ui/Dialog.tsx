import { useEffect, useId, useRef, type ReactNode, type RefObject } from 'react';
import { X } from 'lucide-react';
import { Portal } from '@/components/ui/Portal';
import { cn } from '@/lib/utils';

/**
 * The one modal dialog. Every overlay in the app (settings sheets, the
 * command palette, the image editors, confirms) is built on it, so they all
 * share the same behaviour:
 *
 * - renders into <body> through Portal (invariant #13), over a bg-overlay scrim;
 * - role="dialog", aria-modal, aria-labelledby on the title (or aria-label
 *   when `title` is not a plain heading);
 * - Escape closes the topmost open dialog only. A control inside that wants
 *   Escape for itself (an inline rename) calls `e.preventDefault()`, and the
 *   dialog leaves it alone;
 * - Tab and Shift+Tab stay inside; focus moves in on open (initialFocus, else
 *   the first [autofocus] or focusable element, else the sheet) and goes back
 *   to whatever had it before on close;
 * - a click on the scrim closes unless `dismissible` is false (a busy export);
 * - mousedown, click and contextmenu stop at the scrim, so the component
 *   that rendered the dialog never handles them (React bubbles portal events
 *   through the component tree).
 *
 * Mount it while open, or pass `open`. Stacking follows open order: a dialog
 * opened from another one is appended later to <body> and sits on top.
 */

/** Open dialogs, oldest first. Only the last one answers Escape. */
const stack: string[] = [];

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"]), [contenteditable="true"]';

/** jsdom lays nothing out, so a rendered-size check would hide every control there. */
const NO_LAYOUT = typeof navigator !== 'undefined' && /jsdom/i.test(navigator.userAgent);

export function focusables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (el) => !el.closest('[inert], [hidden]') && (NO_LAYOUT || el.getClientRects().length > 0),
  );
}

export type DialogSize = 'sm' | 'md' | 'lg' | 'xl' | 'full';
const SIZE: Record<DialogSize, string> = {
  sm: 'w-full max-w-sm',
  md: 'w-full max-w-md',
  lg: 'w-full max-w-2xl',
  xl: 'w-full max-w-4xl',
  full: 'h-[min(calc(92*var(--vh)),900px)] w-[min(1600px,calc(96*var(--vw)))]',
};

export interface DialogProps {
  open?: boolean;
  onClose: () => void;
  /** Heading text. Rendered in the header unless `hideHeader`. */
  title: ReactNode;
  /** Accessible name when `title` is not plain text or the header is hidden. */
  ariaLabel?: string;
  icon?: ReactNode;
  /** Extra controls in the header, left of the close button. */
  headerActions?: ReactNode;
  footer?: ReactNode;
  children: ReactNode;
  size?: DialogSize;
  /** false: Escape and the scrim do nothing (a run in progress). */
  dismissible?: boolean;
  hideHeader?: boolean;
  initialFocus?: RefObject<HTMLElement | null>;
  /** Vertical placement; the command palette sits high. */
  placement?: 'center' | 'top';
  className?: string;
  bodyClassName?: string;
  /** Override the sheet's role (alertdialog for destructive confirms). */
  role?: 'dialog' | 'alertdialog';
}

export function Dialog({
  open = true,
  onClose,
  title,
  ariaLabel,
  icon,
  headerActions,
  footer,
  children,
  size = 'md',
  dismissible = true,
  hideHeader,
  initialFocus,
  placement = 'center',
  className,
  bodyClassName,
  role = 'dialog',
}: DialogProps) {
  const id = useId();
  const titleId = `${id}-title`;
  const sheetRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  const dismissRef = useRef(dismissible);
  dismissRef.current = dismissible;

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    stack.push(id);
    const sheet = sheetRef.current;
    if (sheet) {
      const target =
        initialFocus?.current ??
        sheet.querySelector<HTMLElement>('[autofocus], [data-autofocus]') ??
        focusables(sheet).find((el) => !el.dataset.dialogClose) ??
        sheet;
      target.focus({ preventScroll: true });
    }
    const onKey = (e: KeyboardEvent) => {
      if (stack[stack.length - 1] !== id) return;
      if (e.key === 'Escape') {
        if (e.defaultPrevented || !dismissRef.current) return;
        e.preventDefault();
        e.stopPropagation();
        onCloseRef.current();
        return;
      }
      if (e.key === 'Tab' && sheetRef.current) {
        const list = focusables(sheetRef.current);
        if (list.length === 0) {
          e.preventDefault();
          sheetRef.current.focus();
          return;
        }
        const first = list[0]!;
        const last = list[list.length - 1]!;
        const active = document.activeElement as HTMLElement | null;
        const inside = !!active && sheetRef.current.contains(active);
        if (e.shiftKey && (active === first || !inside)) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && (active === last || !inside)) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    // Bubble phase on document: a control inside that handles Escape first
    // marks it defaultPrevented and keeps the dialog open.
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      const i = stack.lastIndexOf(id);
      if (i >= 0) stack.splice(i, 1);
      if (previous && previous.isConnected && typeof previous.focus === 'function') previous.focus({ preventScroll: true });
    };
    // initialFocus is read once on open on purpose.
  }, [open, id]);

  if (!open) return null;
  const plainTitle = typeof title === 'string' ? title : undefined;
  return (
    <Portal>
      <div
        className={cn(
          'fixed inset-0 z-[100] flex justify-center bg-overlay p-4',
          placement === 'top' ? 'items-start pt-[calc(16*var(--vh))]' : 'items-center',
        )}
        // A portal still bubbles through the React tree: keep the opener (a
        // toolbar that preventDefaults mousedown, a row that toggles on click)
        // from seeing pointer events meant for the dialog.
        onMouseDown={(e) => {
          e.stopPropagation();
          if (e.target === e.currentTarget && dismissRef.current) onCloseRef.current();
        }}
        onClick={(e) => e.stopPropagation()}
        onContextMenu={(e) => e.stopPropagation()}
      >
        <div
          ref={sheetRef}
          role={role}
          aria-modal="true"
          aria-labelledby={!hideHeader && !ariaLabel ? titleId : undefined}
          aria-label={hideHeader || ariaLabel ? (ariaLabel ?? plainTitle) : undefined}
          tabIndex={-1}
          className={cn(
            'flex max-h-[calc(92*var(--vh))] flex-col overflow-hidden rounded-lg bg-popover text-popover-foreground shadow-pane outline-none',
            SIZE[size],
            className,
          )}
        >
          {!hideHeader && (
            <div className="flex shrink-0 items-center gap-2 border-b border-border px-4 py-2">
              {icon && <span className="shrink-0 text-muted-foreground">{icon}</span>}
              <h2 id={titleId} className="min-w-0 flex-1 truncate text-sm font-semibold">
                {title}
              </h2>
              {headerActions}
              {dismissible && (
                <button
                  type="button"
                  data-dialog-close="true"
                  onClick={onClose}
                  aria-label="Close"
                  title="Close (Esc)"
                  className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
                >
                  <X size={14} />
                </button>
              )}
            </div>
          )}
          <div className={cn('min-h-0 flex-1 overflow-y-auto', !hideHeader && 'px-4 py-3', bodyClassName)}>{children}</div>
          {footer && <div className="flex shrink-0 items-center justify-end gap-2 border-t border-border px-4 py-2">{footer}</div>}
        </div>
      </div>
    </Portal>
  );
}
