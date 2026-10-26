// ─────────────────────────────────────────────────────────────────────────
// The preview's find bar: Ctrl/⌘+F over the rendered report.
//
// Floats over the top right of the page area, like a browser's find bar. The
// matching is lib/preview-find; this component only edits the query and
// steps through the results the preview hands it.
// ─────────────────────────────────────────────────────────────────────────

import { useEffect, useRef, type KeyboardEvent, type RefObject } from 'react';
import { CaseSensitive, ChevronDown, ChevronUp, Search, X } from 'lucide-react';
import { IconButton } from '@/components/ui/Button';

interface Props {
  query: string;
  onQuery: (q: string) => void;
  caseSensitive: boolean;
  onToggleCase: () => void;
  /** "3 of 12", "No matches", or "" (lib/preview-find `matchLabel`). */
  label: string;
  total: number;
  onNext: () => void;
  onPrev: () => void;
  onClose: () => void;
  /** Bumped by every Ctrl/⌘+F, so a second press re-focuses and selects the query. */
  focusNonce: number;
  inputRef?: RefObject<HTMLInputElement | null>;
}

export function PreviewFindBar({ query, onQuery, caseSensitive, onToggleCase, label, total, onNext, onPrev, onClose, focusNonce, inputRef }: Props) {
  const ownRef = useRef<HTMLInputElement>(null);
  const ref = inputRef ?? ownRef;

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.focus();
    el.select();
  }, [focusNonce, ref]);

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (e.shiftKey) onPrev(); else onNext();
    } else if (e.key === 'Escape') {
      // Claim the key (invariant 14): nothing behind the bar should also close.
      e.preventDefault();
      e.stopPropagation();
      onClose();
    }
  };

  return (
    <div
      role="search"
      aria-label="Find in the preview"
      data-testid="preview-find-bar"
      className="absolute left-3 right-3 top-2 z-20 ml-auto flex w-fit max-w-full items-center gap-1 rounded-md border border-border bg-popover px-1.5 py-1 shadow-pane"
    >
      <div className="flex min-w-0 flex-1 items-center gap-1 rounded border border-border bg-background px-1.5">
        <Search size={12} className="shrink-0 text-muted-foreground" />
        <input
          ref={ref}
          value={query}
          onChange={(e) => onQuery(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Find in the preview"
          aria-label="Find in the preview"
          spellCheck={false}
          className="w-44 min-w-0 flex-1 bg-transparent py-1 text-meta text-foreground outline-none placeholder:text-muted-foreground"
        />
        <span aria-live="polite" data-testid="preview-find-count" className="shrink-0 whitespace-nowrap font-mono text-caption tabular-nums text-muted-foreground">
          {label}
        </span>
      </div>
      <IconButton label="Match case" pressed={caseSensitive} onClick={onToggleCase} className="h-6 w-6">
        <CaseSensitive size={14} />
      </IconButton>
      <div aria-hidden className="mx-0.5 h-4 w-px bg-border" />
      <IconButton label="Previous match" title="Previous match (Shift+Enter)" onClick={onPrev} disabled={total === 0} className="h-6 w-6">
        <ChevronUp size={14} />
      </IconButton>
      <IconButton label="Next match" title="Next match (Enter)" onClick={onNext} disabled={total === 0} className="h-6 w-6">
        <ChevronDown size={14} />
      </IconButton>
      <IconButton label="Close find" title="Close (Esc)" onClick={onClose} className="h-6 w-6">
        <X size={14} />
      </IconButton>
    </div>
  );
}
