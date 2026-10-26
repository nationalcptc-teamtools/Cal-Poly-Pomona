import { forwardRef, useId, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from 'react';
import { cn } from '@/lib/utils';

/**
 * Form controls. Text fields have no focus ring of their own (the Typst
 * Studio rule): focus shows as the accent border. Native <select> keeps the
 * chevron and popup theming from index.css (invariant #14).
 */
const FIELD =
  'w-full rounded-md border border-input bg-background px-2 py-1 text-xs text-foreground outline-none placeholder:text-muted-foreground focus:border-primary disabled:opacity-50';

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }>(
  function Input({ className, mono, ...rest }, ref) {
    return <input ref={ref} className={cn(FIELD, mono && 'font-mono', className)} {...rest} />;
  },
);

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement> & { mono?: boolean }>(
  function Textarea({ className, mono, ...rest }, ref) {
    return <textarea ref={ref} className={cn(FIELD, 'leading-relaxed', mono && 'font-mono', className)} {...rest} />;
  },
);

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select(
  { className, ...rest },
  ref,
) {
  return <select ref={ref} className={cn(FIELD, 'w-auto pr-7', className)} {...rest} />;
});

/** Small uppercase label over a control, the spec's "field label". */
export function FieldLabel({ children, htmlFor, className }: { children: ReactNode; htmlFor?: string; className?: string }) {
  return (
    <label htmlFor={htmlFor} className={cn('mb-1 block text-caption uppercase tracking-wider text-muted-foreground', className)}>
      {children}
    </label>
  );
}

/** Native checkbox with its label; the box takes the accent (index.css). */
export function Checkbox({
  checked,
  onChange,
  label,
  description,
  disabled,
  className,
  title,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: ReactNode;
  description?: ReactNode;
  disabled?: boolean;
  className?: string;
  title?: string;
}) {
  const id = useId();
  return (
    <label htmlFor={id} title={title} className={cn('flex cursor-pointer items-start gap-2 text-meta', disabled && 'cursor-not-allowed opacity-50', className)}>
      <input id={id} type="checkbox" className="mt-0.5" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span>
        <span className="block">{label}</span>
        {description && <span className="block text-caption text-muted-foreground">{description}</span>}
      </span>
    </label>
  );
}

/** On/off switch (role=switch). */
export function Switch({
  checked,
  onChange,
  label,
  disabled,
  className,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
  disabled?: boolean;
  className?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        'relative inline-flex h-4 w-7 shrink-0 items-center rounded-full border border-border transition-colors disabled:opacity-40',
        checked ? 'bg-primary' : 'bg-muted',
        className,
      )}
    >
      <span
        aria-hidden
        className={cn(
          'absolute h-3 w-3 rounded-full transition-[left]',
          checked ? 'left-[13px] bg-primary-foreground' : 'left-px bg-muted-foreground',
        )}
      />
    </button>
  );
}
