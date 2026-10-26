import { useRef, useState, type ReactNode } from 'react';
import { AlertTriangle } from 'lucide-react';
import { Dialog } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Field';
import { cn } from '@/lib/utils';

/**
 * The app's replacement for `window.confirm` / `window.prompt`, built on
 * Dialog (portal, focus trap, Escape cancels, labelled). With `input` it asks
 * for a value (Enter confirms); otherwise it is a plain yes/no whose confirm
 * button takes focus. `busy` disables both buttons and dismissal while the
 * action runs; `error` shows under the message.
 */
export function ConfirmDialog({
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  destructive = false,
  input,
  busy = false,
  error,
  children,
  onConfirm,
  onCancel,
}: {
  title: string;
  message?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  destructive?: boolean;
  /** Ask for a text value; `initial` prefills it. `match` requires exact text (type-to-confirm). */
  input?: { initial?: string; placeholder?: string; match?: string; label?: string };
  busy?: boolean;
  error?: string | null;
  /** Extra content between the message and the buttons. */
  children?: ReactNode;
  onConfirm: (value: string) => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState(input?.initial ?? '');
  const confirmRef = useRef<HTMLButtonElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const ready = !input || (input.match !== undefined ? value === input.match : !!value.trim());
  const submit = () => {
    if (!ready || busy) return;
    onConfirm(input?.match !== undefined ? value : value.trim());
  };

  return (
    <Dialog
      title={title}
      onClose={onCancel}
      size="sm"
      hideHeader
      ariaLabel={title}
      role={destructive ? 'alertdialog' : 'dialog'}
      dismissible={!busy}
      initialFocus={input ? inputRef : confirmRef}
      className="rounded-2xl bg-card"
      bodyClassName="p-6"
    >
      <div className={cn('mb-2 flex items-center gap-2 text-sm font-semibold', destructive && 'text-status-red')}>
        {destructive && <AlertTriangle size={16} />}
        {title}
      </div>
      {message && <div className="mb-4 text-xs leading-relaxed text-muted-foreground">{message}</div>}
      {children}
      {input && (
        <>
          {input.label && <div className="mb-1 text-meta text-muted-foreground">{input.label}</div>}
          <Input
            ref={inputRef}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); submit(); } }}
            placeholder={input.placeholder}
            disabled={busy}
            className="mb-4 rounded-lg px-3 py-2 text-sm"
          />
        </>
      )}
      {error && <div className="mb-3 text-meta text-status-red">{error}</div>}
      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={onCancel} disabled={busy}>
          {cancelLabel}
        </Button>
        <Button ref={confirmRef} variant={destructive ? 'danger' : 'primary'} onClick={submit} disabled={!ready || busy}>
          {busy ? `${confirmLabel}…` : confirmLabel}
        </Button>
      </div>
    </Dialog>
  );
}
