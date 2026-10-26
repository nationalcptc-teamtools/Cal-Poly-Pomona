// The "Ask where to save each export" switch (only where the browser has a
// system save dialog) and the one-time Firefox hint about the browser's own
// "Always ask you where to save files" setting. Both read src/lib/save-dialog.ts.
import { useEffect, useState } from 'react';
import { X } from 'lucide-react';
import { Checkbox } from '@/components/ui/Field';
import { IconButton } from '@/components/ui/Button';
import { getAskWhereToSave, onAskWhereToSaveChange, saveDialogSupported, setAskWhereToSave } from '@/lib/save-dialog';

const HINT_KEY = 'btct.hint.firefoxSaveDialog';

function isFirefox(): boolean {
  return typeof navigator !== 'undefined' && /firefox\//i.test(navigator.userAgent);
}

function hintDismissed(): boolean {
  try { return localStorage.getItem(HINT_KEY) === 'dismissed'; } catch { return false; }
}

/** Checkbox for the per-device preference. Renders nothing without a save dialog. */
export function AskWhereToSaveToggle({ className = '' }: { className?: string }) {
  const [on, setOn] = useState(getAskWhereToSave);
  useEffect(() => onAskWhereToSaveChange(setOn), []);
  if (!saveDialogSupported()) return null;
  return (
    <Checkbox
      className={`items-center ${className}`}
      title="Open the system save dialog for every export, so you pick the folder and name. Off: files go straight to your Downloads folder."
      checked={on}
      onChange={setAskWhereToSave}
      label={<>Ask where to save each export <span className="text-muted-foreground">(this device)</span></>}
    />
  );
}

/**
 * Firefox has no save dialog for pages to open, so it saves wherever its own
 * download setting says. Shown in Firefox until dismissed (per browser).
 */
export function FirefoxSaveHint() {
  const [hidden, setHidden] = useState(() => saveDialogSupported() || !isFirefox() || hintDismissed());
  if (hidden) return null;
  const dismiss = () => {
    try { localStorage.setItem(HINT_KEY, 'dismissed'); } catch { /* storage blocked: hidden for this view only */ }
    setHidden(true);
  };
  return (
    <div role="note" data-testid="firefox-save-hint" className="flex items-start gap-2 rounded-md border border-border bg-muted/40 px-2 py-1.5 text-meta leading-relaxed text-muted-foreground">
      <p className="flex-1">
        Firefox saves downloads straight to your Downloads folder. To choose the folder for each file, open
        Firefox <b>Settings &gt; General &gt; Files and Applications &gt; Downloads</b> and select
        <b> Always ask you where to save files</b>.
      </p>
      <IconButton size="sm" label="Dismiss" title="Do not show this again" onClick={dismiss}>
        <X size={12} />
      </IconButton>
    </div>
  );
}
