import { useState } from 'react';
import { Keyboard, RotateCcw } from 'lucide-react';
import { Dialog } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';
import { Banner } from '@/components/ui/Banner';
import { useAuthStore, type AuthUser } from '@/auth/auth-store';
import {
  KEYBIND_ACTIONS,
  DEFAULT_KEYBINDS,
  resolvePrefs,
  formatShortcut,
  shortcutFromEvent,
  parseShortcut,
  type KeybindAction,
} from '@/lib/editor-prefs';

// Editor keybinds are stored per account. This dialog captures new shortcuts
// and persists them through the same `/api/me/profile` endpoint that stores the
// profile color, so they follow the account across devices. Changes apply live
// (the editor reads keybinds from a module-level ref synced in App.tsx).
export function KeybindsDialog({ onClose }: { onClose: () => void }) {
  const user = useAuthStore((s) => s.user) as AuthUser;
  const updateProfile = useAuthStore((s) => s.updateProfile);

  const resolved = resolvePrefs(user);
  const [keybinds, setKeybinds] = useState<Record<KeybindAction, string>>(resolved.keybinds);
  const [capturing, setCapturing] = useState<KeybindAction | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const dirty = KEYBIND_ACTIONS.some(({ id }) => keybinds[id] !== resolved.keybinds[id]);

  const captureKeydown = (action: KeybindAction, e: React.KeyboardEvent) => {
    // Keep this dialog's capture from leaking to the global app shortcuts
    // (Ctrl+K command palette, arrow tab-switching, etc.).
    e.preventDefault();
    e.stopPropagation();
    if (e.key === 'Escape') {
      setCapturing(null);
      setError(null);
      return;
    }
    const shortcut = shortcutFromEvent(e.nativeEvent);
    if (!shortcut) return; // still waiting for a non-modifier key
    const parsed = parseShortcut(shortcut);
    if (!parsed || !(parsed.mod || parsed.alt)) {
      setError('Use a shortcut with Ctrl/⌘ or Alt');
      return;
    }
    setKeybinds((prev) => ({ ...prev, [action]: shortcut }));
    setCapturing(null);
    setError(null);
  };

  const handleReset = () => {
    setKeybinds({ ...DEFAULT_KEYBINDS });
    setCapturing(null);
    setError(null);
  };

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      await updateProfile({ prefs: { ...resolved, keybinds } });
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'save failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog
      title="Editor Keybinds"
      icon={<Keyboard size={14} className="text-primary" />}
      onClose={onClose}
      size="md"
      footer={
        <>
          <Button size="sm" variant="outline" icon={<RotateCcw size={11} />} onClick={handleReset} className="mr-auto text-muted-foreground">
            Defaults
          </Button>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={handleSave} disabled={!dirty || saving}>
            {saving ? 'Saving…' : 'Save'}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-meta text-muted-foreground">
          Shortcuts for this account. Click a binding, then press the keys (must include Ctrl/⌘ or Alt).
        </p>

        <div className="flex flex-col gap-1.5">
          {KEYBIND_ACTIONS.map(({ id, label }) => {
            const isCapturing = capturing === id;
            return (
              <div
                key={id}
                className="flex items-center justify-between gap-3 rounded-md border border-border bg-background px-3 py-2"
              >
                <span className="text-xs">{label}</span>
                <button
                  type="button"
                  onClick={() => { setCapturing(id); setError(null); }}
                  onKeyDown={isCapturing ? (e) => captureKeydown(id, e) : undefined}
                  className={`min-w-[120px] rounded-md border px-2 py-1 text-center font-mono text-meta outline-none transition ${
                    isCapturing
                      ? 'border-primary bg-primary/10 text-primary'
                      : 'border-input hover:border-primary/60'
                  }`}
                >
                  {isCapturing ? 'Press keys…' : formatShortcut(keybinds[id])}
                </button>
              </div>
            );
          })}
        </div>

        <div className="rounded-md border border-border bg-background px-3 py-2">
          <div className="mb-1 text-micro font-bold uppercase tracking-widest text-muted-foreground">
            Built-in (not rebindable)
          </div>
          <ul className="space-y-0.5 text-meta text-muted-foreground">
            <li><span className="font-mono">Esc</span> selects the current block; arrows move, Shift extends</li>
            <li><span className="font-mono">Ctrl+A</span> selects block text, then the block, then all blocks</li>
            <li><span className="font-mono">Ctrl+Shift+↑/↓</span> moves a block; <span className="font-mono">Ctrl+D</span> duplicates (block selected)</li>
            <li><span className="font-mono">Ctrl+Shift+0..8</span> turns into text / H1-H3 / to-do / lists / code</li>
          </ul>
        </div>

        {error && <Banner tone="red">{error}</Banner>}
      </div>
    </Dialog>
  );
}
