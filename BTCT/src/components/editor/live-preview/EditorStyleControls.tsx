// Editor style controls: the Profile segmented toggle and the command
// palette item. Both apply the style live (no editor rebuild) through
// `applyEditorStyle`; the palette item also saves it to the account prefs.

import { useCallback } from 'react';
import { Command } from 'cmdk';
import { Code2, PenLine } from 'lucide-react';
import { useAuthStore } from '@/auth/auth-store';
import { resolvePrefs } from '@/lib/editor-prefs';
import { Segmented } from '@/components/ui/Segmented';
import {
  EDITOR_STYLES,
  EDITOR_STYLE_LABELS,
  applyEditorStyle,
  isSourceMode,
  otherEditorStyle,
  setSourceMode,
  type EditorStyle,
} from './editor-style';

/** Segmented "Live preview (Obsidian) | Blocks (Notion)" toggle. */
export function EditorStyleToggle({
  value,
  onChange,
}: {
  value: EditorStyle;
  onChange: (style: EditorStyle) => void;
}) {
  return (
    <Segmented
      label="Editor style"
      stretch
      options={EDITOR_STYLES.map((s) => ({ id: s, label: EDITOR_STYLE_LABELS[s] }))}
      value={value}
      onChange={onChange}
    />
  );
}

/**
 * Switch to the other editor style now and save it to the account. The
 * switch is applied before the save so it feels instant; a failed save puts
 * the saved style back.
 */
export function useToggleEditorStyle(): () => Promise<void> {
  const updateProfile = useAuthStore((s) => s.updateProfile);
  return useCallback(async () => {
    const user = useAuthStore.getState().user;
    const resolved = resolvePrefs(user);
    const next = otherEditorStyle(resolved.editorStyle);
    applyEditorStyle(next);
    if (!user) return;
    try {
      await updateProfile({ prefs: { ...resolved, editorStyle: next } });
    } catch {
      applyEditorStyle(resolved.editorStyle);
    }
  }, [updateProfile]);
}

/** Command palette entry: "Editor style: switch to …". */
export function EditorStyleCommandItem({ onDone, className }: { onDone: () => void; className?: string }) {
  const user = useAuthStore((s) => s.user);
  const toggle = useToggleEditorStyle();
  const next = otherEditorStyle(resolvePrefs(user).editorStyle);
  return (
    <Command.Item
      value={`Editor style: switch to ${EDITOR_STYLE_LABELS[next]} live preview obsidian blocks notion`}
      onSelect={() => { void toggle(); onDone(); }}
      className={className}
    >
      <PenLine size={14} /> Editor style: switch to {EDITOR_STYLE_LABELS[next]}
    </Command.Item>
  );
}

/**
 * Command palette entry: Obsidian's "Toggle Live Preview/Source mode". Source
 * mode shows every line's markdown, not only the cursor line's; it lasts for
 * this browser session and exists only in the Live preview style.
 */
export function SourceModeCommandItem({ onDone, className }: { onDone: () => void; className?: string }) {
  const user = useAuthStore((s) => s.user);
  if (resolvePrefs(user).editorStyle !== 'live') return null;
  const on = isSourceMode();
  return (
    <Command.Item
      value={`Toggle Live Preview/Source mode ${on ? 'live preview' : 'source mode'} markdown obsidian`}
      onSelect={() => { setSourceMode(!on); onDone(); }}
      className={className}
    >
      <Code2 size={14} /> {on ? 'Source mode: back to Live preview' : 'Source mode: show all markdown'}
    </Command.Item>
  );
}
