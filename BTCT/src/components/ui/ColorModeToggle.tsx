import { Moon, Sun } from 'lucide-react';
import { useAppStore } from '@/stores/app-store';
import { Segmented } from '@/components/ui/Segmented';

/**
 * Light / Dark segmented control. Applies at once and is saved for this
 * device (src/lib/color-mode.ts); it is not an account pref. Used in Profile
 * and the admin Theme dialog; the sidebar header keeps its one-click toggle.
 */
export function ColorModeToggle({ className }: { className?: string }) {
  const darkMode = useAppStore((s) => s.darkMode);
  const setDarkMode = useAppStore((s) => s.setDarkMode);
  return (
    <Segmented
      label="Colour mode"
      className={className}
      options={[
        { id: 'light', label: <><Sun size={12} /> Light</> },
        { id: 'dark', label: <><Moon size={12} /> Dark</> },
      ]}
      value={darkMode ? 'dark' : 'light'}
      onChange={(m) => setDarkMode(m === 'dark')}
    />
  );
}
