import { useState, useRef, useEffect } from 'react';
import { Palette, RotateCcw, Lock } from 'lucide-react';
import { Dialog } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';
import { Banner } from '@/components/ui/Banner';
import { Checkbox, FieldLabel, Input } from '@/components/ui/Field';
import { useThemeStore } from '@/stores/theme-store';
import { useAppStore } from '@/stores';
import { useAuthStore } from '@/auth/auth-store';
import { applyHeadingColors, DEFAULT_THEME_COLOR, resolveEffectiveHeadings, THEME_PRIMARY } from '@/lib/theme';
import { readableTextOn } from '@/lib/contrast';
import { resolvePrefs, type ThemePrefs } from '@/lib/editor-prefs';
import { HeadingColorPicker } from '@/components/ui/HeadingColorPicker';
import { ColorModeToggle } from '@/components/ui/ColorModeToggle';
import { Swatches } from '@/components/ui/Swatches';
import { ACCENT_SWATCHES } from '@/lib/swatches';


const HEX_RE = /^#[0-9a-fA-F]{6}$/;

export function ThemePicker({ onClose }: { onClose: () => void }) {
  const currentColor = useThemeStore((s) => s.color);
  const storeHeadings = useThemeStore((s) => s.headings);
  const storeLock = useThemeStore((s) => s.lock);
  const updateTheme = useThemeStore((s) => s.updateTheme);
  const user = useAuthStore((s) => s.user);

  const [color, setColor] = useState(currentColor);
  const [headings, setHeadings] = useState<ThemePrefs>(storeHeadings);
  const [lock, setLock] = useState(storeLock);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // Preview the candidate default heading colours in open editors while the
  // dialog is open (what an account without its own colours will see);
  // revert to this admin's own effective colours on close unless saved.
  const initialHeadings = useRef(
    resolveEffectiveHeadings({ headings: storeHeadings, lock: storeLock }, resolvePrefs(user).theme).headings,
  );
  const saved = useRef(false);
  useEffect(() => () => {
    if (!saved.current) applyHeadingColors(initialHeadings.current);
  }, []);
  const handleHeadingsChange = (t: ThemePrefs) => {
    setHeadings(t);
    applyHeadingColors(t);
  };

  const dirty =
    color.toLowerCase() !== currentColor.toLowerCase() ||
    JSON.stringify(headings) !== JSON.stringify(storeHeadings) ||
    lock !== storeLock;

  const handleSave = async () => {
    if (color !== '' && !HEX_RE.test(color)) {
      setError('color must be a #RRGGBB hex value, or Default');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await updateTheme({ color, headings, lock });
      saved.current = true;
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'save failed');
    } finally {
      setSaving(false);
    }
  };

  // '' means "no accent": the theme's own primary, which differs per mode.
  const darkMode = useAppStore((st) => st.darkMode);
  const shown = HEX_RE.test(color) ? color : THEME_PRIMARY[darkMode ? 'dark' : 'light'];
  const handleReset = () => {
    setColor(DEFAULT_THEME_COLOR);
    setError(null);
  };

  return (
    <Dialog
      title="Theme"
      icon={<Palette size={14} style={{ color: shown }} />}
      onClose={onClose}
      size="md"
      footer={
        <>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={handleSave} disabled={!dirty || saving}>
            {saving ? 'Saving…' : 'Save'}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <p className="text-meta text-muted-foreground">
          The accent colour and default note heading colours for the entire workspace. Affects every user; saved on the server.
        </p>

        <div className="flex items-center justify-between">
          <FieldLabel className="mb-0">
            Mode <span className="normal-case tracking-normal">(this device)</span>
          </FieldLabel>
          <ColorModeToggle />
        </div>

        {/* Live preview */}
        <div className="flex items-center gap-3 rounded-md border border-border bg-background p-3">
          <div className="h-12 w-12 shrink-0 rounded-full border border-border" style={{ backgroundColor: shown }} aria-hidden />
          <div className="flex min-w-0 flex-1 flex-col gap-1.5">
            <div className="font-mono text-meta uppercase text-muted-foreground">
              {HEX_RE.test(color) ? color.toUpperCase() : 'Theme default'}
            </div>
            <span
              aria-hidden
              className="self-start rounded-md px-2.5 py-1 text-meta font-medium"
              style={{ backgroundColor: shown, color: readableTextOn(shown) }}
            >
              Preview button
            </span>
          </div>
        </div>

        <div>
          <FieldLabel>Accent presets</FieldLabel>
          <Swatches label="Accent presets" size="lg" colors={ACCENT_SWATCHES} value={color} onPick={setColor} />
        </div>

        <div>
          <FieldLabel>Custom</FieldLabel>
          <div className="flex items-center gap-2">
            <input
              type="color"
              value={shown}
              onChange={(e) => setColor(e.target.value)}
              title="Open color wheel"
              aria-label="Accent colour wheel"
              className="h-8 w-12 cursor-pointer rounded-md border border-input bg-background p-0.5"
            />
            <Input mono value={color} onChange={(e) => setColor(e.target.value)} placeholder="theme default" aria-label="Accent hex" className="flex-1 py-1.5" />
            <Button size="sm" variant="outline" icon={<RotateCcw size={11} />} onClick={handleReset} title="Reset to the theme's own accent">
              Default
            </Button>
          </div>
        </div>

        <div>
          <FieldLabel>Note headings</FieldLabel>
          <p className="mb-1.5 text-caption text-muted-foreground">
            Default heading colours for every account. Users can pick their own unless you lock them.
          </p>
          <HeadingColorPicker value={headings} onChange={handleHeadingsChange} />
          <div className="mt-3 rounded-md border border-border bg-background p-2.5">
            <Checkbox
              checked={lock}
              onChange={setLock}
              label={<span className="flex items-center gap-1 font-medium"><Lock size={11} /> Hardlock heading colours</span>}
              description="Force these colours on everyone. Users' own choices are kept but ignored until you unlock."
            />
          </div>
        </div>

        {error && <Banner tone="red">{error}</Banner>}
      </div>
    </Dialog>
  );
}
