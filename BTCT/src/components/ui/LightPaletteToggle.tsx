import { useState } from 'react';
import { Segmented } from '@/components/ui/Segmented';
import {
  LIGHT_PALETTES, LIGHT_PALETTE_LABELS, currentLightPalette, setLightPalette, type LightPalette,
} from '@/lib/light-palette';

/**
 * Paper / Linen / Dimmed / Classic: which colours light mode uses on this
 * device (src/lib/light-palette.ts). Applies at once and is saved for this
 * device; dark mode is not affected. Shown in Profile under the colour mode.
 */
export function LightPaletteToggle({ className }: { className?: string }) {
  const [palette, setPalette] = useState<LightPalette>(currentLightPalette);
  return (
    <Segmented
      label="Light palette"
      className={className}
      options={LIGHT_PALETTES.map((id) => ({ id, label: LIGHT_PALETTE_LABELS[id].label, title: LIGHT_PALETTE_LABELS[id].hint }))}
      value={palette}
      onChange={(p) => { setLightPalette(p); setPalette(p); }}
    />
  );
}
