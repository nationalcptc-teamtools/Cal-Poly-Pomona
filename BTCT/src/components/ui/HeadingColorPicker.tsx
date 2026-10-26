import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { HEADING_LEVELS, type HeadingLevel, type ThemePrefs } from '@/lib/editor-prefs';
import { HEADING_SWATCHES } from '@/lib/swatches';
import { Swatches, swatchChipClass } from '@/components/ui/Swatches';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Field';

/** Colour-wheel start value when nothing is set (the dark theme's body text). */
const WHEEL_FALLBACK = '#d1d1d1';

/**
 * Picker for note heading colours, shared by the per-user Profile editor
 * and the admin Theme dialog. Edits a `ThemePrefs` value: one colour for
 * every heading level plus optional per-level overrides. "Auto" clears a
 * colour back to "inherit the body text colour".
 */


const HEX_RE = /^#[0-9a-fA-F]{6}$/;

export function HeadingColorPicker({
  value,
  onChange,
  disabled,
}: {
  value: ThemePrefs;
  onChange: (next: ThemePrefs) => void;
  disabled?: boolean;
}) {
  const [advanced, setAdvanced] = useState(Object.keys(value.headings).length > 0);

  const setAll = (hex: string | null) => onChange({ ...value, headingColor: hex });
  const setLevel = (level: HeadingLevel, hex: string | null) => {
    const headings = { ...value.headings };
    if (hex) headings[level] = hex;
    else delete headings[level];
    onChange({ ...value, headings });
  };
  const colorFor = (level: HeadingLevel): string | undefined =>
    value.headings[level] ?? value.headingColor ?? undefined;

  return (
    <div className={disabled ? 'pointer-events-none opacity-50' : ''} aria-disabled={disabled}>
      {/* Sample so the choice is visible even with no editor open. */}
      <div className="mb-2 rounded-lg border border-border bg-background px-3 py-2">
        <div className="text-base font-bold leading-tight" style={{ color: colorFor('h1') }}>Heading 1</div>
        <div className="text-sm font-bold leading-tight" style={{ color: colorFor('h2') }}>Heading 2</div>
        <div className="text-meta text-muted-foreground">Body text is not affected.</div>
      </div>

      {/* One colour for every level */}
      <Swatches label="Heading colour presets" colors={HEADING_SWATCHES} value={value.headingColor} onPick={setAll}>
        <button
          type="button"
          onClick={() => setAll(null)}
          title="Inherit the body text colour"
          aria-pressed={value.headingColor === null}
          className={swatchChipClass(value.headingColor === null)}
        >
          Auto
        </button>
      </Swatches>
      <div className="mt-2 flex items-center gap-2">
        <input
          type="color"
          value={value.headingColor ?? WHEEL_FALLBACK}
          onChange={(e) => setAll(e.target.value)}
          title="Open colour wheel"
          aria-label="Heading colour"
          className="h-8 w-10 cursor-pointer rounded-md border border-input bg-background"
        />
        <HexInput value={value.headingColor} onCommit={setAll} placeholder="inherit" />
      </div>

      {/* Per-level overrides */}
      <Button
        variant="ghost"
        size="sm"
        aria-expanded={advanced}
        icon={advanced ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
        onClick={() => setAdvanced((a) => !a)}
        className="-ml-1 mt-2 px-1 py-0.5 text-caption text-muted-foreground hover:text-foreground"
      >
        Per-level overrides{Object.keys(value.headings).length > 0 ? ` (${Object.keys(value.headings).length})` : ''}
      </Button>
      {advanced && (
        <div className="mt-1.5 grid grid-cols-2 gap-x-3 gap-y-1.5">
          {HEADING_LEVELS.map((level) => (
            <div key={level} className="flex items-center gap-1.5">
              <span className="w-5 font-mono text-caption uppercase text-muted-foreground">{level}</span>
              <input
                type="color"
                value={value.headings[level] ?? value.headingColor ?? WHEEL_FALLBACK}
                onChange={(e) => setLevel(level, e.target.value)}
                aria-label={`${level} colour`}
                className="h-6 w-8 cursor-pointer rounded border border-input bg-background"
              />
              <HexInput value={value.headings[level] ?? null} onCommit={(hex) => setLevel(level, hex)} placeholder="auto" compact />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Hex text field that only commits a complete #RRGGBB (or empty, meaning
 * "auto"); partial typing stays local so a half-typed value never reaches
 * the live preview.
 */
function HexInput({
  value,
  onCommit,
  placeholder,
  compact,
}: {
  value: string | null;
  onCommit: (hex: string | null) => void;
  placeholder: string;
  compact?: boolean;
}) {
  const [draft, setDraft] = useState(value ?? '');
  // Re-sync when the committed value changes from outside (preset click).
  const [seen, setSeen] = useState(value);
  if (value !== seen) {
    setSeen(value);
    setDraft(value ?? '');
  }
  return (
    <Input
      mono
      type="text"
      aria-label="Hex colour"
      value={draft}
      placeholder={placeholder}
      onChange={(e) => {
        const v = e.target.value;
        setDraft(v);
        const t = v.trim();
        if (!t) onCommit(null);
        else if (HEX_RE.test(t)) onCommit(t);
      }}
      className={compact ? 'w-20 px-1.5 py-0.5 text-caption' : 'flex-1 py-1.5'}
    />
  );
}
