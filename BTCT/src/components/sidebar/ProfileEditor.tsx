import { useState, useRef, useEffect } from 'react';
import { Download, Minus, Plus, Upload } from 'lucide-react';
import { Dialog } from '@/components/ui/Dialog';
import { Button, IconButton } from '@/components/ui/Button';
import { Input } from '@/components/ui/Field';
import { Segmented } from '@/components/ui/Segmented';
import { Banner } from '@/components/ui/Banner';
import { useAuthStore, type AuthUser } from '@/auth/auth-store';
import {
  resolvePrefs,
  resolveBlurStrengthPolicy,
  isThemeCustomized,
  applyNoteWidth,
  NOTE_WIDTHS,
  type BlurDefaults,
  type EditorPrefs,
  type FollowPrefs,
  type FollowPrecision,
  type ThemePrefs,
  type NoteWidth,
} from '@/lib/editor-prefs';
import { MAX_STRENGTH, MIN_STRENGTH } from '@/lib/blur-math';
import { applyCodeAccent } from '@/lib/code-accent';
import { ColorModeToggle } from '@/components/ui/ColorModeToggle';
import { LightPaletteToggle } from '@/components/ui/LightPaletteToggle';
import { Swatches } from '@/components/ui/Swatches';
import { USER_SWATCHES } from '@/lib/swatches';
import { DEFAULT_UI_ZOOM, MAX_UI_ZOOM, MIN_UI_ZOOM, applyUiZoom, getUiZoom, onUiZoomChange, stepUiZoom, uiZoomSupported } from '@/lib/ui-zoom';
import { applyHeadingColors, resolveEffectiveHeadings } from '@/lib/theme';
import { useThemeStore } from '@/stores/theme-store';
import { usePresenceRoster } from '@/realtime/presence';
import { HeadingColorPicker } from '@/components/ui/HeadingColorPicker';
import { downloadAsZip } from '@/lib/download-zip';
import { readUploadText } from '@/lib/zip-upload';
import { sanitizeSegment } from '@/lib/export-names';
import { saveDialogSupported } from '@/lib/save-dialog';
import { AskWhereToSaveToggle, FirefoxSaveHint } from '@/components/ui/SaveLocationSetting';
import { applyEditorStyle, type EditorStyle } from '@/components/editor/live-preview/editor-style';
import { EditorStyleToggle } from '@/components/editor/live-preview/EditorStyleControls';

/** A settings export is a few KB; anything past this is not one. */
const PREFS_FILE_MAX_BYTES = 1024 * 1024;


const HEX_RE = /^#[0-9a-fA-F]{6}$/;

export function ProfileEditor({ onClose }: { onClose: () => void }) {
  const user = useAuthStore((s) => s.user) as AuthUser;
  const updateProfile = useAuthStore((s) => s.updateProfile);
  const resolved = resolvePrefs(user);

  const [color, setColor] = useState(user.color);
  const [codeAccent, setCodeAccent] = useState(resolved.codeAccent);
  const [keybinds, setKeybinds] = useState(resolved.keybinds);
  const [follow, setFollow] = useState<FollowPrefs>(resolved.follow);
  const [theme, setTheme] = useState<ThemePrefs>(resolved.theme);
  const [blurDefaults, setBlurDefaults] = useState<BlurDefaults>(resolved.blurDefaults);
  const [noteWidth, setNoteWidth] = useState<NoteWidth>(resolved.noteWidth);
  const [editorStyle, setEditorStyle] = useState<EditorStyle>(resolved.editorStyle);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  // Admin theme policy: the workspace default heading colours, and whether
  // they are hard-locked (then the picker is shown read-only).
  const adminHeadings = useThemeStore((s) => s.headings);
  const themeLock = useThemeStore((s) => s.lock);
  // Workspace default blur strengths (admin policy), for hints + fallback.
  const adminBlur = useThemeStore((s) => s.blurDefaults);

  // Online teammates plus anyone with an existing precision override, so
  // saved overrides for offline users remain editable.
  const roster = usePresenceRoster();
  const followableUsers = (() => {
    const map = new Map<number, string>();
    for (const p of roster) map.set(p.user.id, p.user.name);
    for (const uid of Object.keys(follow.precisionByUserId)) {
      const n = Number(uid);
      if (!map.has(n)) map.set(n, `User ${uid}`);
    }
    return [...map.entries()].map(([id, name]) => ({ id, name }));
  })();

  const precisionFor = (uid: number): FollowPrecision =>
    follow.precisionByUserId[String(uid)] ?? follow.defaultPrecision;

  // Live-preview the code accent and heading colours against open editors
  // while the dialog is open; revert on unmount unless the change was saved.
  const initialCodeAccent = useRef(resolved.codeAccent);
  const initialHeadings = useRef(
    resolveEffectiveHeadings({ headings: adminHeadings, lock: themeLock }, resolved.theme).headings,
  );
  const initialNoteWidth = useRef(resolved.noteWidth);
  const initialEditorStyle = useRef(resolved.editorStyle);
  const saved = useRef(false);
  useEffect(() => () => {
    if (!saved.current) {
      applyCodeAccent(initialCodeAccent.current);
      applyHeadingColors(initialHeadings.current);
      applyNoteWidth(initialNoteWidth.current);
      applyEditorStyle(initialEditorStyle.current);
    }
  }, []);
  const handleCodeAccentChange = (v: string) => {
    setCodeAccent(v);
    if (HEX_RE.test(v)) applyCodeAccent(v);
  };
  const handleNoteWidthChange = (w: NoteWidth) => {
    setNoteWidth(w);
    applyNoteWidth(w);
  };
  const handleEditorStyleChange = (s: EditorStyle) => {
    setEditorStyle(s);
    applyEditorStyle(s);
  };
  const handleThemeChange = (t: ThemePrefs) => {
    setTheme(t);
    if (!themeLock) {
      applyHeadingColors(resolveEffectiveHeadings({ headings: adminHeadings, lock: false }, t).headings);
    }
  };

  // "Config file per user": the same prefs blob the server stores, as a
  // JSON file (inside `btct-prefs-<user>_<date>_json.zip`, like every download)
  // the user can keep and re-apply on another machine.
  const exportPrefs = async () => {
    const payload = {
      format: 'btct-prefs',
      version: 1,
      exportedAt: new Date().toISOString(),
      prefs: { codeAccent, keybinds, follow, theme, blurDefaults, noteWidth, editorStyle },
    };
    const stem = `btct-prefs-${sanitizeSegment(user.username)}`;
    try {
      const saved = await downloadAsZip(stem, [{ name: `${stem}.json`, data: JSON.stringify(payload, null, 2) }]);
      if (saved) setNotice('Settings exported.');
    } catch (err) {
      setError(`Export failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };
  const importPrefs = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    try {
      // The .zip this build downloads, or the bare .json an older one did.
      const { text } = await readUploadText(file, { pick: (n) => /\.json$/i.test(n), maxBytes: PREFS_FILE_MAX_BYTES, what: 'BTCT settings export' });
      const parsed = JSON.parse(text) as unknown;
      const raw =
        parsed && typeof parsed === 'object' && 'prefs' in (parsed as Record<string, unknown>)
          ? (parsed as { prefs: unknown }).prefs
          : parsed;
      // resolvePrefs() drops every malformed field, so a tampered file can
      // only ever produce a valid prefs object.
      const next = resolvePrefs({ prefs: raw as Partial<EditorPrefs> });
      setCodeAccent(next.codeAccent);
      applyCodeAccent(next.codeAccent);
      setKeybinds(next.keybinds);
      setFollow(next.follow);
      setBlurDefaults(next.blurDefaults);
      handleNoteWidthChange(next.noteWidth);
      handleEditorStyleChange(next.editorStyle);
      handleThemeChange(next.theme);
      setError(null);
      setNotice(`Loaded ${file.name}. Review, then Save to apply.`);
    } catch (err) {
      setError(err instanceof Error && / too large | holds no | not a readable ZIP/.test(err.message) ? err.message : 'That file is not a BTCT settings export.');
    }
  };

  const dirty =
    color !== user.color ||
    codeAccent.toLowerCase() !== resolved.codeAccent.toLowerCase() ||
    JSON.stringify(keybinds) !== JSON.stringify(resolved.keybinds) ||
    JSON.stringify(follow) !== JSON.stringify(resolved.follow) ||
    JSON.stringify(theme) !== JSON.stringify(resolved.theme) ||
    JSON.stringify(blurDefaults) !== JSON.stringify(resolved.blurDefaults) ||
    noteWidth !== resolved.noteWidth ||
    editorStyle !== resolved.editorStyle;

  const handleSave = async () => {
    if (!HEX_RE.test(color)) {
      setError('color must be a #RRGGBB hex value');
      return;
    }
    if (!HEX_RE.test(codeAccent)) {
      setError('code accent must be a #RRGGBB hex value');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await updateProfile({ color, prefs: { codeAccent, keybinds, follow, theme, blurDefaults, noteWidth, editorStyle } });
      saved.current = true;
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'save failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog
      title="Edit Profile"
      onClose={onClose}
      size="sm"
      className="max-w-96"
      bodyClassName="space-y-4 p-4"
      footer={
        <>
          {/* Settings file: export the prefs blob, or load one to review and save. */}
          <div className="mr-auto flex items-center gap-1.5">
            <Button size="sm" variant="outline" icon={<Download size={11} />} onClick={() => { void exportPrefs(); }} title="Download your settings (a JSON file in a .zip)">
              Export
            </Button>
            <Button size="sm" variant="outline" icon={<Upload size={11} />} onClick={() => fileRef.current?.click()} title="Load settings from an exported .zip or .json (review, then Save)">
              Import
            </Button>
            <input
              ref={fileRef}
              type="file"
              accept="application/zip,.zip,application/json,.json"
              className="hidden"
              onChange={(e) => { void importPrefs(e); }}
            />
          </div>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={handleSave} disabled={!dirty || saving}>
            {saving ? 'Saving…' : 'Save'}
          </Button>
        </>
      }
    >
          {/* Username (read-only) */}
          <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">
              Username
            </label>
            <div className="rounded-lg border border-input bg-background px-3 py-2 text-xs text-muted-foreground">
              {user.username}
            </div>
          </div>

          {/* Color */}
          <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">
              Color
            </label>
            <Swatches label="Colour presets" colors={USER_SWATCHES} value={color} onPick={setColor} />
            <div className="mt-2 flex items-center gap-2">
              <input
                type="color"
                value={HEX_RE.test(color) ? color : USER_SWATCHES[3]}
                onChange={(e) => setColor(e.target.value)}
                aria-label="Pick a colour"
                className="h-8 w-10 cursor-pointer rounded-md border border-input bg-background"
              />
              <Input
                mono
                type="text"
                aria-label="Profile colour hex"
                value={color}
                onChange={(e) => setColor(e.target.value)}
                placeholder="#rrggbb"
                className="flex-1 py-1.5"
              />
            </div>
          </div>

          {/* Code accent: tints syntax highlighting in code blocks. Previews
              live against any open code blocks while this dialog is open. */}
          <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">
              Code Accent
            </label>
            <Swatches label="Code accent presets" colors={USER_SWATCHES} value={codeAccent} onPick={handleCodeAccentChange} />
            <div className="mt-2 flex items-center gap-2">
              <input
                type="color"
                value={HEX_RE.test(codeAccent) ? codeAccent : USER_SWATCHES[1]}
                onChange={(e) => handleCodeAccentChange(e.target.value)}
                aria-label="Pick a colour"
                className="h-8 w-10 cursor-pointer rounded-md border border-input bg-background"
              />
              <Input
                mono
                type="text"
                aria-label="Code accent hex"
                value={codeAccent}
                onChange={(e) => handleCodeAccentChange(e.target.value)}
                placeholder="#rrggbb"
                className="flex-1 py-1.5"
              />
            </div>
          </div>

          {/* Heading colours: this account's note heading colours. Previews
              live in open editors; read-only while the admin hard-lock is on. */}
          <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">
              Heading Colours
            </label>
            {themeLock ? (
              <p className="mb-1.5 text-caption text-status-amber">
                Locked by your admin: the workspace heading colours apply to everyone.
              </p>
            ) : !isThemeCustomized(theme) && isThemeCustomized(adminHeadings) ? (
              <p className="mb-1.5 text-caption text-muted-foreground">
                Showing the workspace default. Pick a colour to use your own.
              </p>
            ) : null}
            <HeadingColorPicker
              value={themeLock ? adminHeadings : theme}
              onChange={handleThemeChange}
              disabled={themeLock}
            />
          </div>

          {/* Default strength for new blur (redaction) regions on report
              screenshots. Null = follow the workspace default. */}
          <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">
              Redaction Defaults
            </label>
            <div className="space-y-2 rounded-lg border border-border bg-background p-2.5">
              {([['gaussian', 'Blur'], ['pixelate', 'Pixels']] as const).map(([styleKey, label]) => {
                const own = blurDefaults[styleKey];
                const adminVal = resolveBlurStrengthPolicy(adminBlur, { gaussian: null, pixelate: null })[styleKey];
                return (
                  <div key={styleKey} className="flex items-center gap-2">
                    <span className="w-12 shrink-0 text-meta text-muted-foreground">{label}</span>
                    {own === null ? (
                      <>
                        <span className="min-w-0 flex-1 truncate text-caption text-muted-foreground">
                          Workspace default ({Math.round(adminVal * 100)}%)
                        </span>
                        <Button variant="outline" size="sm" className="px-2 py-0.5 text-caption" onClick={() => setBlurDefaults((b) => ({ ...b, [styleKey]: adminVal }))}>
                          Customize
                        </Button>
                      </>
                    ) : (
                      <>
                        <input
                          type="range"
                          min={MIN_STRENGTH}
                          max={MAX_STRENGTH}
                          step={0.05}
                          value={own}
                          onChange={(e) => setBlurDefaults((b) => ({ ...b, [styleKey]: Number(e.target.value) }))}
                          aria-label={`${label} strength`}
                          className="min-w-0 flex-1 accent-status-purple"
                        />
                        <span className="w-10 shrink-0 text-right font-mono text-caption">{Math.round(own * 100)}%</span>
                        <Button variant="outline" size="sm" className="px-2 py-0.5 text-caption text-muted-foreground" title="Follow the workspace default again" onClick={() => setBlurDefaults((b) => ({ ...b, [styleKey]: null }))}>
                          Default
                        </Button>
                      </>
                    )}
                  </div>
                );
              })}
              <p className="text-micro leading-relaxed text-muted-foreground">
                Applied to newly drawn redaction regions in the screenshot editor; existing regions keep their strength.
              </p>
            </div>
          </div>

          {/* Light / dark: this device, applied and saved at once. */}
          <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">
              Appearance <span className="normal-case tracking-normal">(this device)</span>
            </label>
            <ColorModeToggle />
          </div>

          {/* Which colours light mode uses: this device, applied at once. */}
          <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">
              Light Palette <span className="normal-case tracking-normal">(this device, light mode)</span>
            </label>
            <LightPaletteToggle />
          </div>

          {/* Interface zoom: scales the whole app on this device. Applies and
              saves immediately; it is not part of the account prefs below.
              Hidden where the browser ignores CSS zoom (Firefox before 126). */}
          {uiZoomSupported() && <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">
              Interface Zoom <span className="normal-case tracking-normal">(this device)</span>
            </label>
            <UiZoomControl />
          </div>}

          {/* Exports: system save dialog or straight to Downloads (this device). */}
          {(saveDialogSupported() || /firefox\//i.test(navigator.userAgent)) && <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">
              Saving Exports <span className="normal-case tracking-normal">(this device)</span>
            </label>
            <AskWhereToSaveToggle className="text-meta" />
            <FirefoxSaveHint />
          </div>}

          {/* Note width: how wide the note content column renders. */}
          <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">
              Note Width
            </label>
            <NoteWidthToggle value={noteWidth} onChange={handleNoteWidthChange} />
          </div>

          {/* Editor style: Obsidian-style live preview or Notion blocks. */}
          <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">
              Editor Style
            </label>
            <EditorStyleToggle value={editorStyle} onChange={handleEditorStyleChange} />
          </div>

          {/* Following: how precisely to mirror a teammate when you follow
              them. Applies to graphs (their node), pages (their cursor), and
              nmap (their host). */}
          <div>
            <label className="mb-1 block text-caption uppercase tracking-wider text-muted-foreground">
              Following
            </label>
            <div className="rounded-lg border border-border bg-background p-2.5">
              <div className="flex items-center justify-between gap-2">
                <span className="text-meta text-muted-foreground">Default precision</span>
                <PrecisionToggle
                  value={follow.defaultPrecision}
                  onChange={(p) => setFollow((f) => ({ ...f, defaultPrecision: p }))}
                />
              </div>

              {followableUsers.length > 0 && (
                <div className="mt-2 flex flex-col gap-1.5 border-t border-border pt-2">
                  {followableUsers.map((u) => (
                    <div key={u.id} className="flex items-center justify-between gap-2">
                      <span className="truncate text-meta">{u.name}</span>
                      <PrecisionToggle
                        value={precisionFor(u.id)}
                        onChange={(p) =>
                          setFollow((f) => ({
                            ...f,
                            precisionByUserId: { ...f.precisionByUserId, [String(u.id)]: p },
                          }))
                        }
                      />
                    </div>
                  ))}
                </div>
              )}

              {follow.panePlacement && (
                <Button variant="outline" size="sm" className="mt-2 w-full text-caption text-muted-foreground" onClick={() => setFollow((f) => ({ ...f, panePlacement: null }))}>
                  Reset pane layout choice (currently: {follow.panePlacement})
                </Button>
              )}
            </div>
          </div>

          {notice && !error && <Banner tone="neutral">{notice}</Banner>}
          {error && <Banner tone="red">{error}</Banner>}
    </Dialog>
  );
}

/** − / percentage / + stepper for the interface zoom, plus a reset. */
function UiZoomControl() {
  const [zoom, setZoom] = useState(getUiZoom);
  useEffect(() => onUiZoomChange(setZoom), []);
  const min = MIN_UI_ZOOM;
  const max = MAX_UI_ZOOM;
  return (
    <div className="flex items-center gap-2">
      <div role="group" aria-label="Interface zoom" className="flex items-center overflow-hidden rounded-md border border-input">
        <IconButton label="Zoom out" disabled={zoom <= min} className="rounded-none px-2.5" onClick={() => applyUiZoom(stepUiZoom(zoom, -1))}>
          <Minus size={12} />
        </IconButton>
        <span aria-live="polite" className="min-w-[3.5rem] border-x border-input px-2 py-1 text-center font-mono text-meta tabular-nums">
          {Math.round(zoom * 100)}%
        </span>
        <IconButton label="Zoom in" disabled={zoom >= max} className="rounded-none px-2.5" onClick={() => applyUiZoom(stepUiZoom(zoom, 1))}>
          <Plus size={12} />
        </IconButton>
      </div>
      {zoom !== DEFAULT_UI_ZOOM && (
        <Button variant="ghost" size="sm" className="text-caption text-muted-foreground" onClick={() => applyUiZoom(DEFAULT_UI_ZOOM)}>
          Reset
        </Button>
      )}
    </div>
  );
}

const NOTE_WIDTH_LABELS: Record<NoteWidth, string> = {
  narrow: 'Narrow',
  default: 'Default',
  wide: 'Wide',
  full: 'Full',
};

/** Four-way segmented toggle for the note content column's width preset. */
function NoteWidthToggle({
  value,
  onChange,
}: {
  value: NoteWidth;
  onChange: (w: NoteWidth) => void;
}) {
  return (
    <Segmented
      label="Note width"
      stretch
      options={NOTE_WIDTHS.map((w) => ({ id: w, label: NOTE_WIDTH_LABELS[w] }))}
      value={value}
      onChange={onChange}
    />
  );
}

/** Compact Precise / View-only segmented toggle for follow precision. */
function PrecisionToggle({
  value,
  onChange,
}: {
  value: FollowPrecision;
  onChange: (p: FollowPrecision) => void;
}) {
  const opts: ReadonlyArray<{ id: FollowPrecision; label: string }> = [
    { id: 'precise', label: 'Precise' },
    { id: 'view', label: 'View only' },
  ];
  return <Segmented label="Follow precision" options={opts} value={value} onChange={onChange} className="[&>button]:py-0.5" />;
}
