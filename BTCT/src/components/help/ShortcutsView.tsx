// ─────────────────────────────────────────────────────────────────────────
// Keyboard shortcuts reference (a `shortcuts` TabKind).
//
// A short, grouped cheat-sheet to get started. The rebindable editor shortcuts
// show the account's *current* binding (via resolvePrefs), so this always
// matches what the Keybinds dialog has set; the fixed gestures are listed as
// they are wired in App.tsx / the editor plugins.
// ─────────────────────────────────────────────────────────────────────────

import { useMemo } from 'react';
import { Keyboard } from 'lucide-react';
import { useAuthStore } from '@/auth/auth-store';
import { resolvePrefs, formatShortcut, type KeybindAction } from '@/lib/editor-prefs';

interface Row {
  keys: string;
  label: string;
  /** A shell command rather than a key chord: monospace, and it wraps. */
  mono?: boolean;
}
interface Section {
  title: string;
  hint?: string;
  rows: Row[];
}

const MOD = typeof navigator !== 'undefined' && /Mac|iP(hone|ad)/.test(navigator.platform) ? '⌘' : 'Ctrl';
/** A literal chord, e.g. `chord('Shift', '↑')`. */
const chord = (...keys: string[]) => keys.join(' + ');

/** The btct.sh / btct.ps1 subcommands, as implemented (src/test/shortcuts-btct.test.tsx checks them against btct.sh). */
export const BTCT_CLI_ROWS: Row[] = [
  { mono: true, keys: 'btct', label: 'Open the menu' },
  { mono: true, keys: 'btct status', label: 'Health, container, URLs (LAN too), RAM and CPU, backup folder, last backup' },
  { mono: true, keys: 'btct start | stop | restart', label: 'Start, stop or restart BTCT (waits for /healthz)' },
  { mono: true, keys: 'btct backup-dir PATH', label: 'Set the folder server backups are saved to; recreates BTCT and checks it can write there' },
  { mono: true, keys: 'btct backup-dir', label: 'Same, asking for the folder (Tab completes; Enter opens the folder dialog)' },
  { mono: true, keys: 'btct backup-dir --show', label: 'Print the backup folder and the one the container mounts' },
  { mono: true, keys: 'btct backup', label: 'Back up now and print the ZIP name, size and host path' },
  { mono: true, keys: 'btct backups', label: 'List backups with size and date' },
  { mono: true, keys: 'btct schedule on --every 60 --keep 12', label: 'Scheduled backups: on or off, interval in minutes, how many to keep (no arguments asks)' },
  { mono: true, keys: 'btct restore [NAME]', label: 'Verify, then restore a backup (you type its name to confirm)' },
  { mono: true, keys: 'btct passwords', label: 'Print the generated account passwords (secrets on screen)' },
  { mono: true, keys: 'btct logs [-f] [LINES]', label: 'Last 100 log lines, or follow them (Ctrl+C stops)' },
  { mono: true, keys: 'btct update', label: 'Update to the latest comp-ready: builds while BTCT runs, snapshots the data, restarts, keeps every note (asks first; -y does not)' },
  { mono: true, keys: 'btct update --branch NAME', label: 'Same, from another branch' },
  { mono: true, keys: 'btct rollback [--data]', label: 'Run the version from before the last update again; --data also puts back its pre-update snapshot' },
  { mono: true, keys: 'btct check', label: 'Competition-day check (./competition-day.sh --check-only)' },
  { mono: true, keys: 'btct install | uninstall', label: 'Add or remove the btct command and shell alias' },
  { mono: true, keys: 'btct help', label: 'Every subcommand and option' },
  { mono: true, keys: '.\\btct.ps1 install', label: 'Windows: adds a btct function to your PowerShell profile; same subcommands (btct update, btct rollback)' },
];

export function ShortcutsView() {
  const user = useAuthStore((s) => s.user);
  const kb = useMemo(() => resolvePrefs(user).keybinds, [user]);
  const bound = (a: KeybindAction) => formatShortcut(kb[a]);

  const sections: Section[] = [
    {
      title: 'Getting around',
      rows: [
        { keys: chord(MOD, 'K'), label: 'Command palette: create pages, open tools, jump anywhere' },
        { keys: bound('openFollowPanel'), label: 'Active users / follow a teammate' },
        { keys: chord('Alt', '←  /  →'), label: 'Switch between open tabs' },
        { keys: chord(MOD, 'Alt', '=  /  −'), label: 'Zoom the interface in / out (this device; also in Profile)' },
        { keys: chord(MOD, 'Alt', '0'), label: 'Reset interface zoom to 100%' },
      ],
    },
    {
      title: 'Text editor',
      hint: 'Rebindable in Profile → Keybinds.',
      rows: [
        { keys: bound('bold'), label: 'Bold' },
        { keys: bound('italic'), label: 'Italic' },
        { keys: bound('strikethrough'), label: 'Strikethrough' },
        { keys: bound('inlineCode'), label: 'Inline code' },
        { keys: bound('link'), label: 'Insert / edit link (on a selection)' },
        { keys: bound('highlight'), label: 'Highlight (last colour)' },
        { keys: chord(MOD, 'Shift', '0–8'), label: 'Turn the block into text / H1–H3 / to-do / list / code' },
      ],
    },
    {
      title: 'Editor style',
      hint: 'Profile → Editor Style, or "Editor style" in the command palette. Switching applies at once.',
      rows: [
        { keys: 'Live preview', label: 'Default, like Obsidian: one continuous document, no block handles. The line or block holding the cursor shows its markdown (# , > , - , - [ ] , **, *, ~~, `, ==, [text](url), ``` fences), dimmed; the rest stays rendered' },
        { keys: chord('# ', '**x**', '- [ ] ', '```'), label: 'Markdown typing turns into formatting as you type, in both styles' },
        { keys: 'Backspace', label: 'At the start of a heading: one level down (## → #), then plain text' },
        { keys: chord(MOD, 'A'), label: 'Live preview: select all text. Esc does not select blocks' },
        { keys: 'Click - [ ]', label: 'Live preview: the revealed to-do marker ticks the box' },
        { keys: 'Blocks', label: 'Notion style: drag handles, + button and block selection (below)' },
      ],
    },
    {
      title: 'Blocks & selection',
      hint: 'Blocks (Notion) style only; Live preview keeps Ctrl/⌘+Shift+↑/↓. Copy carries the block, so a code box stays a code box when pasted elsewhere.',
      rows: [
        { keys: 'Esc', label: 'Select the current block (leave text editing)' },
        { keys: chord('↑', '/', '↓'), label: 'Move the selection between blocks' },
        { keys: chord('Shift', '↑ / ↓'), label: 'Extend the selection across blocks' },
        { keys: chord(MOD, 'Shift', '↑ / ↓'), label: 'Move the selected block(s) up / down' },
        { keys: chord(MOD, 'D'), label: 'Duplicate the selected block(s)' },
        { keys: chord(MOD, 'A'), label: 'Ladder: select text → block → all blocks' },
        { keys: 'Enter', label: 'Edit the selected block · Backspace deletes it' },
      ],
    },
    {
      title: 'Code blocks',
      rows: [
        { keys: bound('focusLanguage'), label: 'Focus the language picker (inside a block or with it selected): type to search, Enter drops to the closest match, ↑/↓ to choose, Enter to set' },
        { keys: '``` + Enter', label: 'New code block (defaults to shell; type a language after the fence)' },
      ],
    },
    {
      title: 'Images',
      rows: [
        { keys: 'Drag corner', label: 'Resize a selected image' },
        { keys: 'Right-click', label: 'Blur / edit a note image, or open it in the Assets Manager' },
        { keys: bound('blurImage'), label: 'Blur / edit the selected image' },
        { keys: 'Paste / drop', label: 'Add an image (it becomes a shared, redactable asset)' },
      ],
    },
    {
      title: 'Typst report',
      hint: 'Preview keys work while the preview has focus or the pointer is over it, and not while you type in the code.',
      rows: [
        { keys: chord(MOD, 'F'), label: 'In the code: find & replace across the whole source' },
        { keys: chord(MOD, 'F'), label: 'Over the preview: find in the rendered pages (Enter / Shift + Enter for next / previous, Esc closes)' },
        { keys: 'L', label: 'Over the preview: lock or unlock it. Locked, a click selects text instead of jumping to the code. Only for you, on this browser' },
        { keys: 'Click preview', label: 'Jump from the rendered page to that spot in the source (unlocked)' },
      ],
    },
    {
      title: 'Command line (btct)',
      hint: 'Run on the machine that hosts BTCT. Install once with ./btct.sh install (Windows: .\\btct.ps1 install), then type btct for the menu.',
      rows: BTCT_CLI_ROWS,
    },
  ];

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto w-full max-w-4xl px-4 py-5 sm:px-6">
        <div className="mb-1 flex items-center gap-2">
          <Keyboard size={16} className="text-primary" />
          <h1 className="text-base font-semibold">Keyboard shortcuts</h1>
        </div>
        <p className="mb-5 text-xs text-muted-foreground">
          A quick tour of the gestures worth knowing. Editor shortcuts show your current bindings; change them in Profile → Keybinds.
        </p>

        <div className="grid grid-cols-1 gap-[var(--pane-gap)] md:grid-cols-2">
          {sections.map((s) => (
            <section key={s.title} aria-label={s.title} className="min-w-0 rounded-md border border-border p-3">
              <div className="mb-2">
                <h2 className="text-caption font-bold uppercase tracking-widest text-muted-foreground">{s.title}</h2>
                {s.hint && <p className="mt-0.5 text-caption leading-relaxed text-muted-foreground">{s.hint}</p>}
              </div>
              <div className="flex flex-col gap-1.5">
                {s.rows.map((r, i) => r.mono ? (
                  <div key={i} className="flex min-w-0 flex-col gap-0.5">
                    <code className="self-start max-w-full whitespace-pre-wrap [overflow-wrap:anywhere] rounded bg-background px-1.5 py-0.5 font-mono text-meta text-foreground">
                      {r.keys}
                    </code>
                    <span className="text-meta leading-snug text-muted-foreground">{r.label}</span>
                  </div>
                ) : (
                  <div key={i} className="flex items-start gap-3">
                    <kbd className="mt-0.5 shrink-0 whitespace-nowrap rounded border border-border bg-background px-1.5 py-0.5 font-mono text-caption text-foreground shadow-[inset_0_-1px_0_hsl(var(--border))]">
                      {r.keys}
                    </kbd>
                    <span className="text-meta leading-snug text-muted-foreground">{r.label}</span>
                  </div>
                ))}
              </div>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}
