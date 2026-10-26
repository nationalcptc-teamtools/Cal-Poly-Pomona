// The Shortcuts page lists the btct command-line menu's subcommands. This
// keeps that list honest: every subcommand btct.sh dispatches appears on the
// page, and every btct command the page shows is one btct.sh knows.
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { render, screen } from '@testing-library/react';
import { ShortcutsView, BTCT_CLI_ROWS } from '@/components/help/ShortcutsView';

const script = fs.readFileSync(path.resolve(__dirname, '../../btct.sh'), 'utf8');

/** The names in btct.sh's main dispatch (`case "$cmd" in ... esac`). */
function dispatchedCommands(): Set<string> {
  const body = script.slice(script.indexOf('case "$cmd" in'));
  const block = body.slice(0, body.indexOf('esac'));
  const names = new Set<string>();
  for (const m of block.matchAll(/^\s+([a-z|-]+)\)/gm)) {
    for (const n of (m[1] ?? '').split('|')) if (!n.startsWith('-')) names.add(n);
  }
  return names;
}

/** The subcommand words a row shows: `btct start | stop | restart` gives three. */
function shownCommands(): Set<string> {
  const out = new Set<string>();
  for (const r of BTCT_CLI_ROWS) {
    const m = /^btct(?: (.*))?$/.exec(r.keys);
    if (!m) continue;
    if (!m[1]) { out.add('menu'); continue; }
    for (const alt of m[1].split(' | ')) out.add(alt.split(' ')[0] ?? '');
  }
  return out;
}

describe('Shortcuts page: btct command line', () => {
  it('shows every subcommand btct.sh dispatches', () => {
    const shown = shownCommands();
    // Aliases kept for convenience, not advertised.
    const aliases = new Set(['backup-folder', 'list']);
    const missing = [...dispatchedCommands()].filter((c) => !aliases.has(c) && !shown.has(c));
    expect(missing).toEqual([]);
  });

  it('shows no command btct.sh does not have', () => {
    const known = dispatchedCommands();
    const unknown = [...shownCommands()].filter((c) => !known.has(c));
    expect(unknown).toEqual([]);
  });

  it('renders the section with the commands as monospace code', () => {
    render(<ShortcutsView />);
    expect(screen.getByText('Command line (btct)')).toBeTruthy();
    const el = screen.getByText('btct backup-dir PATH');
    expect(el.tagName).toBe('CODE');
    expect(el.className).toContain('font-mono');
    expect(el.className).not.toContain('whitespace-nowrap');
  });
});
