// CLI-8 / C3: a tab that throws on render must not blank the app; the other
// pane keeps working and the broken one offers Reload and Close this tab.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { useAppStore } from '@/stores';
import { SplitContainer } from '@/components/ui/SplitContainer';
import { isChunkLoadError, shouldReloadForPreloadError, PRELOAD_RELOAD_WINDOW_MS } from '@/lib/preload-recovery';

vi.mock('@/components/help/ShortcutsView', () => ({
  ShortcutsView: () => { throw new Error('corrupt record'); },
}));
vi.mock('@/components/cmdlog/CommandLogView', () => ({
  CommandLogView: () => <div>command log works</div>,
}));

beforeEach(() => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
  useAppStore.setState({
    tabs: [
      { id: 't-bad', kind: 'shortcuts', entityId: 'x', title: 'Shortcuts' },
      { id: 't-ok', kind: 'cmdlog', entityId: 'y', title: 'Command log' },
    ],
    paneLayout: {
      type: 'split', id: 's', direction: 'horizontal', ratio: 0.5,
      children: [
        { type: 'leaf', id: 'p1', tabIds: ['t-bad'], activeTabId: 't-bad' },
        { type: 'leaf', id: 'p2', tabIds: ['t-ok'], activeTabId: 't-ok' },
      ],
    },
    activeTabId: 't-bad',
    activePaneId: 'p1',
  });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('pane error boundary', () => {
  it('contains a throwing tab to its pane', async () => {
    render(<SplitContainer />);
    expect(await screen.findByText('command log works')).toBeTruthy();
    expect(await screen.findByText(/Something went wrong in the "Shortcuts" tab/)).toBeTruthy();
    expect(screen.getByText('corrupt record')).toBeTruthy();
  });

  it('Close this tab removes the broken tab and keeps the other', async () => {
    render(<SplitContainer />);
    fireEvent.click(await screen.findByText('Close this tab'));
    expect(useAppStore.getState().tabs.map((t) => t.id)).toEqual(['t-ok']);
    expect(await screen.findByText('command log works')).toBeTruthy();
  });
});

describe('preload recovery', () => {
  it('reloads once per window, guarded by session storage', () => {
    const store = new Map<string, string>();
    const storage = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => { store.set(k, v); } };
    expect(shouldReloadForPreloadError(storage, 1_000_000)).toBe(true);
    expect(shouldReloadForPreloadError(storage, 1_000_000 + 10)).toBe(false);
    expect(shouldReloadForPreloadError(storage, 1_000_000 + PRELOAD_RELOAD_WINDOW_MS)).toBe(true);
    expect(shouldReloadForPreloadError(null, 0)).toBe(false);
  });

  it('recognises the browsers\' chunk errors', () => {
    expect(isChunkLoadError(new TypeError('Failed to fetch dynamically imported module: http://x/assets/a.js'))).toBe(true);
    expect(isChunkLoadError(new TypeError('error loading dynamically imported module'))).toBe(true);
    expect(isChunkLoadError(new Error('corrupt record'))).toBe(false);
  });
});
