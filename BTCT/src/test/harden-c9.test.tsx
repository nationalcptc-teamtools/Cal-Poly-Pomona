import 'fake-indexeddb/auto';
import { describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import type { PageVersion } from '@/types';

// C9: the History tab's per-version byte cache must be bounded. Stepping
// through many versions of a large page must not keep every full state in
// memory until the tab closes, so an early version is fetched again once
// enough newer ones have been viewed.
const MB = 1024 * 1024;
const N = 60;
const versions: PageVersion[] = Array.from({ length: N }, (_, i) => ({
  id: `v${i}`, pageId: 'p-c9', workspaceId: 'w', createdAt: 1_700_000_000_000 - i * 60_000, trigger: 'named',
  name: `Version ${i}`, createdBy: 1, changedBy: [1], diffable: false, size: MB,
}));
const api = vi.hoisted(() => ({ getVersion: vi.fn() }));
vi.mock('@/realtime/page-history-api', () => ({
  listVersions: async () => ({ versions, users: {}, tracked: true, dirty: false, twinExists: false }),
  fetchTwin: async () => null,
  getVersion: api.getVersion,
  createVersion: vi.fn(), deleteVersion: vi.fn(), renameVersion: vi.fn(),
}));
vi.mock('@milkdown/crepe', () => ({ Crepe: class { editor = { use: () => {}, ctx: { get: () => null } }; create() { return Promise.reject(new Error('no viewer in test')); } } }));
vi.mock('@/realtime/yjs-providers', () => ({ getPageYContext: () => null }));
vi.mock('@/realtime/use-page-synced', () => ({ usePageServerSynced: () => true }));
vi.mock('@/lib/visible-poll', () => ({ pollWhileVisible: (fn: () => void) => { void fn(); return () => {}; } }));
import { HistoryView } from '@/components/history/HistoryView';

api.getVersion.mockImplementation(async (_p: string, id: string) => ({
  version: versions.find((v) => v.id === id)!, snapshot: null, state: new Uint8Array(MB),
}));

describe('C9 history byte cache bound', () => {
  it('does not retain every viewed version', async () => {
    render(<HistoryView pageId="p-c9" />);
    await screen.findByText('Version 0');
    for (let i = 0; i < N; i++) {
      await act(async () => { fireEvent.click(screen.getByText(`Version ${i}`)); });
      await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
    }
    const before = api.getVersion.mock.calls.filter((c) => c[1] === 'v0').length;
    expect(before).toBe(1);
    await act(async () => { fireEvent.click(screen.getByText('Version 0')); });
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
    // 60 MB of states were viewed; a bounded cache cannot still hold v0.
    expect(api.getVersion.mock.calls.filter((c) => c[1] === 'v0').length).toBe(2);
  }, 60_000);
});
