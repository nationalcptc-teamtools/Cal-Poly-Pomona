// `typstTabState` is unit-tested next door; this renders the branch that
// consumes it, so that deleting `&& typstState === 'on'` from SplitContainer
// fails a test rather than quietly shipping the compiler to a flag-off box.
//
// The lazy module is mocked with a factory that counts its own evaluation:
// Vitest runs the factory the first time the module is actually imported, so
// a count of 0 means `lazy()` never resolved it, which is the property that
// matters (the real chunk carries 28 MB of wasm behind it).
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { useThemeStore } from '@/stores/theme-store';
import { useAppStore } from '@/stores';
import { SplitContainer } from '@/components/ui/SplitContainer';

const typstModule = vi.hoisted(() => ({ loads: 0 }));

vi.mock('@/components/typst/TypstView', () => {
  typstModule.loads++;
  return {
    TypstView: ({ workspaceId }: { workspaceId: string }) => (
      <div>report editor for {workspaceId}</div>
    ),
  };
});

describe('SplitContainer renders a typst tab only once the flag says so', () => {
  // Vitest evaluates a mock factory once per file, so the counter cannot be
  // reset between cases. Each case compares against the count it started
  // with instead, which makes them independent of the order they run in.
  let loadsBefore = 0;

  beforeEach(() => {
    loadsBefore = typstModule.loads;
    useAppStore.setState({
      tabs: [{ id: 'tab-1', kind: 'typst', entityId: 'ws-1', title: 'Report' }],
      paneLayout: { type: 'leaf', id: 'pane-1', tabIds: ['tab-1'], activeTabId: 'tab-1' },
      activePaneId: 'pane-1',
    });
  });

  it('shows the loading notice, and loads nothing, while settings are in flight', async () => {
    useThemeStore.setState({ features: { typst: true }, featuresLoaded: false });
    render(<SplitContainer />);

    expect(await screen.findByText(/Checking whether the report editor is available/)).toBeTruthy();
    expect(typstModule.loads).toBe(loadsBefore);
  });

  it('shows the off notice, and loads nothing, on a flag-off server', async () => {
    useThemeStore.setState({ features: { typst: false }, featuresLoaded: true });
    render(<SplitContainer />);

    expect(await screen.findByText('Report tab is turned off')).toBeTruthy();
    expect(screen.queryByText(/report editor for/)).toBeNull();
    expect(typstModule.loads).toBe(loadsBefore);
  });

  it('loads and renders the editor once the flag is on', async () => {
    useThemeStore.setState({ features: { typst: true }, featuresLoaded: true });
    render(<SplitContainer />);

    // Rendering the mock's output is the proof that the module was loaded in
    // this case; the counter confirms the factory ran at all.
    expect(await screen.findByText(/report editor for ws-1/)).toBeTruthy();
    expect(typstModule.loads).toBeGreaterThanOrEqual(1);
  });
});
