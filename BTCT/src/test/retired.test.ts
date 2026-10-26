import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as Y from 'yjs';
vi.mock('@/realtime/shared-doc', () => ({ getSharedDoc: vi.fn() }));
import { getSharedDoc } from '@/realtime/shared-doc';
import { collectRetired, restoreRetired, emptyRetired } from '@/export/retired';

let doc: Y.Doc;
beforeEach(() => {
  doc = new Y.Doc();
  vi.mocked(getSharedDoc).mockReturnValue({ doc } as ReturnType<typeof getSharedDoc>);
});

describe('retired feature archive compatibility', () => {
  it('exports only records belonging to the selected workspace', () => {
    doc.getMap('siteMaps').set('map-a', { id: 'map-a', workspaceId: 'a' });
    doc.getMap('siteMaps').set('map-b', { id: 'map-b', workspaceId: 'b' });
    doc.getMap('siteMapNodes').set('node-a', { id: 'node-a', siteMapId: 'map-a', notes: 'preserved' });
    doc.getMap('siteMapNodes').set('node-b', { id: 'node-b', siteMapId: 'map-b' });
    const data = collectRetired('a');
    expect(data.siteMaps.map((r) => r.id)).toEqual(['map-a']);
    expect(data.siteMapNodes.map((r) => r.id)).toEqual(['node-a']);
  });

  it('exports graphs, their nodes and edges, chains and timeline events', () => {
    doc.getMap('graphs').set('g1', { id: 'g1', workspaceId: 'a', name: 'Internal' });
    doc.getMap('graphs').set('g2', { id: 'g2', workspaceId: 'other', name: 'Elsewhere' });
    doc.getMap('graphNodes').set('n1', { id: 'n1', graphId: 'g1', label: 'DC-01' });
    doc.getMap('graphNodes').set('n2', { id: 'n2', graphId: 'g2', label: 'Not mine' });
    doc.getMap('graphEdges').set('e1', { id: 'e1', graphId: 'g1', sourceNodeId: 'n1', targetNodeId: 'n1' });
    doc.getMap('attackChains').set('c1', { id: 'c1', workspaceId: 'a', graphId: 'g1', nodeIds: ['n1'] });
    doc.getMap('timelineEvents').set('t1', { id: 't1', workspaceId: 'a', title: 'Got DA' });

    const data = collectRetired('a');
    expect(data.graphs.map((r) => r.id)).toEqual(['g1']);
    expect(data.graphNodes.map((r) => r.id)).toEqual(['n1']);
    expect(data.graphEdges.map((r) => r.id)).toEqual(['e1']);
    expect(data.attackChains.map((r) => r.id)).toEqual(['c1']);
    expect(data.timelineEvents.map((r) => r.id)).toEqual(['t1']);
  });

  it('remaps archived relationships when importing a copy', () => {
    restoreRetired({
      ...emptyRetired(),
      graphs: [{ id: 'g', workspaceId: 'old', name: 'Internal' }],
      graphNodes: [{ id: 'n', graphId: 'g', label: 'DC-01', linkedPageId: 'p' }],
      graphEdges: [{ id: 'e', graphId: 'g', sourceNodeId: 'n', targetNodeId: 'n' }],
      attackChains: [{ id: 'c', workspaceId: 'old', graphId: 'g', nodeIds: ['n'], linkedPageId: null }],
    }, 'new', (id) => `copy-${id}`);

    const data = collectRetired('new');
    expect(data.graphs).toEqual([{ id: 'copy-g', workspaceId: 'new', name: 'Internal' }]);
    expect(data.graphNodes).toEqual([{ id: 'copy-n', graphId: 'copy-g', label: 'DC-01', linkedPageId: 'copy-p' }]);
    expect(data.graphEdges).toEqual([{ id: 'copy-e', graphId: 'copy-g', sourceNodeId: 'copy-n', targetNodeId: 'copy-n' }]);
    expect(data.attackChains).toEqual([
      { id: 'copy-c', workspaceId: 'new', graphId: 'copy-g', nodeIds: ['copy-n'], linkedPageId: null },
    ]);
  });

  it('round-trips a workspace with nothing archived', () => {
    restoreRetired(undefined, 'new', (id) => id);
    expect(collectRetired('new')).toEqual(emptyRetired());
  });
});
