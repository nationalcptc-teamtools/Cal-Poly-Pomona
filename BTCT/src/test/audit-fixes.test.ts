import { describe, it, expect } from 'vitest';
import * as Y from 'yjs';
import { createLeaf, findLeafContainingTab, moveTab } from '@/lib/pane-layout';
import type { SplitPane } from '@/types';
import { changedUsersBetween } from '../../server/history-diff.mjs';
import { normalizeBackupConfig } from '../../server/backup-format.mjs';
import { dayLabel } from '@/lib/page-history';
import { fitCropToBox, zoomCrop, MAX_VISIBLE_FRACTION } from '@/lib/crop-math';

// Regression tests for the defects the 2026-08-28 audit's test-breaker found
// (docs/perf-bug-audit-2026-08-28.md).

describe('moveTab never strands a tab', () => {
  it('splitting off the sole tab of its own pane keeps the tab', () => {
    const a = createLeaf(['t1'], 't1');
    const b = createLeaf(['t2'], 't2');
    const split: SplitPane = { type: 'split', id: 's', direction: 'horizontal', children: [a, b], ratio: 0.5 };
    const out = moveTab(split, 't1', a.id, 'right');
    expect(findLeafContainingTab(out, 't1')).not.toBeNull();
    expect(findLeafContainingTab(out, 't2')).not.toBeNull();
  });

  it('dropping the sole tab onto the centre of its own pane is a no-op', () => {
    const a = createLeaf(['t1'], 't1');
    const b = createLeaf(['t2'], 't2');
    const split: SplitPane = { type: 'split', id: 's', direction: 'horizontal', children: [a, b], ratio: 0.5 };
    expect(moveTab(split, 't2', b.id, 'center')).toBe(split);
  });

  it('an unknown target pane leaves the layout untouched', () => {
    const a = createLeaf(['t1', 't2'], 't1');
    expect(moveTab(a, 't1', 'ghost', 'center')).toBe(a);
  });

  it('an edge drop on a single root leaf leaves no empty pane behind', () => {
    const a = createLeaf(['t1'], 't1');
    const out = moveTab(a, 't1', a.id, 'left');
    expect(out.type).toBe('leaf');
    expect(findLeafContainingTab(out, 't1')).not.toBeNull();
  });
});

const settle = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
function link(from: Y.Doc, ...to: Y.Doc[]) {
  from.on('update', (u: Uint8Array) => { for (const d of to) Y.applyUpdate(d, u); });
}

describe('changedUsersBetween with adjacent deletions', () => {
  it('credits a second deletion that Yjs merged into an earlier range', async () => {
    const twin = new Y.Doc({ gc: false });
    const a = new Y.Doc();
    const b = new Y.Doc();
    link(a, twin, b);
    link(b, twin, a);
    new Y.PermanentUserData(a).setUserMapping(a, a.clientID, '1');
    new Y.PermanentUserData(b).setUserMapping(b, b.clientID, '2');
    const pud = new Y.PermanentUserData(twin);
    a.transact(() => {
      const p = new Y.XmlElement('paragraph');
      const t = new Y.XmlText();
      t.insert(0, 'hello world');
      p.insert(0, [t]);
      a.getXmlFragment('prosemirror').insert(0, [p]);
    });
    const s1 = Y.snapshot(twin);
    b.transact(() => { ((b.getXmlFragment('prosemirror').get(0) as Y.XmlElement).get(0) as Y.XmlText).delete(0, 6); });
    await settle();
    const s2 = Y.snapshot(twin);
    expect(changedUsersBetween(Y, twin, 'prosemirror', s1, s2, pud)).toEqual({ changed: true, users: ['2'] });
    a.transact(() => { ((a.getXmlFragment('prosemirror').get(0) as Y.XmlElement).get(0) as Y.XmlText).delete(0, 2); });
    await settle();
    const s3 = Y.snapshot(twin);
    const d = changedUsersBetween(Y, twin, 'prosemirror', s2, s3, pud);
    expect(d.changed).toBe(true);
    expect(d.users).toEqual(['1']);
  });
});

describe('backup config', () => {
  it('a blank interval means the default, not one minute', () => {
    expect(normalizeBackupConfig({ fullIntervalMin: '' }).fullIntervalMin).toBe(60);
    expect(normalizeBackupConfig({ fullIntervalMin: null }).fullIntervalMin).toBe(60);
    expect(normalizeBackupConfig({ fullIntervalMin: '15' }).fullIntervalMin).toBe(15);
  });
});

describe('dayLabel', () => {
  it('uses calendar days for Yesterday', () => {
    const now = new Date(2026, 7, 28, 0, 30).getTime();
    const yesterdayNoon = new Date(2026, 7, 27, 12, 0).getTime();
    const twoDaysAgo = new Date(2026, 7, 26, 12, 0).getTime();
    expect(dayLabel(yesterdayNoon, now)).toBe('Yesterday');
    expect(dayLabel(twoDaysAgo, now)).not.toBe('Yesterday');
  });
});

describe('crop math', () => {
  it('zooming out never lets either side exceed the visible maximum', () => {
    let crop = fitCropToBox(3000, 1000, 0.5, 'contain');
    for (let i = 0; i < 40; i++) crop = zoomCrop(crop, 1.5);
    expect(crop.w).toBeLessThanOrEqual(MAX_VISIBLE_FRACTION + 1e-9);
    expect(crop.h).toBeLessThanOrEqual(MAX_VISIBLE_FRACTION + 1e-9);
  });
});
