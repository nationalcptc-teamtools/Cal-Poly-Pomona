import { describe, it, expect } from 'vitest';
import * as Y from 'yjs';
import { changedUsersBetween } from '../../server/history-diff.mjs';
import { groupVersionsByDay, versionLabel } from '@/lib/page-history';
import type { PageVersion } from '@/types';

/** Wire docs together the way the relay does: every update reaches every peer. */
function link(from: Y.Doc, ...to: Y.Doc[]) {
  from.on('update', (u: Uint8Array) => { for (const d of to) Y.applyUpdate(d, u); });
}

/** PermanentUserData writes a transaction's delete set on a setTimeout; let it land. */
const settle = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

describe('changedUsersBetween (server/history-diff.mjs)', () => {
  it('attributes insertions to the writer and deletions to the deleter, ignoring the users map', async () => {
    const twin = new Y.Doc({ gc: false });
    const a = new Y.Doc();
    const b = new Y.Doc();
    link(a, twin, b);
    link(b, twin, a);
    new Y.PermanentUserData(a).setUserMapping(a, a.clientID, '1');
    new Y.PermanentUserData(b).setUserMapping(b, b.clientID, '2');
    const pud = new Y.PermanentUserData(twin);

    // Opening the page only wrote the user mapping: not a content change.
    const s0 = Y.snapshot(twin);
    expect(changedUsersBetween(Y, twin, 'prosemirror', Y.emptySnapshot, s0, pud).changed).toBe(false);

    // A writes a paragraph.
    a.transact(() => {
      const p = new Y.XmlElement('paragraph');
      const t = new Y.XmlText();
      t.insert(0, 'hello world');
      p.insert(0, [t]);
      a.getXmlFragment('prosemirror').insert(0, [p]);
    });
    const s1 = Y.snapshot(twin);
    const d1 = changedUsersBetween(Y, twin, 'prosemirror', s0, s1, pud);
    expect(d1.changed).toBe(true);
    expect(d1.users).toEqual(['1']);

    // B deletes part of it: the deleter is credited, not the author.
    b.transact(() => {
      const p = b.getXmlFragment('prosemirror').get(0) as Y.XmlElement;
      const t = p.get(0) as Y.XmlText;
      t.delete(0, 6);
    });
    await settle();
    const s2 = Y.snapshot(twin);
    const d2 = changedUsersBetween(Y, twin, 'prosemirror', s1, s2, pud);
    expect(d2.changed).toBe(true);
    expect(d2.users).toEqual(['2']);

    // Nothing since: no version would be written.
    expect(changedUsersBetween(Y, twin, 'prosemirror', s2, Y.snapshot(twin), pud).changed).toBe(false);
  });

  it('reports unknown for clients that never registered a mapping', () => {
    const twin = new Y.Doc({ gc: false });
    const anon = new Y.Doc();
    link(anon, twin);
    anon.getXmlFragment('prosemirror').insert(0, [new Y.XmlElement('paragraph')]);
    const d = changedUsersBetween(Y, twin, 'prosemirror', Y.emptySnapshot, Y.snapshot(twin), new Y.PermanentUserData(twin));
    expect(d).toEqual({ changed: true, users: ['unknown'] });
  });
});

function v(partial: Partial<PageVersion> & { createdAt: number }): PageVersion {
  return {
    id: String(partial.createdAt),
    pageId: 'p',
    workspaceId: 'w',
    trigger: 'auto',
    name: null,
    createdBy: null,
    changedBy: [],
    diffable: true,
    size: 0,
    ...partial,
  };
}

describe('groupVersionsByDay', () => {
  it('groups newest-first into local calendar days and keeps order inside a day', () => {
    const day1 = new Date(2026, 7, 28, 9, 0).getTime();
    const day1Later = new Date(2026, 7, 28, 17, 30).getTime();
    const day2 = new Date(2026, 7, 27, 23, 59).getTime();
    const groups = groupVersionsByDay([v({ createdAt: day1Later }), v({ createdAt: day1 }), v({ createdAt: day2 })]);
    expect(groups.map((g) => g.versions.length)).toEqual([2, 1]);
    expect(groups[0]?.versions[0]?.createdAt).toBe(day1Later);
    expect(groups[0]?.dayKey).not.toBe(groups[1]?.dayKey);
  });

  it('labels versions by name, then by trigger', () => {
    expect(versionLabel(v({ createdAt: 1, name: 'Before cleanup' }))).toBe('Before cleanup');
    expect(versionLabel(v({ createdAt: 1, trigger: 'restore' }))).toBe('Restored version');
    expect(versionLabel(v({ createdAt: 1, trigger: 'import' }))).toBe('Imported version');
    expect(versionLabel(v({ createdAt: 1 }))).toBe('Auto-saved');
  });
});
