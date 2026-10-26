import { describe, it, expect } from 'vitest';
import * as Y from 'yjs';
import { createRelayInbox } from '../../server/relay-inbox.mjs';

// A manual scheduler: turns run only when the test says so, the way the
// event loop runs them between socket reads.
function manual() {
  const queue: Array<() => void> = [];
  return {
    schedule: (fn: () => void) => { queue.push(fn); },
    runOne() { const fn = queue.shift(); fn?.(); return !!fn; },
    runAll() { let n = 0; while (this.runOne()) n++; return n; },
    get waiting() { return queue.length; },
  };
}

describe('relay inbox', () => {
  it('queues messages and applies them a batch per turn, in order', () => {
    const s = manual();
    const seen: number[][] = [];
    const inbox = createRelayInbox<number>({ deliver: (b) => seen.push([...b]), schedule: s.schedule, batch: 3 });
    for (let i = 0; i < 7; i++) inbox.push(i);
    expect(seen).toEqual([]);
    expect(s.waiting).toBe(1);
    s.runOne();
    expect(seen).toEqual([[0, 1, 2]]);
    expect(s.runAll()).toBe(2);
    expect(seen).toEqual([[0, 1, 2], [3, 4, 5], [6]]);
    expect(inbox.size).toBe(0);
  });

  it('flush applies what is left at once (socket closing)', () => {
    const s = manual();
    const seen: number[] = [];
    const inbox = createRelayInbox<number>({ deliver: (b) => seen.push(...b), schedule: s.schedule, batch: 2 });
    for (let i = 0; i < 5; i++) inbox.push(i);
    inbox.flush();
    expect(seen).toEqual([0, 1, 2, 3, 4]);
    s.runAll();
    expect(seen).toEqual([0, 1, 2, 3, 4]);
  });

  it('applies everything queued in one turn once the socket is no longer open', () => {
    // A batch for a closed socket makes y-websocket close the room, and the
    // doc is destroyed once its last write is stored; a later batch would be
    // dropped. So the first turn after the socket left OPEN applies it all.
    const s = manual();
    const seen: number[][] = [];
    let open = true;
    const inbox = createRelayInbox<number>({ deliver: (b) => seen.push([...b]), schedule: s.schedule, batch: 2, isOpen: () => open });
    for (let i = 0; i < 7; i++) inbox.push(i);
    s.runOne();
    expect(seen).toEqual([[0, 1]]);
    open = false;
    s.runOne();
    expect(seen).toEqual([[0, 1], [2, 3], [4, 5], [6]]);
    expect(s.runAll()).toBe(0);
    expect(inbox.size).toBe(0);
  });

  it('discard drops the queue and refuses more (account deleted)', () => {
    const s = manual();
    const seen: number[] = [];
    const inbox = createRelayInbox<number>({ deliver: (b) => seen.push(...b), schedule: s.schedule });
    inbox.push(1);
    inbox.discard();
    expect(inbox.push(2)).toBe(false);
    s.runAll();
    inbox.flush();
    expect(seen).toEqual([]);
    expect(inbox.closed).toBe(true);
  });

  it('cuts a socket off past the message or byte cap and drops its queue', () => {
    const s = manual();
    const overflow: Array<{ messages: number; bytes: number }> = [];
    const inbox = createRelayInbox<Uint8Array>({
      deliver: () => { throw new Error('nothing should be applied'); },
      schedule: s.schedule,
      maxQueued: 3,
      onOverflow: (info) => overflow.push(info),
    });
    for (let i = 0; i < 3; i++) expect(inbox.push(new Uint8Array(10))).toBe(true);
    expect(inbox.push(new Uint8Array(10))).toBe(false);
    expect(overflow).toEqual([{ messages: 4, bytes: 40 }]);
    expect(inbox.size).toBe(0);
    s.runAll();

    const byBytes = createRelayInbox<Uint8Array>({ deliver: () => {}, schedule: s.schedule, maxQueuedBytes: 25, onOverflow: (info) => overflow.push(info) });
    byBytes.push(new Uint8Array(20));
    expect(byBytes.push(new Uint8Array(20))).toBe(false);
    expect(overflow[1]).toEqual({ messages: 2, bytes: 40 });
  });

  it('keeps byte accounting right across batches', () => {
    const s = manual();
    const inbox = createRelayInbox<Uint8Array>({ deliver: () => {}, schedule: s.schedule, batch: 2 });
    for (let i = 0; i < 5; i++) inbox.push(new Uint8Array(7));
    expect(inbox.bytes).toBe(35);
    s.runOne();
    expect(inbox.bytes).toBe(21);
    s.runAll();
    expect(inbox.bytes).toBe(0);
  });

  it('a batch applied in one transaction gives the same doc and one update event', () => {
    // The relay delivers each batch as doc.transact(() => apply each, conn).
    const src = new Y.Doc();
    const text = src.getText('t');
    const updates: Uint8Array[] = [];
    src.on('update', (u: Uint8Array) => updates.push(u));
    for (let i = 0; i < 600; i++) {
      if (i % 3 === 2 && text.length > 4) text.delete(i % text.length, 1);
      else text.insert(Math.floor(text.length / 2), String.fromCharCode(97 + (i % 26)));
    }

    const relay = new Y.Doc();
    const events: unknown[] = [];
    relay.on('update', (_u: Uint8Array, origin: unknown) => events.push(origin));
    const conn = { id: 'socket' };
    const s = manual();
    const inbox = createRelayInbox<Uint8Array>({
      deliver: (batch) => relay.transact(() => { for (const u of batch) Y.applyUpdate(relay, u); }, conn),
      schedule: s.schedule,
      batch: 256,
    });
    for (const u of updates) inbox.push(u);
    s.runAll();
    expect(relay.getText('t').toString()).toBe(text.toString());
    expect(events.length).toBe(3);
    expect(events.every((o) => o === conn)).toBe(true);
  });
});
