// ─────────────────────────────────────────────────────────────────────────
// Per-socket inbox for the Yjs relay.
//
// y-websocket applies each websocket message as it arrives: one Yjs
// transaction, one broadcast, one persistence push and one history-twin
// apply per keystroke. Bun dispatches a socket's buffered messages without
// returning to the event loop while more data is waiting, so a client that
// sends faster than the server applies (3200 updates a second against a box
// on half a CPU) kept the loop busy for 40 s and more: no timers, no LevelDB
// write completions, no SIGTERM handler, and docker's SIGKILL dropped
// everything buffered.
//
// The inbox makes the message handler cheap (queue the bytes) and applies
// the queue in batches from a macrotask, one batch per turn, so timers,
// I/O and signals run between batches. A batch is applied by `deliver`,
// which index.mjs wraps in one doc transaction: 256 churn updates applied
// in one transaction cost 49 us each against 164 us one by one (0.5 CPU),
// and the batch makes one broadcast and one persistence entry.
//
// A socket whose inbox passes `maxQueued` messages or `maxQueuedBytes` is
// cut off (`onOverflow`): its queue is dropped and the socket terminated.
// The client still holds those edits and sends them again, as one sync
// step 2, when it reconnects, so nothing it typed is lost; without the cap
// a client could fill the server's memory, since the queue takes away the
// TCP back-pressure a busy handler gave.
//
// A socket that is no longer open has everything it queued applied in one
// go, at the next turn or on close, whichever comes first. Applying a batch
// for such a socket makes y-websocket close the room (its broadcast to the
// closed socket calls closeConn), and the room's doc is destroyed once its
// last write is stored, so a later batch would find no doc to apply to.
//
// Pure: the scheduler, the clock and the delivery are injected, so the
// module is tested from src/test without a server.
// ─────────────────────────────────────────────────────────────────────────

/** Messages applied per turn. 256 churn updates took about 13 ms at 0.5 CPU. */
export const INBOX_BATCH = 256;
/** Messages a socket may have waiting before it is cut off. */
export const INBOX_MAX_QUEUED = 20_000;
/** Bytes a socket may have waiting before it is cut off. */
export const INBOX_MAX_QUEUED_BYTES = 64 * 1024 * 1024;

const sizeOf = (m) => m?.byteLength ?? m?.length ?? 0;

/**
 * @param {{
 *   deliver: (batch: any[]) => void,
 *   schedule?: (fn: () => void) => void,
 *   onOverflow?: (info: { messages: number, bytes: number }) => void,
 *   isOpen?: () => boolean,
 *   batch?: number,
 *   maxQueued?: number,
 *   maxQueuedBytes?: number,
 * }} opts
 */
export function createRelayInbox({
  deliver,
  schedule = (fn) => setImmediate(fn),
  onOverflow = () => {},
  isOpen = () => true,
  batch = INBOX_BATCH,
  maxQueued = INBOX_MAX_QUEUED,
  maxQueuedBytes = INBOX_MAX_QUEUED_BYTES,
} = {}) {
  if (typeof deliver !== 'function') throw new Error('createRelayInbox needs deliver');
  let queue = [];
  let head = 0;
  let bytes = 0;
  let scheduled = false;
  let closed = false;

  function take(n) {
    const part = queue.slice(head, head + n);
    head += part.length;
    if (head >= queue.length) { queue = []; head = 0; }
    else if (head > 4096 && head * 2 > queue.length) { queue = queue.slice(head); head = 0; }
    for (const m of part) bytes -= sizeOf(m);
    return part;
  }

  const pending = () => queue.length - head;

  function flush() {
    while (pending() && !closed) deliver(take(batch));
  }

  function turn() {
    scheduled = false;
    if (closed || !pending()) return;
    if (!isOpen()) { flush(); return; }
    const part = take(batch);
    try {
      deliver(part);
    } finally {
      if (pending() && !closed) arm();
    }
  }

  function arm() {
    if (scheduled) return;
    scheduled = true;
    schedule(turn);
  }

  function drop() {
    closed = true;
    queue = [];
    head = 0;
    bytes = 0;
  }

  return {
    /** Queue one message. Returns false when the socket was cut off. */
    push(message) {
      if (closed) return false;
      queue.push(message);
      bytes += sizeOf(message);
      if (pending() > maxQueued || bytes > maxQueuedBytes) {
        const info = { messages: pending(), bytes };
        drop();
        onOverflow(info);
        return false;
      }
      arm();
      return true;
    },
    /** Apply everything still queued now, in batches (socket closing). */
    flush,
    /** Drop the queue and accept nothing more (account deleted, cut off). */
    discard() {
      drop();
    },
    get size() { return pending(); },
    get bytes() { return bytes; },
    get closed() { return closed; },
  };
}
