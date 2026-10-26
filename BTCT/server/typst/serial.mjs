// One export at a time: a compile is a CPU burst, and two in parallel on a
// small box would starve the Yjs relay. A rejected job must not wedge the queue.
export function createSerial() {
  let tail = Promise.resolve();
  return (job) => {
    const next = tail.then(() => job(), () => job());
    tail = next.then(() => undefined, () => undefined);
    return next;
  };
}
