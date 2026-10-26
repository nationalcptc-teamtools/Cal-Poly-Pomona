/**
 * An LRU of promises capped by the total size of what they resolved to.
 *
 * Entries are promises so concurrent callers share one fetch or encode. An
 * entry still in flight has no size yet and is never evicted (evicting it
 * would only start a second copy of the same work); once it settles its
 * size counts, and the least recently used settled entries go until the
 * total is back under the cap. The newest entry is kept even when it alone
 * is over the cap, since its caller is holding it anyway.
 */
export class ByteLru<V> {
  private readonly entries = new Map<string, { value: Promise<V>; size: number | null }>();
  private total = 0;

  constructor(
    readonly maxBytes: number,
    private readonly sizeOf: (value: V) => number,
  ) {}

  get size(): number { return this.entries.size; }
  /** Bytes held by settled entries. */
  get bytes(): number { return this.total; }

  get(key: string): Promise<V> | undefined {
    const e = this.entries.get(key);
    if (!e) return undefined;
    this.entries.delete(key);
    this.entries.set(key, e);
    return e.value;
  }

  has(key: string): boolean { return this.entries.has(key); }

  set(key: string, value: Promise<V>): Promise<V> {
    this.delete(key);
    const entry = { value, size: null as number | null };
    this.entries.set(key, entry);
    value.then(
      (v) => {
        if (this.entries.get(key) !== entry) return;
        entry.size = Math.max(0, this.sizeOf(v) || 0);
        this.total += entry.size;
        this.evict(key);
      },
      () => { if (this.entries.get(key) === entry) this.entries.delete(key); },
    );
    return value;
  }

  delete(key: string): void {
    const e = this.entries.get(key);
    if (!e) return;
    if (e.size !== null) this.total -= e.size;
    this.entries.delete(key);
  }

  keys(): string[] { return [...this.entries.keys()]; }

  private evict(keep: string): void {
    if (this.total <= this.maxBytes) return;
    for (const [k, e] of this.entries) {
      if (this.total <= this.maxBytes) break;
      if (k === keep || e.size === null) continue;
      this.total -= e.size;
      this.entries.delete(k);
    }
  }
}
