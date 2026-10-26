// ─────────────────────────────────────────────────────────────────────────
// Per-user attribution between two Yjs snapshots of a page body.
//
// Pure: no I/O, no module state. `Y` is injected so the server (which loads
// yjs through the same CJS require as y-websocket, invariant #6) and the
// vitest suite (which imports the ESM build) each hand in their own
// instance. Mixing the two would make `instanceof Y.Item` fail.
//
// Attribution comes from Y.PermanentUserData: every client maps its
// clientID to a user description when it opens a page, and records the
// delete sets of its own transactions under that description. Both live in
// the doc's `users` map and sync to the server twin like any other content.
//
// Only items inside the page body fragment count. The `users` map itself is
// written whenever someone opens a page (setUserMapping appends a clientID),
// and a naive state-vector comparison would report that as an edit.
// ─────────────────────────────────────────────────────────────────────────

const UNKNOWN_USER = 'unknown';

/** True when `item` sits anywhere inside `fragment` (walks up the parent chain). */
export function itemInFragment(item, fragment) {
  let type = item.parent;
  while (type) {
    if (type === fragment) return true;
    const parentItem = type._item;
    if (!parentItem) return false;
    type = parentItem.parent;
  }
  return false;
}

/**
 * Which users changed the body fragment between `prevSnapshot` and
 * `snapshot`, and whether anything in it changed at all.
 *
 * Insertions: a client whose clock advanced owns at least one new struct;
 * the first such struct inside the fragment attributes the client. Deletions:
 * ranges deleted in `snapshot` but not in `prevSnapshot` are attributed
 * through the PermanentUserData delete sets (the deleter, not the author of
 * the deleted text). Structs the live doc already garbage-collected before
 * the twin existed are `Y.GC`, not items, and are skipped.
 */
export function changedUsersBetween(Y, doc, fragmentName, prevSnapshot, snapshot, pud = null) {
  const fragment = doc.getXmlFragment(fragmentName);
  const users = new Set();
  let changed = false;

  snapshot.sv.forEach((clock, client) => {
    const prevClock = prevSnapshot.sv.get(client) ?? 0;
    if (clock <= prevClock) return;
    const structs = doc.store.clients.get(client) ?? [];
    for (const s of structs) {
      if (s.id.clock + s.length <= prevClock) continue;
      if (s.id.clock >= clock) break;
      if (s instanceof Y.Item && itemInFragment(s, fragment)) {
        changed = true;
        users.add(pud?.getUserByClientId(client) ?? UNKNOWN_USER);
        break;
      }
    }
  });

  snapshot.ds.clients.forEach((ranges, client) => {
    const structs = doc.store.clients.get(client) ?? [];
    const prevRanges = prevSnapshot.ds.clients.get(client) ?? [];
    for (const range of ranges) {
      // Yjs merges adjacent deleted ranges (and the deleted structs behind
      // them), so a fresh deletion next to an older one arrives as one wider
      // range. Only the part the previous snapshot did not already cover is
      // new; credit the structs inside it.
      for (const [start, end] of subtractRanges(range, prevRanges)) {
        let clock = start;
        while (clock < end) {
          const s = findStruct(structs, clock);
          if (!s) break;
          if (s instanceof Y.Item && itemInFragment(s, fragment)) {
            changed = true;
            users.add(pud?.getUserByDeletedId(Y.createID(client, clock)) ?? UNKNOWN_USER);
          }
          clock = s.id.clock + s.length;
        }
      }
    }
  });

  return { changed, users: [...users] };
}

function findStruct(structs, clock) {
  let lo = 0;
  let hi = structs.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const s = structs[mid];
    if (clock < s.id.clock) hi = mid - 1;
    else if (clock >= s.id.clock + s.length) lo = mid + 1;
    else return s;
  }
  return null;
}

/** The parts of `range` that no range in `prev` (sorted by clock) covers, as [start, end) pairs. */
function subtractRanges(range, prev) {
  const out = [];
  const end = range.clock + range.len;
  let cursor = range.clock;
  for (const p of prev) {
    const pStart = p.clock;
    const pEnd = p.clock + p.len;
    if (pEnd <= cursor) continue;
    if (pStart >= end) break;
    if (pStart > cursor) out.push([cursor, pStart]);
    cursor = Math.max(cursor, pEnd);
    if (cursor >= end) break;
  }
  if (cursor < end) out.push([cursor, end]);
  return out;
}
