/**
 * React binding for a collaborative text field backed by a Y.Text.
 *
 * Sync model
 * ──────────
 * Per-keystroke insert/delete deltas on a shared CRDT (same as Google
 * Docs / Notion / Linear). Concurrent typing on different machines
 * merges character-by-character.
 *
 * Race-free seeding
 * ─────────────────
 * Y.Texts are only created by the entity's creator (in the repo's
 * `create()` call) or by the post-sync migration in shared-doc.ts.
 * A reader that opens a page before the Y.Text has arrived simply
 * waits for the parent `texts` Y.Map to deliver it via sync; it does
 * NOT race-seed, because two clients both seeding the same slot would
 * each end up bound to their own local Y.Text and miss each other's
 * deltas.
 */
import { useEffect, useRef, useState, useCallback } from 'react';
import * as Y from 'yjs';
import { getSharedDoc, sharedTransact } from './shared-doc';

const isHigh = (c: number) => c >= 0xd800 && c <= 0xdbff;
const isLow = (c: number) => c >= 0xdc00 && c <= 0xdfff;

function diff(oldStr: string, newStr: string): { index: number; remove: number; insert: string } | null {
  if (oldStr === newStr) return null;
  let start = 0;
  const minLen = Math.min(oldStr.length, newStr.length);
  while (start < minLen && oldStr.charCodeAt(start) === newStr.charCodeAt(start)) start++;
  // Never split a surrogate pair: two astral chars can share a high
  // surrogate, and Y.Text stores a lone half as U+FFFD.
  if (start > 0 && isHigh(oldStr.charCodeAt(start - 1))) start--;
  let oldEnd = oldStr.length;
  let newEnd = newStr.length;
  while (
    oldEnd > start &&
    newEnd > start &&
    oldStr.charCodeAt(oldEnd - 1) === newStr.charCodeAt(newEnd - 1)
  ) {
    oldEnd--;
    newEnd--;
  }
  if (oldEnd < oldStr.length && isLow(oldStr.charCodeAt(oldEnd))) {
    oldEnd++;
    newEnd++;
  }
  return {
    index: start,
    remove: oldEnd - start,
    insert: newStr.slice(start, newEnd),
  };
}

/**
 * Rewrite a Y.Text to `next` using a single minimal delta rather than a
 * clear-and-reinsert.
 *
 * Used for programmatic edits to a whole document (assigning a screenshot to
 * a figure slot, upgrading a helper definition). Replacing the full text
 * would delete every character and re-add it, which blows away collaborators'
 * cursors, floods the CRDT with garbage, and makes the change unmergeable
 * with a concurrent edit. Splicing only the changed span leaves untouched
 * regions (and anyone typing in them) alone.
 */
export function replaceYTextContent(ytext: Y.Text, next: string): void {
  const d = diff(ytext.toString(), next);
  if (!d) return;
  sharedTransact(() => {
    if (d.remove > 0) ytext.delete(d.index, d.remove);
    if (d.insert.length > 0) ytext.insert(d.index, d.insert);
  });
}

/**
 * Rewrite a Y.Text from a function of its CURRENT content.
 *
 * The delta `replaceYTextContent` writes is measured against the live text,
 * so `next` has to be computed from the live text too. Building it from a
 * React mirror that lags the CRDT (the Typst tab's is a 120 ms trailing
 * debounce) makes the diff read every character a collaborator typed inside
 * that window as a deletion: their text disappears, their cursor with it,
 * and an append near the end turns into delete-and-reinsert of the whole
 * tail. Reading `toString()` here, one line before the diff, closes that
 * window.
 */
export function updateYTextContent(ytext: Y.Text, compute: (current: string) => string): void {
  const current = ytext.toString();
  const next = compute(current);
  if (next !== current) replaceYTextContent(ytext, next);
}

export function useYTextInput(
  key: string,
  initial: string,
): [
  value: string,
  onChange: (next: string) => void,
  inputRef: React.MutableRefObject<HTMLInputElement | null>,
] {
  const ytextRef = useRef<Y.Text | null>(null);
  const [value, setValue] = useState<string>(initial);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    const sharedTexts = getSharedDoc().texts;

    let bound: Y.Text | null = null;
    let prevString = initial;

    const restoreCaret = (prev: string, next: string, isLocal: boolean) => {
      const el = inputRef.current;
      if (!el || document.activeElement !== el || isLocal) return;
      const start0 = el.selectionStart ?? 0;
      const end0 = el.selectionEnd ?? 0;
      const d = diff(prev, next);
      let start = start0;
      let end = end0;
      if (d) {
        if (d.index <= start) {
          const shift = d.insert.length - d.remove;
          start = Math.max(d.index, start + shift);
          end = Math.max(d.index, end + shift);
        } else if (d.index < end) {
          end = d.index;
        }
      }
      queueMicrotask(() => {
        const e2 = inputRef.current;
        if (!e2) return;
        try {
          e2.setSelectionRange(start, end);
        } catch {
          /* number/email inputs don't support selection range */
        }
      });
    };

    const onTextChange = (_ev: Y.YTextEvent, tr: Y.Transaction) => {
      if (!bound) return;
      const next = bound.toString();
      restoreCaret(prevString, next, tr.local);
      prevString = next;
      setValue(next);
    };

    const bindTo = (t: Y.Text) => {
      if (bound === t) return;
      if (bound) bound.unobserve(onTextChange);
      bound = t;
      ytextRef.current = t;
      t.observe(onTextChange);
      const next = t.toString();
      prevString = next;
      setValue(next);
    };

    // Bind immediately if the Y.Text already exists in the shared doc.
    const existing = sharedTexts.get(key);
    if (existing) {
      bindTo(existing);
    }

    // Watch for the slot to appear (or be replaced) via sync. This is
    // the ONLY way a non-creating client picks up the canonical Y.Text;
    // we never race-seed here.
    const onMapChange = (ev: Y.YMapEvent<Y.Text>) => {
      if (!ev.changes.keys.has(key)) return;
      const next = sharedTexts.get(key);
      if (next) bindTo(next);
    };
    sharedTexts.observe(onMapChange);

    return () => {
      sharedTexts.unobserve(onMapChange);
      if (bound) bound.unobserve(onTextChange);
      bound = null;
      ytextRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  const onChange = useCallback(
    (next: string) => {
      const t = ytextRef.current;
      if (!t) {
        // No Y.Text bound yet: the slot hasn't synced from the server.
        // Reflect the keystroke optimistically so the user isn't blocked.
        // Once the Y.Text arrives, our observer will overwrite this with
        // the canonical content (the user's local typing during this
        // window will be lost, but in practice the slot syncs in <100ms).
        setValue(next);
        return;
      }
      const cur = t.toString();
      const d = diff(cur, next);
      if (!d) return;
      sharedTransact(() => {
        if (d.remove > 0) t.delete(d.index, d.remove);
        if (d.insert.length > 0) t.insert(d.index, d.insert);
      });
      setValue(next);
    },
    [],
  );

  return [value, onChange, inputRef];
}
