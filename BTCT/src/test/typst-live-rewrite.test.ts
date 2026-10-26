// A programmatic rewrite of the report has to be computed from the LIVE
// Y.Text, not from the 120 ms-stale React mirror the view renders. The
// rewrite lands as a minimal delta against the live text (invariant #3b), so
// a `next` built on the stale copy makes the diff read every character a
// collaborator typed inside that window as "deleted".
import { describe, it, expect, beforeEach, vi } from 'vitest';
import * as Y from 'yjs';
import { appendSlot, PLACEHOLDER_HELPER, ensureHelper } from '@/lib/typst-placeholders';

const shared = vi.hoisted(() => ({ doc: null as unknown }));

// `replaceYTextContent` wraps its splice in `sharedTransact`; here that is
// just a transaction on whichever doc the test is driving.
vi.mock('@/realtime/shared-doc', () => ({
  getSharedDoc: () => shared.doc,
  sharedTransact: (fn: () => void) => {
    const doc = shared.doc as Y.Doc | null;
    if (doc) doc.transact(fn); else fn();
  },
}));

import { replaceYTextContent, updateYTextContent } from '@/realtime/use-y-text';

const BASE = `${PLACEHOLDER_HELPER}\n\n= Findings\n\nThe box answered on 445.\n`;

/** How much of `text` a rewrite deleted, summed over its delta. */
function watchDeletes(text: Y.Text): () => number {
  let deleted = 0;
  text.observe((ev) => {
    for (const op of ev.delta) if (typeof op.delete === 'number') deleted += op.delete;
  });
  return () => deleted;
}

let local: Y.Doc;
let remoteDoc: Y.Doc;
let text: Y.Text;
/** What the view's debounced mirror still holds: the source before the remote edit. */
let staleMirror: string;

beforeEach(() => {
  local = new Y.Doc();
  remoteDoc = new Y.Doc();
  shared.doc = local;
  text = local.getText('report');
  text.insert(0, BASE);
  Y.applyUpdate(remoteDoc, Y.encodeStateAsUpdate(local));

  staleMirror = text.toString();

  // A collaborator types near the top of the document while the mirror is
  // still catching up.
  const remoteText = remoteDoc.getText('report');
  remoteText.insert(remoteText.toString().indexOf('= Findings') + 2, 'SMB: ');
  Y.applyUpdate(local, Y.encodeStateAsUpdate(remoteDoc));
});

describe('report rewrites computed from the live text', () => {
  it('leaves the document unchanged when the helper is already current', () => {
    expect(ensureHelper(BASE).changed).toBe(false);
  });

  it('keeps a concurrent edit and deletes nothing when a slot is appended', () => {
    const deleted = watchDeletes(text);

    updateYTextContent(text, (current) => appendSlot(current, 'Share listing'));

    expect(text.toString()).toContain('SMB: Findings');
    expect(text.toString()).toContain('#image-placeholder("Share listing")');
    // An append is pure insertion: nothing in the document was rewritten.
    expect(deleted()).toBe(0);
  });

  it('rewrites a rename target without touching the rest of the document', () => {
    const deleted = watchDeletes(text);

    updateYTextContent(text, (current) => `${current}#image("/assets/new.png")\n`);

    expect(text.toString()).toContain('SMB: Findings');
    expect(deleted()).toBe(0);
  });

  it('is a no-op when the compute function returns the current text', () => {
    const deleted = watchDeletes(text);
    const before = text.toString();

    updateYTextContent(text, (current) => current);

    expect(text.toString()).toBe(before);
    expect(deleted()).toBe(0);
  });

  // Why the helper exists at all: the old shape computed `next` from the
  // mirror and handed the whole string to `replaceYTextContent`, whose diff
  // then read the collaborator's characters as a deletion.
  it('demonstrates the loss when the rewrite is computed from the stale mirror', () => {
    const deleted = watchDeletes(text);

    replaceYTextContent(text, appendSlot(staleMirror, 'Share listing'));

    expect(text.toString()).not.toContain('SMB: ');
    expect(deleted()).toBeGreaterThan(0);
  });
});
