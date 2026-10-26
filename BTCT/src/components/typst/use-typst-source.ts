// ─────────────────────────────────────────────────────────────────────────
// The report's source Y.Text: one per workspace, keyed
// `typst:<workspaceId>:source`.
//
// Split out of TypstView so the seeding rule can be unit-tested on its own,
// without the editor, the preview and the compiler coming with it.
// ─────────────────────────────────────────────────────────────────────────

import { useEffect, useState } from 'react';
import * as Y from 'yjs';
import { getSharedDoc, getOrInitYText, textKey } from '@/realtime/shared-doc';
import { DEFAULT_TYPST_TEMPLATE } from '@/lib/typst-template';

/**
 * Bind to the per-workspace Typst source Y.Text, seeding it on first open.
 *
 * The report is the one Y.Text with no repo `create()` behind it: the tab
 * that opens it is what seeds it. Seeding on mount writes a SECOND Y.Text
 * into the slot whenever the local doc is still cold, and Yjs resolves two
 * concurrent map writes by client id, so half the time the starter template
 * wins and the real report (which has no version history) is gone.
 * `realtime/use-y-text.ts` documents the same footgun for input fields.
 *
 * So a seed needs proof that nothing is coming, and there are exactly two
 * things that count as proof:
 *
 *  - the key is already in the local doc (IndexedDB replay or a live sync),
 *    in which case it is adopted rather than seeded, offline or not; or
 *  - the websocket provider reports synced, so the server has told us what
 *    it has for this room and the absence of the key is an answer.
 *
 * `whenReady` is the gate for the first of those, but it cannot authorize a
 * seed by itself: it also resolves on its own 4 s cap, so a client on a
 * congested link or against a server still booting would seed on a timeout
 * and race the real text. Until one of the two conditions holds the hook
 * returns null and the tab sits in its loading state. That is the intended
 * trade for an operator with no connection and no cached report: waiting
 * beats a template that could later overwrite the real one.
 */
export function useTypstSource(workspaceId: string): Y.Text | null {
  const [ytext, setYtext] = useState<Y.Text | null>(null);

  useEffect(() => {
    let cancelled = false;
    const key = textKey('typst', workspaceId, 'source');
    const shared = getSharedDoc();
    const texts = shared.texts;
    // A workspace switch must never leave the previous workspace's report on
    // screen (and editable) under the new key.
    setYtext(null);
    let current: Y.Text | null = null;

    // Rebind if the canonical Y.Text in the slot arrives, or is replaced, via
    // sync (the rare two-clients-seed-at-once case) so we never edit an
    // orphan.
    const onMapChange = (ev: Y.YMapEvent<Y.Text>) => {
      if (!ev.changes.keys.has(key)) return;
      const next = texts.get(key);
      if (next && next !== current) {
        current = next;
        setYtext(next);
      }
    };
    texts.observe(onMapChange);

    // Adopts whatever is in the slot and seeds the template only if it is
    // genuinely empty. An intentionally-cleared report keeps an empty Y.Text,
    // so it is not re-seeded either.
    const bind = () => {
      if (cancelled) return;
      current = getOrInitYText(key, DEFAULT_TYPST_TEMPLATE);
      setYtext(current);
    };

    let onSync: ((synced: boolean) => void) | null = null;
    const stopWaiting = () => {
      if (!onSync) return;
      shared.provider.off('sync', onSync);
      onSync = null;
    };

    void shared.whenReady.then(() => {
      if (cancelled) return;
      if (texts.has(key) || shared.provider.synced) {
        bind();
        return;
      }
      // Nothing local and nothing from the server yet: wait for the sync
      // instead of seeding on a timeout. If the text arrives first,
      // `onMapChange` adopts it and this seed then finds the slot populated.
      onSync = (synced: boolean) => {
        if (!synced || cancelled) return;
        stopWaiting();
        bind();
      };
      shared.provider.on('sync', onSync);
    });

    return () => {
      cancelled = true;
      texts.unobserve(onMapChange);
      stopWaiting();
    };
  }, [workspaceId]);

  return ytext;
}
