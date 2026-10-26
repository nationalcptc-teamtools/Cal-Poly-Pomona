import type * as YTypes from 'yjs';

export function itemInFragment(item: unknown, fragment: unknown): boolean;

export function changedUsersBetween(
  Y: typeof YTypes,
  doc: YTypes.Doc,
  fragmentName: string,
  prevSnapshot: YTypes.Snapshot,
  snapshot: YTypes.Snapshot,
  pud?: YTypes.PermanentUserData | null,
): { changed: boolean; users: string[] };
