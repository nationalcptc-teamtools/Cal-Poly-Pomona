// The `X-Export-Warnings` response header.
//
// Pure: no fs, no Yjs, so src/test covers it through the .d.mts beside this
// file rather than through index.mjs, which reaches the export pipeline.
import { truncate } from './diagnostics.mjs';

// An HTTP header has a size limit and warnings come from report content, so
// they are capped three times over: at most this many, each no longer than
// this, and the whole encoded value short enough that it cannot push the
// response head over a proxy's limit.
const MAX_WARNINGS = 10;
const MAX_ONE_WARNING_CHARS = 300;
const MAX_WARNING_CHARS = 4000;

/**
 * The `X-Export-Warnings` value, or '' when there is nothing to send.
 *
 * Every entry is shortened first. Nothing that reaches this list has a
 * length bound of its own, and before that an entry longer than the
 * whole-header cap dropped the header entirely: the export succeeded, and the
 * operator was told nothing at all, including about the other nine warnings.
 */
export function encodeWarnings(warnings) {
  // One duplicate asset name produces the same sentence per occurrence.
  // The reader needs it once.
  let list = [...new Set(warnings ?? [])]
    .slice(0, MAX_WARNINGS)
    .map((w) => truncate(String(w), MAX_ONE_WARNING_CHARS));
  while (list.length > 0) {
    const encoded = encodeURIComponent(JSON.stringify(list));
    if (encoded.length <= MAX_WARNING_CHARS) return encoded;
    list = list.slice(0, list.length - 1);
  }
  return '';
}
