// ─────────────────────────────────────────────────────────────────────────
// Internal links to image assets.
//
// "Copy link" on an asset puts `btct-asset:<id>` on the clipboard as plain
// text. The id is the asset's server-minted uuid, which never changes (a
// rename changes the file name, not the id), so a link copied before a
// rename still resolves. Pasting one into BTCT turns it into the right
// thing for the place it lands: a figure in a finding's exploitation step,
// a filled `#image-placeholder` slot in the report source, an image in a
// note. Anywhere else it is just a short line of text.
//
// Pure and dependency-free: the Assets tab (shell bundle) and the Report tab
// both import it, so it must never import Typst code (invariant 17).
// ─────────────────────────────────────────────────────────────────────────

export const ASSET_LINK_PREFIX = 'btct-asset:';

/** Ids are uuids today; the pattern also takes the other id shapes an import can carry. */
const ID = '[A-Za-z0-9][A-Za-z0-9_-]{0,63}';
const LINK_RE = new RegExp(`btct-asset:(${ID})`, 'g');

export function assetLink(id: string): string {
  return `${ASSET_LINK_PREFIX}${id}`;
}

export interface AssetLinkMatch {
  id: string;
  start: number;
  end: number;
}

/** Every `btct-asset:<id>` in `text`, in order. */
export function findAssetLinks(text: string): AssetLinkMatch[] {
  const out: AssetLinkMatch[] = [];
  LINK_RE.lastIndex = 0;
  for (let m = LINK_RE.exec(text); m; m = LINK_RE.exec(text)) {
    out.push({ id: m[1]!, start: m.index, end: m.index + m[0].length });
  }
  return out;
}

/**
 * The ids when `text` is nothing but asset links (separated by whitespace or
 * commas), else null. This is the "paste a link" test: a sentence that
 * happens to mention a link is pasted as text.
 */
export function parseAssetLinkList(text: string): string[] | null {
  const links = findAssetLinks(text);
  if (links.length === 0) return null;
  let rest = text;
  for (let i = links.length - 1; i >= 0; i--) rest = rest.slice(0, links[i]!.start) + ' ' + rest.slice(links[i]!.end);
  if (rest.replace(/[\s,]+/g, '') !== '') return null;
  return links.map((l) => l.id);
}

/**
 * `text` with every asset link whose id `known` accepts taken out (with the
 * whitespace it leaves tidied), plus those ids in order. Links to unknown ids
 * stay in the text, so nothing the operator pasted silently disappears.
 */
export function extractAssetLinks(text: string, known: (id: string) => boolean): { text: string; ids: string[] } {
  const ids: string[] = [];
  let out = '';
  let last = 0;
  for (const l of findAssetLinks(text)) {
    if (!known(l.id)) continue;
    ids.push(l.id);
    out += text.slice(last, l.start);
    last = l.end;
  }
  if (ids.length === 0) return { text, ids };
  out += text.slice(last);
  const tidy = out
    .split('\n')
    .map((l) => l.replace(/[ \t]{2,}/g, ' ').replace(/[ \t]+$/, ''))
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  return { text: tidy, ids };
}

function typstString(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/**
 * The Typst for a figure showing this asset: a filled `#image-placeholder`
 * slot, the shape the report's figure placement writes. "Copy Typst snippet"
 * puts this on the clipboard for a report that is edited outside BTCT.
 */
export function assetTypstSnippet(asset: { filename: string }): string {
  const caption = asset.filename.replace(/\.[A-Za-z0-9]+$/, '');
  return `#image-placeholder(${typstString(caption)}, path: ${typstString(`/assets/${asset.filename}`)})`;
}
