/**
 * Repoint every quoted `"<oldPath>"` literal in a Typst source at `newPath`.
 * Pure string work with no compiler code, so the store (a shell import) can
 * call it when an asset is renamed (invariant 17). Matching the full quoted
 * path keeps a bare mention of the same text in prose from being rewritten.
 */
function literal(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

export function retargetAssetPath(source: string, oldPath: string, newPath: string): string {
  if (oldPath === newPath) return source;
  return source.split(literal(oldPath)).join(literal(newPath));
}
