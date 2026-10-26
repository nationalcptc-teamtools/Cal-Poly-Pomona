// Which asset files a report actually mentions.
//
// Pure: no fs, no Yjs, so src/test covers it through the .d.mts beside this
// file. It lives apart from stage.mjs for that reason alone: stage.mjs
// reaches the shared doc, and importing it from a test would drag in
// y-websocket.

/**
 * Basenames of the `assets/...` paths the report actually mentions.
 *
 * Staging every image in the workspace would cost a copy per unplaced
 * screenshot on every export. Typst resolves an image by path, so a string
 * literal is the only way one can be referenced, and a plain scan of the
 * source finds them all: the figure helper's `path:` argument and a
 * hand-written `#image("/assets/x.png")` are both string literals. A path
 * built at runtime (`image("/assets/" + name)`) is not found, and Typst then
 * reports the unresolved path against its own line, which is the same error
 * an operator would get for a typo.
 *
 * Both spellings count. `main.typ` sits at the compile root, so a relative
 * `"assets/cover.png"` and a rooted `"/assets/cover.png"` name the same file,
 * and a report written elsewhere (Typst Studio writes the relative form) used
 * to render in the browser and then fail on the server with "file not found"
 * because only the rooted spelling was staged. A path with anything before
 * `assets/` is a different directory and is left alone.
 *
 * Two deliberate imprecisions, both in the safe direction. A match inside a
 * comment or a raw block stages one file nobody looks at, in a directory that
 * is deleted with the export. A subfolder path (`/assets/sub/x.png`) matches
 * its basename, so `x.png` is staged flat and Typst reports the subfolder
 * path as unresolved, rather than the file being skipped silently. The one
 * shape it gives up on is a filename carrying an escaped quote, which ends
 * the match: that file is not staged and Typst says so.
 *
 * Fonts are not filtered: Typst resolves a font by family name, never by
 * path, so there is nothing in the source to match against.
 */
export function referencedAssetNames(source) {
  const names = new Set();
  const re = /"\/?assets\/([^"\\]+)"/g;
  let m;
  while ((m = re.exec(String(source ?? ''))) !== null) {
    const base = m[1].split('/').pop();
    if (base) names.add(base);
  }
  return names;
}
