// One image, redacted, in a process of its own. Spawned by stage.mjs, once
// per image that carries a crop or a blur.
//
// THE IMPORT GRAPH IS PART OF THE DESIGN: `node:fs`, `node:path` and
// `./bake.mjs` (which brings jimp and the crop and blur math from src/lib).
// Nothing else, and in particular never `stage.mjs`, `export.mjs` or
// `../yjs-data.mjs`: anything that reaches y-websocket or y-leveldb would
// give every child a second Yjs instance and a child that may try to open
// the LevelDB directory the parent process holds open.
//
// Why a child at all: jimp decodes in the same process it runs in, Bun does
// not hand the memory back between images, and that process is the Yjs relay
// for the whole team. Measured in the 1 GiB container before this change, a
// report with twelve blurred 10 MP screenshots took the relay to 981 MiB and
// made two consecutive /healthz probes time out at 5 s. In a child, the peak
// belongs to a process that exits, and a cgroup OOM kills the child instead
// of the relay.
//
// argv (an array, never a shell string; every value comes from the parent,
// which vetted it):
//   [2] src      absolute path of the original upload, under ASSETS_DIR
//   [3] outDir   an empty directory outside the typst compile root
//   [4] name     the asset's filename, which is what picks the encoder
//   [5] meta     JSON: {"crop": …, "blurs": […]}
//
// It writes `out.part`, renames it to `out.bin`, and only then writes
// `result.json`. The parent stages the bytes only when the result says ok
// AND `out.bin` is non-empty, so a crash, a kill, a timeout or a
// half-written file can never leave the original, unredacted bytes in an
// export.
import fs from 'node:fs';
import path from 'node:path';
import { bakeImage } from './bake.mjs';

const [src, outDir, name, meta] = process.argv.slice(2);

function finish(result, code) {
  try { fs.writeFileSync(path.join(outDir, 'result.json'), JSON.stringify(result)); }
  catch (err) { console.error(String(err)); } // the parent then falls back to this stderr
  process.exit(code);
}

try {
  const { crop = null, blurs = null } = JSON.parse(meta || '{}') ?? {};
  const out = await bakeImage(new Uint8Array(fs.readFileSync(src)), { crop, blurs }, name);
  // The parent never spawns for an image with nothing to apply, so null here
  // means the parent and bakeImage disagree about what counts as work. That
  // is a bug, and refusing the export is the safe way to report it.
  if (!out || out.byteLength === 0) {
    finish({ ok: false, message: `${name}: the redaction produced no image.` }, 1);
  }
  const part = path.join(outDir, 'out.part');
  fs.writeFileSync(part, out);
  fs.renameSync(part, path.join(outDir, 'out.bin'));
  finish({ ok: true }, 0);
} catch (err) {
  // bakeImage's own message already starts with the filename.
  finish({ ok: false, message: err instanceof Error ? err.message : String(err) }, 1);
}
