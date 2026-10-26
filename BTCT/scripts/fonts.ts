// Puts the 17 fonts typst.ts installs by default under public/fonts, so the
// compiler never touches the CDN (the app must work offline).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_FONT_FILES } from '../src/lib/typst-default-fonts';

export const FONT_FILES = DEFAULT_FONT_FILES;
const CDN = 'https://cdn.jsdelivr.net/gh/typst/typst-assets@v0.13.1/files/fonts/';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
  const out = path.resolve(__dirname, '..', 'public', 'fonts');
  fs.mkdirSync(out, { recursive: true });
  let fetched = 0;
  for (const name of FONT_FILES) {
    const target = path.join(out, name);
    if (fs.existsSync(target)) continue;
    const res = await fetch(CDN + name);
    if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`);
    // Write under a temp name and rename once the whole body is on disk. A
    // fetch interrupted halfway would otherwise leave a truncated file that
    // the skip-if-present check above trusts forever, and a truncated font
    // surfaces much later as a parser error inside the compiler.
    const partial = `${target}.partial`;
    fs.writeFileSync(partial, new Uint8Array(await res.arrayBuffer()));
    fs.renameSync(partial, target);
    fetched++;
  }
  console.log(`fonts: ${FONT_FILES.length} files in ${out} (${fetched} fetched, ${FONT_FILES.length - fetched} already present)`);
}

// Top level, not behind an argv check: this runs in the image build, and a
// failure has to be a non-zero exit rather than a script that quietly does
// nothing.
await main();
