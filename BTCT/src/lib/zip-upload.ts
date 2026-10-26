// ─────────────────────────────────────────────────────────────────────────
// Read a file the user picked for import, whether it is the bare file an
// older build downloaded or the .zip this build downloads (download-zip.ts).
//
// A ZIP is recognised by its signature, not its name. Inside it the first
// member that `pick` accepts is read, through JSZip's stream so a member
// larger than `maxBytes` is refused before it is inflated whole (a small
// ZIP can hold a very large file).
// ─────────────────────────────────────────────────────────────────────────

/** JSZip's internal stream (in the runtime, missing from its typings). */
interface JSZipStream {
  on(event: 'data', cb: (chunk: Uint8Array) => void): JSZipStream;
  on(event: 'error', cb: (e: Error) => void): JSZipStream;
  on(event: 'end', cb: () => void): JSZipStream;
  pause(): JSZipStream;
  resume(): JSZipStream;
}

export interface UploadedText {
  /** The bare file's name, or the member's name inside the ZIP. */
  name: string;
  text: string;
  fromZip: boolean;
}

/** `PK\x03\x04` (a ZIP with members) or `PK\x05\x06` (an empty ZIP). */
export function isZipBytes(head: Uint8Array): boolean {
  return head.length >= 4 && head[0] === 0x50 && head[1] === 0x4b
    && ((head[2] === 0x03 && head[3] === 0x04) || (head[2] === 0x05 && head[3] === 0x06));
}

async function blobBytes(blob: Blob): Promise<Uint8Array> {
  if (typeof blob.arrayBuffer === 'function') return new Uint8Array(await blob.arrayBuffer());
  return new Uint8Array(await new Response(blob).arrayBuffer());
}

/** True when `file` starts with a ZIP signature. */
export async function isZipFile(file: Blob): Promise<boolean> {
  return isZipBytes(await blobBytes(file.slice(0, 4)));
}

function baseName(path: string): string {
  const i = path.lastIndexOf('/');
  return i < 0 ? path : path.slice(i + 1);
}

/**
 * The text of an uploaded file: the file itself, or the first member of a
 * ZIP whose base name `pick` accepts. Throws a sentence for the user when
 * the file or the member is larger than `maxBytes`, or when the ZIP holds
 * no member `pick` accepts. `what` names the file without an article
 * ("BTCT settings export").
 */
export async function readUploadText(
  file: Blob & { name?: string },
  opts: { pick: (name: string) => boolean; maxBytes: number; what: string },
): Promise<UploadedText> {
  const label = file.name || 'the file';
  if (!(await isZipFile(file))) {
    if (file.size > opts.maxBytes) throw new Error(`${label} is too large for a ${opts.what}.`);
    return { name: label, text: new TextDecoder().decode(await blobBytes(file)), fromZip: false };
  }
  // A ZIP of a text file is smaller than the file; one much larger than the
  // member cap is not one of ours.
  if (file.size > opts.maxBytes * 2 + 1024 * 1024) throw new Error(`${label} is too large for a ${opts.what}.`);
  const { default: JSZip } = await import('jszip');
  let zip: InstanceType<typeof JSZip>;
  try {
    zip = await JSZip.loadAsync(await blobBytes(file));
  } catch (e) {
    throw new Error(`${label} is not a readable ZIP (${e instanceof Error ? e.message : String(e)}).`);
  }
  const member = Object.values(zip.files).find((f) => !f.dir && opts.pick(baseName(f.name)));
  if (!member) throw new Error(`${label} holds no ${opts.what}.`);
  const bytes = await readZipMember(member, opts.maxBytes, `${member.name} in ${label} is too large for a ${opts.what}.`);
  return { name: member.name, text: new TextDecoder().decode(bytes), fromZip: true };
}

/** The part of a JSZip member `readZipMember` needs. */
export interface ZipMemberLike {
  name: string;
}

/**
 * A ZIP member's bytes, read through JSZip's stream so a member that
 * inflates past `maxBytes` is refused (with `tooLarge` as the message)
 * before it is held whole: a small ZIP can hold a very large file. Shared
 * with the Report tab's report import.
 */
export function readZipMember(member: ZipMemberLike, maxBytes: number, tooLarge: string): Promise<Uint8Array> {
  return new Promise<Uint8Array>((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    let total = 0;
    let done = false;
    const stream = (member as unknown as { internalStream(type: 'uint8array'): JSZipStream }).internalStream('uint8array');
    stream
      .on('data', (chunk: Uint8Array) => {
        if (done) return;
        total += chunk.length;
        if (total > maxBytes) {
          done = true;
          stream.pause();
          reject(new Error(tooLarge));
          return;
        }
        chunks.push(chunk);
      })
      .on('error', (e: Error) => { if (!done) { done = true; reject(e); } })
      .on('end', () => {
        if (done) return;
        done = true;
        const out = new Uint8Array(total);
        let at = 0;
        for (const c of chunks) { out.set(c, at); at += c.length; }
        resolve(out);
      })
      .resume();
  });
}
