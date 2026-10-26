import { describe, expect, it } from 'vitest';
import {
  DirectoryNames, NOTE_SEGMENT_BYTES, PICTURE_STEM_BYTES, assetIdsInMarkdown, buildPageForest, capUtf8,
  dedupeNames, encodeLinkPath, exportRootName, pictureNumber, remapAssetIdsInMarkdown, rewriteAssetLinks,
  sanitizeFileName, sanitizeSegment, splitExtension, utf8Length,
} from '@/lib/export-names';

const A = '0a1b2c3d-0000-4000-8000-000000000001';
const B = '0a1b2c3d-0000-4000-8000-000000000002';

describe('sanitizeSegment', () => {
  it('replaces illegal and control characters, collapses spaces and trims dots and spaces', () => {
    expect(sanitizeSegment('a/b\\c:d*e?f"g<h>i|j%k')).toBe('a_b_c_d_e_f_g_h_i_j_k');
    expect(sanitizeSegment('bell\u0007tab\tnl\nend')).toBe('bell_tab_nl_end');
    expect(sanitizeSegment('c1\u0085del\u007f')).toBe('c1_del_');
    expect(sanitizeSegment('  many    spaces  ')).toBe('many spaces');
    expect(sanitizeSegment('trailing dot. .')).toBe('trailing dot');
    expect(sanitizeSegment('..')).toBe('Untitled');
    expect(sanitizeSegment('')).toBe('Untitled');
    expect(sanitizeSegment(undefined)).toBe('Untitled');
  });

  it('normalizes to NFC so NFD and NFC twins collide', () => {
    expect(sanitizeSegment('Café')).toBe('Café');
  });

  it('suffixes every Windows device name, with or without an extension', () => {
    for (const d of ['CON', 'prn', 'Aux', 'NUL', ...Array.from({ length: 9 }, (_, i) => `COM${i + 1}`), ...Array.from({ length: 9 }, (_, i) => `lpt${i + 1}`)]) {
      expect(sanitizeSegment(d)).toBe(`${d}_`);
    }
    expect(sanitizeSegment('con.txt')).toBe('con_.txt');
    expect(sanitizeSegment('CONSOLE')).toBe('CONSOLE');
    expect(sanitizeSegment('COM0')).toBe('COM0');
  });

  it('caps at the byte limit without splitting a code point', () => {
    const emoji = '\u{1F600}'.repeat(80);
    const out = sanitizeSegment(emoji, NOTE_SEGMENT_BYTES);
    expect(utf8Length(out)).toBeLessThanOrEqual(NOTE_SEGMENT_BYTES);
    expect(out).toBe('\u{1F600}'.repeat(15));
    expect(utf8Length(sanitizeSegment('L'.repeat(300)))).toBe(60);
    expect(capUtf8('ab\u{1F600}', 5)).toBe('ab');
    // A cap that lands right after a space trims it.
    expect(sanitizeSegment(`${'x'.repeat(59)} y`)).toBe('x'.repeat(59));
  });

  it('replaces lone surrogates so the name can be encoded', () => {
    const out = sanitizeSegment('bad\uD800name');
    expect(out).toBe('bad_name');
    expect(() => encodeURIComponent(out)).not.toThrow();
  });
});

describe('file names and dedupe', () => {
  it('keeps the extension through the cap', () => {
    expect(sanitizeFileName(`${'f'.repeat(100)}.woff2`, 40)).toBe(`${'f'.repeat(34)}.woff2`);
    expect(splitExtension('shot.PNG')).toEqual({ stem: 'shot', ext: 'png' });
    expect(splitExtension('.hidden')).toEqual({ stem: '.hidden', ext: '' });
  });

  it('dedupes case-insensitively with -2, -3 in order', () => {
    expect(dedupeNames(['Untitled', 'untitled', 'UNTITLED', '', 'Recon', 'recon'])).toEqual([
      'Untitled', 'untitled-2', 'UNTITLED-3', 'Untitled-4', 'Recon', 'recon-2',
    ]);
  });

  it('honours reserved names, so a child called Recon.attachments gets -2', () => {
    const dir = new DirectoryNames();
    dir.reserve('Recon.md');
    dir.reserve('Recon.attachments');
    expect(dir.claim('Recon.attachments')).toBe('Recon.attachments-2');
    expect(dir.claim('recon.md')).toBe('recon.md-2');
  });

  it('keeps a deduped name within the byte cap', () => {
    const long = 'n'.repeat(60);
    const dir = new DirectoryNames(60);
    expect(dir.claim(long)).toBe(long);
    const second = dir.claim(long);
    expect(second.endsWith('-2')).toBe(true);
    expect(utf8Length(second)).toBeLessThanOrEqual(60);
  });

  it('puts a file suffix before the extension', () => {
    const dir = new DirectoryNames();
    expect(dir.claim('font.ttf', true)).toBe('font.ttf');
    expect(dir.claim('FONT.ttf', true)).toBe('FONT-2.ttf');
  });
});

describe('buildPageForest', () => {
  const p = (id: string, parentId: string | null, sortOrder = 0) => ({ id, parentId, title: id, sortOrder });

  it('nests children, orders siblings, lifts orphans and cross-workspace parents', () => {
    const forest = buildPageForest([p('b', null, 2), p('a', null, 1), p('c', 'a'), p('orphan', 'gone', 3), p('self', 'self', 4)]);
    expect(forest.map((n) => n.page.id)).toEqual(['a', 'b', 'orphan', 'self']);
    expect(forest[0]!.children.map((n) => n.page.id)).toEqual(['c']);
  });

  it('breaks a two-page loop and keeps every page exactly once', () => {
    const forest = buildPageForest([p('x', 'y'), p('y', 'x'), p('z', 'y')]);
    const ids: string[] = [];
    const walk = (nodes: typeof forest) => { for (const n of nodes) { ids.push(n.page.id); walk(n.children); } };
    walk(forest);
    expect(ids.sort()).toEqual(['x', 'y', 'z']);
    expect(forest).toHaveLength(1);
  });

  it('handles a deep chain without recursion limits', () => {
    const pages = Array.from({ length: 5000 }, (_, i) => p(`p${i}`, i === 0 ? null : `p${i - 1}`));
    const forest = buildPageForest(pages);
    expect(forest).toHaveLength(1);
  });
});

describe('asset links', () => {
  it('finds image ids in order, once each', () => {
    expect(assetIdsInMarkdown(`![a](asset:${A}) text ![b](asset:${B} "t") ![again](asset:${A})`)).toEqual([A, B]);
  });

  it('rewrites known ids to encoded relative paths and keeps titles', () => {
    const { text, unresolved } = rewriteAssetLinks(
      `![x](asset:${A} "cap") ![y](asset:${B}) ![z](https://e.x/i.png) ![w](asset:not-a-uuid)`,
      (id) => (id === A ? encodeLinkPath('My Note.attachments/01-shot (1)/modified.png') : null),
    );
    expect(text).toContain('![x](My%20Note.attachments/01-shot%20%281%29/modified.png "cap")');
    expect(text).toContain(`![y](asset:${B})`);
    expect(text).toContain('![z](https://e.x/i.png)');
    expect(text).toContain('![w](asset:not-a-uuid)');
    expect(unresolved).toEqual([B]);
  });

  it('remaps any mapped id and leaves the rest', () => {
    const map = new Map([[A, B]]);
    expect(remapAssetIdsInMarkdown(`![](asset:${A}) ![](asset:other)`, map)).toBe(`![](asset:${B}) ![](asset:other)`);
  });
});

describe('root and numbering', () => {
  it('names the root after the workspace and local time', () => {
    expect(exportRootName('CPTC: Team/5', new Date(2026, 9, 11, 14, 32))).toBe('CPTC_ Team_5_2026-10-11_1432');
  });

  it('pads picture numbers to two digits, three from 100 pictures', () => {
    expect(pictureNumber(0, 5)).toBe('01');
    expect(pictureNumber(9, 120)).toBe('010');
  });

  it('keeps a three-deep tree of maximum names under 260 characters', () => {
    const seg = 'n'.repeat(NOTE_SEGMENT_BYTES);
    const root = exportRootName('w'.repeat(200), new Date(2026, 0, 1));
    const path = `${root}/notes/${seg}/${seg}/${seg}/${seg}.attachments/001-${'s'.repeat(PICTURE_STEM_BYTES)}/original.jpeg`;
    expect(path.length).toBeLessThan(400);
    expect(path.split('/').every((s) => utf8Length(s) <= 255)).toBe(true);
  });
});
