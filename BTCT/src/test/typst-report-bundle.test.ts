import { describe, it, expect } from 'vitest';
import {
  REPORT_ASSET_MAX_BYTES,
  REPORT_IMPORT_MAX_BYTES,
  REPORT_IMPORT_MAX_ENTRIES,
  candidateDisplayNames,
  checkBundleCaps,
  comparisonsNeeded,
  decodeReportSource,
  findReportCandidates,
  normalizeMemberPath,
  planReportImport,
  referencedAssetFilenames,
  resolveReportPath,
  rewriteReportSource,
  sanitizeAssetFilename,
  selectReportFiles,
  stringLiterals,
  type ExistingAsset,
} from '@/lib/typst-report-bundle';

const GH = 'BTCT-report-templates/cptc-comp-reports';
const ghPaths = [
  'BTCT-report-templates/README.md',
  `${GH}/cptc-blank-finding-blocks/main.typ`,
  `${GH}/cptc-blank-finding-blocks/fonts/Poppins-Bold.ttf`,
  `${GH}/cptc-blank-template/main.typ`,
  `${GH}/cptc-blank-template/assets/cover.png`,
  `${GH}/cptc-blank-template/fonts/Poppins-Bold.ttf`,
  `${GH}/cptc-blank-template/fonts/Poppins-Regular.ttf`,
  `${GH}/cptc-prewritten-findings/main.typ`,
  `${GH}/cptc-prewritten-findings/fonts/Poppins-Bold.ttf`,
];

describe('normalizeMemberPath', () => {
  it('keeps safe relative paths and tidies separators', () => {
    expect(normalizeMemberPath('a/b/c.png')).toBe('a/b/c.png');
    expect(normalizeMemberPath('a\\b\\c.png')).toBe('a/b/c.png');
    expect(normalizeMemberPath('a//./b/')).toBe('a/b');
  });
  it('refuses absolute, climbing and empty names', () => {
    for (const bad of ['/etc/passwd', 'C:\\x.png', 'c:x', '../x.png', 'a/../../x', 'a/../b', '', '.', 'a\0b']) {
      expect(normalizeMemberPath(bad)).toBeNull();
    }
  });
});

describe('checkBundleCaps', () => {
  it('accepts what fits and names what does not', () => {
    expect(checkBundleCaps({ bytes: 10, entries: 10 })).toBeNull();
    expect(checkBundleCaps({ bytes: REPORT_IMPORT_MAX_BYTES + 1, entries: 1 })).toMatch(/at most 200 MB/);
    expect(checkBundleCaps({ entries: REPORT_IMPORT_MAX_ENTRIES + 1 })).toMatch(/at most 2000/);
    expect(checkBundleCaps({ entries: REPORT_IMPORT_MAX_ENTRIES })).toBeNull();
  });
});

describe('findReportCandidates', () => {
  it('lists every main.typ of a GitHub ZIP, sorted, labelled by folder', () => {
    const c = findReportCandidates(ghPaths);
    expect(c.map((x) => x.label)).toEqual(['cptc-blank-finding-blocks', 'cptc-blank-template', 'cptc-prewritten-findings']);
    expect(c[1]!.dir).toBe(`${GH}/cptc-blank-template`);
  });
  it('falls back to any .typ when there is no main.typ, and ignores clutter', () => {
    expect(findReportCandidates(['report.typ', '__MACOSX/._report.typ']).map((c) => c.label)).toEqual(['report.typ']);
    expect(findReportCandidates(['x/main.typ', 'x/chapter.typ']).map((c) => c.mainPath)).toEqual(['x/main.typ']);
    expect(findReportCandidates(['a.png'])).toEqual([]);
  });
  it('display names add parents only where two folders share a name', () => {
    const c = findReportCandidates(['a/one/main.typ', 'b/one/main.typ', 'b/two/main.typ']);
    expect(candidateDisplayNames(c)).toEqual(['a/one', 'b/one', 'two']);
  });
});

describe('stringLiterals and resolveReportPath', () => {
  it('skips comments and escaped quotes', () => {
    const src = '// "nope.png"\n#let a = "assets/x.png" /* "no.png" */ #image("y\\".png")';
    expect(stringLiterals(src).map((l) => l.value)).toEqual(['assets/x.png', 'y\\".png']);
  });
  it('resolves against the report folder the way Typst does', () => {
    expect(resolveReportPath('r/t', 'assets/c.png')).toBe('r/t/assets/c.png');
    expect(resolveReportPath('r/t', '/assets/c.png')).toBe('r/t/assets/c.png');
    expect(resolveReportPath('r/t', './img/../assets/c.png')).toBe('r/t/assets/c.png');
    expect(resolveReportPath('r/t', '../shared/logo.png')).toBe('r/shared/logo.png');
    expect(resolveReportPath('', '../x.png')).toBeNull();
    expect(resolveReportPath('r', 'https://x/y.png')).toBeNull();
  });
});

describe('selectReportFiles', () => {
  const files = [
    ...ghPaths.map((path) => ({ path, size: 100 })),
    { path: `${GH}/cptc-blank-template/notes.md`, size: 5 },
    { path: `${GH}/cptc-blank-template/img/logo.png`, size: 5 },
    { path: `${GH}/shared/badge.png`, size: 5 },
    { path: `${GH}/cptc-blank-template/assets/huge.png`, size: REPORT_ASSET_MAX_BYTES + 1 },
  ];
  const [, blank] = findReportCandidates(files.map((f) => f.path));
  const source = '#let cover = "assets/cover.png"\n#image("../shared/badge.png")\n#image("/assets/gone.png")';

  it('takes assets/, fonts/ and referenced files, and lists the rest', () => {
    const s = selectReportFiles(blank!, files, source, ['../evil.png']);
    expect(s.files.map((f) => f.path).sort()).toEqual([
      `${GH}/cptc-blank-template/assets/cover.png`,
      `${GH}/cptc-blank-template/fonts/Poppins-Bold.ttf`,
      `${GH}/cptc-blank-template/fonts/Poppins-Regular.ttf`,
      `${GH}/shared/badge.png`,
    ]);
    expect(s.missing).toEqual(['/assets/gone.png']);
    const reasons = Object.fromEntries(s.ignored.map((i) => [i.path, i.reason]));
    expect(reasons['../evil.png']).toBe('unsafe name');
    expect(reasons[`${GH}/cptc-blank-template/notes.md`]).toBe('not an image or font');
    expect(reasons[`${GH}/cptc-blank-template/img/logo.png`]).toMatch(/not referenced/);
    expect(reasons[`${GH}/cptc-blank-template/assets/huge.png`]).toMatch(/larger than/);
    // README + the two other templates' files; shared/badge.png was taken.
    expect(s.outside).toBe(5);
  });
});

const existing = (over: Partial<ExistingAsset>): ExistingAsset => ({
  id: 'e1', kind: 'image', filename: 'cover.png', size: 100, framed: false, retired: false, ...over,
});

describe('collision planning', () => {
  const sel = [
    { path: 'r/assets/cover.png', size: 100, kind: 'image' as const, wanted: 'cover.png' },
    { path: 'r/fonts/P.ttf', size: 50, kind: 'font' as const, wanted: 'P.ttf' },
  ];

  it('compares only same-name unframed images of equal size, and fonts by size', () => {
    const ex = [existing({}), existing({ id: 'f1', kind: 'font', filename: 'Other.ttf', size: 50 }), existing({ id: 'f2', kind: 'font', filename: 'P.ttf', size: 51 })];
    expect(comparisonsNeeded(sel, ex)).toEqual([{ path: 'r/assets/cover.png', existingId: 'e1' }, { path: 'r/fonts/P.ttf', existingId: 'f1' }]);
    expect(comparisonsNeeded(sel, [existing({ framed: true })])).toEqual([]);
    expect(comparisonsNeeded(sel, [existing({ size: 99 })])).toEqual([]);
  });

  it('same bytes reuse (and unretire); different bytes keep the old and upload renamed', () => {
    const same = planReportImport(sel, [existing({ retired: true })], new Map([['r/assets/cover.png', 'e1']]));
    expect(same[0]).toMatchObject({ action: 'reuse', name: 'cover.png', existingId: 'e1', unretire: true });
    expect(same[1]).toMatchObject({ action: 'upload', name: 'P.ttf' });

    const diff = planReportImport(sel, [existing({ filename: 'COVER.png' }), existing({ id: 'e2', filename: 'cover-2.png' })], new Map());
    expect(diff[0]).toMatchObject({ action: 'upload-renamed', name: 'cover-3.png', keptId: 'e1' });
  });

  it('two bundle files wanting one name get distinct names', () => {
    const two = [
      { path: 'r/assets/a/x.png', size: 1, kind: 'image' as const, wanted: 'x.png' },
      { path: 'r/assets/b/x.png', size: 2, kind: 'image' as const, wanted: 'x.png' },
    ];
    expect(planReportImport(two, [], new Map()).map((p) => [p.action, p.name])).toEqual([['upload', 'x.png'], ['upload-renamed', 'x-2.png']]);
  });
});

describe('rewriteReportSource', () => {
  const src = '#let cover = "assets/cover.png"\n#image("img/logo.png")\n#image("/assets/x.png") // "assets/cover.png"';
  it('leaves literals that already land on the right asset untouched', () => {
    const names = new Map([['r/assets/cover.png', 'cover.png'], ['r/assets/x.png', 'x.png']]);
    expect(rewriteReportSource(src, 'r', names)).toBe(src);
  });
  it('points renamed and flattened files at /assets/<name>', () => {
    const names = new Map([['r/assets/cover.png', 'cover-2.png'], ['r/img/logo.png', 'logo.png']]);
    expect(rewriteReportSource(src, 'r', names)).toBe(
      '#let cover = "/assets/cover-2.png"\n#image("/assets/logo.png")\n#image("/assets/x.png") // "assets/cover.png"',
    );
  });
});

describe('small helpers', () => {
  it('sanitizes like the server', () => {
    expect(sanitizeAssetFilename('My Cover (1).PNG')).toBe('My_Cover__1_.png');
    expect(sanitizeAssetFilename('..hidden.ttf')).toBe('hidden.ttf');
    expect(sanitizeAssetFilename('.png')).toBe('png');
  });
  it('decodes a BOM and CRLF source', () => {
    expect(decodeReportSource(new TextEncoder().encode('\uFEFFa\r\nb\rc'))).toBe('a\nb\nc');
  });
  it('finds the asset names a report references, both spellings, no subfolders', () => {
    expect([...referencedAssetFilenames('"assets/a.png" "/assets/b.jpg" "/assets/s/c.png" "x/assets/d.png"')].sort()).toEqual(['a.png', 'b.jpg']);
  });
});
