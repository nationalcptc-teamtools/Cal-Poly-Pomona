import { describe, it, expect } from 'vitest';
import {
  findFindings,
  escapeMarkupComments,
  unescapeMarkupComments,
  findSeveritySections,
  setFindingArg,
  setFindingField,
  setFindingStatus,
  ensureFindingMarker,
  insertFinding,
  removeFinding,
  serializeFinding,
  blankFinding,
  FINDING_HELPER,
  displaySeverity,
  moveFindingToSeverity,
  movesOnSeverityChange,
  liftFinding,
  UI_SEVERITIES,
  ensureFindingHelper,
  hasFindingHelper,
  readFindingFields,
  decodeContent,
  encodeContent,
  decodeScope,
  encodeScope,
  decodeStringArray,
  decodeContentArray,
  matchClose,
  matchesFilter,
  newFindingId,
  isNoSeverity,
  levelLiteral,
  findingAcceptsNoSeverity,
  allowNoSeverity,
  type FindingBlock,
  type FindingFilter,
  type UiSeverity,
  type FindingStatus,
} from '@/lib/typst-findings';

const seqRand = () => {
  let i = 0;
  const seq = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8];
  return () => seq[i++ % seq.length]!;
};

// A compact two-finding report used across the parsing tests.
const REPORT = `#set page(margin: 1cm)
#set heading(numbering: "1.1")

#let finding(level: "medium", title: "x", description: [d], exploitation: [e]) = [#title]

= TECHNICAL FINDINGS

== CRITICAL-RISK FINDINGS <sec-critical>

// @finding id=fb-aaa status=completed
#finding(
  level: "critical",
  title: "Domain compromise",
  cvss: "9.8",
  scope: (("10.0.0.5", "SMB", "445"),),
  description: [A real description of the issue.],
)

#end-of-block

== HIGH-RISK FINDINGS <sec-high>

#finding(
  level: "high",
  title: "SMB signing",
  cvss: "8.1",
  description: [{{VULNERABILITY DESCRIPTION}}],
)
`;

describe('matchClose', () => {
  it('matches nested parens', () => {
    expect(matchClose('(a(b)c)', 0)).toBe(6);
  });
  it('ignores brackets inside strings', () => {
    const s = '("a)b", 1)';
    expect(matchClose(s, 0)).toBe(s.length - 1);
  });
  it('ignores brackets inside raw blocks', () => {
    const s = '(```bash\nif [ x ]; then )\n```)';
    expect(matchClose(s, 0)).toBe(s.length - 1);
  });
  it('treats quotes in markup as literal text', () => {
    const s = '[he said "hi)" to me]';
    expect(matchClose(s, 0)).toBe(s.length - 1);
  });
  it('returns -1 when unbalanced', () => {
    expect(matchClose('(a(b)', 0)).toBe(-1);
  });
});

describe('findFindings', () => {
  it('finds both calls, not the #let definition', () => {
    const fs = findFindings(REPORT);
    expect(fs).toHaveLength(2);
    expect(fs[0]!.title).toBe('Domain compromise');
    expect(fs[1]!.title).toBe('SMB signing');
  });
  it('reads the marker id and status', () => {
    const [a, b] = findFindings(REPORT);
    expect(a!.id).toBe('fb-aaa');
    expect(a!.tag).toBe('completed');
    expect(a!.status).toBe('completed');
    expect(a!.auto).toBe(false);
    expect(b!.id).toBeNull();
    expect(b!.auto).toBe(true);
  });
  it('computes blank vs written from the prose fields', () => {
    const [, b] = findFindings(REPORT);
    // b has no tag; its status is computed and is blank (only a placeholder description).
    expect(b!.status).toBe('blank');
    const written = REPORT.replace('{{VULNERABILITY DESCRIPTION}}', 'Signing is off.');
    expect(findFindings(written)[1]!.status).toBe('written');
  });
  it('reads severity and cvss', () => {
    const [a, b] = findFindings(REPORT);
    expect(a!.severity).toBe('critical');
    expect(a!.cvss).toBe('9.8');
    expect(b!.severity).toBe('high');
  });
  it('includes #end-of-block in the block it follows', () => {
    const a = findFindings(REPORT)[0]!;
    expect(REPORT.slice(a.start, a.end)).toContain('#end-of-block');
  });
  it('skips a call inside a comment', () => {
    const s = `// #finding(level: "low", title: "nope")\n#finding(level: "low", title: "yes")`;
    const fs = findFindings(s);
    expect(fs).toHaveLength(1);
    expect(fs[0]!.title).toBe('yes');
  });
});

describe('values', () => {
  it('round-trips a one-line content block', () => {
    expect(decodeContent('[hello world]')).toBe('hello world');
    expect(encodeContent('hello world')).toBe('[hello world]');
  });
  it('dedents a multi-line content block', () => {
    const raw = '[\n    *Step 1* \\\n    do the thing\n  ]';
    expect(decodeContent(raw)).toBe('*Step 1* \\\ndo the thing');
  });
  it('round-trips scope rows', () => {
    const rows = decodeScope('(("10.0.0.5", "SMB", "445"), ("10.0.0.6", "HTTP", "80"))');
    expect(rows).toEqual([['10.0.0.5', 'SMB', '445'], ['10.0.0.6', 'HTTP', '80']]);
    expect(decodeScope(encodeScope(rows!))).toEqual(rows);
  });
  it('keeps a single scope row an array (trailing comma)', () => {
    expect(encodeScope([['a', 'b', 'c']])).toContain('),)');
  });
  it('decodes string and content arrays', () => {
    expect(decodeStringArray('("T1110", "T1078")')).toEqual(['T1110', 'T1078']);
    expect(decodeContentArray('([a], [b])')).toEqual(['a', 'b']);
  });
});

describe('setFindingArg', () => {
  it('replaces one argument, leaving the rest', () => {
    const f = findFindings(REPORT)[0]!;
    const next = setFindingArg(REPORT, f, 'cvss', '"7.7"');
    expect(next).toContain('cvss: "7.7"');
    expect(next).toContain('title: "Domain compromise"');
    expect(findFindings(next)).toHaveLength(2);
  });
  it('adds a missing argument', () => {
    const f = findFindings(REPORT)[1]!;
    const next = setFindingArg(REPORT, f, 'vector', '"CVSS:3.1/..."');
    const nf = findFindings(next)[1]!;
    expect(readFindingFields(next, nf).vector?.value).toBe('CVSS:3.1/...');
  });
  it('removes an argument', () => {
    const f = findFindings(REPORT)[0]!;
    const next = setFindingArg(REPORT, f, 'cvss', null);
    expect(findFindings(next)).toHaveLength(2);
    expect(findFindings(next)[0]!.cvss).toBeNull();
    // The other finding's cvss is untouched.
    expect(findFindings(next)[1]!.cvss).toBe('8.1');
  });
  it('a replace then re-read gives the new value (via setFindingField)', () => {
    const f = findFindings(REPORT)[0]!;
    const next = setFindingField(REPORT, f, 'title', 'string', 'Renamed finding');
    expect(findFindings(next)[0]!.title).toBe('Renamed finding');
  });
  it('writes a multi-line content field as a dedented block', () => {
    const f = findFindings(REPORT)[0]!;
    const next = setFindingField(REPORT, f, 'remediation', 'content', '+ One\n+ Two');
    const nf = findFindings(next)[0]!;
    expect(readFindingFields(next, nf).remediation?.value).toBe('+ One\n+ Two');
  });
});

describe('status', () => {
  it('rewrites an existing marker in place', () => {
    const f = findFindings(REPORT)[0]!;
    const { source, id } = setFindingStatus(REPORT, f, 'needs-work');
    expect(id).toBe('fb-aaa');
    expect(source).toContain('// @finding id=fb-aaa status=needs-work');
    expect(findFindings(source)[0]?.status).toBe('needs-work');
  });
  it('adds a marker to an untagged finding', () => {
    const f = findFindings(REPORT)[1]!;
    const { source, id } = setFindingStatus(REPORT, f, 'written', seqRand());
    expect(id).toMatch(/^fb-/);
    const nf = findFindings(source)[1];
    expect(nf?.id).toBe(id);
    expect(nf?.status).toBe('written');
    expect(findFindings(source)).toHaveLength(2);
  });
  it('ensureFindingMarker is idempotent for a tagged finding', () => {
    const f = findFindings(REPORT)[0]!;
    expect(ensureFindingMarker(REPORT, f).source).toBe(REPORT);
  });
});

describe('sections', () => {
  it('finds severity sections by their labels', () => {
    const secs = findSeveritySections(REPORT);
    expect(secs.map((s) => s.severity)).toEqual(['critical', 'high']);
  });
  it('does not treat a code line starting with = as a heading', () => {
    const s = `== HIGH-RISK FINDINGS <sec-high>\n\n#finding(level: "high", title: "t", exploitation: [\n\`\`\`bash\n== not a heading\n\`\`\`\n])`;
    expect(findSeveritySections(s).map((x) => x.severity)).toEqual(['high']);
  });
});

describe('insertFinding', () => {
  it('inserts into the matching section after its last finding', () => {
    const block = serializeFinding({ severity: 'critical', title: 'New crit' }, { id: 'fb-new', status: 'blank', endOfBlock: true });
    const next = insertFinding(REPORT, block, 'critical');
    const crit = findFindings(next).filter((f) => f.severity === 'critical');
    expect(crit).toHaveLength(2);
    expect(crit[1]!.title).toBe('New crit');
    // It landed in the critical section, before the high one.
    expect(next.indexOf('New crit')).toBeLessThan(next.indexOf('HIGH-RISK'));
  });
  it('creates a section when the severity has none', () => {
    const block = serializeFinding({ severity: 'low', title: 'Low one' }, { id: 'fb-low', status: 'blank' });
    const next = insertFinding(REPORT, block, 'low');
    expect(next).toContain('<sec-low>');
    expect(findSeveritySections(next).map((s) => s.severity)).toContain('low');
    // After high (the less-severe section goes last).
    expect(next.indexOf('<sec-low>')).toBeGreaterThan(next.indexOf('<sec-high>'));
  });
});

describe('removeFinding', () => {
  it('removes the block, its marker and its #end-of-block', () => {
    const f = findFindings(REPORT)[0]!;
    const next = removeFinding(REPORT, f);
    const fs = findFindings(next);
    expect(fs).toHaveLength(1);
    expect(next).not.toContain('fb-aaa');
    expect(next).not.toContain('Domain compromise');
    // Only one #end-of-block remained in the original; it is gone.
    expect(next).not.toContain('#end-of-block');
  });
});

describe('ensureFindingHelper', () => {
  it('adds the helper when there is none', () => {
    const s = '#set page(margin: 1cm)\n\n= Findings\n';
    expect(hasFindingHelper(s)).toBe(false);
    const { source, changed } = ensureFindingHelper(s);
    expect(changed).toBe(true);
    expect(hasFindingHelper(source)).toBe(true);
    // It went after the leading #set rule.
    expect(source.indexOf('#let finding(')).toBeGreaterThan(source.indexOf('#set page'));
  });
  it('is a no-op when the report defines finding itself', () => {
    expect(ensureFindingHelper(REPORT).changed).toBe(false);
  });
});

describe('blank findings', () => {
  it('a blank block has no placeholder or sample text', () => {
    const block = blankFinding('high', { id: 'fb-new' });
    expect(block).not.toContain('{{');
    expect(block).toContain('// @finding id=fb-new status=blank');
    expect(block).toContain('title: ""');
    expect(block).toContain('description: []');
  });
  it('parses back as an empty, Blank finding of that severity', () => {
    const whole = `#let finding(..args) = []\n\n${blankFinding('medium', { id: 'fb-b' })}\n`;
    const [f] = findFindings(whole);
    expect(f?.severity).toBe('medium');
    expect(f?.status).toBe('blank');
    expect(f?.title).toBe('');
    const fields = readFindingFields(whole, f!);
    expect(fields.description?.value).toBe('');
    expect(fields.scope?.value).toEqual([]);
    expect(fields.tactics?.value).toEqual([]);
  });
  it('a blank block with no severity is written level: none and reads back as none', () => {
    const block = blankFinding(null, { id: 'fb-n' });
    expect(block).toContain('level: none,');
    const whole = `#let finding(..args) = []\n\n${block}\n`;
    const [f] = findFindings(whole);
    expect(f?.severity).toBeNull();
    expect(isNoSeverity(whole, f!)).toBe(true);
  });
  it('the helper definition carries no placeholder text either', () => {
    expect(FINDING_HELPER).not.toContain('{{');
  });
  it('writes every argument, so the team definition fills in no defaults', () => {
    const block = serializeFinding({ severity: 'low' }, { id: 'fb-x', status: 'blank' });
    for (const name of ['title', 'cvss', 'vector', 'likelihood', 'impact', 'scope', 'description',
      'business-impact', 'likelihood-description', 'tactics', 'mitigations', 'exploitation', 'remediation', 'resources']) {
      expect(block, name).toContain(`  ${name}: `);
    }
  });
  it('inserts into its section with the CPTC separator when the report defines it', () => {
    const src = `#let end-of-block = []\n${REPORT}`;
    const next = insertFinding(src, blankFinding('high', { id: 'fb-h', endOfBlock: true }), 'high');
    const highs = findFindings(next).filter((f) => f.severity === 'high');
    expect(highs).toHaveLength(2);
    expect(next.slice(highs[1]!.start, highs[1]!.end)).toContain('#end-of-block');
  });
});

describe('severities in the UI', () => {
  it('offers exactly four', () => {
    expect([...UI_SEVERITIES]).toEqual(['critical', 'high', 'medium', 'low']);
  });
  it('lists an info finding under Low without touching the source', () => {
    const src = `#finding(level: "info", title: "Banner")`;
    const [f] = findFindings(src);
    expect(f?.severity).toBe('info');
    expect(displaySeverity(f!)).toBe('low');
  });
  it('the Low filter includes an info finding', () => {
    const [f] = findFindings(`#finding(level: "info", title: "Banner")`);
    const filter = { statuses: new Set<FindingStatus>(), severities: new Set<UiSeverity | 'none'>(['low']), query: '' };
    expect(matchesFilter(f!, filter)).toBe(true);
  });
});

describe('severity change', () => {
  it('moves the block into the target section and rewrites level', () => {
    const f = findFindings(REPORT)[1]!; // high, untagged
    const next = moveFindingToSeverity(REPORT, f, 'critical', seqRand());
    const crit = findFindings(next).filter((x) => x.severity === 'critical');
    expect(crit.map((x) => x.title)).toEqual(['Domain compromise', 'SMB signing']);
    expect(findFindings(next).filter((x) => x.severity === 'high')).toHaveLength(0);
    // It now sits inside the critical section, before the high heading.
    expect(next.indexOf('SMB signing')).toBeLessThan(next.indexOf('HIGH-RISK'));
  });
  it('keeps the block identity (marker id) through the move', () => {
    const f = findFindings(REPORT)[0]!; // fb-aaa
    const next = moveFindingToSeverity(REPORT, f, 'low');
    const moved = findFindings(next).find((x) => x.id === 'fb-aaa');
    expect(moved?.severity).toBe('low');
    expect(moved?.status).toBe('completed');
    expect(next).toContain('<sec-low>');
  });
  it('lift returns the block text and a source without it', () => {
    const f = findFindings(REPORT)[0]!;
    const lifted = liftFinding(REPORT, f, 'medium');
    expect(lifted.text).toContain('level: "medium"');
    expect(findFindings(lifted.source)).toHaveLength(1);
  });
  it('without severity sections only the level changes, in place', () => {
    const src = '= Findings\n\n#finding(level: "low", title: "A")\n\n#finding(level: "high", title: "B")\n';
    expect(movesOnSeverityChange(src)).toBe(false);
    const next = moveFindingToSeverity(src, findFindings(src)[0]!, 'critical');
    expect(next).toBe(src.replace('level: "low"', 'level: "critical"'));
  });
});

describe('matchesFilter', () => {
  const block = (over: Partial<FindingBlock>): FindingBlock => ({
    index: 0, id: null, tag: null, status: 'written', auto: true, severity: 'high',
    title: 'SMB signing', cvss: '8.1', line: 1, start: 0, pagebreakStart: null, end: 0, markerStart: null,
    markerEnd: null, callStart: 0, callClose: 0, indent: '', args: [], ...over,
  });
  const filter = (over: Partial<FindingFilter>): FindingFilter => ({
    statuses: new Set<FindingStatus>(), severities: new Set<UiSeverity | 'none'>(), query: '', ...over,
  });
  it('empty filters match everything', () => {
    expect(matchesFilter(block({}), filter({}))).toBe(true);
  });
  it('filters by status', () => {
    expect(matchesFilter(block({ status: 'blank' }), filter({ statuses: new Set(['written']) }))).toBe(false);
    expect(matchesFilter(block({ status: 'written' }), filter({ statuses: new Set(['written']) }))).toBe(true);
  });
  it('filters by severity', () => {
    expect(matchesFilter(block({ severity: 'low' }), filter({ severities: new Set(['high']) }))).toBe(false);
  });
  it('filters by query against title and cvss', () => {
    expect(matchesFilter(block({}), filter({ query: 'smb' }))).toBe(true);
    expect(matchesFilter(block({}), filter({ query: 'kerberos' }))).toBe(false);
    expect(matchesFilter(block({}), filter({ query: '8.1' }))).toBe(true);
  });
});

describe('newFindingId', () => {
  it('is fb- prefixed and stable for a seed', () => {
    expect(newFindingId(seqRand())).toMatch(/^fb-[0-9a-z]{6}$/);
  });
});

describe('no severity', () => {
  const ACCEPTS = REPORT.replace('= [#title]', '= if level == none [#title] else [#level #title]');
  const report = (body: string) => `${ACCEPTS}\n== MEDIUM-RISK FINDINGS <sec-medium>\n\n#finding(level: "medium", title: "M")\n\n#pagebreak(weak: true)\n\n= APPENDIX\n\nText.\n${body}`;

  it('reads a block with no level, or level: none, as no severity', () => {
    const src = '#finding(title: "A")\n\n#finding(level: none, title: "B")\n\n#finding(level: "low", title: "C")\n';
    const fs = findFindings(src);
    expect(fs.map((f) => f.severity)).toEqual([null, null, 'low']);
    expect(fs.map((f) => isNoSeverity(src, f))).toEqual([true, true, false]);
    expect(fs.map((f) => displaySeverity(f) ?? 'none')).toEqual(['none', 'none', 'low']);
    // An expression level is not "no severity": the form leaves it alone.
    const expr = '#finding(level: lvl, title: "D")\n';
    expect(isNoSeverity(expr, findFindings(expr)[0]!)).toBe(false);
  });

  it('writes level: none and round-trips', () => {
    expect(levelLiteral(null)).toBe('none');
    expect(levelLiteral('low')).toBe('"low"');
    const src = '= Notes\n\n#finding(level: "low", title: "A")\n';
    const next = moveFindingToSeverity(src, findFindings(src)[0]!, null);
    expect(next).toBe(src.replace('level: "low"', 'level: none'));
    const f = findFindings(next)[0]!;
    expect(f.severity).toBeNull();
    expect(readFindingFields(next, f).level).toEqual({ value: null, expression: 'none' });
    // And back.
    expect(moveFindingToSeverity(next, f, 'low')).toBe(src);
  });

  it('moves out of the severity sections to the end of the findings area, before a closing pagebreak and the next chapter', () => {
    const src = report('');
    const crit = findFindings(src)[0]!;
    const next = moveFindingToSeverity(src, crit, null, seqRand());
    const moved = findFindings(next).find((x) => x.title === 'Domain compromise')!;
    expect(moved.severity).toBeNull();
    expect(next.indexOf('Domain compromise')).toBeGreaterThan(next.indexOf('title: "M"'));
    expect(next.indexOf('Domain compromise')).toBeLessThan(next.indexOf('#pagebreak'));
    expect(next.indexOf('#pagebreak')).toBeLessThan(next.indexOf('= APPENDIX'));
    // Its #end-of-block and marker travel with it.
    expect(next.slice(next.indexOf('Domain compromise'))).toMatch(/^[^=]*#end-of-block/);
    expect(moved.id).toBe('fb-aaa');
    // A second one goes after the first.
    const high = findFindings(next).find((x) => x.title === 'SMB signing')!;
    const twice = moveFindingToSeverity(next, high, null, seqRand());
    expect(twice.indexOf('SMB signing')).toBeGreaterThan(twice.indexOf('Domain compromise'));
    expect(twice.indexOf('SMB signing')).toBeLessThan(twice.indexOf('#pagebreak'));
  });

  it('moving back to a severity goes into that section, ahead of parked unrated blocks', () => {
    const src = report('');
    const out = moveFindingToSeverity(src, findFindings(src)[0]!, null, seqRand());
    const parked = findFindings(out).find((x) => x.title === 'Domain compromise')!;
    const back = moveFindingToSeverity(out, parked, 'medium', seqRand());
    const order = findFindings(back).map((x) => x.title);
    expect(order).toEqual(['SMB signing', 'M', 'Domain compromise']);
    expect(findFindings(back)[2]!.severity).toBe('medium');
    // A rated block added to the last section lands before a parked unrated one.
    const block = serializeFinding({ severity: 'medium', title: 'M2' }, { id: 'fb-m2', status: 'blank' });
    const withM2 = insertFinding(out, block, 'medium');
    expect(withM2.indexOf('M2')).toBeLessThan(withM2.indexOf('Domain compromise'));
  });

  it('stays in place when the report has no severity sections', () => {
    const src = '= Findings\n\n#finding(level: "high", title: "A")\n\n#finding(level: "low", title: "B")\n';
    const next = moveFindingToSeverity(src, findFindings(src)[0]!, null);
    expect(findFindings(next).map((f) => f.title)).toEqual(['A', 'B']);
    expect(next).toContain('level: none, title: "A"');
  });

  it('knows which definitions accept none', () => {
    expect(findingAcceptsNoSeverity('#finding(title: "A")')).toBe(true); // no definition: the helper is added
    expect(findingAcceptsNoSeverity(FINDING_HELPER)).toBe(true);
    expect(findingAcceptsNoSeverity(REPORT)).toBe(false);
    expect(findingAcceptsNoSeverity(CPTC_DEF)).toBe(false);
  });

  it('teaches a CPTC-shaped definition to draw none, once and only on its lookup line', () => {
    const taught = allowNoSeverity(CPTC_DEF)!;
    expect(taught).toContain('let lvl = if level == none { (bar: luma(110), fg: white, name: "") } else { levels.at(level) }');
    expect(findingAcceptsNoSeverity(taught)).toBe(true);
    expect(allowNoSeverity(taught)).toBe(taught);
    // BTCT's older helper (default: in the lookup) is taught the same way.
    const old = FINDING_HELPER.replace(/let lvl = if level == none \{[^\n]*\n/, 'let lvl = finding-levels.at(level, default: finding-levels.medium)\n');
    expect(findingAcceptsNoSeverity(old)).toBe(false);
    expect(allowNoSeverity(old)).toContain('else { finding-levels.at(level, default: finding-levels.medium) }');
    // A definition with no lookup line cannot be taught: the form explains instead.
    expect(allowNoSeverity(REPORT)).toBeNull();
  });

  it("BTCT's helper draws no severity with a neutral bar and no label", () => {
    expect(FINDING_HELPER).toContain('let lvl = if level == none { (bar: luma(110), name: none) }');
    expect(FINDING_HELPER).toContain('if lvl.name != none { pill(lvl.name');
  });
});

const CPTC_DEF = `#let levels = (
  critical: (bar: rgb("#674ea7"), fg: white, name: "Critical"),
  low: (bar: rgb("#F5D979"), fg: white, name: "Low"),
)
#let finding(
  level: "medium",
  title: "",
) = {
  let lvl = levels.at(level)
  table(table.cell(fill: lvl.bar, text(fill: lvl.fg, title)))
}
`;

describe('comment markers typed into a content field', () => {
  it('escapes a bare // and /* so the block is still found', () => {
    for (const text of ['two // slashes', '//', 'a /* b', 'ends with //']) {
      const block = serializeFinding({ severity: 'high', title: 'T', description: text }, { id: 'c1', status: 'blank' });
      const [f] = findFindings(block);
      expect(f, text).toBeDefined();
      expect(readFindingFields(block, f!).description!.value).toBe(text);
    }
  });

  it('leaves a URL and raw code alone', () => {
    expect(escapeMarkupComments('see http://10.0.0.5/x')).toBe('see http://10.0.0.5/x');
    expect(escapeMarkupComments('run `curl a//b` then // note')).toBe('run `curl a//b` then \\// note');
    expect(unescapeMarkupComments(escapeMarkupComments('a // b /* c'))).toBe('a // b /* c');
  });
});

describe('page break belongs to the block it opens', () => {
  const call = (title: string, level = 'high') => `#finding(\n  level: "${level}",\n  title: "${title}",\n)`;
  const brk = (n: number) => (src: string) => (src.match(/#pagebreak/g) ?? []).length === n;

  it('blankFinding with pagebreak starts with the weak break line', () => {
    const block = blankFinding('high', { id: 'fb-p', pagebreak: true });
    expect(block.startsWith('#pagebreak(weak: true)\n// @finding id=fb-p')).toBe(true);
    expect(blankFinding('high', { id: 'fb-q' })).not.toContain('#pagebreak');
  });

  it('findFindings absorbs a break directly above, with or without a marker', () => {
    const a = `#pagebreak()\n\n// @finding id=fb-a status=blank\n${call('A')}\n`;
    const [fa] = findFindings(a);
    expect(fa!.start).toBe(0);
    expect(fa!.pagebreakStart).toBe(0);
    expect(fa!.markerStart).toBe(a.indexOf('// @finding'));
    const b = `text\n#pagebreak(weak: true)\n${call('B')}\n`;
    const [fb] = findFindings(b);
    expect(fb!.start).toBe(b.indexOf('#pagebreak'));
    expect(fb!.callStart).toBe(b.indexOf('#finding('));
    expect(fb!.markerStart).toBeNull();
  });

  it('does not absorb a break separated by a heading, a comment or text', () => {
    for (const mid of ['== H\n', '// note\n', 'some text\n']) {
      const src = `#pagebreak()\n${mid}${call('A')}\n`;
      const [f] = findFindings(src);
      expect(f!.pagebreakStart).toBeNull();
      expect(f!.start).toBe(src.indexOf('#finding('));
    }
  });

  it('a CPTC-style break after #end-of-block belongs to the next block; titles are unchanged', () => {
    const src = `${call('One')}\n\n#end-of-block\n\n#pagebreak()\n\n${call('Two')}\n\n#end-of-block\n`;
    const fs = findFindings(src);
    expect(fs.map((f) => f.title)).toEqual(['One', 'Two']);
    expect(fs[0]!.pagebreakStart).toBeNull();
    expect(fs[0]!.end).toBe(src.indexOf('#end-of-block') + '#end-of-block'.length);
    expect(fs[1]!.pagebreakStart).toBe(src.indexOf('#pagebreak'));
  });

  it('removeFinding takes the break with the block and keeps the previous block intact', () => {
    const src = `${call('One')}\n\n#end-of-block\n\n#pagebreak()\n\n${call('Two')}\n\n#end-of-block\n\n== Next\n`;
    const [, two] = findFindings(src);
    const out = removeFinding(src, two!);
    expect(brk(0)(out)).toBe(true);
    expect(findFindings(out).map((f) => f.title)).toEqual(['One']);
    expect(out).toContain('#end-of-block');
    expect(out).toContain('== Next');
    expect(out).toBe(`${call('One')}\n\n#end-of-block\n\n== Next\n`);
  });

  const REPORT = `${FINDING_HELPER}

= Findings

== HIGH-RISK FINDINGS <sec-high>

#pagebreak(weak: true)
// @finding id=fb-1 status=blank
${call('One')}

== LOW-RISK FINDINGS <sec-low>

`;

  it('a severity move carries the break with the block', () => {
    const [f] = findFindings(REPORT);
    const out = moveFindingToSeverity(REPORT, f!, 'low', () => 0.5);
    expect(findFindings(out)).toHaveLength(1);
    const g = findFindings(out)[0]!;
    expect(g.severity).toBe('low');
    // Low had no rated block: the break is above its heading, not under it.
    expect(out.indexOf('#pagebreak')).toBeLessThan(out.indexOf('== LOW-RISK'));
    expect(out.indexOf('== LOW-RISK')).toBeLessThan(out.indexOf('// @finding'));
    expect(brk(1)(out)).toBe(true);
    // The old section is left without a stray break.
    expect(out.slice(out.indexOf('== HIGH-RISK') + '== HIGH-RISK FINDINGS <sec-high>'.length, out.indexOf('#pagebreak')).trim()).toBe('');
  });

  it('inserting under the heading of an empty section puts the break above the heading', () => {
    const src = `${FINDING_HELPER}\n\n= Findings\n\n== HIGH-RISK FINDINGS <sec-high>\n\n== LOW-RISK FINDINGS <sec-low>\n`;
    const out = insertFinding(src, blankFinding('high', { id: 'fb-n', pagebreak: true }), 'high');
    const i = out.indexOf('#pagebreak(weak: true)');
    expect(i).toBeGreaterThan(-1);
    expect(i).toBeLessThan(out.indexOf('== HIGH-RISK'));
    expect(out.slice(out.indexOf('== HIGH-RISK'))).not.toContain('#pagebreak');
    expect(findFindings(out)[0]!.pagebreakStart).toBeNull();
    expect(brk(1)(out)).toBe(true);
  });

  it('a heading already preceded by a break gets no second one', () => {
    const src = `= Findings\n\n#pagebreak()\n\n== HIGH-RISK FINDINGS <sec-high>\n\n== LOW-RISK FINDINGS <sec-low>\n`;
    const out = insertFinding(src, blankFinding('high', { id: 'fb-n', pagebreak: true }), 'high');
    expect(brk(1)(out)).toBe(true);
    expect(findFindings(out)).toHaveLength(1);
  });

  it('a new section heading gets the break above it, and none when one is already there', () => {
    const src = `${FINDING_HELPER}\n\n= Findings\n\n== LOW-RISK FINDINGS <sec-low>\n\n`;
    const out = insertFinding(src, blankFinding('high', { id: 'fb-n', pagebreak: true }), 'high');
    const h = out.indexOf('== HIGH-RISK');
    expect(h).toBeGreaterThan(-1);
    expect(out.lastIndexOf('#pagebreak', h)).toBeGreaterThan(-1);
    expect(out.slice(h, out.indexOf('== LOW-RISK'))).not.toContain('#pagebreak');
    expect(brk(1)(out)).toBe(true);
    const src2 = `${FINDING_HELPER}\n\n= Findings\n\n== LOW-RISK FINDINGS <sec-low>\n\n#pagebreak()\n`;
    const out2 = insertFinding(src2, blankFinding('critical', { id: 'fb-c', pagebreak: true }), 'critical');
    expect(findFindings(out2)).toHaveLength(1);
  });

  it('after a rated block the break stays with the new block', () => {
    const out = insertFinding(REPORT, blankFinding('high', { id: 'fb-2', pagebreak: true }), 'high');
    const fs = findFindings(out);
    expect(fs).toHaveLength(2);
    expect(fs[1]!.pagebreakStart).not.toBeNull();
    expect(brk(2)(out)).toBe(true);
  });

  it('a No severity block keeps its break', () => {
    const out = insertFinding(REPORT, blankFinding(null, { id: 'fb-u', pagebreak: true }), null);
    const fs = findFindings(out);
    expect(fs).toHaveLength(2);
    expect(fs[1]!.pagebreakStart).not.toBeNull();
  });
});
