import { describe, it, expect } from 'vitest';
import {
  FINDING_SCHEMA,
  addFindingArg,
  argForRole,
  declaresArg,
  findingFormPlan,
  kindFromDefault,
  labelFromName,
  parseFindingSignature,
  proseArgs,
  removeFindingArg,
  renameFindingArg,
  searchArgs,
} from '@/lib/typst-finding-schema';
import {
  FINDING_HELPER,
  blankFinding,
  findFindings,
  matchesFilter,
  readFindingFields,
  serializeFinding,
  type FindingStatus,
  type UiSeverity,
} from '@/lib/typst-findings';

const CPTC_DEF = `#let finding(
  level: "medium",
  number: auto,
  title: "{{FINDING NAME}}",
  impact: "{{IMPACT}}",
  likelihood: "{{LIKELIHOOD}}",
  cvss: "{{SCORE}}",
  vector: "{{CVSS VECTOR}}",
  scope: (("{{IP}}", "{{SERVICE}}", "{{PORT}}"),),
  rediscovered: false,
  description: [{{VULNERABILITY DESCRIPTION}}],
  business-impact: [{{BUSINESS IMPACT DESCRIPTION}}],
  likelihood-description: [{{LIKELIHOOD DESCRIPTION}}],
  tactics: ("{{TECHNIQUE}}",),
  mitigations: ("{{MITIGATION}}",),
  exploitation: [],
  remediation: [],
  resources: ([{{RESOURCE}}],),
) = {
  let lvl = levels.at(level)
  block[#title]
}`;

describe('the schema', () => {
  it('names every argument once, in the order a block is written', () => {
    const names = FINDING_SCHEMA.map((s) => s.name);
    expect(new Set(names).size).toBe(names.length);
    expect(names).toEqual([
      'level', 'title', 'number', 'cvss', 'vector', 'likelihood', 'impact', 'scope', 'rediscovered',
      'description', 'business-impact', 'likelihood-description', 'tactics', 'mitigations',
      'exploitation', 'remediation', 'resources',
    ]);
  });
  it('declares the roles the rail reads', () => {
    expect(argForRole('level')).toBe('level');
    expect(argForRole('title')).toBe('title');
    expect(argForRole('score')).toBe('cvss');
    expect(proseArgs()).toEqual(['description', 'business-impact', 'exploitation', 'remediation']);
    expect(searchArgs()).toEqual(['title', 'cvss']);
  });
  it('matches the arguments of BTCT\'s own helper', () => {
    const sig = parseFindingSignature(FINDING_HELPER)!;
    expect(sig.params.map((p) => p.name).sort()).toEqual(FINDING_SCHEMA.map((s) => s.name).sort());
    expect(findingFormPlan(sig, []).generic).toEqual([]);
  });
});

describe('the schema drives serialization and parsing', () => {
  it('a blank block writes exactly the schema arguments marked blank, in schema order', () => {
    const block = blankFinding('high', { id: 'fb-x' });
    const written = [...block.matchAll(/^ {2}([a-z-]+): /gm)].map((m) => m[1]);
    expect(written).toEqual(FINDING_SCHEMA.filter((s) => s.blank).map((s) => s.name));
  });
  it('reads back every schema field it wrote', () => {
    const block = serializeFinding(
      { severity: 'low', title: 'T', cvss: '5.0', scope: [['10.0.0.1', 'http', '80']], businessImpact: 'Bad', tactics: ['T1190'], resources: ['#link("https://x")[x]'] },
      { id: 'fb-r', status: 'written' },
    );
    const [f] = findFindings(block);
    const fields = readFindingFields(block, f!);
    for (const spec of FINDING_SCHEMA) expect(fields, spec.name).toHaveProperty(spec.name);
    expect(fields.title?.value).toBe('T');
    expect(fields['business-impact']?.value).toBe('Bad');
    expect(fields.scope?.value).toEqual([['10.0.0.1', 'http', '80']]);
    expect(fields.tactics?.value).toEqual(['T1190']);
    expect(fields.resources?.value).toEqual(['#link("https://x")[x]']);
    expect(fields.number?.value).toBeNull();
  });
  it('leaves out an argument the report\'s definition does not declare', () => {
    const def = '#let finding(level: "low", title: "", description: []) = []\n';
    const block = blankFinding('low', { id: 'fb-s', signature: parseFindingSignature(def) });
    expect(block).toContain('level: "low"');
    expect(block).toContain('title: ""');
    expect(block).toContain('description: []');
    expect(block).not.toContain('cvss:');
    expect(block).not.toContain('resources:');
  });
  it('a ..sink definition takes every schema argument', () => {
    const block = blankFinding('low', { id: 'fb-s', signature: parseFindingSignature('#let finding(..args) = []') });
    expect(block).toContain('resources: ()');
  });
  it('search reads the schema\'s search arguments', () => {
    const src = '#finding(level: "high", title: "SMB signing", cvss: "8.1")';
    const [f] = findFindings(src);
    expect(f!.searchText).toBe('SMB signing 8.1');
    const filter = { statuses: new Set<FindingStatus>(), severities: new Set<UiSeverity | 'none'>(), query: '8.1' };
    expect(matchesFilter(f!, filter)).toBe(true);
  });
  it('generic fields are read with the kind their default suggests', () => {
    const src = '#finding(title: "A", owner: "Rob", notes: [Some *notes*])';
    const [f] = findFindings(src);
    const fields = readFindingFields(src, f!, [{ name: 'owner', kind: 'string' }, { name: 'notes', kind: 'content' }]);
    expect(fields.owner?.value).toBe('Rob');
    expect(fields.notes?.value).toBe('Some *notes*');
  });
});

describe('the report\'s #finding signature', () => {
  it('reads CPTC\'s named parameters and their defaults', () => {
    const sig = parseFindingSignature(`#let levels = ()\n${CPTC_DEF}\n`)!;
    expect(sig.sink).toBe(false);
    expect(sig.params.map((p) => p.name)).toContain('likelihood-description');
    expect(sig.params.find((p) => p.name === 'scope')?.default).toBe('(("{{IP}}", "{{SERVICE}}", "{{PORT}}"),)');
    expect(sig.params.find((p) => p.name === 'number')?.default).toBe('auto');
  });
  it('is null with no definition, and then every argument is declared', () => {
    expect(parseFindingSignature('= Report\n#finding(title: "x")')).toBeNull();
    expect(declaresArg(null, 'anything')).toBe(true);
  });
  it('skips positional parameters and notes a sink', () => {
    const sig = parseFindingSignature('#let finding(body, title: "", ..rest) = body')!;
    expect(sig.params.map((p) => p.name)).toEqual(['title']);
    expect(sig.sink).toBe(true);
  });
  it('CPTC\'s definition shows every schema field and no generic or unused one', () => {
    const plan = findingFormPlan(parseFindingSignature(CPTC_DEF), ['level', 'title']);
    expect(plan.known.map((s) => s.name)).toEqual(FINDING_SCHEMA.map((s) => s.name));
    expect(plan.generic).toEqual([]);
    expect(plan.unused).toEqual([]);
  });
  it('a custom parameter gets a generic field; an undeclared schema one is hidden', () => {
    const def = CPTC_DEF.replace('  rediscovered: false,\n', '  owner: "",\n  retest-notes: [],\n  verified: false,\n  refs: (),\n');
    const plan = findingFormPlan(parseFindingSignature(def), ['title', 'rediscovered']);
    expect(plan.known.map((s) => s.name)).not.toContain('rediscovered');
    expect(plan.generic).toEqual([
      { name: 'owner', label: 'Owner', kind: 'string' },
      { name: 'retest-notes', label: 'Retest notes', kind: 'content' },
      { name: 'verified', label: 'Verified', kind: 'bool' },
      { name: 'refs', label: 'Refs', kind: 'strings' },
    ]);
    // The block still passes rediscovered: shown as unused, kept untouched.
    expect(plan.unused).toEqual(['rediscovered']);
  });
  it('picks a generic kind from the default\'s shape', () => {
    expect(kindFromDefault('[]')).toBe('content');
    expect(kindFromDefault('"x"')).toBe('string');
    expect(kindFromDefault('true')).toBe('bool');
    expect(kindFromDefault('("a",)')).toBe('strings');
    expect(kindFromDefault('none')).toBe('string');
    expect(labelFromName('client_short-name')).toBe('Client short name');
  });
});

describe('migrations', () => {
  const REPORT = [
    '#let finding(..a) = []',
    '= Findings',
    '// @finding id=fb-a status=written',
    '#finding(',
    '  level: "high",',
    '  title: "A",',
    '  likelihood: "Likely",',
    ')',
    '',
    'Prose between, with likelihood: "not an argument".',
    '',
    '#finding(level: "low", title: "B", likelihood: "Rare")',
    '',
    '#finding(level: "low", title: "C")',
    '',
  ].join('\n');

  it('renames an argument in every block, touching nothing else', () => {
    const next = renameFindingArg(REPORT, 'likelihood', 'chance');
    expect(next).toContain('  chance: "Likely",');
    expect(next).toContain('#finding(level: "low", title: "B", chance: "Rare")');
    expect(next).toContain('with likelihood: "not an argument"');
    expect(next.length).toBe(REPORT.length - 2 * ('likelihood'.length - 'chance'.length));
    expect(findFindings(next).map((f) => f.args.map((a) => a.name))).toEqual([
      ['level', 'title', 'chance'], ['level', 'title', 'chance'], ['level', 'title'],
    ]);
  });
  it('leaves a block that already has the new name alone', () => {
    const src = '#finding(a: 1, b: 2)';
    expect(renameFindingArg(src, 'a', 'b')).toBe(src);
  });
  it('adds an argument to every block that lacks it', () => {
    const next = addFindingArg(REPORT, 'owner', '""');
    const blocks = findFindings(next);
    expect(blocks.every((f) => f.args.some((a) => a.name === 'owner'))).toBe(true);
    expect(next).toContain('  likelihood: "Likely",\n  owner: "",\n)');
    expect(next).toContain('#finding(level: "low", title: "C", owner: "")');
    // A second pass is a no-op.
    expect(addFindingArg(next, 'owner', '"x"')).toBe(next);
  });
  it('removes an argument from every block', () => {
    const next = removeFindingArg(REPORT, 'likelihood');
    expect(findFindings(next).flatMap((f) => f.args.map((a) => a.name))).not.toContain('likelihood');
    expect(next).toContain('#finding(level: "low", title: "B")');
    expect(next).toContain('with likelihood: "not an argument"');
    expect(findFindings(next)).toHaveLength(3);
  });
  it('refuses a name that is not a Typst identifier', () => {
    expect(() => renameFindingArg(REPORT, 'title', 'bad name')).toThrow();
    expect(() => addFindingArg(REPORT, '1x', '""')).toThrow();
  });
});
