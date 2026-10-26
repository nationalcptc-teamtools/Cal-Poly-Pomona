// ─────────────────────────────────────────────────────────────────────────
// The finding block's arguments, in one place.
//
// Every `#finding(...)` argument BTCT knows is one row of FINDING_SCHEMA:
// its Typst name, the label the form shows, the value shape it is read and
// written as, the editor that renders it, whether a new blank block writes
// it, and what the rail reads from it (title, severity, score, search, the
// computed "written" status). The parser (`readFindingFields`,
// `findFindings`), the serializer (`serializeFinding`, `blankFinding`), the
// form (FindingsPanel's FindingForm), the rail's search and the finding
// copy and paste all read this table instead of naming arguments of their
// own.
//
// To change the finding template: edit `#let finding` in the report (the
// look), and if its arguments change, change this table (one place);
// everything else follows. The migration helpers at the bottom
// (`renameFindingArg`, `addFindingArg`, `removeFindingArg`) then rewrite
// every block of a report in one pass, so the existing findings follow too.
//
// The form also adapts to the report's own definition at run time
// (`parseFindingSignature`, `findingFormPlan`): a schema argument the
// definition does not declare is hidden and never written, a parameter the
// definition declares that the schema does not know gets a generic editor,
// and an argument a block carries that the definition does not declare is
// listed as unused and left alone.
//
// Pure. Lazy with the rest of the Report tab (invariant 17): only
// lib/typst-* modules and components/typst import it.
//
// Import note: this module and `typst-findings.ts` import each other. Keep
// every cross use inside a function body (never at module top level), so
// either can be loaded first.
// ─────────────────────────────────────────────────────────────────────────

import {
  findFindings,
  findingDefinitionRange,
  matchClose,
  setFindingArg,
  splitCallArgs,
  decodeStringArray,
  type FindingBlock,
} from './typst-findings';

/** How a value is read from and written to the source. */
export type FieldKind = 'string' | 'content' | 'strings' | 'contents' | 'scope' | 'bool';

/** Which form editor renders an argument. */
export type FieldEditor =
  | 'severity'
  | 'text'
  | 'number'
  | 'scope'
  | 'checkbox'
  | 'content'
  | 'list'
  | 'exploitation'
  | 'remediation';

export interface FindingArgSpec {
  /** The Typst argument name. */
  name: string;
  /** The `FindingFields` key `serializeFinding` takes its value from. */
  key: string;
  label: string;
  kind: FieldKind;
  editor: FieldEditor;
  /** Written (empty) by `blankFinding`, so a template's default or placeholder text never shows. */
  blank: boolean;
  /** What the rail reads it as. */
  role?: 'level' | 'title' | 'score';
  /** A non-empty value marks the block as written (the computed status). */
  prose?: boolean;
  /** The rail's search box matches its text. */
  search?: boolean;
  // Editor options.
  mono?: boolean;
  rows?: number;
  placeholder?: string;
  addLabel?: string;
  /** Sits beside the next paired field in a two-column row. */
  pair?: boolean;
}

/**
 * The CPTC finding block, plus BTCT's `level: "info"` and `level: none`.
 * Order is the form's order and the order a new block is written in.
 */
export const FINDING_SCHEMA: readonly FindingArgSpec[] = [
  { name: 'level', key: 'severity', label: 'Severity', kind: 'string', editor: 'severity', blank: true, role: 'level' },
  { name: 'title', key: 'title', label: 'Title', kind: 'string', editor: 'text', blank: true, role: 'title', search: true },
  { name: 'number', key: 'number', label: 'Number', kind: 'string', editor: 'number', blank: false },
  { name: 'cvss', key: 'cvss', label: 'CVSS score', kind: 'string', editor: 'text', blank: true, role: 'score', search: true, mono: true, pair: true },
  { name: 'vector', key: 'vector', label: 'CVSS vector', kind: 'string', editor: 'text', blank: true, mono: true, pair: true },
  { name: 'likelihood', key: 'likelihood', label: 'Likelihood', kind: 'string', editor: 'text', blank: true, pair: true },
  { name: 'impact', key: 'impact', label: 'Impact', kind: 'string', editor: 'text', blank: true, pair: true },
  { name: 'scope', key: 'scope', label: 'Affected scope', kind: 'scope', editor: 'scope', blank: true },
  { name: 'rediscovered', key: 'rediscovered', label: 'Rediscovered vulnerability', kind: 'bool', editor: 'checkbox', blank: false },
  { name: 'description', key: 'description', label: 'Vulnerability description', kind: 'content', editor: 'content', blank: true, prose: true, rows: 4 },
  { name: 'business-impact', key: 'businessImpact', label: 'Business impact', kind: 'content', editor: 'content', blank: true, prose: true, rows: 3 },
  { name: 'likelihood-description', key: 'likelihoodDescription', label: 'Likelihood description', kind: 'content', editor: 'content', blank: true, rows: 2 },
  { name: 'tactics', key: 'tactics', label: 'MITRE techniques', kind: 'strings', editor: 'list', blank: true, placeholder: 'T1190 Exploit Public-Facing Application', addLabel: 'Add technique' },
  { name: 'mitigations', key: 'mitigations', label: 'MITRE mitigations', kind: 'strings', editor: 'list', blank: true, placeholder: 'M1051 Update Software', addLabel: 'Add mitigation' },
  { name: 'exploitation', key: 'exploitation', label: 'Exploitation details', kind: 'content', editor: 'exploitation', blank: true, prose: true },
  { name: 'remediation', key: 'remediation', label: 'Remediation', kind: 'content', editor: 'remediation', blank: true, prose: true },
  { name: 'resources', key: 'resources', label: 'Resources', kind: 'contents', editor: 'list', blank: true, placeholder: '#link("https://...")[Advisory title]', addLabel: 'Add resource' },
];

/** The spec of an argument, or undefined when the schema does not know it. */
export function findingArgSpec(name: string): FindingArgSpec | undefined {
  return FINDING_SCHEMA.find((s) => s.name === name);
}

/** The argument name that plays a role (level, title, score). */
export function argForRole(role: NonNullable<FindingArgSpec['role']>): string {
  return FINDING_SCHEMA.find((s) => s.role === role)!.name;
}

/** Arguments whose text counts toward the computed "written" status. */
export function proseArgs(): string[] {
  return FINDING_SCHEMA.filter((s) => s.prose).map((s) => s.name);
}

/** Arguments the rail's search matches. */
export function searchArgs(): string[] {
  return FINDING_SCHEMA.filter((s) => s.search).map((s) => s.name);
}

/** The empty value of a kind: what a blank block writes. */
export function emptyValue(kind: FieldKind): string | string[] | boolean {
  switch (kind) {
    case 'string':
    case 'content':
      return '';
    case 'bool':
      return false;
    default:
      return [];
  }
}

// ── the report's own definition ──────────────────────────────────────────

export interface FindingParam {
  name: string;
  /** The default's source text, trimmed. */
  default: string;
}

export interface FindingSignature {
  /** Named parameters, in definition order. */
  params: FindingParam[];
  /** The definition takes `..rest`, so it accepts any named argument. */
  sink: boolean;
}

/**
 * The named parameters of the report's `#let finding(...)`, or null when
 * the report has no definition of its own (BTCT's helper is added then, and
 * it declares every schema argument). Positional parameters are skipped: a
 * block never passes one by name.
 */
export function parseFindingSignature(src: string): FindingSignature | null {
  const def = findingDefinitionRange(src);
  if (!def) return null;
  const open = src.indexOf('(', def.start);
  const close = open === -1 ? -1 : matchClose(src, open);
  if (close === -1) return null;
  const params: FindingParam[] = [];
  let sink = false;
  for (const a of splitCallArgs(src, open, close)) {
    const value = src.slice(a.valueStart, a.valueEnd).trim();
    if (a.name === null) {
      if (value.startsWith('..')) sink = true;
      continue;
    }
    params.push({ name: a.name, default: value });
  }
  return { params, sink };
}

/** Does the definition take this argument? No definition, or a `..sink`, takes all. */
export function declaresArg(sig: FindingSignature | null, name: string): boolean {
  return sig === null || sig.sink || sig.params.some((p) => p.name === name);
}

/** The value shape a generic field edits, chosen from the default's shape. */
export function kindFromDefault(def: string): FieldKind {
  const t = def.trim();
  if (t.startsWith('[')) return 'content';
  if (t === 'true' || t === 'false') return 'bool';
  if (t.startsWith('(') && decodeStringArray(t) !== null) return 'strings';
  return 'string';
}

/** `client-name` as "Client name". */
export function labelFromName(name: string): string {
  const words = name.replace(/[-_]+/g, ' ').trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export interface GenericField {
  name: string;
  label: string;
  kind: FieldKind;
}

export interface FindingFormPlan {
  /** Schema arguments the definition declares, in schema order. */
  known: FindingArgSpec[];
  /** Parameters the definition declares that the schema does not know. */
  generic: GenericField[];
  /** Arguments this block carries that the definition does not declare. */
  unused: string[];
}

/**
 * What the form shows for one block under the report's definition. With no
 * definition (or a `..sink`) every schema argument is shown and nothing is
 * unused.
 */
export function findingFormPlan(sig: FindingSignature | null, blockArgs: readonly string[]): FindingFormPlan {
  const known = FINDING_SCHEMA.filter((s) => declaresArg(sig, s.name));
  const generic: GenericField[] = (sig?.params ?? [])
    .filter((p) => !findingArgSpec(p.name))
    .map((p) => ({ name: p.name, label: labelFromName(p.name), kind: kindFromDefault(p.default) }));
  const unused = sig && !sig.sink
    ? [...new Set(blockArgs)].filter((n) => !sig.params.some((p) => p.name === n))
    : [];
  return { known, generic, unused };
}

// ── migrations ───────────────────────────────────────────────────────────
//
// For a template change: rewrite every `#finding(...)` block of a report in
// one pass. Blocks are edited last to first, so each edit leaves the earlier
// offsets valid, and nothing outside an argument's own text is touched, so
// handing the result to `applySource` makes a minimal delta.

function eachBlockBackwards(src: string, edit: (s: string, f: FindingBlock) => string): string {
  const blocks = findFindings(src);
  let out = src;
  for (let i = blocks.length - 1; i >= 0; i--) out = edit(out, blocks[i]!);
  return out;
}

/** Rename an argument in every block. A block that already has `to` keeps both as they are. */
export function renameFindingArg(src: string, from: string, to: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_-]*$/.test(to)) throw new Error(`not an argument name: ${to}`);
  return eachBlockBackwards(src, (s, f) => {
    const arg = f.args.find((a) => a.name === from);
    if (!arg || f.args.some((a) => a.name === to)) return s;
    const at = s.indexOf(from, arg.start);
    if (at === -1 || at >= arg.valueStart) return s;
    return s.slice(0, at) + to + s.slice(at + from.length);
  });
}

/** Add `name: literal` to every block that does not have it yet. */
export function addFindingArg(src: string, name: string, literal: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_-]*$/.test(name)) throw new Error(`not an argument name: ${name}`);
  return eachBlockBackwards(src, (s, f) => (f.args.some((a) => a.name === name) ? s : setFindingArg(s, f, name, literal)));
}

/** Remove an argument from every block that has it. */
export function removeFindingArg(src: string, name: string): string {
  return eachBlockBackwards(src, (s, f) => (f.args.some((a) => a.name === name) ? setFindingArg(s, f, name, null) : s));
}
