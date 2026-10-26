import { describe, it, expect } from 'vitest';
import {
  FINDING_COPY_TAG,
  assetFilesIn,
  findingCopyPayload,
  freshFindingId,
  parseFindingPayload,
  pasteFindings,
  planAssetCopies,
  reidentifyBlock,
  rewriteAssetPaths,
} from '@/lib/typst-finding-copy';
import { FINDING_HELPER, findFindings, findSeveritySections, findingAcceptsNoSeverity } from '@/lib/typst-findings';

function seqRand(seed = 1): () => number {
  let x = seed;
  return () => {
    x = (x * 16807) % 2147483647;
    return x / 2147483647;
  };
}

const SOURCE = `${FINDING_HELPER}

= Findings

== HIGH-RISK FINDINGS <sec-high>

  // @finding id=fb-aaa status=written
  #finding(
    level: "high",
    title: "SMB signing",
    exploitation: [
      *1. Relay* \\
      Relayed.

      #image-placeholder("Relay", path: "/assets/relay.png", height: 3in)
      #image-placeholder("Again", path: "/assets/relay.png")
      #image-placeholder("Hash", path: "/assets/hash.png")
    ],
  )

== LOW-RISK FINDINGS <sec-low>
`;

const TARGET = `${FINDING_HELPER}

= Findings

== CRITICAL-RISK FINDINGS <sec-critical>

// @finding id=fb-aaa status=blank
#finding(level: "critical", title: "Existing")

== HIGH-RISK FINDINGS <sec-high>

// @finding id=fb-hhh status=completed
#finding(level: "high", title: "Existing high")

== LOW-RISK FINDINGS <sec-low>
`;

describe('the clipboard payload', () => {
  it('is the plain block (dedented) under one header comment that names the workspace', () => {
    const f = findFindings(SOURCE)[0]!;
    const text = findingCopyPayload(SOURCE, f, 'ws-123');
    const lines = text.split('\n');
    expect(lines[0]).toBe(`// ${FINDING_COPY_TAG} v=1 workspace=ws-123`);
    expect(lines[1]).toBe('// @finding id=fb-aaa status=written');
    expect(lines[2]).toBe('#finding(');
    // Still a valid block on its own.
    expect(findFindings(text)).toHaveLength(1);
  });
  it('is recognised on paste, with the source workspace', () => {
    const f = findFindings(SOURCE)[0]!;
    const p = parseFindingPayload(findingCopyPayload(SOURCE, f, 'ws-123'))!;
    expect(p.workspaceId).toBe('ws-123');
    expect(p.blocks).toHaveLength(1);
    expect(p.blocks[0]).toContain('title: "SMB signing"');
  });
  it('takes a plain #finding block with no header (copied from the code)', () => {
    const p = parseFindingPayload('#finding(level: "low", title: "Plain")')!;
    expect(p.workspaceId).toBeNull();
    expect(p.blocks).toEqual(['#finding(level: "low", title: "Plain")']);
  });
  it('survives Windows line endings', () => {
    const f = findFindings(SOURCE)[0]!;
    const crlf = findingCopyPayload(SOURCE, f, 'ws-1').replace(/\n/g, '\r\n');
    expect(parseFindingPayload(crlf)?.workspaceId).toBe('ws-1');
  });
  it('refuses text with no complete block', () => {
    expect(parseFindingPayload('hello')).toBeNull();
    expect(parseFindingPayload('#finding(level: "high", title: "cut off')).toBeNull();
    expect(parseFindingPayload('// @btct-finding-copy v=1 workspace=x\n')).toBeNull();
  });
  it('never writes an unsafe workspace id into the header', () => {
    const f = findFindings(SOURCE)[0]!;
    expect(findingCopyPayload(SOURCE, f, 'a b\nc').split('\n')[0]).toBe(`// ${FINDING_COPY_TAG} v=1`);
  });
});

describe('ids', () => {
  it('a fresh id is free in the target', () => {
    const rand = seqRand();
    const id = freshFindingId(TARGET, new Set(), rand);
    expect(id).toMatch(/^fb-[0-9a-z]{6}$/);
    expect(findFindings(TARGET).map((f) => f.id)).not.toContain(id);
  });
  it('skips ids that are taken', () => {
    // A generator that repeats a taken id first.
    let n = 0;
    const values = [0, 0, 0, 0, 0, 0, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5];
    const rand = () => values[n++ % values.length]!;
    const id = freshFindingId(TARGET, new Set(['fb-000000']), rand);
    expect(id).not.toBe('fb-000000');
  });
  it('reidentify gives a new marker and keeps the status', () => {
    const block = parseFindingPayload(findingCopyPayload(SOURCE, findFindings(SOURCE)[0]!, 'w'))!.blocks[0]!;
    const r = reidentifyBlock(TARGET, block, { id: 'fb-new111' })!;
    expect(r.text.split('\n')[0]).toBe('// @finding id=fb-new111 status=written');
    expect(r.severity).toBe('high');
    expect(r.title).toBe('SMB signing');
  });
  it('adds a marker to a block that had none, with the status it reads as', () => {
    const r = reidentifyBlock(TARGET, '#finding(level: "low", title: "x", description: [Real text])', { id: 'fb-m' })!;
    expect(r.text).toBe('// @finding id=fb-m status=written\n#finding(level: "low", title: "x", description: [Real text])');
  });
  it('fits #end-of-block to the target', () => {
    const block = '// @finding id=fb-1 status=blank\n#finding(level: "low", title: "x")\n\n#end-of-block';
    expect(reidentifyBlock(TARGET, block, { id: 'fb-2' })!.text).not.toContain('#end-of-block');
    const cptc = `#let end-of-block = []\n${TARGET}`;
    expect(reidentifyBlock(cptc, '#finding(level: "low", title: "x")', { id: 'fb-3' })!.text).toMatch(/\n\n#end-of-block$/);
  });
});

describe('pasteFindings', () => {
  const copied = () => parseFindingPayload(findingCopyPayload(SOURCE, findFindings(SOURCE)[0]!, 'ws-a'))!.blocks;

  it('lands in its severity section with a new id, never a duplicate', () => {
    const r = pasteFindings(TARGET, copied(), { rand: seqRand() });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const all = findFindings(r.source);
    const ids = all.map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
    const pasted = all.find((f) => f.id === r.ids[0])!;
    expect(pasted.title).toBe('SMB signing');
    expect(pasted.status).toBe('written');
    const high = findSeveritySections(r.source).find((s) => s.severity === 'high')!;
    expect(pasted.start).toBeGreaterThan(high.headingEnd);
    expect(pasted.start).toBeLessThan(high.end);
    // After the section's existing finding.
    expect(r.source.indexOf('SMB signing')).toBeGreaterThan(r.source.indexOf('Existing high'));
  });
  it('pasting into the same report duplicates it under a new id', () => {
    const r = pasteFindings(SOURCE, copied(), { rand: seqRand(7) });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const smb = findFindings(r.source).filter((f) => f.title === 'SMB signing');
    expect(smb).toHaveLength(2);
    expect(smb[0]!.id).toBe('fb-aaa');
    expect(smb[1]!.id).not.toBe('fb-aaa');
  });
  it('adds the finding, slot and cmd helpers a report lacks', () => {
    const block = '#finding(level: "low", title: "x", exploitation: [#cmd[```bash\nid\n```]\n#image-placeholder("a", path: "/assets/a.png")])';
    const r = pasteFindings('= Report\n', [block]);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.source).toContain('#let finding(');
    expect(r.source).toContain('#let cmd(');
    expect(r.source).toContain('#let image-placeholder(');
  });
  it('follows the No severity rule: teaches CPTC-style lookups, refuses when it cannot', () => {
    const cptc = '#let levels = (high: (bar: red))\n#let finding(level: "medium", title: "") = {\n  let lvl = levels.at(level)\n  [#title]\n}\n\n== HIGH-RISK FINDINGS <sec-high>\n';
    expect(findingAcceptsNoSeverity(cptc)).toBe(false);
    const none = '// @finding id=fb-n status=blank\n#finding(level: none, title: "Unrated")';
    const taught = pasteFindings(cptc, [none]);
    expect(taught.ok).toBe(true);
    if (taught.ok) expect(findingAcceptsNoSeverity(taught.source)).toBe(true);
    const stubborn = '#let finding(level: "medium", title: "") = [#title #level.len()]\n';
    expect(pasteFindings(stubborn, [none])).toEqual({ ok: false, reason: 'no-severity' });
  });
  it('pastes several blocks with distinct ids', () => {
    const r = pasteFindings(TARGET, ['#finding(level: "low", title: "1")', '#finding(level: "low", title: "2")'], { rand: seqRand(3) });
    expect(r.ok && r.ids.length === 2 && r.ids[0] !== r.ids[1]).toBe(true);
  });
});

describe('asset paths', () => {
  it('lists the files a block references, once each', () => {
    expect(assetFilesIn(SOURCE)).toEqual(['relay.png', 'hash.png']);
  });
  it('rewrites only the renamed paths, every occurrence', () => {
    const out = rewriteAssetPaths(SOURCE, new Map([['relay.png', 'relay-2.png']]));
    expect(out.match(/"\/assets\/relay-2\.png"/g)).toHaveLength(2);
    expect(out).toContain('"/assets/hash.png"');
    expect(out).not.toContain('"/assets/relay.png"');
  });

  const src = [{ id: 's1', filename: 'relay.png', kind: 'image' }, { id: 's2', filename: 'hash.png', kind: 'image' }];
  it('copies what the target lacks, keeps what it has, reports what is nowhere', () => {
    const plan = planAssetCopies(['relay.png', 'hash.png', 'gone.png'], {
      sourceWorkspaceId: 'A', targetWorkspaceId: 'B', source: src, target: [],
    });
    expect(plan).toEqual([
      { file: 'relay.png', action: 'copy', sourceId: 's1' },
      { file: 'hash.png', action: 'copy', sourceId: 's2' },
      { file: 'gone.png', action: 'missing' },
    ]);
  });
  it('a same-named different image in the target is a collision: copy (renamed by the caller)', () => {
    const target = [{ id: 't1', filename: 'Relay.PNG', kind: 'image' }];
    expect(planAssetCopies(['relay.png'], { sourceWorkspaceId: 'A', targetWorkspaceId: 'B', source: src, target })[0])
      .toEqual({ file: 'relay.png', action: 'copy', sourceId: 's1' });
    // ...unless it is the same image.
    expect(planAssetCopies(['relay.png'], {
      sourceWorkspaceId: 'A', targetWorkspaceId: 'B', source: src, target, identical: (id) => (id === 's1' ? 'Relay.PNG' : null),
    })[0]).toEqual({ file: 'relay.png', action: 'keep', as: 'Relay.PNG' });
  });
  it('a second paste reuses the renamed copy of the first', () => {
    const target = [{ id: 't1', filename: 'relay.png', kind: 'image' }, { id: 't2', filename: 'relay-2.png', kind: 'image' }];
    expect(planAssetCopies(['relay.png'], {
      sourceWorkspaceId: 'A', targetWorkspaceId: 'B', source: src, target, identical: (id) => (id === 's1' ? 'relay-2.png' : null),
    })[0]).toEqual({ file: 'relay.png', action: 'keep', as: 'relay-2.png' });
  });
  it('same workspace, or no header: never copies', () => {
    const plan = planAssetCopies(['relay.png', 'x.png'], {
      sourceWorkspaceId: 'A', targetWorkspaceId: 'A', source: src, target: [{ id: 's1', filename: 'relay.png' }],
    });
    expect(plan).toEqual([{ file: 'relay.png', action: 'keep' }, { file: 'x.png', action: 'missing' }]);
    expect(planAssetCopies(['relay.png'], { sourceWorkspaceId: null, targetWorkspaceId: 'B', source: src, target: [] })[0])
      .toEqual({ file: 'relay.png', action: 'missing' });
  });
  it('ignores retired assets on both sides', () => {
    const plan = planAssetCopies(['relay.png'], {
      sourceWorkspaceId: 'A', targetWorkspaceId: 'B',
      source: [{ id: 's1', filename: 'relay.png', deletedAt: 5 }], target: [],
    });
    expect(plan[0]!.action).toBe('missing');
  });
});

describe('page break travels with a copied block', () => {
  const SRC = `${FINDING_HELPER}

= Findings

== HIGH-RISK FINDINGS <sec-high>

  #pagebreak(weak: true)
  // @finding id=fb-pb status=written
  #finding(
    level: "high",
    title: "Breaky",
  )

== LOW-RISK FINDINGS <sec-low>
`;

  it('copy then paste keeps exactly one break on the copy', () => {
    const [f] = findFindings(SRC);
    const payload = findingCopyPayload(SRC, f!, 'ws1');
    expect(payload).toContain('#pagebreak(weak: true)');
    const parsed = parseFindingPayload(payload)!;
    expect(parsed.blocks).toHaveLength(1);
    expect(parsed.blocks[0]!.startsWith('#pagebreak(weak: true)\n')).toBe(true);
    const res = pasteFindings(SRC, parsed.blocks, { rand: seqRand(3) });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    const fs = findFindings(res.source);
    expect(fs).toHaveLength(2);
    expect(fs.every((x) => x.pagebreakStart !== null)).toBe(true);
    expect((res.source.match(/#pagebreak/g) ?? []).length).toBe(2);
  });
});
