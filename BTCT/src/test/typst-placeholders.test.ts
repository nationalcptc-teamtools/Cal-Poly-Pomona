import { describe, it, expect } from 'vitest';
import {
  ensureHelper,
  findScreenshotSlots,
  inspectHelper,
  newSlotSnippet,
  parseStringLiteral,
  setSlotPath,
  setSlotWidth,
  ensureHelperWidth,
  PLACEHOLDER_HELPER,
  toStringLiteral,
} from '@/lib/typst-placeholders';

/** The original, path-unaware helper: what existing documents contain. */
const LEGACY_HELPER = `#let image-placeholder(caption, height: 2.2in) = figure(
  block(
    width: 90%,
    height: height,
    fill: luma(245),
    stroke: 1pt + luma(180),
    radius: 4pt,
    align(center + horizon,
      text(fill: luma(120), style: "italic", size: 11pt)[
        \\[ {{TODO: Insert screenshot here}} \\]
      ],
    ),
  ),
  caption: caption,
)`;

const DOC = `#set page(margin: 1.5cm)
#set text(size: 11pt)

${LEGACY_HELPER}

= Findings

#image-placeholder("Login bypass")

Some prose here.

#image-placeholder("Shell on host, with a \\"quoted\\" caption", height: 3in)

#image-placeholder("Already placed", path: "/assets/old.png")
`;

describe('string literals', () => {
  it('round-trips a plain value', () => {
    expect(parseStringLiteral(toStringLiteral('hello'))).toBe('hello');
  });

  it('round-trips quotes and backslashes', () => {
    const nasty = 'a "quoted" \\ backslash';
    expect(parseStringLiteral(toStringLiteral(nasty))).toBe(nasty);
  });

  it('rejects a non-literal', () => {
    expect(parseStringLiteral('someVariable')).toBeNull();
    expect(parseStringLiteral('none')).toBeNull();
  });

  // A concatenation starts and ends with a quote, so a start/end check alone
  // accepts it and hands back the operators as if they were text. That text
  // then becomes a literal caption in the Word file while the PDF, which
  // Typst evaluates properly, reads correctly.
  it('rejects a sandwich concatenation that merely starts and ends with a quote', () => {
    expect(parseStringLiteral('"Host " + host + " admin login"')).toBeNull();
    expect(parseStringLiteral('"a" + "b"')).toBeNull();
  });

  it('still accepts a literal whose quotes are escaped', () => {
    expect(parseStringLiteral('"Host \\" + host + \\" admin login"')).toBe('Host " + host + " admin login');
  });
});

describe('findScreenshotSlots', () => {
  const slots = findScreenshotSlots(DOC);

  it('finds every call site', () => {
    expect(slots).toHaveLength(3);
  });

  it('does not mistake the #let definition for a slot', () => {
    for (const s of slots) expect(DOC.slice(s.start, s.start + 5)).not.toBe('#let ');
  });

  it('parses captions, including escaped quotes', () => {
    expect(slots[0]!.caption).toBe('Login bypass');
    expect(slots[1]!.caption).toBe('Shell on host, with a "quoted" caption');
  });

  it('distinguishes empty slots from filled ones', () => {
    expect(slots[0]!.path).toBeNull();
    expect(slots[2]!.path).toBe('/assets/old.png');
  });

  it('reports ascending line numbers', () => {
    expect(slots[1]!.line).toBeGreaterThan(slots[0]!.line);
  });

  it('ignores a commented-out call', () => {
    const found = findScreenshotSlots('// #image-placeholder("nope")\n#image-placeholder("yes")\n');
    expect(found.map((s) => s.caption)).toEqual(['yes']);
  });

  it('tolerates unbalanced source mid-edit rather than throwing', () => {
    expect(() => findScreenshotSlots('#image-placeholder("half typed"')).not.toThrow();
    expect(findScreenshotSlots('#image-placeholder("half typed"')).toHaveLength(0);
  });

  it('handles nested parens inside arguments', () => {
    const found = findScreenshotSlots('#image-placeholder("cap (parens)", height: calc.max(2in, 3in))\n');
    expect(found).toHaveLength(1);
    expect(found[0]!.caption).toBe('cap (parens)');
  });
});

describe('setSlotPath', () => {
  const slots = findScreenshotSlots(DOC);

  it('assigns a path to an empty slot', () => {
    const next = setSlotPath(DOC, slots[0]!, '/assets/shot.png');
    expect(findScreenshotSlots(next)[0]!.path).toBe('/assets/shot.png');
  });

  it('leaves the other slots untouched', () => {
    const next = findScreenshotSlots(setSlotPath(DOC, slots[0]!, '/assets/shot.png'));
    expect(next).toHaveLength(3);
    expect(next[1]!.caption).toBe(slots[1]!.caption);
    expect(next[2]!.path).toBe('/assets/old.png');
  });

  it("preserves the author's other arguments", () => {
    const next = setSlotPath(DOC, slots[1]!, '/assets/b.png');
    expect(next).toContain('height: 3in');
    expect(findScreenshotSlots(next)[1]!.path).toBe('/assets/b.png');
  });

  it('replaces rather than duplicates an existing path', () => {
    const next = setSlotPath(DOC, slots[2]!, '/assets/new.png');
    expect(findScreenshotSlots(next)[2]!.path).toBe('/assets/new.png');
    expect(next.match(/path:/g)).toHaveLength(1);
  });

  it('clears a path without leaving a dangling comma', () => {
    const next = setSlotPath(DOC, slots[2]!, null);
    const line = next.split('\n').find((l) => l.includes('Already placed'))!;
    expect(findScreenshotSlots(next)[2]!.path).toBeNull();
    expect(findScreenshotSlots(next)[2]!.caption).toBe('Already placed');
    expect(line).not.toMatch(/,\s*\)/);
  });

  it('escapes a path containing a quote', () => {
    const next = setSlotPath(DOC, slots[0]!, '/assets/we"ird.png');
    expect(findScreenshotSlots(next)[0]!.path).toBe('/assets/we"ird.png');
  });
});

describe('ensureHelper', () => {
  it('detects the legacy helper as path-unaware', () => {
    const state = inspectHelper(DOC);
    expect(state.defined).toBe(true);
    expect(state.supportsPath).toBe(false);
  });

  it('upgrades the legacy helper in place, preserving the document', () => {
    const { source, changed } = ensureHelper(DOC);
    expect(changed).toBe(true);
    expect(inspectHelper(source).supportsPath).toBe(true);
    expect(source).toContain('= Findings');
    expect(source).toContain('Some prose here.');
    expect(findScreenshotSlots(source)).toHaveLength(3);
  });

  it('does not duplicate the helper when upgrading', () => {
    const { source } = ensureHelper(DOC);
    expect(source.match(/#let image-placeholder\(/g)).toHaveLength(1);
  });

  it('is idempotent', () => {
    const once = ensureHelper(DOC).source;
    expect(ensureHelper(once).changed).toBe(false);
  });

  it('allows placing after an upgrade', () => {
    const upgraded = ensureHelper(DOC).source;
    const slot = findScreenshotSlots(upgraded)[0]!;
    const placed = setSlotPath(upgraded, slot, '/assets/z.png');
    expect(findScreenshotSlots(placed)[0]!.path).toBe('/assets/z.png');
  });

  it('inserts a missing helper after the #set preamble', () => {
    const bare = '#set page(margin: 1cm)\n#set text(size: 11pt)\n\n= Report\n\nBody.\n';
    const { source, changed } = ensureHelper(bare);
    expect(changed).toBe(true);
    expect(inspectHelper(source).supportsPath).toBe(true);
    expect(source.indexOf('#let image-placeholder')).toBeGreaterThan(source.indexOf('#set text'));
    expect(source).toContain('= Report');
    expect(source).toContain('Body.');
  });
});

describe('newSlotSnippet', () => {
  it('produces a slot the scanner can find', () => {
    const doc = ensureHelper('').source + newSlotSnippet('New figure');
    const slots = findScreenshotSlots(doc);
    expect(slots).toHaveLength(1);
    expect(slots[0]!.caption).toBe('New figure');
    expect(slots[0]!.path).toBeNull();
  });

  it('escapes a caption containing a quote', () => {
    const doc = ensureHelper('').source + newSlotSnippet('The "admin" panel');
    expect(findScreenshotSlots(doc)[0]!.caption).toBe('The "admin" panel');
  });
});

describe('figure width', () => {
  // The BTCT report template's own helper: a filled slot is the image at its
  // natural shape, 90% wide, so only the width sizes it.
  const BTCT_HELPER = `#let image-placeholder(caption, path: none, height: 2.2in) = figure(
  if path == none {
    block(
      width: 90%,
      height: height,
      fill: luma(245),
      align(center + horizon, text[\\[ Screenshot placeholder \\]]),
    )
  } else {
    align(center, image(path, width: 90%))
  },
  caption: caption,
)`;

  it('reads and writes a slot width as a share of the text width', () => {
    const src = `${PLACEHOLDER_HELPER}\n#image-placeholder("a", path: "/assets/a.png", width: 60%)\n`;
    const [slot] = findScreenshotSlots(src);
    expect(slot!.widthFraction).toBeCloseTo(0.6);
    const next = setSlotWidth(src, slot!, 0.45);
    expect(next).toContain('#image-placeholder("a", path: "/assets/a.png", width: 45%)');
    expect(findScreenshotSlots(setSlotWidth(next, findScreenshotSlots(next)[0]!, null))[0]!.widthFraction).toBeNull();
  });

  it('the current helper takes a width already', () => {
    const src = `${PLACEHOLDER_HELPER}\n`;
    expect(inspectHelper(src).supportsWidth).toBe(true);
    expect(ensureHelperWidth(src)).toEqual({ source: src, changed: false, scalable: true });
  });

  it('teaches a customized helper a width without touching its styling', () => {
    const src = `#set page(margin: 1in)\n\n${BTCT_HELPER}\n\n#image-placeholder("a")\n`;
    const out = ensureHelperWidth(src);
    expect(out.scalable).toBe(true);
    expect(out.source).toContain('#let image-placeholder(caption, path: none, height: 2.2in, width: 90%) = figure(');
    expect(out.source).toContain('image(path, width: width)');
    expect(out.source).toContain('      width: width,\n      height: height,');
    expect(out.source).toContain('fill: luma(245)');
    expect(inspectHelper(out.source).supportsWidth).toBe(true);
    // Idempotent.
    expect(ensureHelperWidth(out.source).changed).toBe(false);
  });

  it('upgrades the previous built-in helper to the current one', () => {
    const old = PLACEHOLDER_HELPER
      .replace('height: 2.2in, width: 90%)', 'height: 2.2in)')
      .replace('width: width,', 'width: 90%,');
    const out = ensureHelperWidth(`${old}\n`);
    expect(out.source).toBe(`${PLACEHOLDER_HELPER}\n`);
  });

  it('reports a helper with no width literal as not scalable', () => {
    const src = '#let image-placeholder(caption, path: none) = figure(image(path), caption: caption)\n';
    expect(ensureHelperWidth(src).scalable).toBe(false);
  });
});
