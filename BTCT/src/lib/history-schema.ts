// ─────────────────────────────────────────────────────────────────────────
// A ProseMirror schema for the read-only version viewer.
//
// y-prosemirror's snapshot renderer tags every node it builds with a
// `ychange` attribute ({ user, type: 'added' | 'removed', color }) and wraps
// changed text in a `ychange` mark. ProseMirror silently drops attributes a
// node type does not declare and throws for a mark type it does not know,
// so the viewer needs the editor's schema with `ychange` declared on every
// node and mark and a `ychange` mark added. The `toDOM` wrappers turn the
// attribute into `data-ychange-*` attributes plus a `--ychange-color`
// custom property that index.css paints (the History tab's per-user
// highlighting).
// ─────────────────────────────────────────────────────────────────────────
import { Schema, type DOMOutputSpec, type MarkSpec, type Node as PmNode, type NodeSpec, type Mark } from '@milkdown/prose/model';

export interface YChange {
  user?: string | null;
  type: 'added' | 'removed';
  color?: { light: string; dark: string } | null;
}

function isDark(): boolean {
  return typeof document !== 'undefined' && document.documentElement.classList.contains('dark');
}

/** DOM attributes that mark a changed node or run. Empty for unchanged content. */
export function ychangeDomAttrs(ychange: YChange | null | undefined): Record<string, string> {
  if (!ychange || !ychange.type) return {};
  const color = ychange.color ? (isDark() ? ychange.color.dark : ychange.color.light) : 'hsl(var(--status-amber))';
  return {
    'data-ychange-type': ychange.type,
    'data-ychange-user': ychange.user ?? '',
    style: `--ychange-color: ${color}`,
  };
}

function mergeAttrs(target: Record<string, unknown>, extra: Record<string, string>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...target };
  for (const [k, v] of Object.entries(extra)) {
    if (k === 'style' && typeof out.style === 'string' && out.style) out.style = `${out.style}; ${v}`;
    else if (k === 'class' && typeof out.class === 'string' && out.class) out.class = `${out.class} ${v}`;
    else out[k] = v;
  }
  return out;
}

function isAttrsObject(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x) && !(typeof Node !== 'undefined' && x instanceof Node);
}

/** Inject attributes into a DOMOutputSpec (array form or DOM node form). */
function decorateOutputSpec(spec: DOMOutputSpec, extra: Record<string, string>): DOMOutputSpec {
  if (!Object.keys(extra).length) return spec;
  if (Array.isArray(spec)) {
    const [tag, second, ...rest] = spec as unknown[];
    if (isAttrsObject(second)) {
      return [tag, mergeAttrs(second, extra), ...rest] as unknown as DOMOutputSpec;
    }
    return [tag, extra, ...(second === undefined ? [] : [second]), ...rest] as unknown as DOMOutputSpec;
  }
  const el = (spec as { dom?: Node }).dom ?? (spec as Node);
  if (el instanceof Element) {
    for (const [k, v] of Object.entries(extra)) {
      if (k === 'style') el.setAttribute('style', `${el.getAttribute('style') ?? ''}; ${v}`);
      else el.setAttribute(k, v);
    }
  }
  return spec;
}

function withYChangeAttr<T extends NodeSpec | MarkSpec>(spec: T, kind: 'node' | 'mark'): T {
  if (!spec.toDOM) return spec;
  const orig = spec.toDOM as (x: PmNode | Mark, inline?: boolean) => DOMOutputSpec;
  return {
    ...spec,
    attrs: { ...(spec.attrs ?? {}), ychange: { default: null } },
    toDOM: (x: PmNode | Mark, inline?: boolean) =>
      decorateOutputSpec(kind === 'node' ? orig(x) : orig(x, inline), ychangeDomAttrs((x.attrs as { ychange?: YChange }).ychange ?? null)),
  } as T;
}

const ychangeMark: MarkSpec = {
  attrs: { user: { default: null }, type: { default: null }, color: { default: null } },
  inclusive: false,
  excludes: '',
  toDOM: (mark) => ['span', ychangeDomAttrs(mark.attrs as YChange), 0],
};

/** The editor's schema, extended so snapshot diffs render with per-user colours. */
export function withYChange(base: Schema): Schema {
  // OrderedMap keeps insertion order and so does a plain object with string
  // keys, which is what Schema accepts; the ychange mark goes last.
  const nodes: Record<string, NodeSpec> = {};
  base.spec.nodes.forEach((name: string, spec: NodeSpec) => { nodes[name] = withYChangeAttr(spec, 'node'); });
  const marks: Record<string, MarkSpec> = {};
  base.spec.marks.forEach((name: string, spec: MarkSpec) => { marks[name] = withYChangeAttr(spec, 'mark'); });
  marks.ychange = ychangeMark;
  return new Schema({ nodes, marks, topNode: base.spec.topNode });
}
