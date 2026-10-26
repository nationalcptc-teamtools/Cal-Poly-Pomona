import type { Page } from '@/types';

// ─── Inline text styling ──────────────────────────────────────────────────

type InlineStyles = Record<string, boolean | string | undefined>;
type InlineContent =
  | { type: 'text'; text?: string; styles?: InlineStyles }
  | { type: 'link'; href?: string; content?: InlineContent[] }
  | Record<string, unknown>;

function styleInline(text: string, styles?: InlineStyles): string {
  if (!styles) return text;
  let out = text;
  if (styles['code']) out = `\`${out}\``;
  if (styles['strike']) out = `~~${out}~~`;
  if (styles['bold']) out = `**${out}**`;
  if (styles['italic']) out = `*${out}*`;
  return out;
}

function inlineToMarkdown(nodes: InlineContent[] | undefined): string {
  if (!nodes?.length) return '';
  return nodes
    .map((n) => {
      const node = n as Record<string, unknown>;
      const t = node['type'];
      if (t === 'link') {
        const href = (node['href'] as string) ?? '';
        const inner = inlineToMarkdown(node['content'] as InlineContent[] | undefined);
        return `[${inner}](${href})`;
      }
      const text = (node['text'] as string | undefined) ?? '';
      const styles = node['styles'] as InlineStyles | undefined;
      return styleInline(text, styles);
    })
    .join('');
}

// ─── Block-level conversion ───────────────────────────────────────────────

interface BlockLike {
  type?: string;
  props?: Record<string, unknown>;
  content?: InlineContent[] | string;
  children?: BlockLike[];
}

function tableToMarkdown(b: BlockLike): string {
  const props = b.props ?? {};
  const tableContent = (props['content'] ?? (b as unknown as { content?: unknown }).content) as
    | { rows?: Array<{ cells?: InlineContent[][] }> }
    | undefined;
  const rows = tableContent?.rows ?? [];
  if (rows.length === 0) return '';
  const cellText = (cell: InlineContent[] | undefined) => inlineToMarkdown(cell).replace(/\|/g, '\\|');
  const [first, ...rest] = rows;
  const header = first!.cells ?? [];
  const headerLine = `| ${header.map((c) => cellText(c)).join(' | ')} |`;
  const separator = `| ${header.map(() => '---').join(' | ')} |`;
  const bodyLines = rest.map((r) => `| ${(r.cells ?? []).map((c) => cellText(c)).join(' | ')} |`);
  return [headerLine, separator, ...bodyLines].join('\n');
}

function blockToMarkdown(b: BlockLike, depth: number): string[] {
  const out: string[] = [];
  const indent = '  '.repeat(depth);
  const inlineText = typeof b.content === 'string' ? b.content : inlineToMarkdown(b.content);
  const props = b.props ?? {};

  switch (b.type) {
    case 'heading': {
      const level = Math.min(Math.max(Number(props['level']) || 1, 1), 6);
      out.push(`${'#'.repeat(level)} ${inlineText}`);
      break;
    }
    case 'bulletListItem':
      out.push(`${indent}- ${inlineText}`);
      break;
    case 'numberedListItem':
      out.push(`${indent}1. ${inlineText}`);
      break;
    case 'checkListItem': {
      const checked = Boolean(props['checked']);
      out.push(`${indent}- [${checked ? 'x' : ' '}] ${inlineText}`);
      break;
    }
    case 'quote':
      out.push(`> ${inlineText}`);
      break;
    case 'codeBlock': {
      const lang = (props['language'] as string | undefined) ?? '';
      const code = typeof b.content === 'string'
        ? b.content
        : (b.content as Array<Record<string, unknown>> | undefined)
            ?.map((c) => (c['text'] as string) ?? '')
            .join('') ?? '';
      out.push('```' + lang);
      out.push(code);
      out.push('```');
      break;
    }
    case 'divider':
      out.push('---');
      break;
    case 'image': {
      const url = (props['url'] as string) ?? '';
      const caption = (props['caption'] as string) ?? '';
      if (url) out.push(`![${caption}](${url})`);
      break;
    }
    case 'table': {
      const md = tableToMarkdown(b);
      if (md) out.push(md);
      break;
    }
    case 'paragraph':
    default:
      out.push(indent ? `${indent}${inlineText}` : inlineText);
      break;
  }

  if (b.children?.length) {
    for (const child of b.children) {
      out.push(...blockToMarkdown(child, depth + 1));
    }
  }
  return out;
}

export function blocksToMarkdown(blocks: readonly BlockLike[] | readonly Record<string, unknown>[]): string {
  const lines: string[] = [];
  let prevType: string | undefined;
  const isListItem = (t?: string) =>
    t === 'bulletListItem' || t === 'numberedListItem' || t === 'checkListItem';
  for (const raw of blocks) {
    const block = raw as BlockLike;
    const rendered = blockToMarkdown(block, 0);
    const needsSpacer =
      lines.length > 0
      && !(isListItem(prevType) && isListItem(block.type) && prevType === block.type);
    if (needsSpacer) lines.push('');
    lines.push(...rendered);
    prevType = block.type;
  }
  return lines.join('\n');
}

// ─── Normalizer used when loading/saving pages ───────────────────────────
// Older page records stored `content` as BlockNote's PartialBlock[] (JSON).
// New records store plain markdown. This helper accepts either shape.
export function normalizePageContent(raw: unknown): string {
  if (typeof raw === 'string') return raw;
  if (Array.isArray(raw)) return blocksToMarkdown(raw as BlockLike[]);
  return '';
}

// ─── Full-page markdown (used for exports) ────────────────────────────────

export function pageToMarkdown(page: Page): string {
  const lines: string[] = [];
  const heading = page.icon ? `# ${page.icon} ${page.title}` : `# ${page.title}`;
  lines.push(heading);
  lines.push('');
  if (page.tags.length > 0) {
    lines.push(`Tags: ${page.tags.join(', ')}`);
    lines.push('');
  }
  lines.push(normalizePageContent(page.content));
  return lines.join('\n');
}

export function pagesToMarkdownBundle(pages: Page[]): string {
  return pages.map((p) => pageToMarkdown(p)).join('\n---\n\n');
}
