import { describe, it, expect } from 'vitest';
import { pageToMarkdown, pagesToMarkdownBundle } from '@/export/markdown';
import { fixturePages } from './fixtures';

describe('Markdown export', () => {
  it('converts a single page to markdown with title and tags', () => {
    const page = fixturePages[0]!;
    const md = pageToMarkdown(page);

    expect(md).toContain('# Test Page');
    expect(md).toContain('Tags: test, demo');
    expect(md).toContain('## Hello World');
    expect(md).toContain('This is a test page.');
    expect(md).toContain('- Item one');
    expect(md).toContain('- **Bold item**');
  });

  it('bundles multiple pages with separator', () => {
    const bundle = pagesToMarkdownBundle(fixturePages);
    expect(bundle).toContain('# Test Page');
    expect(bundle).toContain('# Node Page');
    expect(bundle).toContain('---');
  });
});
