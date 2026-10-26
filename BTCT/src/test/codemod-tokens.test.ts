import { describe, it, expect } from 'vitest';
import { rewrite } from '../../scripts/codemod-tokens.mjs';

describe('token codemod', () => {
  it('maps arbitrary token colours to semantic utilities, keeping opacity', () => {
    expect(rewrite('bg-[hsl(var(--card))] text-[hsl(var(--muted-foreground))]')).toBe('bg-card text-muted-foreground');
    expect(rewrite('hover:bg-[hsl(var(--primary))]/15')).toBe('hover:bg-primary/15');
    expect(rewrite('bg-[hsl(var(--muted)/0.4)]')).toBe('bg-muted/40');
    expect(rewrite('bg-[hsl(var(--primary)/0.18)]')).toBe('bg-primary/18');
  });

  it('leaves non-class uses and unknown tokens alone', () => {
    const style = "backgroundColor: 'hsl(var(--primary) / 0.25)'";
    expect(rewrite(style)).toBe(style);
    expect(rewrite('bg-[hsl(var(--made-up))]')).toBe('bg-[hsl(var(--made-up))]');
  });

  it('maps pixel text sizes to the named scale', () => {
    expect(rewrite('text-[9px] text-[10px] text-[11px] text-[12px]')).toBe('text-micro text-caption text-meta text-xs');
    expect(rewrite('text-[15px]')).toBe('text-[15px]');
  });
});
