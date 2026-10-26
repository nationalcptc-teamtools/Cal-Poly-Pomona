import { describe, expect, it } from 'vitest';
import { expandReplacement } from '@/lib/typst-search';

// CLI-18: replaceOne splices the expanded replacement itself instead of
// relying on String.replace honouring lastIndex on a sticky regex (JSC does
// not). The expansion must agree with native String.replace for a first match.
function native(src: string, re: RegExp, tpl: string): string {
  return src.replace(re, tpl);
}
function spliced(src: string, re: RegExp, tpl: string): string {
  const m = re.exec(src);
  if (!m) return src;
  return src.slice(0, m.index) + expandReplacement(tpl, m, src) + src.slice(m.index + m[0].length);
}

describe('expandReplacement matches String.replace', () => {
  const cases: Array<[string, RegExp, string]> = [
    ['user=admin pass=1234', /(\w+)=(\d+)/, '$2:$1'],
    ['abc abc', /b/, '[$&]'],
    ['abc abc', /b/, "[$`|$']"],
    ['abc', /b/, '$$ and $$$'],
    ['abc', /(b)/, '$0 $2 $9 $'],
    ['a1b2c3d4e5f6g7h8i9j0k', /(a)(1)(b)(2)(c)(3)(d)(4)(e)(5)(f)(6)/, '$12-$11-$10-$1x'],
    ['abc', /(b)/, '$01|$10'],
    ['key: value', /(?<k>\w+): (?<v>\w+)/, '$<v>=$<k> $<missing>|$<open'],
    ['key: value', /(\w+): (\w+)/, '$<k>'],
    ['tail$', /\$/, 'x$'],
  ];
  for (const [src, re, tpl] of cases) {
    it(`${re} with ${JSON.stringify(tpl)}`, () => {
      expect(spliced(src, new RegExp(re.source, re.flags), tpl)).toBe(native(src, new RegExp(re.source, re.flags), tpl));
    });
  }
});
