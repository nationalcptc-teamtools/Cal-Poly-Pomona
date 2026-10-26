import { describe, it, expect } from 'vitest';
import { closestMatchIndex } from '@/lib/editor-keybinds';

// The code-block language picker pins the *current* language at index 0 even
// when it doesn't match what was just typed, so Enter/ArrowDown from the search
// box must skip that pinned entry to land on the real closest match.
describe('closestMatchIndex', () => {
  it('skips the pinned current language when it does not match the query', () => {
    // Current is "Shell" (pinned at 0); typing "pyth" should target "Python".
    expect(closestMatchIndex(['Shell', 'Python'], 'pyth')).toBe(1);
  });

  it('keeps the pinned entry when it does match the query', () => {
    expect(closestMatchIndex(['Shell', 'Shell Session'], 'she')).toBe(0);
  });

  it('matches the pinned entry case-insensitively', () => {
    expect(closestMatchIndex(['Python', 'IPython'], 'PY')).toBe(0);
  });

  it('targets index 0 for an empty or whitespace query', () => {
    expect(closestMatchIndex(['Shell', 'Python'], '')).toBe(0);
    expect(closestMatchIndex(['Shell', 'Python'], '   ')).toBe(0);
  });

  it('targets index 0 when there is only one (or no) item', () => {
    expect(closestMatchIndex(['Shell'], 'pyth')).toBe(0);
    expect(closestMatchIndex([], 'pyth')).toBe(0);
  });

  it('still skips to index 1 even if that entry matches only by alias (no textual name match)', () => {
    // e.g. querying "js" pins non-matching "Shell" at 0 while "JavaScript"
    // (a match only via its alias) sits at 1; we still leave the pinned entry.
    expect(closestMatchIndex(['Shell', 'JavaScript'], 'js')).toBe(1);
  });
});
