import { describe, it, expect } from 'vitest';
import { DEFAULT_CODE_LANGUAGE, displayLanguageName, fenceLanguage } from '@/lib/code-theme';

describe('displayLanguageName', () => {
  it('canonicalises a name to the picker\'s own casing', () => {
    // The regression: a new code block stored 'shell' and its button read
    // "shell", while the picker listed (and, once clicked, stored) "Shell".
    expect(displayLanguageName('shell')).toBe('Shell');
    expect(displayLanguageName('Shell')).toBe('Shell');
    expect(displayLanguageName('SHELL')).toBe('Shell');
  });

  it('resolves aliases to the canonical name', () => {
    expect(displayLanguageName('sh')).toBe('Shell');
    expect(displayLanguageName('bash')).toBe('Shell');
    expect(displayLanguageName('zsh')).toBe('Shell');
    expect(displayLanguageName('js')).toBe('JavaScript');
    expect(displayLanguageName('ts')).toBe('TypeScript');
  });

  it('leaves an unknown language for the caller to pass through', () => {
    expect(displayLanguageName('nonexistent-lang')).toBeNull();
    expect(displayLanguageName('')).toBeNull();
    expect(displayLanguageName(null)).toBeNull();
    expect(displayLanguageName(undefined)).toBeNull();
  });

  it('exports a default that matches what the picker would store', () => {
    expect(DEFAULT_CODE_LANGUAGE).toBe('Shell');
    expect(displayLanguageName(DEFAULT_CODE_LANGUAGE)).toBe(DEFAULT_CODE_LANGUAGE);
  });
});

describe('fenceLanguage', () => {
  // The regression: typing ``` and pressing Enter went through commonmark's
  // own input rule, which stores the captured language verbatim. A bare fence
  // captures nothing, so the block landed as plain text even though the
  // schema default (and `/code`) is Shell.
  it('falls back to the default language for a bare fence', () => {
    expect(fenceLanguage(undefined)).toBe(DEFAULT_CODE_LANGUAGE);
    expect(fenceLanguage('')).toBe(DEFAULT_CODE_LANGUAGE);
  });

  it('keeps a language the user typed after the fence', () => {
    expect(fenceLanguage('python')).toBe('python');
    expect(fenceLanguage('js')).toBe('js');
  });
});
