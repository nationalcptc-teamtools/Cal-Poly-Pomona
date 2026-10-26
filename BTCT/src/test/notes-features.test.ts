import { describe, it, expect } from 'vitest';
import { canonicalLanguage } from '@/lib/code-theme';
import { clampImageWidth, MIN_IMAGE_WIDTH } from '@/lib/image-resize';

describe('canonicalLanguage (terminal highlighting key)', () => {
  it('folds every shell alias to "shell"', () => {
    for (const alias of ['shell', 'bash', 'sh', 'zsh', 'Bash', 'CONSOLE', 'shell-session']) {
      expect(canonicalLanguage(alias)).toBe('shell');
    }
  });

  it('folds every PowerShell alias to "powershell"', () => {
    for (const alias of ['PowerShell', 'powershell', 'pwsh', 'posh', 'ps1', 'PS1', 'psm1']) {
      expect(canonicalLanguage(alias)).toBe('powershell');
    }
  });

  it('lowercases other languages and blanks empties', () => {
    expect(canonicalLanguage('Python')).toBe('python');
    expect(canonicalLanguage('  TypeScript ')).toBe('typescript');
    expect(canonicalLanguage('')).toBe('');
    expect(canonicalLanguage(null)).toBe('');
    expect(canonicalLanguage(undefined)).toBe('');
  });
});

describe('clampImageWidth (drag-to-resize)', () => {
  it('shrinks and grows by the drag delta, rounded', () => {
    expect(clampImageWidth(300, -120.4, 600)).toBe(180);
    expect(clampImageWidth(300, 40.6, 600)).toBe(341);
  });

  it('never goes below the minimum width', () => {
    expect(clampImageWidth(300, -1000, 600)).toBe(MIN_IMAGE_WIDTH);
  });

  it('never exceeds the column width', () => {
    expect(clampImageWidth(300, 1000, 600)).toBe(600);
  });

  it('keeps the minimum usable even in a very narrow column', () => {
    expect(clampImageWidth(20, 5, 10)).toBe(MIN_IMAGE_WIDTH);
  });
});
