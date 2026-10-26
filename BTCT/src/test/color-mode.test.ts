import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  COLOR_MODE_KEY, DEFAULT_COLOR_MODE, currentColorMode, parseColorMode, readStoredColorMode, setColorMode,
} from '@/lib/color-mode';

describe('colour mode', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.classList.add('dark');
  });

  it('defaults to dark, the theme defaultMode', () => {
    expect(DEFAULT_COLOR_MODE).toBe('dark');
    expect(readStoredColorMode()).toBe('dark');
    expect(parseColorMode('purple')).toBe('dark');
  });

  it('persists the choice per device and toggles the class', () => {
    setColorMode('light');
    expect(localStorage.getItem(COLOR_MODE_KEY)).toBe('light');
    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(currentColorMode()).toBe('light');
    expect(readStoredColorMode()).toBe('light');
    setColorMode('dark');
    expect(readStoredColorMode()).toBe('dark');
    expect(currentColorMode()).toBe('dark');
  });

  it('index.html applies the same key before first paint', () => {
    const html = readFileSync(join(process.cwd(), 'index.html'), 'utf8');
    expect(html).toMatch(/<html[^>]*class="dark"/);
    expect(html).toContain(`localStorage.getItem('${COLOR_MODE_KEY}') === 'light'`);
    // The inline script must sit in <head>, before the module entry runs.
    expect(html.indexOf(COLOR_MODE_KEY)).toBeLessThan(html.indexOf('/src/main.tsx'));
  });

  it('the store toggle writes through to storage', async () => {
    const { useAppStore } = await import('@/stores/app-store');
    useAppStore.getState().setDarkMode(false);
    expect(localStorage.getItem(COLOR_MODE_KEY)).toBe('light');
    useAppStore.getState().toggleDarkMode();
    expect(localStorage.getItem(COLOR_MODE_KEY)).toBe('dark');
    expect(useAppStore.getState().darkMode).toBe(true);
  });
});
