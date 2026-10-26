import { describe, it, expect, beforeEach } from 'vitest';
import {
  setActiveMilkdownEditor,
  getActiveMilkdownEditor,
  hasMilkdownSelection,
} from '@/lib/active-editor';

describe('active-editor', () => {
  beforeEach(() => {
    setActiveMilkdownEditor(null);
    document.body.innerHTML = '';
    window.getSelection()?.removeAllRanges();
  });

  it('round-trips the active editor reference', () => {
    expect(getActiveMilkdownEditor()).toBeNull();
    const fake = { __mark: 'editor' } as unknown as Parameters<typeof setActiveMilkdownEditor>[0];
    setActiveMilkdownEditor(fake);
    expect(getActiveMilkdownEditor()).toBe(fake);
    setActiveMilkdownEditor(null);
    expect(getActiveMilkdownEditor()).toBeNull();
  });

  it('returns false when there is no selection', () => {
    expect(hasMilkdownSelection()).toBe(false);
  });

  it('returns false when the selection is outside the milkdown host', () => {
    const div = document.createElement('div');
    div.textContent = 'hello world';
    document.body.appendChild(div);
    const range = document.createRange();
    range.selectNodeContents(div);
    const sel = window.getSelection()!;
    sel.removeAllRanges();
    sel.addRange(range);
    expect(hasMilkdownSelection()).toBe(false);
  });

  it('returns true when the selection lives inside .milkdown-host .ProseMirror', () => {
    const host = document.createElement('div');
    host.className = 'milkdown-host';
    const pm = document.createElement('div');
    pm.className = 'ProseMirror';
    const p = document.createElement('p');
    p.textContent = 'highlighted';
    pm.appendChild(p);
    host.appendChild(pm);
    document.body.appendChild(host);
    const range = document.createRange();
    range.selectNodeContents(p);
    const sel = window.getSelection()!;
    sel.removeAllRanges();
    sel.addRange(range);
    expect(hasMilkdownSelection()).toBe(true);
  });
});
