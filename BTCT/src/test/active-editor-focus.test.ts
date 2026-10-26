import { describe, expect, it } from 'vitest';
import {
  clearActiveMilkdownEditor, getActiveMilkdownEditor, registerPageEditor, setActiveMilkdownEditor, unregisterPageEditor,
} from '@/lib/active-editor';

// M3: unmounting an editor clears the active reference only if it is still
// that editor, and falls back to another mounted page editor.
type Ed = Parameters<typeof setActiveMilkdownEditor>[0];
const ed = (name: string) => ({ name }) as unknown as NonNullable<Ed>;

describe('active editor bookkeeping', () => {
  it('a stale unmount does not clear a newer active editor', () => {
    const a = ed('a');
    const b = ed('b');
    setActiveMilkdownEditor(a);
    setActiveMilkdownEditor(b);
    clearActiveMilkdownEditor(a);
    expect(getActiveMilkdownEditor()).toBe(b);
  });

  it('falls back to a remaining registered editor', () => {
    const left = ed('left');
    const right = ed('right');
    registerPageEditor('p-left', left);
    registerPageEditor('p-right', right);
    setActiveMilkdownEditor(right);
    unregisterPageEditor('p-right', right);
    clearActiveMilkdownEditor(right);
    expect(getActiveMilkdownEditor()).toBe(left);
    unregisterPageEditor('p-left', left);
    clearActiveMilkdownEditor(left);
    expect(getActiveMilkdownEditor()).toBeNull();
  });
});
