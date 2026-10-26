import { DEFAULT_KEYBINDS, type KeybindAction } from './editor-prefs';

export let currentKeybinds: Record<KeybindAction, string> = { ...DEFAULT_KEYBINDS };

export function setEditorKeybinds(keybinds: Record<KeybindAction, string>): void {
  currentKeybinds = keybinds;
}

/** Current (live) keybinds, for UI that wants to print shortcut hints. */
export function getEditorKeybinds(): Record<KeybindAction, string> {
  return currentKeybinds;
}
