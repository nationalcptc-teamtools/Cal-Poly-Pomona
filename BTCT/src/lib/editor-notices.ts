/**
 * Short-lived notices from editor plugins (a failed image upload, a paste
 * too large for a note), shown by `EditorNotices` in the shell. A notice may
 * carry actions such as Retry; the plugin keeps whatever the action needs
 * (the File) in its closure, so nothing is lost when an upload fails.
 */
import { create } from 'zustand';

export interface NoticeAction {
  label: string;
  run: () => void;
}

export interface EditorNotice {
  id: number;
  tone: 'error' | 'info';
  message: string;
  actions: NoticeAction[];
}

interface NoticeState {
  notices: EditorNotice[];
}

export const useEditorNotices = create<NoticeState>(() => ({ notices: [] }));

/** Keep at most this many on screen; the oldest goes first. */
const MAX_NOTICES = 4;
let nextId = 1;

export function pushNotice(n: Omit<EditorNotice, 'id' | 'actions'> & { actions?: NoticeAction[] }): number {
  const id = nextId++;
  const notice: EditorNotice = { id, tone: n.tone, message: n.message, actions: n.actions ?? [] };
  useEditorNotices.setState((s) => ({ notices: [...s.notices, notice].slice(-MAX_NOTICES) }));
  return id;
}

export function dismissNotice(id: number): void {
  useEditorNotices.setState((s) => ({ notices: s.notices.filter((n) => n.id !== id) }));
}
