import { createPortal } from 'react-dom';
import type { ReactNode } from 'react';

/**
 * Render children at the end of <body>.
 *
 * Dialogs opened from the rails use it so their fixed overlay is a child of
 * <body>, after every pane. Left in place inside a rail, Chrome could paint
 * the content column's composited scrollers (the History tab's viewer and
 * timeline) over a `position: fixed; z-index: 100` overlay even though
 * hit-testing put the overlay on top. React events still bubble through the
 * portal to the opener, and the `.dark` / `data-ui-theme` hooks live on
 * <html>, so styling is unchanged.
 */
export function Portal({ children }: { children: ReactNode }) {
  return createPortal(children, document.body);
}
