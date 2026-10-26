import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { Dialog } from '@/components/ui/Dialog';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';

afterEach(cleanup);

const esc = () => fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Escape' });

describe('Dialog', () => {
  it('is a labelled modal in a body portal', () => {
    render(<div id="host"><Dialog title="Export" onClose={() => {}}><p>body</p></Dialog></div>);
    const dlg = screen.getByRole('dialog');
    expect(dlg).toHaveAttribute('aria-modal', 'true');
    expect(dlg).toHaveAccessibleName('Export');
    expect(document.getElementById('host')!.contains(dlg)).toBe(false);
  });

  it('closes on Escape and on a scrim click, not on a click inside', () => {
    const onClose = vi.fn();
    render(<Dialog title="T" onClose={onClose}><button>inside</button></Dialog>);
    fireEvent.mouseDown(screen.getByText('inside'));
    expect(onClose).not.toHaveBeenCalled();
    esc();
    expect(onClose).toHaveBeenCalledTimes(1);
    fireEvent.mouseDown(screen.getByRole('dialog').parentElement!);
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it('ignores Escape while not dismissible, and when a control consumed it', () => {
    const onClose = vi.fn();
    const { rerender } = render(<Dialog title="T" onClose={onClose} dismissible={false}><input /></Dialog>);
    esc();
    expect(onClose).not.toHaveBeenCalled();
    rerender(
      <Dialog title="T" onClose={onClose}>
        <input aria-label="rename" onKeyDown={(e) => { if (e.key === 'Escape') e.preventDefault(); }} />
      </Dialog>,
    );
    fireEvent.keyDown(screen.getByLabelText('rename'), { key: 'Escape' });
    expect(onClose).not.toHaveBeenCalled();
  });

  it('moves focus in, traps Tab and restores focus on close', () => {
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button onClick={() => setOpen(true)}>opener</button>
          {open && (
            <Dialog title="T" onClose={() => setOpen(false)}>
              <button>first</button>
              <button>last</button>
            </Dialog>
          )}
        </>
      );
    }
    render(<Harness />);
    const opener = screen.getByText('opener');
    opener.focus();
    fireEvent.click(opener);
    expect(screen.getByText('first')).toHaveFocus();
    // Shift+Tab from the first control wraps to the last (the header close button
    // comes first in the DOM, so wrapping from it goes to "last").
    screen.getByLabelText('Close').focus();
    fireEvent.keyDown(document.activeElement!, { key: 'Tab', shiftKey: true });
    expect(screen.getByText('last')).toHaveFocus();
    fireEvent.keyDown(document.activeElement!, { key: 'Tab' });
    expect(screen.getByLabelText('Close')).toHaveFocus();
    esc();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(opener).toHaveFocus();
  });

  it('Escape closes only the topmost of two stacked dialogs', () => {
    const outer = vi.fn();
    const inner = vi.fn();
    render(
      <>
        <Dialog title="Outer" onClose={outer}><p>o</p></Dialog>
        <Dialog title="Inner" onClose={inner}><p>i</p></Dialog>
      </>,
    );
    esc();
    expect(inner).toHaveBeenCalledTimes(1);
    expect(outer).not.toHaveBeenCalled();
  });
});

describe('ConfirmDialog', () => {
  it('focuses confirm, cancels on Escape', () => {
    const onCancel = vi.fn();
    render(<ConfirmDialog title="Delete page?" destructive confirmLabel="Delete" onConfirm={() => {}} onCancel={onCancel} />);
    expect(screen.getByRole('alertdialog')).toHaveAccessibleName('Delete page?');
    expect(screen.getByText('Delete')).toHaveFocus();
    esc();
    expect(onCancel).toHaveBeenCalled();
  });

  it('type-to-confirm only enables on an exact match', () => {
    const onConfirm = vi.fn();
    render(<ConfirmDialog title="Delete workspace" destructive input={{ match: 'Acme' }} confirmLabel="Delete" onConfirm={onConfirm} onCancel={() => {}} />);
    const field = screen.getByRole('textbox');
    expect(field).toHaveFocus();
    fireEvent.change(field, { target: { value: 'acme' } });
    expect(screen.getByText('Delete')).toBeDisabled();
    fireEvent.change(field, { target: { value: 'Acme' } });
    fireEvent.keyDown(field, { key: 'Enter' });
    expect(onConfirm).toHaveBeenCalledWith('Acme');
  });
});
