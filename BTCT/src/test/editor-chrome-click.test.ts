import { describe, it, expect, afterEach, beforeAll } from 'vitest';
import { EditorState } from '@milkdown/prose/state';
import { EditorView } from '@milkdown/prose/view';
import { Schema } from '@milkdown/prose/model';
import { createEditorChromeClickPlugin, isEditorChrome } from '@/lib/editor-chrome-click';

// A block with a code-block-like node view: a contenteditable=false shell
// holding a header bar (a label, a button) and an editable body.
const schema = new Schema({
  nodes: {
    doc: { content: 'block+' },
    paragraph: { group: 'block', content: 'text*', toDOM: () => ['p', 0] },
    box: { group: 'block', content: 'text*', toDOM: () => ['section', 0] },
    text: {},
  },
});

function mount() {
  const host = document.createElement('div');
  document.body.appendChild(host);
  const doc = schema.node('doc', null, [
    schema.node('paragraph', null, [schema.text('before')]),
    schema.node('box', null, [schema.text('code')]),
  ]);
  const view = new EditorView(host, {
    state: EditorState.create({ doc, plugins: [createEditorChromeClickPlugin()] }),
    nodeViews: {
      box: () => {
        const dom = document.createElement('div');
        dom.className = 'code-shell';
        dom.setAttribute('contenteditable', 'false');
        const tools = document.createElement('div');
        tools.className = 'tools';
        const label = document.createElement('span');
        label.textContent = 'bash';
        const button = document.createElement('button');
        button.textContent = 'Copy';
        tools.append(label, button);
        const contentDOM = document.createElement('div');
        contentDOM.setAttribute('contenteditable', 'true');
        dom.append(tools, contentDOM);
        return { dom, contentDOM };
      },
    },
  });
  return { host, view };
}

function mousedown(target: Element): boolean {
  const ev = new MouseEvent('mousedown', { bubbles: true, cancelable: true, button: 0 });
  target.dispatchEvent(ev);
  return ev.defaultPrevented;
}

// jsdom has no layout: ProseMirror's own mousedown asks elementFromPoint.
beforeAll(() => {
  if (!document.elementFromPoint) document.elementFromPoint = () => null;
});

let cleanup: (() => void) | null = null;
afterEach(() => {
  cleanup?.();
  cleanup = null;
});

describe('isEditorChrome', () => {
  it('is true only for bare parts of a contenteditable=false island', () => {
    const { host, view } = mount();
    cleanup = () => { view.destroy(); host.remove(); };
    const root = view.dom;
    expect(isEditorChrome(root.querySelector('.tools'), root)).toBe(true);
    expect(isEditorChrome(root.querySelector('.tools span'), root)).toBe(true);
    expect(isEditorChrome(root.querySelector('.tools span')!.firstChild, root)).toBe(true);
    expect(isEditorChrome(root.querySelector('.tools button'), root)).toBe(false);
    expect(isEditorChrome(root.querySelector('[contenteditable="true"]'), root)).toBe(false);
    expect(isEditorChrome(root.querySelector('p'), root)).toBe(false);
    expect(isEditorChrome(root, root)).toBe(false);
    expect(isEditorChrome(document.body, root)).toBe(false);
  });

  it('leaves list markers, draggable handles and nested editors alone', () => {
    const root = document.createElement('div');
    root.setAttribute('contenteditable', 'true');
    root.innerHTML = '<div contenteditable="false">'
      + '<div class="label-wrapper"><span class="m">1.</span></div>'
      + '<div class="handle" draggable="true"><i class="h"></i></div>'
      + '<div class="cm-editor"><div class="cm-gutter"></div></div>'
      + '<div class="bare"></div></div>';
    expect(isEditorChrome(root.querySelector('.m'), root)).toBe(false);
    expect(isEditorChrome(root.querySelector('.h'), root)).toBe(false);
    expect(isEditorChrome(root.querySelector('.cm-gutter'), root)).toBe(false);
    expect(isEditorChrome(root.querySelector('.bare'), root)).toBe(true);
  });
});

describe('editor chrome click plugin', () => {
  it('cancels the caret-placing mousedown on bare chrome only', () => {
    const { host, view } = mount();
    cleanup = () => { view.destroy(); host.remove(); };
    const root = view.dom;
    expect(mousedown(root.querySelector('.tools')!)).toBe(true);
    expect(mousedown(root.querySelector('.tools span')!)).toBe(true);
    expect(mousedown(root.querySelector('.tools button')!)).toBe(false);
    expect(mousedown(root.querySelector('p')!)).toBe(false);
  });

  it('ignores buttons other than the primary one', () => {
    const { host, view } = mount();
    cleanup = () => { view.destroy(); host.remove(); };
    const ev = new MouseEvent('mousedown', { bubbles: true, cancelable: true, button: 2 });
    view.dom.querySelector('.tools')!.dispatchEvent(ev);
    expect(ev.defaultPrevented).toBe(false);
  });
});
