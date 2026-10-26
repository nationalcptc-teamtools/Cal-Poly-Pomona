import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Schema, type Node as ProseNode } from '@milkdown/prose/model';
import { EditorState } from '@milkdown/prose/state';
import { convertHighlightSyntax, highlightInputHandler, HIGHLIGHT_INPUT } from '@/components/editor/live-preview/highlight-syntax';
import { __resetEditorStyleForTests, applyEditorStyle } from '@/components/editor/live-preview/editor-style';

const schema = new Schema({
  nodes: {
    doc: { content: 'block+' },
    paragraph: { group: 'block', content: 'inline*', toDOM: () => ['p', 0] },
    code_block: { group: 'block', content: 'text*', marks: '', code: true, toDOM: () => ['pre', ['code', 0]] },
    text: { group: 'inline' },
  },
  marks: {
    inlineCode: { inclusive: false, toDOM: () => ['code', 0] },
    highlight: { attrs: { color: { default: 'yellow' } }, inclusive: false, toDOM: () => ['mark', 0] },
  },
});
const t = (text: string, ...marks: ReturnType<typeof schema.mark>[]) => schema.text(text, marks);
const p = (...c: ProseNode[]) => schema.node('paragraph', null, c);
const doc = (...c: ProseNode[]) => schema.node('doc', null, c);
const code = schema.marks.inlineCode!.create();

describe('==highlight== syntax (Live preview)', () => {
  beforeEach(() => __resetEditorStyleForTests());
  afterEach(() => __resetEditorStyleForTests());
  const hlType = schema.marks.highlight!;

  it('converts pasted `==text==` in place, but not in code', () => {
    const d = doc(p(t('a ==hot== b ==two words== c')), schema.node('code_block', null, [schema.text('x ==no== y')]), p(t('== x ==')), p(t('`'), t('==c==', code)));
    const state = EditorState.create({ doc: d });
    const tr = state.tr;
    expect(convertHighlightSyntax(tr, 0, d.content.size, hlType)).toBe(2);
    const first = tr.doc.child(0);
    expect(first.textContent).toBe('a hot b two words c');
    expect(first.child(1).text).toBe('hot');
    expect(first.child(1).marks.map((m) => m.type.name)).toEqual(['highlight']);
    expect(tr.doc.child(1).textContent).toBe('x ==no== y');
    expect(tr.doc.child(2).textContent).toBe('== x ==');
    expect(tr.doc.child(3).textContent).toBe('`==c==');
  });

  it('typing the closing `==` highlights, only in Live preview', () => {
    const d = doc(p(t('see ==this=')));
    const state = EditorState.create({ doc: d });
    const text = 'see ==this==';
    const match = text.match(HIGHLIGHT_INPUT)!;
    expect(match).not.toBeNull();
    const start = 1 + match.index!;
    const end = d.content.size - 1;
    const tr = highlightInputHandler(hlType)(state, match, start, end)!;
    expect(tr.doc.child(0).textContent).toBe('see this');
    expect(tr.doc.child(0).child(1).marks.map((m) => m.type.name)).toEqual(['highlight']);
    applyEditorStyle('blocks');
    expect(highlightInputHandler(hlType)(state, match, start, end)).toBeNull();
  });

});
