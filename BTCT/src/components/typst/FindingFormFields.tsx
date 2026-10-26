// ─────────────────────────────────────────────────────────────────────────
// Field editors for the Findings form (FindingsPanel's FindingForm).
//
// Every editor keeps a local draft and commits on blur or on a structural
// action (add, remove, move), never per keystroke: a commit rewrites the
// report Y.Text, and doing that on every key would fight a teammate's cursor
// and lose characters to the 420 ms settle of the source the form reads.
//
// The list editors keep their latest value in a ref that every handler reads,
// so a blur that commits a typed word and the click that caused it (a Move
// up, say) apply in order instead of the click undoing the word.
//
// Lazy with the rest of Findings mode (invariant 17).
// ─────────────────────────────────────────────────────────────────────────

import { lazy, memo, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowDown, ArrowUp, Code2, ImageOff, ImagePlus, LayoutTemplate, Link2, Pencil, Plus, Replace, TextCursorInput, Trash2, X,
} from 'lucide-react';
import { useAppStore } from '@/stores';
import type { BlurRegion, CropRect, TypstAsset } from '@/types';
import { Button, IconButton, ToggleChip } from '@/components/ui/Button';
import { Input, Textarea, FieldLabel, Select } from '@/components/ui/Field';
import { Banner } from '@/components/ui/Banner';
import { Portal } from '@/components/ui/Portal';
import { assetPath } from '@/lib/assets';
import { extractAssetLinks, parseAssetLinkList } from '@/lib/asset-link';
import { FIGURE_WIDTH_FRACTION, figureWidthPt, formatRatio, parseRatio } from '@/lib/typst-geometry';
import { contentIsBalanced, letContent, type DecodedField, type FieldValue, type ScopeRow } from '@/lib/typst-findings';
import {
  captionFor,
  fitFigureHeight,
  moveItem,
  newStep,
  parseExploitSteps,
  parseMarkupList,
  serializeExploitSteps,
  serializeMarkupList,
  stepDescription,
  scaleFigureHeight,
  stepsUseCmd,
  stepsUseSlot,
  stepsUseWidth,
  templateFigureCaption,
  templateImageBlock,
  withDescription,
  type CmdBlock,
  type ExploitStep,
  type ImageBlock,
  type StepBlock,
} from '@/lib/typst-exploit-steps';
import { useAssetPreview } from '@/components/assets/use-asset-preview';
import { cn } from '@/lib/utils';

const AssetPickerDialog = lazy(() => import('./AssetPickerDialog').then((m) => ({ default: m.AssetPickerDialog })));
const ImageEditorDialog = lazy(() =>
  import('@/components/assets/ImageEditorDialog').then((m) => ({ default: m.ImageEditorDialog })),
);

const UNBALANCED = 'This text has a [ or ] without its partner, which would break the finding block. Fix the brackets (or escape them as \\[ \\]) and it saves.';

// ── small fields ─────────────────────────────────────────────────────────

/** A one-line input that commits on blur. */
export function TextField({
  label, value, onCommit, mono, autoFocus, onAutoFocused, placeholder,
}: {
  label: string;
  value: string;
  onCommit: (v: string) => void;
  mono?: boolean;
  autoFocus?: boolean;
  onAutoFocused?: () => void;
  placeholder?: string;
}) {
  const [draft, setDraft] = useState(value);
  const focused = useRef(false);
  const inputRef = useRef<HTMLInputElement>(null);
  useEffect(() => { if (!focused.current) setDraft(value); }, [value]);
  useEffect(() => {
    if (!autoFocus) return;
    inputRef.current?.focus();
    onAutoFocused?.();
  }, [autoFocus, onAutoFocused]);
  return (
    <div>
      <FieldLabel>{label}</FieldLabel>
      <Input
        ref={inputRef}
        value={draft}
        mono={mono}
        placeholder={placeholder}
        aria-label={label}
        onFocus={() => { focused.current = true; }}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={() => { focused.current = false; if (draft !== value) onCommit(draft); }}
        onKeyDown={(e) => { if (e.key === 'Enter') (e.target as HTMLInputElement).blur(); }}
      />
    </div>
  );
}

/** Multi-line Typst markup that commits on blur, refusing unbalanced brackets. */
export function ContentField({
  label, field, onCommit, rows = 3, mono, source, templateHint,
}: {
  label: string;
  field: DecodedField;
  onCommit: (v: string) => void;
  rows?: number;
  mono?: boolean;
  source?: string;
  templateHint?: boolean;
}) {
  const value = typeof field.value === 'string' ? field.value : '';
  const [draft, setDraft] = useState(value);
  const [bad, setBad] = useState(false);
  const focused = useRef(false);
  useEffect(() => { if (!focused.current) { setDraft(value); setBad(false); } }, [value]);
  if (field.expression) {
    return (
      <div>
        <FieldLabel>{label}</FieldLabel>
        <Expression text={field.expression} source={source} onReplace={onCommit} offerTemplate={templateHint} />
      </div>
    );
  }
  return (
    <div>
      <FieldLabel>{label}</FieldLabel>
      <Textarea
        value={draft}
        rows={rows}
        mono={mono}
        aria-label={label}
        onFocus={() => { focused.current = true; }}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={() => {
          focused.current = false;
          if (draft === value) return;
          if (!contentIsBalanced(draft)) { setBad(true); return; }
          setBad(false);
          onCommit(draft);
        }}
      />
      {bad && <p className="mt-1 text-caption text-status-red">{UNBALANCED}</p>}
    </div>
  );
}

/** `number: auto` (a numbered heading) or a fixed label such as "6.1.x". */
export function NumberField({ field, onAuto, onCustom }: {
  field: DecodedField;
  onAuto: () => void;
  onCustom: (v: string) => void;
}) {
  const custom = typeof field.value === 'string';
  const other = field.expression !== null && field.expression.trim() !== 'auto';
  const [editing, setEditing] = useState(custom);
  useEffect(() => { setEditing(custom); }, [custom]);
  if (other) {
    return (
      <div>
        <FieldLabel>Number</FieldLabel>
        <Expression text={field.expression!} onReplace={() => onAuto()} replaceLabel="Use automatic numbering" />
      </div>
    );
  }
  return (
    <div>
      <FieldLabel>Number</FieldLabel>
      <div className="flex items-center gap-1">
        <ToggleChip pressed={!editing} onClick={() => { setEditing(false); if (custom) onAuto(); }} title="Numbered heading (6.3.1, 6.3.2, ...)">
          Auto
        </ToggleChip>
        <ToggleChip pressed={editing} onClick={() => setEditing(true)} title="A fixed label, as the template blocks use">
          Fixed
        </ToggleChip>
        {editing && (
          <InlineInput
            value={custom ? (field.value as string) : ''}
            placeholder="6.1.x"
            label="Fixed number"
            mono
            onCommit={(v) => { if (v.trim()) onCustom(v.trim()); }}
          />
        )}
      </div>
    </div>
  );
}

function InlineInput({ value, onCommit, placeholder, label, mono, className, list }: {
  list?: string;
  value: string;
  onCommit: (v: string) => void;
  placeholder?: string;
  label: string;
  mono?: boolean;
  className?: string;
}) {
  const [draft, setDraft] = useState(value);
  const focused = useRef(false);
  useEffect(() => { if (!focused.current) setDraft(value); }, [value]);
  return (
    <Input
      value={draft}
      mono={mono}
      placeholder={placeholder}
      aria-label={label}
      list={list}
      className={cn('min-w-0 flex-1', className)}
      onFocus={() => { focused.current = true; }}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={() => { focused.current = false; if (draft !== value) onCommit(draft); }}
      onKeyDown={(e) => { if (e.key === 'Enter') (e.target as HTMLInputElement).blur(); }}
    />
  );
}

function InlineTextarea({ value, onCommit, placeholder, label, mono, rows, onPaste, validate }: {
  value: string;
  onCommit: (v: string) => void;
  placeholder?: string;
  label: string;
  mono?: boolean;
  rows?: number;
  onPaste?: (e: React.ClipboardEvent<HTMLTextAreaElement>) => void;
  validate?: (v: string) => string | null;
}) {
  const [draft, setDraft] = useState(value);
  const [err, setErr] = useState<string | null>(null);
  const focused = useRef(false);
  useEffect(() => { if (!focused.current) { setDraft(value); setErr(null); } }, [value]);
  const lines = draft.split('\n').length;
  return (
    <>
      <Textarea
        value={draft}
        mono={mono}
        placeholder={placeholder}
        aria-label={label}
        rows={Math.min(14, Math.max(rows ?? 2, lines))}
        onFocus={() => { focused.current = true; }}
        onChange={(e) => setDraft(e.target.value)}
        onPaste={onPaste}
        onBlur={() => {
          focused.current = false;
          if (draft === value) return;
          const problem = validate?.(draft) ?? null;
          setErr(problem);
          if (!problem) onCommit(draft);
        }}
      />
      {err && <p className="mt-1 text-caption text-status-red">{err}</p>}
    </>
  );
}

/**
 * A list of short values (MITRE techniques, mitigations, resources,
 * remediation items): one row each, with add, remove and move.
 */
export function ListEditor({
  label, items, onCommit, placeholder, addLabel, multiline, mono, validate,
}: {
  label: string;
  items: string[];
  onCommit: (items: string[]) => void;
  placeholder?: string;
  addLabel: string;
  multiline?: boolean;
  mono?: boolean;
  validate?: (v: string) => string | null;
}) {
  const [list, setList] = useState(items);
  const ref = useRef(items);
  const key = items.join('\u0000');
  useEffect(() => { ref.current = items; setList(items); }, [key]); // eslint-disable-line react-hooks/exhaustive-deps
  const [focusLast, setFocusLast] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!focusLast) return;
    const els = wrapRef.current?.querySelectorAll<HTMLElement>('input, textarea');
    els?.[els.length - 1]?.focus();
    setFocusLast(false);
  }, [focusLast, list.length]);

  const commit = (next: string[], write = true) => {
    ref.current = next;
    setList(next);
    if (write) onCommit(next.filter((s) => s.trim() !== ''));
  };
  return (
    <div>
      <FieldLabel>{label}</FieldLabel>
      <div ref={wrapRef} className="space-y-1">
        {list.map((it, i) => (
          <div key={i} className="flex items-start gap-1">
            <span className="mt-1.5 w-4 shrink-0 text-right font-mono text-micro text-muted-foreground">{i + 1}.</span>
            <div className="min-w-0 flex-1">
              {multiline ? (
                <InlineTextarea
                  value={it}
                  label={`${label} ${i + 1}`}
                  placeholder={placeholder}
                  rows={1}
                  mono={mono}
                  validate={validate}
                  onCommit={(v) => commit(ref.current.map((x, k) => (k === i ? v : x)))}
                />
              ) : (
                <InlineInput
                  value={it}
                  label={`${label} ${i + 1}`}
                  placeholder={placeholder}
                  mono={mono}
                  onCommit={(v) => {
                    const problem = validate?.(v) ?? null;
                    if (!problem) commit(ref.current.map((x, k) => (k === i ? v : x)));
                  }}
                />
              )}
            </div>
            <div className="flex shrink-0 items-center">
              <IconButton size="sm" label={`Move ${label} item ${i + 1} up`} title="Move up" disabled={i === 0} onClick={() => commit(moveItem(ref.current, i, i - 1))}><ArrowUp size={12} /></IconButton>
              <IconButton size="sm" label={`Move ${label} item ${i + 1} down`} title="Move down" disabled={i === list.length - 1} onClick={() => commit(moveItem(ref.current, i, i + 1))}><ArrowDown size={12} /></IconButton>
              <IconButton size="sm" tone="danger" label={`Remove ${label} item ${i + 1}`} title="Remove" onClick={() => commit(ref.current.filter((_, k) => k !== i))}><X size={12} /></IconButton>
            </div>
          </div>
        ))}
        <Button
          variant="ghost"
          size="sm"
          icon={<Plus size={12} />}
          onClick={() => { commit([...ref.current, ''], false); setFocusLast(true); }}
        >
          {addLabel}
        </Button>
      </div>
    </div>
  );
}

/** Array fields (`strings` / `contents`), or the expression notice. */
export function ArrayField({ label, field, onCommit, placeholder, addLabel, content }: {
  label: string;
  field: DecodedField;
  onCommit: (items: string[]) => void;
  placeholder?: string;
  addLabel: string;
  content?: boolean;
}) {
  if (field.expression) {
    return (
      <div>
        <FieldLabel>{label}</FieldLabel>
        <Expression text={field.expression} onReplace={() => onCommit([])} />
      </div>
    );
  }
  const items = Array.isArray(field.value) ? (field.value as string[]) : [];
  return (
    <ListEditor
      label={label}
      items={items}
      onCommit={onCommit}
      placeholder={placeholder}
      addLabel={addLabel}
      validate={content ? (v) => (contentIsBalanced(v) ? null : UNBALANCED) : undefined}
    />
  );
}

export function ScopeField({ label = 'Affected scope', rows, expression, onCommit }: {
  label?: string;
  rows: ScopeRow[];
  expression: string | null;
  onCommit: (rows: ScopeRow[]) => void;
}) {
  const [draft, setDraft] = useState(rows);
  const ref = useRef(rows);
  const focused = useRef(false);
  const key = JSON.stringify(rows);
  useEffect(() => { if (!focused.current) { ref.current = rows; setDraft(rows); } }, [key]); // eslint-disable-line react-hooks/exhaustive-deps
  if (expression) {
    return (
      <div>
        <FieldLabel>{label}</FieldLabel>
        <Expression text={expression} onReplace={() => onCommit([])} />
      </div>
    );
  }
  const set = (next: ScopeRow[], write: boolean) => {
    ref.current = next;
    setDraft(next);
    if (write) onCommit(next);
  };
  const cell = (i: number, j: number, mono: boolean, label: string) => (
    <Input
      mono={mono}
      aria-label={`${label} ${i + 1}`}
      value={draft[i]![j]}
      onFocus={() => { focused.current = true; }}
      onChange={(e) => set(ref.current.map((r, k) => (k === i ? (r.map((c, m) => (m === j ? e.target.value : c)) as ScopeRow) : r)), false)}
      onBlur={() => { focused.current = false; if (JSON.stringify(ref.current) !== key) onCommit(ref.current); }}
      onKeyDown={(e) => { if (e.key === 'Enter') (e.target as HTMLInputElement).blur(); }}
    />
  );
  return (
    <div>
      <FieldLabel>{label}</FieldLabel>
      <div className="space-y-1">
        <div className="grid grid-cols-[1fr_1fr_56px_24px] gap-1 text-caption text-muted-foreground">
          <span>Host</span><span>Service</span><span>Port</span><span />
        </div>
        {draft.map((_, i) => (
          <div key={i} className="grid grid-cols-[1fr_1fr_56px_24px] gap-1">
            {cell(i, 0, true, 'Host')}
            {cell(i, 1, false, 'Service')}
            {cell(i, 2, true, 'Port')}
            <IconButton label={`Remove host row ${i + 1}`} title="Remove row" size="sm" onClick={() => set(ref.current.filter((_, k) => k !== i), true)}><X size={12} /></IconButton>
          </div>
        ))}
        <Button variant="ghost" size="sm" icon={<Plus size={12} />} onClick={() => set([...ref.current, ['', '', '']], true)}>
          Add host
        </Button>
      </div>
    </div>
  );
}

/**
 * A field the form cannot edit (a Typst expression such as CPTC's
 * `template-exploitation`). When it names a `#let ... = [...]` in the report,
 * offer to copy that text into this finding so it can be edited here.
 */
export function Expression({ text, onReplace, source, offerTemplate, replaceLabel }: {
  text: string;
  onReplace: (value: string) => void;
  source?: string;
  offerTemplate?: boolean;
  replaceLabel?: string;
}) {
  const name = text.trim();
  const template = offerTemplate && source && /^[A-Za-z_][\w-]*$/.test(name) ? letContent(source, name) : null;
  return (
    <div className="rounded-md border border-dashed border-border bg-muted/40 p-2">
      <p className="mb-1 text-caption text-muted-foreground">This field is a Typst expression, so the form shows it read-only:</p>
      <code className="block overflow-x-auto whitespace-pre-wrap break-all font-mono text-caption text-foreground">{text.length > 200 ? text.slice(0, 200) + '…' : text}</code>
      <div className="mt-1 flex flex-wrap gap-1">
        {template !== null && (
          <Button variant="subtle" size="sm" onClick={() => onReplace(template)} title={`Copy the text of ${name} into this finding, where the form can edit it`}>
            Copy {name} here
          </Button>
        )}
        <Button variant="ghost" size="sm" onClick={() => onReplace('')}>{replaceLabel ?? 'Write it here instead'}</Button>
      </div>
    </div>
  );
}

// ── remediation ──────────────────────────────────────────────────────────

export function RemediationField({ field, source, onCommit }: {
  field: DecodedField;
  source: string;
  onCommit: (markup: string) => void;
}) {
  if (field.expression) {
    return (
      <div>
        <FieldLabel>Remediation</FieldLabel>
        <Expression text={field.expression} source={source} offerTemplate onReplace={onCommit} />
      </div>
    );
  }
  const value = typeof field.value === 'string' ? field.value : '';
  const list = parseMarkupList(value);
  if (!list) {
    return (
      <div>
        <ContentField label="Remediation (Typst markup)" field={field} onCommit={onCommit} rows={4} mono />
        <p className="mt-1 text-caption text-muted-foreground">
          Not a <code className="font-mono">+ item</code> list, so it is shown as markup. Nothing is lost.
        </p>
      </div>
    );
  }
  return (
    <ListEditor
      label="Remediation"
      items={list.items}
      multiline
      placeholder="A remediation step"
      addLabel="Add remediation step"
      validate={(v) => (contentIsBalanced(v) ? null : UNBALANCED)}
      onCommit={(items) => onCommit(serializeMarkupList({ marker: list.marker, items }))}
    />
  );
}

// ── exploitation steps ───────────────────────────────────────────────────

/** What a commit needs besides the markup: helpers the report must define. */
export interface StepNeeds {
  slot: boolean;
  cmd: boolean;
  /** A figure sets `width:`, so the slot helper must take one. */
  width?: boolean;
}

/** Figure sizes the screenshot card offers, as fractions of the text width. */
const FIGURE_SIZES = [1, 0.9, 0.75, 0.6, 0.5, 0.4, 0.3];

const LANGS = ['bash', 'sh', 'zsh', 'powershell', 'cmd', 'python', 'http', 'sql', 'json', 'text'];

export function ExploitationField({ field, source, onCommit, onRenameAsset }: {
  field: DecodedField;
  source: string;
  onCommit: (markup: string, needs: StepNeeds) => void;
  onRenameAsset: (asset: TypstAsset, stem: string) => void;
}) {
  const value = typeof field.value === 'string' ? field.value : '';
  const parsed = useMemo(() => (field.expression ? null : parseExploitSteps(value)), [field.expression, value]);
  const [raw, setRaw] = useState(false);

  if (field.expression) {
    return (
      <div>
        <FieldLabel>Exploitation details</FieldLabel>
        <Expression
          text={field.expression}
          source={source}
          offerTemplate
          onReplace={(v) => onCommit(v, { slot: v.includes('#image-placeholder('), cmd: v.includes('#cmd[') })}
        />
      </div>
    );
  }
  if (!parsed || raw) {
    return (
      <div>
        <ContentField
          label="Exploitation details (Typst markup)"
          field={field}
          rows={8}
          mono
          onCommit={(v) => onCommit(v, { slot: false, cmd: false })}
        />
        {!parsed ? (
          <div className="mt-1 space-y-1">
            <p className="text-caption text-muted-foreground">
              This text is not in the step shape (<code className="font-mono">*1. Title* \</code>, then the step), so it is shown as Typst markup. Nothing is lost.
            </p>
            <Button
              variant="ghost"
              size="sm"
              title="Keep this text as the first step's body and edit it as steps from now on"
              onClick={() => {
                const steps: ExploitStep[] = [{ ...newStep('Step'), blocks: value.trim() ? [{ kind: 'text', text: value }] : [] }];
                onCommit(serializeExploitSteps(steps), { slot: false, cmd: false });
              }}
            >
              Turn it into steps
            </Button>
          </div>
        ) : (
          <Button variant="ghost" size="sm" className="mt-1" onClick={() => setRaw(false)}>Back to the step editor</Button>
        )}
      </div>
    );
  }
  return (
    <StepsEditor
      value={value}
      steps={parsed}
      source={source}
      onCommit={onCommit}
      onRenameAsset={onRenameAsset}
      onShowRaw={() => setRaw(true)}
    />
  );
}

function StepsEditor({ value, steps: fromSource, source, onCommit, onRenameAsset, onShowRaw }: {
  value: string;
  steps: ExploitStep[];
  source: string;
  onCommit: (markup: string, needs: StepNeeds) => void;
  onRenameAsset: (asset: TypstAsset, stem: string) => void;
  onShowRaw: () => void;
}) {
  const assets = useAppStore((s) => s.typstAssets);
  const images = useMemo(() => assets.filter((a) => a.kind === 'image' && !a.deletedAt), [assets]);
  const imagesRef = useRef(images);
  imagesRef.current = images;
  const [steps, setSteps] = useState(fromSource);
  const ref = useRef(fromSource);
  const lastSent = useRef<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [picker, setPicker] = useState<{ step: number; block: number | null } | null>(null);

  // Adopt the source unless it is our own write coming back.
  useEffect(() => {
    if (value === lastSent.current) return;
    ref.current = fromSource;
    setSteps(fromSource);
  }, [value, fromSource]);

  // Inside a finding the figure is 90% of the table cell, which is inset
  // 10 pt a side from the text width.
  const boxWidth = useMemo(() => figureWidthPt(source) - 18, [source]);

  const commit = useCallback((next: ExploitStep[]) => {
    const markup = serializeExploitSteps(next);
    if (!contentIsBalanced(markup)) { setNotice(UNBALANCED); return; }
    ref.current = next;
    setSteps(next);
    lastSent.current = markup;
    onCommit(markup, { slot: stepsUseSlot(next), cmd: stepsUseCmd(next), width: stepsUseWidth(next) });
  }, [onCommit]);

  // An empty slot shaped like the template's, so a screenshot the template
  // had (and that was removed or replaced) can be put back.
  const templateCaption = useMemo(
    () => templateFigureCaption(letContent(source, 'template-exploitation')),
    [source],
  );

  const updateStep = useCallback((i: number, fn: (s: ExploitStep) => ExploitStep) => {
    commit(ref.current.map((s, k) => (k === i ? fn(s) : s)));
  }, [commit]);

  const imageBlock = useCallback((a: TypstAsset, caption?: string): ImageBlock => ({
    kind: 'image',
    caption: caption ?? captionFor(a.filename),
    path: assetPath(a),
    height: fitFigureHeight(a, boxWidth),
  }), [boxWidth]);

  /** Ids of pasted links that name an image here; a notice for the rest. */
  const knownIds = useCallback((ids: string[]): TypstAsset[] => {
    const found = ids.map((id) => imagesRef.current.find((a) => a.id === id)).filter((a): a is TypstAsset => !!a);
    if (found.length < ids.length) setNotice('A pasted link points to an image that is not in this workspace (or was deleted), so it was left as text.');
    return found;
  }, []);

  const addImages = useCallback((i: number, list: TypstAsset[]) => {
    if (list.length === 0) return;
    updateStep(i, (s) => ({ ...s, blocks: [...s.blocks, ...list.map((a) => imageBlock(a))] }));
  }, [updateStep, imageBlock]);

  const onPick = useCallback((a: TypstAsset) => {
    const target = picker;
    setPicker(null);
    if (!target) return;
    if (target.block === null) { addImages(target.step, [a]); return; }
    updateStep(target.step, (s) => ({
      ...s,
      blocks: s.blocks.map((b, k) => (k === target.block && b.kind === 'image' ? imageBlock(a, b.caption) : b)),
    }));
  }, [picker, addImages, updateStep, imageBlock]);

  const isKnown = useCallback((id: string) => imagesRef.current.some((a) => a.id === id), []);

  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <FieldLabel>Exploitation steps</FieldLabel>
        <Button variant="ghost" size="xs" onClick={onShowRaw} title="Edit the exploitation as Typst markup">Edit as markup</Button>
      </div>
      {notice && (
        <Banner tone="amber" flush className="mb-2 items-center rounded" onDismiss={() => setNotice(null)}>
          <span className="text-caption">{notice}</span>
        </Banner>
      )}
      {steps.length === 0 && (
        <p className="mb-2 text-caption text-muted-foreground">No steps yet. Each step gets a title, a description, commands and screenshots.</p>
      )}
      <ol className="space-y-2">
        {steps.map((step, i) => (
          <li key={i} data-step={i + 1} className="rounded-md border border-border bg-muted/20 p-2">
            <div className="flex items-center gap-1">
              <span className="shrink-0 rounded bg-muted px-1.5 font-mono text-caption font-semibold text-foreground">{i + 1}.</span>
              <InlineInput
                value={step.title}
                label={`Step ${i + 1} title`}
                placeholder="Step title"
                onCommit={(v) => updateStep(i, (s) => ({ ...s, title: v }))}
              />
              <IconButton size="sm" label={`Move step ${i + 1} up`} title="Move step up" disabled={i === 0} onClick={() => commit(moveItem(ref.current, i, i - 1))}><ArrowUp size={12} /></IconButton>
              <IconButton size="sm" label={`Move step ${i + 1} down`} title="Move step down" disabled={i === steps.length - 1} onClick={() => commit(moveItem(ref.current, i, i + 1))}><ArrowDown size={12} /></IconButton>
              <IconButton size="sm" tone="danger" label={`Remove step ${i + 1}`} title="Remove step" onClick={() => commit(ref.current.filter((_, k) => k !== i))}><Trash2 size={12} /></IconButton>
            </div>

            <div className="mt-1.5">
              <InlineTextarea
                value={stepDescription(step)}
                label={`Step ${i + 1} description`}
                placeholder="What was done and what it showed. Paste an asset link to add its image."
                rows={2}
                onPaste={(e) => {
                  const ids = parseAssetLinkList(e.clipboardData.getData('text/plain'));
                  if (!ids) return;
                  e.preventDefault();
                  addImages(i, knownIds(ids));
                }}
                validate={(v) => (contentIsBalanced(v) ? null : UNBALANCED)}
                onCommit={(v) => {
                  // A link typed or pasted among other words becomes a figure too.
                  const { text, ids } = extractAssetLinks(v, isKnown);
                  const found = knownIds(ids);
                  updateStep(i, (s) => {
                    const next = withDescription(s, text);
                    return { ...next, blocks: [...next.blocks, ...found.map((a) => imageBlock(a))] };
                  });
                }}
              />
            </div>

            {step.blocks.map((b, k) => {
              if (k === 0 && b.kind === 'text') return null; // the description above
              const move = (dir: -1 | 1) => updateStep(i, (s) => ({ ...s, blocks: moveItem(s.blocks, k, k + dir) }));
              const remove = () => updateStep(i, (s) => ({ ...s, blocks: s.blocks.filter((_, m) => m !== k) }));
              const replace = (nb: StepBlock) => updateStep(i, (s) => ({ ...s, blocks: s.blocks.map((x, m) => (m === k ? nb : x)) }));
              const tools = (
                <div className="ml-auto flex shrink-0 items-center">
                  <IconButton size="sm" label={`Move block ${k + 1} of step ${i + 1} up`} title="Move up" disabled={k === 0 || (k === 1 && step.blocks[0]!.kind === 'text')} onClick={() => move(-1)}><ArrowUp size={11} /></IconButton>
                  <IconButton size="sm" label={`Move block ${k + 1} of step ${i + 1} down`} title="Move down" disabled={k === step.blocks.length - 1} onClick={() => move(1)}><ArrowDown size={11} /></IconButton>
                  <IconButton size="sm" tone="danger" label={`Remove block ${k + 1} of step ${i + 1}`} title="Remove" onClick={remove}><X size={11} /></IconButton>
                </div>
              );
              if (b.kind === 'cmd') return <CmdCard key={k} block={b} step={i} tools={tools} onChange={replace} />;
              if (b.kind === 'image') {
                return (
                  <ImageCard
                    key={k}
                    block={b}
                    step={i}
                    images={images}
                    boxWidth={boxWidth}
                    templateCaption={templateCaption}
                    tools={tools}
                    onChange={replace}
                    onChangeImage={() => setPicker({ step: i, block: k })}
                    onPasteIds={(ids) => {
                      const [a] = knownIds(ids);
                      if (a) replace(imageBlock(a, b.caption));
                    }}
                    onRenameAsset={onRenameAsset}
                  />
                );
              }
              return (
                <div key={k} className="mt-1.5 rounded border border-border bg-card p-1.5">
                  <div className="mb-1 flex items-center gap-1 text-micro font-bold uppercase tracking-widest text-muted-foreground">
                    <TextCursorInput size={10} /> Text
                    {tools}
                  </div>
                  <InlineTextarea
                    value={b.text}
                    label={`Step ${i + 1} text ${k + 1}`}
                    rows={2}
                    validate={(v) => (contentIsBalanced(v) ? null : UNBALANCED)}
                    onCommit={(v) => (v.trim() ? replace({ kind: 'text', text: v }) : remove())}
                  />
                </div>
              );
            })}

            <ScreenshotDrop
              step={i}
              onAdd={() => setPicker({ step: i, block: null })}
              onPasteIds={(ids) => addImages(i, knownIds(ids))}
            />
            <div className="mt-1 flex flex-wrap gap-1">
              <Button
                variant="ghost"
                size="xs"
                icon={<Code2 size={11} />}
                onClick={() => updateStep(i, (s) => ({ ...s, blocks: [...s.blocks, { kind: 'cmd', lang: 'bash', code: '' }] }))}
              >
                Add command
              </Button>
              <Button
                variant="ghost"
                size="xs"
                icon={<TextCursorInput size={11} />}
                onClick={() => updateStep(i, (s) => ({ ...s, blocks: [...s.blocks, { kind: 'text', text: ' ' }] }))}
                title="A paragraph after the commands or screenshots"
              >
                Add text
              </Button>
              <Button
                variant="ghost"
                size="xs"
                icon={<LayoutTemplate size={11} />}
                onClick={() => updateStep(i, (s) => ({ ...s, blocks: [...s.blocks, templateImageBlock(templateCaption)] }))}
                title={`Add the template's empty screenshot slot ("${templateCaption}"); pick an image for it later`}
              >
                Add template screenshot
              </Button>
            </div>
          </li>
        ))}
      </ol>
      <Button
        variant="subtle"
        size="sm"
        className="mt-2"
        icon={<Plus size={12} />}
        onClick={() => commit([...ref.current, newStep('')])}
      >
        Add step
      </Button>

      {picker && (
        <Portal>
          <Suspense fallback={null}>
            <AssetPickerDialog
              title={picker.block === null ? `Add screenshot to step ${picker.step + 1}` : `Change screenshot in step ${picker.step + 1}`}
              onPick={onPick}
              onClose={() => setPicker(null)}
            />
          </Suspense>
        </Portal>
      )}
    </div>
  );
}

function CmdCard({ block, step, tools, onChange }: {
  block: CmdBlock;
  step: number;
  tools: React.ReactNode;
  onChange: (b: CmdBlock) => void;
}) {
  // Editing regenerates the block, so it drops its original text (`raw`).
  const edit = (patch: Partial<CmdBlock>) => onChange({ kind: 'cmd', lang: block.lang, code: block.code, bare: block.bare, ...patch });
  return (
    <div className="mt-1.5 rounded border border-border bg-card p-1.5" data-block="cmd">
      <div className="mb-1 flex items-center gap-1 text-micro font-bold uppercase tracking-widest text-muted-foreground">
        <Code2 size={10} /> Command
        <InlineInput
          value={block.lang}
          label={`Step ${step + 1} command language`}
          placeholder="bash"
          mono
          list="btct-cmd-langs"
          className="ml-1 h-6 max-w-28 py-0 text-caption normal-case tracking-normal"
          onCommit={(v) => edit({ lang: v.replace(/[^A-Za-z0-9_+.#-]/g, '') })}
        />
        <datalist id="btct-cmd-langs">{LANGS.map((l) => <option key={l} value={l} />)}</datalist>
        {tools}
      </div>
      <InlineTextarea
        value={block.code}
        label={`Step ${step + 1} command`}
        placeholder="nmap -sV -p 80 10.0.0.5"
        mono
        rows={2}
        onCommit={(v) => edit({ code: v })}
      />
    </div>
  );
}

function ImageCard({ block, step, images, boxWidth, templateCaption, tools, onChange, onChangeImage, onPasteIds, onRenameAsset }: {
  block: ImageBlock;
  step: number;
  images: TypstAsset[];
  /** The figure's width at the helper's default `width:`, in points. */
  boxWidth: number;
  templateCaption: string;
  tools: React.ReactNode;
  onChange: (b: ImageBlock) => void;
  onChangeImage: () => void;
  onPasteIds: (ids: string[]) => void;
  onRenameAsset: (asset: TypstAsset, stem: string) => void;
}) {
  const asset = block.path ? images.find((a) => assetPath(a) === block.path) ?? null : null;
  const setTypstAssetCrop = useAppStore((s) => s.setTypstAssetCrop);
  const [editing, setEditing] = useState(false);
  const edit = (patch: Partial<ImageBlock>) => onChange({ kind: 'image', caption: block.caption, path: block.path, height: block.height, width: block.width ?? null, ...patch });
  // The figure's share of the text width; the helper's own when unset.
  const fraction = (block.width ? parseRatio(block.width) : null) ?? FIGURE_WIDTH_FRACTION;
  // The height that keeps the image's shape at width `f`: fitted at the
  // default width, then scaled, so a small figure is not held to the fitted
  // height's floor and squashed out of shape.
  const heightFor = (a: Parameters<typeof fitFigureHeight>[0], f: number) =>
    scaleFigureHeight(fitFigureHeight(a, boxWidth), FIGURE_WIDTH_FRACTION, f);
  // Shrink or grow the figure keeping its shape: the height follows the width.
  const resize = (f: number | null) => {
    const to = f ?? FIGURE_WIDTH_FRACTION;
    const height = asset ? heightFor(asset, to) : scaleFigureHeight(block.height, fraction, to);
    edit({ width: f === null ? null : formatRatio(f), height });
  };
  return (
    <div
      className="mt-1.5 rounded border border-border bg-card p-1.5 focus-within:border-primary"
      data-block="image"
      onPaste={(e) => {
        if ((e.target as HTMLElement).tagName === 'INPUT') return;
        const ids = parseAssetLinkList(e.clipboardData.getData('text/plain'));
        if (!ids) return;
        e.preventDefault();
        onPasteIds(ids);
      }}
    >
      <div className="mb-1 flex items-center gap-1 text-micro font-bold uppercase tracking-widest text-muted-foreground">
        <ImagePlus size={10} /> Screenshot
        {block.height && <span className="font-mono normal-case tracking-normal">{block.height}</span>}
        {block.width && <span className="font-mono normal-case tracking-normal">· {block.width} wide</span>}
        {tools}
      </div>
      <div className="flex gap-2">
        <button
          type="button"
          onClick={onChangeImage}
          title={block.path ? `${block.path}: click to pick another image, or paste a link here` : 'Empty slot: click to pick an image'}
          className="h-16 w-24 shrink-0 overflow-hidden rounded border border-border bg-muted/40"
        >
          {asset ? <Thumb asset={asset} /> : (
            <span className="flex h-full items-center justify-center px-1 text-center text-micro text-muted-foreground">
              {block.path ? 'not in assets' : 'empty slot'}
            </span>
          )}
        </button>
        <div className="min-w-0 flex-1 space-y-1">
          <InlineInput value={block.caption} label={`Step ${step + 1} screenshot caption`} placeholder="Figure caption" onCommit={(v) => edit({ caption: v })} />
          <div className="flex flex-wrap items-center gap-1">
            <Button variant="ghost" size="xs" icon={<Replace size={11} />} onClick={onChangeImage}>Change</Button>
            {asset && <Button variant="ghost" size="xs" icon={<Pencil size={11} />} onClick={() => setEditing(true)} title="Crop or redact this image (applies wherever it is used)">Crop / redact</Button>}
            {block.path && (
              <Button
                variant="ghost"
                size="xs"
                icon={<ImageOff size={11} />}
                onClick={() => edit({ path: null, height: null, width: null, caption: block.caption || templateCaption })}
                title="Take the image out and leave the template's empty screenshot slot"
              >
                Back to placeholder
              </Button>
            )}
            <label className="ml-auto flex items-center gap-1 text-micro text-muted-foreground" title="Shrink or grow the figure; its height follows, so it keeps its shape">
              Size
              <Select
                aria-label={`Step ${step + 1} screenshot size`}
                value={block.width ? String(fraction) : ''}
                onChange={(e) => resize(e.target.value === '' ? null : Number(e.target.value))}
                className="h-6 py-0 text-caption"
              >
                <option value="">Default ({formatRatio(FIGURE_WIDTH_FRACTION)})</option>
                {FIGURE_SIZES.map((f) => <option key={f} value={String(f)}>{formatRatio(f)}</option>)}
                {block.width && !FIGURE_SIZES.includes(fraction) && <option value={String(fraction)}>{formatRatio(fraction)}</option>}
              </Select>
            </label>
          </div>
        </div>
      </div>
      {editing && asset && (
        <Portal>
          <Suspense fallback={null}>
            <ImageEditorDialog
              asset={asset}
              onApply={(crop: CropRect | null, blurs: BlurRegion[] | null) => {
                void setTypstAssetCrop(asset.id, crop, blurs);
                setEditing(false);
                // Re-fit the figure to the new crop's shape at its own width.
                const h = heightFor({ ...asset, crop }, fraction);
                if (h !== block.height) edit({ height: h });
              }}
              onRename={(stem) => onRenameAsset(asset, stem)}
              onClose={() => setEditing(false)}
            />
          </Suspense>
        </Portal>
      )}
    </div>
  );
}

const Thumb = memo(function Thumb({ asset }: { asset: TypstAsset }) {
  const { url, error } = useAssetPreview(asset, true);
  if (error) return <span className="flex h-full items-center justify-center text-micro text-status-red">missing</span>;
  if (!url) return <span className="block h-full w-full animate-pulse bg-muted" />;
  return <img src={url} alt={asset.filename} className="h-full w-full object-contain" />;
});

/** The step's screenshot slot: click to pick, or focus it and paste a link. */
function ScreenshotDrop({ step, onAdd, onPasteIds }: {
  step: number;
  onAdd: () => void;
  onPasteIds: (ids: string[]) => void;
}) {
  return (
    <div
      role="group"
      aria-label={`Screenshot slot for step ${step + 1}`}
      tabIndex={0}
      data-screenshot-slot={step + 1}
      onPaste={(e) => {
        const ids = parseAssetLinkList(e.clipboardData.getData('text/plain'));
        if (!ids) return;
        e.preventDefault();
        onPasteIds(ids);
      }}
      onKeyDown={(e) => { if (e.key === 'Enter' && e.target === e.currentTarget) { e.preventDefault(); onAdd(); } }}
      className="mt-1.5 flex items-center gap-2 rounded border border-dashed border-border px-2 py-1.5 text-caption text-muted-foreground outline-none focus:border-primary focus:bg-primary/5"
    >
      <Button variant="outline" size="xs" icon={<ImagePlus size={11} />} onClick={onAdd}>
        Add screenshot
      </Button>
      <span className="flex min-w-0 items-center gap-1">
        <Link2 size={11} className="shrink-0" /> <span className="truncate">or click here and paste an asset link</span>
      </span>
    </div>
  );
}

export function strOf(f: { value: FieldValue | null }): string {
  return typeof f.value === 'string' ? f.value : '';
}
