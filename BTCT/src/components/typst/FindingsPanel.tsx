// ─────────────────────────────────────────────────────────────────────────
// Findings mode for the Report tab.
//
// A rail that lists the report's finding blocks grouped by severity, with a
// team-shared status tag per finding and filters over status and severity.
// Selecting a finding opens a structured form that writes its fields back to
// the Typst source as minimal edits, spotlights the block in the code and
// jumps the preview to it. Add inserts one blank block (status Blank, every
// field empty) at the end of a severity section. There is no pre-written text.
// Copy finding puts one block on the clipboard (lib/typst-finding-copy) and
// Paste finding inserts it into this workspace's report with a new id,
// copying the screenshots it names from the workspace it came from.
//
// The form is drawn from lib/typst-finding-schema.ts and the report's own
// `#let finding` signature: a schema argument the definition does not
// declare is hidden, a parameter only the definition knows gets a generic
// editor, and an argument the definition does not take is listed as unused.
//
// All of this is lazy-loaded with the rest of the Report tab (invariant #17):
// this file lives under components/typst/ and every Typst import it makes is
// a lib/typst-* module or this folder.
// ─────────────────────────────────────────────────────────────────────────

import { useMemo, useState, useCallback, useEffect, useRef, memo } from 'react';
import {
  ChevronRight, ChevronDown, Plus, Trash2, Code2, X, Search,
  ListFilter, CircleCheck, CircleDashed, PencilLine, Circle, Crosshair, Lock,
  Copy, ClipboardPaste,
} from 'lucide-react';
import { useAppStore } from '@/stores';
import { typstAssetRepo } from '@/db/asset-repo';
import { fetchAssetBytes, fetchAssetBytesUncached } from '@/lib/assets';
import { copyText } from '@/lib/clipboard';
import { Dialog } from '@/components/ui/Dialog';
import { Textarea } from '@/components/ui/Field';
import { Button, IconButton, ToggleChip } from '@/components/ui/Button';
import { Input, FieldLabel, Checkbox } from '@/components/ui/Field';
import { Badge } from '@/components/ui/Badge';
import { Banner } from '@/components/ui/Banner';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { cn } from '@/lib/utils';
import {
  findFindings,
  locateFinding,
  readFindingFields,
  setFindingStatus,
  ensureFindingMarker,
  insertFinding,
  removeFinding,
  blankFinding,
  ensureFindingHelper,
  hasEndOfBlock,
  matchesFilter,
  newFindingId,
  UI_SEVERITIES,
  displaySeverity,
  liftFinding,
  movesOnSeverityChange,
  setFindingArg,
  STATUSES,
  SEVERITY_LABEL,
  STATUS_LABEL,
  encodeField,
  argIndent,
  findingArgRaw,
  ensureCmdHelper,
  isNoSeverity,
  levelLiteral,
  findingAcceptsNoSeverity,
  allowNoSeverity,
  type SeverityPick,
  type FieldKind,
  type FindingBlock,
  type Severity,
  type UiSeverity,
  type FindingStatus,
  type FindingFilter,
  type ScopeRow,
  type FieldValue,
  type DecodedField,
} from '@/lib/typst-findings';
import { ensureHelper, ensureHelperWidth } from '@/lib/typst-placeholders';
import {
  findingFormPlan,
  parseFindingSignature,
  type FindingArgSpec,
  type GenericField,
} from '@/lib/typst-finding-schema';
import {
  assetFilesIn,
  findingCopyPayload,
  parseFindingPayload,
  pasteFindings,
  planAssetCopies,
  rewriteAssetPaths,
  type PasteResult,
} from '@/lib/typst-finding-copy';
import { findingSelectEffects, findingTarget, type FindingTarget } from '@/lib/finding-jump';
import type { TypstAsset } from '@/types';
import {
  ArrayField,
  ContentField,
  Expression,
  ExploitationField,
  NumberField,
  RemediationField,
  ScopeField,
  TextField,
  strOf,
  type StepNeeds,
} from './FindingFormFields';

/**
 * The rail's "Tinted section" look (BTCT Theme Studio, variant B): each
 * severity section sits on a tint of the CPTC report's finding-bar colour,
 * with a stripe, a solid badge (white bold text on `--sev-*-solid`, the
 * report colour darkened where white needs it) and a coloured chevron and
 * count on its header. Every colour is a token (src/themes/tokens.css, `--sev-*`),
 * re-mixed per palette; tokens.test pins the contrast. Literal class strings
 * so Tailwind's scanner keeps them. `none` (no severity) stays neutral.
 */
interface SevClasses {
  stripe: string;
  badge: string;
  ink: string;
  muted: string;
  head: string;
  row: string;
  hover: string;
  pillHover: string;
  dot: string;
  /** A pressed severity chip in the form: the badge's solid fill. */
  chip: string;
}
const SEV_CLASS: Record<UiSeverity | 'none', SevClasses> = {
  critical: {
    stripe: 'bg-sev-critical', badge: 'bg-sev-critical-solid font-bold text-sev-critical-fg', ink: 'text-sev-critical-ink',
    muted: 'text-sev-critical-muted', head: 'bg-sev-critical-head', row: 'bg-sev-critical-row',
    hover: 'hover:bg-sev-critical-hover', pillHover: 'hover:bg-sev-critical-head', dot: 'bg-sev-critical',
    chip: 'border-sev-critical-solid bg-sev-critical-solid text-sev-critical-fg',
  },
  high: {
    stripe: 'bg-sev-high', badge: 'bg-sev-high-solid font-bold text-sev-high-fg', ink: 'text-sev-high-ink',
    muted: 'text-sev-high-muted', head: 'bg-sev-high-head', row: 'bg-sev-high-row',
    hover: 'hover:bg-sev-high-hover', pillHover: 'hover:bg-sev-high-head', dot: 'bg-sev-high',
    chip: 'border-sev-high-solid bg-sev-high-solid text-sev-high-fg',
  },
  medium: {
    stripe: 'bg-sev-medium', badge: 'bg-sev-medium-solid font-bold text-sev-medium-fg', ink: 'text-sev-medium-ink',
    muted: 'text-sev-medium-muted', head: 'bg-sev-medium-head', row: 'bg-sev-medium-row',
    hover: 'hover:bg-sev-medium-hover', pillHover: 'hover:bg-sev-medium-head', dot: 'bg-sev-medium',
    chip: 'border-sev-medium-solid bg-sev-medium-solid text-sev-medium-fg',
  },
  low: {
    stripe: 'bg-sev-low', badge: 'bg-sev-low-solid font-bold text-sev-low-fg', ink: 'text-sev-low-ink',
    muted: 'text-sev-low-muted', head: 'bg-sev-low-head', row: 'bg-sev-low-row',
    hover: 'hover:bg-sev-low-hover', pillHover: 'hover:bg-sev-low-head', dot: 'bg-sev-low',
    chip: 'border-sev-low-solid bg-sev-low-solid text-sev-low-fg',
  },
  none: {
    stripe: '', badge: 'bg-muted font-semibold text-foreground', ink: 'text-muted-foreground',
    muted: 'text-muted-foreground', head: 'bg-card', row: 'bg-card',
    hover: 'hover:bg-accent', pillHover: 'hover:bg-accent', dot: 'bg-muted-foreground', chip: '',
  },
};

/** The rail's groups and severity filter chips: the four severities, then No severity. */
const groupsOrder: (UiSeverity | 'none')[] = [...UI_SEVERITIES, 'none'];

const STATUS_ICON: Record<FindingStatus, typeof Circle> = {
  blank: CircleDashed,
  'needs-work': Circle,
  written: PencilLine,
  completed: CircleCheck,
};

// Literal class strings so Tailwind's JIT keeps them (no dynamic names).
const STATUS_ICON_CLASS: Record<FindingStatus, string> = {
  blank: 'text-muted-foreground',
  'needs-work': 'text-status-amber',
  written: 'text-status-blue',
  completed: 'text-status-green',
};
const STATUS_PILL_ON: Record<FindingStatus, string> = {
  blank: 'bg-muted text-foreground ring-1 ring-inset ring-border',
  'needs-work': 'bg-status-amber/20 text-foreground ring-1 ring-inset ring-border',
  written: 'bg-status-blue/20 text-foreground ring-1 ring-inset ring-border',
  completed: 'bg-status-green/20 text-foreground ring-1 ring-inset ring-border',
};

export interface FindingsPanelProps {
  /** A 300 ms-settled mirror of the report source (parsing is cosmetic). */
  source: string;
  /** Rewrite the LIVE Y.Text through a function of its current text (invariant 3b). */
  applySource: (compute: (current: string) => string) => void;
  /** Spotlight the block at a source range in the editor, or clear it. */
  onFocus: (range: { from: number; to: number } | null) => void;
  /** Bring the block into view in the preview and outline it (lib/finding-jump). */
  onRevealPreview: (target: FindingTarget) => void;
  /**
   * This operator's preview lock (invariant 34). Read when a finding is
   * selected: locked, the selection leaves the code editor alone.
   */
  previewLocked: boolean;
  /** Leave Findings mode (Escape in the list). */
  onExit: () => void;
  /** Rename an asset and repoint the report at its new path (the Crop / redact window's rename). */
  onRenameAsset: (asset: TypstAsset, stem: string) => void;
}

/** Document-order ref that survives a reparse: by id, else by index. */
interface Selection {
  id: string | null;
  index: number;
  /**
   * Whether the code editor follows this selection (spotlight and scroll).
   * Decided when the finding is selected, from the preview lock, so flipping
   * the lock with a finding open applies to the next selection.
   */
  showCode: boolean;
}

export const FindingsPanel = memo(function FindingsPanel({
  source,
  applySource,
  onFocus,
  onRevealPreview,
  onExit,
  onRenameAsset,
  previewLocked,
}: FindingsPanelProps) {
  const findings = useMemo(() => findFindings(source), [source]);

  const [statuses, setStatuses] = useState<Set<FindingStatus>>(new Set());
  const [severities, setSeverities] = useState<Set<UiSeverity | 'none'>>(new Set());
  const [query, setQuery] = useState('');
  const [collapsed, setCollapsed] = useState<Set<UiSeverity | 'none'>>(new Set());
  const [selected, setSelected] = useState<Selection | null>(null);
  // The header's Add opens a row of the four severities to pick from.
  const [addOpen, setAddOpen] = useState(false);
  // Focus the title of the block just added, once its form opens.
  const [focusTitle, setFocusTitle] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<Omit<Selection, 'showCode'> | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // Paste finding's window, or the copied text shown for a manual copy.
  const [clip, setClip] = useState<{ mode: 'paste' } | { mode: 'copy'; text: string } | null>(null);
  const [pasting, setPasting] = useState(false);
  const sourceRef = useRef(source);
  sourceRef.current = source;

  const filter: FindingFilter = useMemo(
    () => ({ statuses, severities, query }),
    [statuses, severities, query],
  );

  // The selected block, re-resolved against the current (settled) source.
  const current = useMemo(() => {
    if (!selected) return null;
    return locateFinding(source, selected);
  }, [source, selected]);

  // Keep the code spotlight in step with the selection, when the selection
  // was made with the preview unlocked (or Show in code was pressed).
  const showCode = selected?.showCode ?? false;
  useEffect(() => {
    if (current && showCode) onFocus({ from: current.start, to: current.end });
    else onFocus(null);
    return () => { /* cleared on unmount by the parent */ };
  }, [current, showCode, onFocus]);

  // Read at selection time only, through a ref, so a lock flipped while a
  // finding is open does not re-run the spotlight effect.
  const lockedRef = useRef(previewLocked);
  lockedRef.current = previewLocked;
  const findingsRef = useRef(findings);
  findingsRef.current = findings;
  const jumpTo = useCallback((f: FindingBlock) => {
    onRevealPreview(findingTarget(findingsRef.current.map((x) => x.title), f.index));
  }, [onRevealPreview]);

  const select = useCallback((f: FindingBlock) => {
    const effects = findingSelectEffects(lockedRef.current);
    setSelected({ id: f.id, index: f.index, showCode: effects.spotlightCode });
    if (effects.jumpPreview) jumpTo(f);
  }, [jumpTo]);

  const back = useCallback(() => {
    setSelected(null);
    onFocus(null);
  }, [onFocus]);

  // Escape, only while focus is inside this rail (so the editor's keys and
  // the preview's find bar keep their own Escape): leave the form, else
  // leave Findings mode. A dialog on top gets it first.
  const onKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key !== 'Escape' || e.defaultPrevented) return;
    if (document.querySelector('[aria-modal="true"]')) return;
    e.preventDefault();
    e.stopPropagation();
    if (selected) back();
    else onExit();
  }, [selected, back, onExit]);

  const retag = useCallback((f: FindingBlock, status: FindingStatus) => {
    applySource((src) => {
      const live = locateFinding(src, { id: f.id, index: f.index });
      if (!live) return src;
      return setFindingStatus(src, live, status).source;
    });
  }, [applySource]);

  const insertBlank = useCallback((severity: SeverityPick) => {
    // A report whose own #finding can't draw `level: none` (CPTC's) is taught
    // to first, the same one-line change the form offers: picking No severity
    // here is the request. When it can't be taught, nothing is added.
    if (severity === null) {
      const helped = ensureFindingHelper(source).source;
      if (!findingAcceptsNoSeverity(helped) && allowNoSeverity(helped) === null) {
        setAddOpen(false);
        setNotice("This report's #finding needs a level, so a finding with no severity can't be added. Add a branch for level == none to its definition to allow it.");
        return;
      }
    }
    let newId = '';
    applySource((src) => {
      let next = ensureFindingHelper(src).source;
      if (severity === null) next = allowNoSeverity(next) ?? next;
      newId = newFindingId();
      // Only the arguments the report's own #finding declares are written.
      const signature = parseFindingSignature(next);
      return insertFinding(next, blankFinding(severity, { id: newId, endOfBlock: hasEndOfBlock(next), signature, pagebreak: true }), severity);
    });
    setAddOpen(false);
    setFocusTitle(true);
    // Open its form once the settled source has the new block.
    const show = findingSelectEffects(lockedRef.current).spotlightCode;
    setTimeout(() => setSelected({ id: newId, index: -1, showCode: show }), 350);
  }, [applySource, source]);

  // Change a finding's severity. In a report organised by severity sections
  // the block moves to the matching section as two minimal deltas (cut, then
  // insert); otherwise only its `level` changes, in place.
  const changeSeverity = useCallback((f: FindingBlock, severity: UiSeverity | null) => {
    if (severity === null ? f.severity === null && isNoSeverity(source, f) : f.severity === severity) return;
    let text: string | null = null;
    let id = f.id;
    applySource((src) => {
      const live = locateFinding(src, { id: f.id, index: f.index });
      if (!live) return src;
      if (!movesOnSeverityChange(src)) {
        const marked = ensureFindingMarker(src, live);
        id = marked.id;
        const again = locateFinding(marked.source, { id: marked.id, index: live.index });
        return again ? setFindingArg(marked.source, again, 'level', levelLiteral(severity)) : src;
      }
      const lifted = liftFinding(src, live, severity);
      id = lifted.id;
      text = lifted.text;
      return lifted.text === null ? src : lifted.source;
    });
    if (text !== null) {
      const block: string = text;
      const pick: SeverityPick = severity;
      applySource((src) => insertFinding(src, block, pick));
      setNotice(severity === null ? 'Moved to the end of the findings, after the severity sections.' : `Moved to the ${SEVERITY_LABEL[severity]} section.`);
    }
    setSelected((prev) => ({ id, index: f.index, showCode: prev?.showCode ?? false }));
  }, [applySource, source]);

  const doDelete = useCallback((sel: Omit<Selection, 'showCode'>) => {
    applySource((src) => {
      const live = locateFinding(src, sel);
      if (!live) return src;
      return removeFinding(src, live);
    });
    setConfirmDelete(null);
    if (selected && selected.id === sel.id) back();
  }, [applySource, selected, back]);

  // Copy one block, with the header that lets a paste find its screenshots.
  // copyText works over plain http (a hidden textarea in the click's task);
  // when even that fails the text is shown for a manual copy.
  const copyFinding = useCallback((f: FindingBlock) => {
    const text = findingCopyPayload(sourceRef.current, f, useAppStore.getState().activeWorkspaceId);
    void copyText(text).then((ok) => {
      if (ok) setNotice(`Copied "${f.title || 'Untitled finding'}". Paste it with Paste in the Findings rail of any workspace, or as text into any Typst file.`);
      else setClip({ mode: 'copy', text });
    });
  }, []);

  // Paste copied block text into this workspace's report. Screenshots the
  // block names that this workspace lacks are copied from the source
  // workspace first (bytes uploaded again, crop and blur kept as metadata,
  // so a redaction stays removable), with a renamed file and rewritten path
  // when the name is taken by a different image here.
  const pasteText = useCallback(async (text: string): Promise<boolean> => {
    const payload = parseFindingPayload(text);
    if (!payload) {
      setNotice('That text holds no complete #finding(...) block. Use Copy finding on a finding first.');
      return false;
    }
    // The No severity rule first, against the settled source, so a refused
    // paste copies no images.
    const dry: PasteResult = pasteFindings(sourceRef.current, payload.blocks);
    if (!dry.ok) {
      setNotice(dry.reason === 'no-severity'
        ? "This finding has no severity, and this report's #finding needs a level, so it can't be pasted here. Add a branch for level == none to its definition, or give the finding a severity first."
        : 'That text holds no complete #finding(...) block.');
      return false;
    }
    const store = useAppStore.getState();
    const targetWs = store.activeWorkspaceId;
    if (!targetWs) return false;
    setPasting(true);
    const copied: string[] = [];
    const missing: string[] = [];
    const renames = new Map<string, string>();
    try {
      const files = [...new Set(payload.blocks.flatMap(assetFilesIn))];
      const cross = payload.workspaceId !== null && payload.workspaceId !== targetWs;
      const sourceAssets = cross && files.length > 0 ? await typstAssetRepo.getByWorkspace(payload.workspaceId!) : [];
      const targetAssets = store.typstAssets;
      // A target image counts as the same picture when its bytes and framing
      // match (whatever its name), so pasting the same finding twice reuses
      // the first paste's copy instead of making another.
      const identicalTo = new Map<string, string>();
      for (const file of files) {
        const a = sourceAssets.find((x) => x.filename.toLowerCase() === file.toLowerCase() && !x.deletedAt);
        if (!a) continue;
        const framing = JSON.stringify([a.crop ?? null, a.blurs ?? null]);
        for (const b of targetAssets) {
          if (b.deletedAt || b.kind !== 'image' || b.size !== a.size || b.mime !== a.mime) continue;
          if (JSON.stringify([b.crop ?? null, b.blurs ?? null]) !== framing) continue;
          try {
            const [x, y] = await Promise.all([fetchAssetBytes(a.id), fetchAssetBytes(b.id)]);
            if (x.length === y.length && x.every((v, i) => v === y[i])) { identicalTo.set(a.id, b.filename); break; }
          } catch { /* unreadable: copy it again */ }
        }
      }
      const plan = planAssetCopies(files, {
        sourceWorkspaceId: payload.workspaceId,
        targetWorkspaceId: targetWs,
        source: sourceAssets,
        target: targetAssets,
        identical: (id) => identicalTo.get(id) ?? null,
      });
      for (const p of plan) {
        if (p.action === 'missing') { missing.push(p.file); continue; }
        if (p.action === 'keep') { if (p.as) renames.set(p.file, p.as); continue; }
        const from = sourceAssets.find((x) => x.id === p.sourceId)!;
        try {
          const bytes = await fetchAssetBytesUncached(from.id);
          const file = new File([bytes as BlobPart], from.filename, { type: from.mime });
          const added = await useAppStore.getState().addTypstAsset(file, 'image');
          if (from.crop || (from.blurs && from.blurs.length > 0)) {
            await useAppStore.getState().setTypstAssetCrop(added.id, from.crop ?? null, from.blurs ?? null);
          }
          if (added.filename !== p.file) renames.set(p.file, added.filename);
          copied.push(added.filename);
        } catch {
          missing.push(p.file);
        }
      }
    } finally {
      setPasting(false);
    }
    const blocks = payload.blocks.map((b) => rewriteAssetPaths(b, renames));
    let result: PasteResult | null = null;
    applySource((current) => {
      const r = pasteFindings(current, blocks);
      result = r;
      return r.ok ? r.source : current;
    });
    const done: PasteResult | null = result;
    if (!done || !(done as PasteResult).ok) {
      setNotice("The report changed while pasting and the finding couldn't be inserted. Try again.");
      return false;
    }
    const ok = done as Extract<PasteResult, { ok: true }>;
    const parts = [ok.ids.length === 1
      ? `Pasted "${ok.titles[0] || 'Untitled finding'}" as a new finding (${ok.ids[0]}).`
      : `Pasted ${ok.ids.length} findings.`];
    if (copied.length > 0) parts.push(`Copied ${copied.length} screenshot${copied.length === 1 ? '' : 's'} into this workspace: ${copied.join(', ')}.`);
    if (missing.length > 0) parts.push(`Not found, so not copied: ${missing.join(', ')}. The paths are kept; add those images here.`);
    setNotice(parts.join(' '));
    const show = findingSelectEffects(lockedRef.current).spotlightCode;
    const first = ok.ids[0]!;
    setTimeout(() => setSelected({ id: first, index: -1, showCode: show }), 350);
    return true;
  }, [applySource]);

  // A paste while the rail itself has focus (not one of its inputs).
  const onRailPaste = useCallback((e: React.ClipboardEvent) => {
    const el = e.target as HTMLElement;
    if (el.closest('input, textarea, [contenteditable="true"], .cm-editor')) return;
    const text = e.clipboardData.getData('text/plain');
    if (!parseFindingPayload(text)) return;
    e.preventDefault();
    void pasteText(text);
  }, [pasteText]);

  const clipDialog = clip && (
    <FindingClipboardDialog
      mode={clip.mode}
      text={clip.mode === 'copy' ? clip.text : ''}
      busy={pasting}
      onPaste={async (t) => { if (await pasteText(t)) setClip(null); }}
      onClose={() => setClip(null)}
    />
  );

  const total = findings.length;
  const done = findings.filter((f) => f.status === 'completed').length;

  if (current) {
    return (
      <div className="h-full" onKeyDown={onKeyDown} onPaste={onRailPaste}>
        <FindingForm
          source={source}
          block={current}
          applySource={applySource}
          onBack={back}
          onShowInCode={() => {
            setSelected((prev) => (prev ? { ...prev, showCode: true } : prev));
            onFocus({ from: current.start, to: current.end });
          }}
          onShowInPreview={() => jumpTo(current)}
          codeShown={showCode}
          onRetag={(status) => retag(current, status)}
          onSeverity={(sev) => changeSeverity(current, sev)}
          focusTitle={focusTitle}
          onTitleFocused={() => setFocusTitle(false)}
          onDelete={() => setConfirmDelete({ id: current.id, index: current.index })}
          onCopy={() => copyFinding(current)}
          notice={notice}
          onDismissNotice={() => setNotice(null)}
          onRenameAsset={onRenameAsset}
        />
        {clipDialog}
        {confirmDelete && (
          <ConfirmDialog
            title="Delete this finding?"
            message="The whole block is removed from the report source. This cannot be undone from here (use Ctrl+Z in the code editor)."
            confirmLabel="Delete finding"
            destructive
            onConfirm={() => doDelete(confirmDelete)}
            onCancel={() => setConfirmDelete(null)}
          />
        )}
      </div>
    );
  }

  const visible = findings.filter((f) => matchesFilter(f, filter));
  const groups = groupsOrder;

  return (
    <div className="flex h-full flex-col bg-card outline-none" tabIndex={-1} onKeyDown={onKeyDown} onPaste={onRailPaste}>
      {/* Header */}
      <div className="flex shrink-0 items-center justify-between border-b border-border px-3 py-2">
        <div className="flex items-center gap-2">
          <ListFilter size={13} className="text-status-purple" />
          <span className="text-meta font-bold uppercase tracking-widest text-foreground">Findings</span>
          <Badge tone="neutral">{total}</Badge>
        </div>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            icon={<ClipboardPaste size={13} />}
            disabled={pasting}
            title="Paste finding: insert a finding copied with Copy finding (from this or another workspace) into its severity section, with its screenshots"
            onClick={() => setClip({ mode: 'paste' })}
          >
            Paste
          </Button>
          <Button variant="subtle" size="sm" icon={<Plus size={13} />} aria-expanded={addOpen} onClick={() => setAddOpen((o) => !o)}>
            Add
          </Button>
        </div>
      </div>
      {addOpen && (
        <div role="group" aria-label="New blank finding" className="flex shrink-0 flex-wrap items-center gap-1 border-b border-border px-3 py-2">
          <span className="mr-1 text-caption text-muted-foreground">New blank finding:</span>
          {UI_SEVERITIES.map((s) => (
            <Button key={s} variant="outline" size="sm" onClick={() => insertBlank(s)}>{SEVERITY_LABEL[s]}</Button>
          ))}
          <Button variant="outline" size="sm" onClick={() => insertBlank(null)}>No severity</Button>
        </div>
      )}

      {/* Progress */}
      <div className="shrink-0 border-b border-border px-3 py-2">
        <div className="mb-1 flex items-center justify-between text-caption text-muted-foreground">
          <span>{done} of {total} completed</span>
          <span>{total - done} to go</span>
        </div>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
          <div
            className="h-full rounded-full bg-status-green transition-all"
            style={{ width: total > 0 ? `${(done / total) * 100}%` : '0%' }}
          />
        </div>
      </div>

      {/* Filters */}
      <div className="shrink-0 space-y-2 border-b border-border px-3 py-2">
        <div className="relative">
          <Search size={12} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search findings"
            className="pl-6"
            aria-label="Search findings"
          />
        </div>
        <div>
          <FieldLabel>Status</FieldLabel>
          <div className="flex flex-wrap gap-1">
            {STATUSES.map((s) => {
              const n = findings.filter((f) => f.status === s).length;
              return (
                <ToggleChip
                  key={s}
                  pressed={statuses.has(s)}
                  onClick={() => setStatuses(toggle(statuses, s))}
                >
                  {STATUS_LABEL[s]} {n > 0 && <span className="font-mono">{n}</span>}
                </ToggleChip>
              );
            })}
          </div>
        </div>
        <div>
          <FieldLabel>Severity</FieldLabel>
          <div className="flex flex-wrap gap-1">
            {groupsOrder.map((s) => {
              const n = findings.filter((f) => (displaySeverity(f) ?? 'none') === s).length;
              return (
                <ToggleChip
                  key={s}
                  pressed={severities.has(s)}
                  onClick={() => setSeverities(toggle(severities, s))}
                >
                  <i aria-hidden className={cn('inline-block size-1.75 shrink-0 rounded-full ring-1 ring-foreground/25', SEV_CLASS[s].dot)} />
                  {s === 'none' ? 'No severity' : SEVERITY_LABEL[s]} {n > 0 && <span className="font-mono">{n}</span>}
                </ToggleChip>
              );
            })}
          </div>
        </div>
        {(statuses.size > 0 || severities.size > 0 || query) && (
          <button
            type="button"
            className="text-caption text-muted-foreground underline hover:text-foreground"
            onClick={() => { setStatuses(new Set()); setSeverities(new Set()); setQuery(''); }}
          >
            Clear filters
          </button>
        )}
      </div>

      {notice && (
        <Banner tone="neutral" flush className="shrink-0 items-center" actions={<IconButton label="Dismiss" onClick={() => setNotice(null)}><X size={13} /></IconButton>}>
          <span className="text-caption">{notice}</span>
        </Banner>
      )}

      {/* The list */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {total === 0 ? (
          <Empty
            title="No findings yet"
            body="Add a blank finding block in a severity section."
            action={<Button variant="subtle" size="sm" icon={<Plus size={13} />} onClick={() => setAddOpen(true)}>Add a finding</Button>}
          />
        ) : visible.length === 0 ? (
          <Empty
            title="Nothing matches"
            body="No findings match these filters."
            action={<Button variant="ghost" size="sm" onClick={() => { setStatuses(new Set()); setSeverities(new Set()); setQuery(''); }}>Clear filters</Button>}
          />
        ) : (
          groups.map((g) => {
            const inGroup = visible.filter((f) => (displaySeverity(f) ?? 'none') === g);
            if (inGroup.length === 0) return null;
            const isCollapsed = collapsed.has(g);
            return (
              <div key={g} data-sev={g} className={cn('border-b border-border/60', SEV_CLASS[g].row)}>
                <div className={cn('relative flex items-center gap-1 py-1.5 pr-2', g === 'none' ? 'pl-2' : 'pl-3', SEV_CLASS[g].head)}>
                  {g !== 'none' && <i aria-hidden className={cn('absolute inset-y-0 left-0 w-0.75', SEV_CLASS[g].stripe)} />}
                  <button
                    type="button"
                    className="flex flex-1 items-center gap-1.5 text-left"
                    onClick={() => setCollapsed(toggle(collapsed, g))}
                    aria-expanded={!isCollapsed}
                  >
                    {isCollapsed
                      ? <ChevronRight size={13} className={SEV_CLASS[g].ink} />
                      : <ChevronDown size={13} className={SEV_CLASS[g].ink} />}
                    <span className={cn('inline-flex shrink-0 items-center rounded px-1 py-px text-micro uppercase tracking-wide', SEV_CLASS[g].badge)}>
                      {g === 'none' ? 'No severity' : SEVERITY_LABEL[g]}
                    </span>
                    <span className={cn('text-caption font-bold', SEV_CLASS[g].ink)}>{inGroup.length}</span>
                  </button>
                  <IconButton
                    label={g === 'none' ? 'Add a finding with no severity' : `Add a ${SEVERITY_LABEL[g]} finding`}
                    size="sm"
                    className={SEV_CLASS[g].muted}
                    onClick={() => insertBlank(g === 'none' ? null : g)}
                  >
                    <Plus size={13} />
                  </IconButton>
                </div>
                {!isCollapsed && (
                  <ul>
                    {inGroup.map((f) => (
                      <FindingRow
                        key={f.id ?? `idx-${f.index}`}
                        f={f}
                        tone={SEV_CLASS[g]}
                        onSelect={() => select(f)}
                        locked={previewLocked}
                        onRetag={(s) => retag(f, s)}
                        onCopy={() => copyFinding(f)}
                      />
                    ))}
                  </ul>
                )}
              </div>
            );
          })
        )}
      </div>
      {clipDialog}
    </div>
  );
});

/**
 * Paste finding's window (a textarea the operator pastes into: over plain
 * http the page cannot read the clipboard itself), or, when a copy could not
 * reach the clipboard, the copied text selected for a manual Ctrl+C.
 */
function FindingClipboardDialog({ mode, text, busy, onPaste, onClose }: {
  mode: 'paste' | 'copy';
  text: string;
  busy: boolean;
  onPaste: (text: string) => void;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState('');
  const taRef = useRef<HTMLTextAreaElement>(null);
  useEffect(() => {
    if (mode === 'copy') taRef.current?.select();
  }, [mode]);
  const recognised = mode === 'paste' && parseFindingPayload(draft) !== null;
  return (
    <Dialog
      title={mode === 'paste' ? 'Paste finding' : 'Copy finding'}
      icon={mode === 'paste' ? <ClipboardPaste size={14} /> : <Copy size={14} />}
      onClose={onClose}
      size="lg"
      initialFocus={taRef}
      footer={
        <div className="flex w-full items-center justify-end gap-2">
          <Button variant="ghost" size="sm" onClick={onClose}>{mode === 'paste' ? 'Cancel' : 'Close'}</Button>
          {mode === 'paste' && (
            <Button variant="primary" size="sm" disabled={!recognised || busy} onClick={() => onPaste(draft)}>
              {busy ? 'Pasting…' : 'Paste finding'}
            </Button>
          )}
        </div>
      }
    >
      <div className="space-y-2">
        <p className="text-caption text-muted-foreground">
          {mode === 'paste'
            ? 'Press Ctrl+V (Cmd+V) here to paste a finding copied with Copy finding. It goes into its severity section with a new id, and screenshots it names are copied from the workspace it came from.'
            : "The browser would not put this on the clipboard. Press Ctrl+C (Cmd+C) to copy the selected text, then use Paste in another workspace's Findings rail."}
        </p>
        <Textarea
          ref={taRef}
          mono
          rows={12}
          aria-label={mode === 'paste' ? 'Finding to paste' : 'Copied finding'}
          readOnly={mode === 'copy'}
          value={mode === 'copy' ? text : draft}
          placeholder={mode === 'paste' ? '// @btct-finding-copy v=1 workspace=...\n// @finding id=... status=...\n#finding(\n  ...\n)' : undefined}
          onChange={(e) => setDraft(e.target.value)}
          onPaste={(e) => {
            if (mode !== 'paste') return;
            const pasted = e.clipboardData.getData('text/plain');
            if (!parseFindingPayload(pasted)) return;
            e.preventDefault();
            setDraft(pasted);
            onPaste(pasted);
          }}
        />
        {mode === 'paste' && draft.trim() !== '' && !recognised && (
          <p className="text-caption text-status-red">This text holds no complete #finding(...) block.</p>
        )}
      </div>
    </Dialog>
  );
}

function toggle<T>(set: Set<T>, value: T): Set<T> {
  const next = new Set(set);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next;
}

function Empty({ title, body, action }: { title: string; body: string; action: React.ReactNode }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 px-6 text-center">
      <p className="text-xs font-medium text-foreground">{title}</p>
      <p className="text-caption text-muted-foreground">{body}</p>
      {action}
    </div>
  );
}

// ── one row ──────────────────────────────────────────────────────────────

const FindingRow = memo(function FindingRow({
  f,
  tone,
  onSelect,
  onRetag,
  onCopy,
  locked,
}: {
  f: FindingBlock;
  tone: SevClasses;
  onSelect: () => void;
  onRetag: (s: FindingStatus) => void;
  onCopy: () => void;
  /** The preview lock, for the tooltip: locked, selecting leaves the code alone. */
  locked: boolean;
}) {
  const StatusIcon = STATUS_ICON[f.status];
  return (
    <li className={tone.hover}>
      <div className="group flex items-start gap-2 px-3 py-2">
        <button type="button" className="flex min-w-0 flex-1 items-start gap-2 text-left" onClick={onSelect} title={locked
          ? 'Edit this finding. The preview is locked, so only the preview jumps to it; the code stays where it is.'
          : 'Edit this finding. Jumps the preview to it and shows it in the code (lock the preview to leave the code alone).'}>
          <StatusIcon size={13} className={cn('mt-0.5 shrink-0', f.status === 'blank' ? tone.muted : STATUS_ICON_CLASS[f.status])} />
          <span className="min-w-0 flex-1">
            <span className="block truncate text-xs text-foreground">{f.title || 'Untitled finding'}</span>
            <span className={cn('mt-0.5 flex items-center gap-1.5 text-caption', tone.muted)}>
              {f.cvss && <span className="font-mono">{f.cvss}</span>}
              {f.severity === 'info' && (
                <span className="rounded bg-muted px-1 text-micro uppercase tracking-wide" title='Written as level "info" in the source; listed under Low'>info</span>
              )}
              {f.auto && <span className="italic">auto</span>}
            </span>
          </span>
        </button>
        <IconButton
          label={`Copy finding ${f.title || 'Untitled finding'}`}
          title="Copy finding: the whole block, to paste into another workspace's Findings rail (or any Typst file)"
          size="sm"
          className={cn('shrink-0 opacity-0 focus-visible:opacity-100 group-hover:opacity-100', tone.muted)}
          onClick={onCopy}
        >
          <Copy size={12} />
        </IconButton>
      </div>
      <div className="flex flex-wrap gap-1 px-3 pb-2 pl-8">
        {STATUSES.map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => onRetag(s)}
            aria-pressed={f.status === s}
            className={cn(
              'rounded px-1.5 py-0.5 text-micro font-semibold uppercase tracking-wide',
              f.status === s
                ? STATUS_PILL_ON[s]
                : cn(tone.muted, tone.pillHover),
            )}
            title={`Tag as ${STATUS_LABEL[s]}`}
          >
            {STATUS_LABEL[s]}
          </button>
        ))}
      </div>
    </li>
  );
});

// ── the form ───────────────────────────────────────────────────────────────

const FindingForm = memo(function FindingForm({
  source,
  block,
  applySource,
  onBack,
  onShowInCode,
  onShowInPreview,
  codeShown,
  onRetag,
  onSeverity,
  focusTitle,
  onTitleFocused,
  onDelete,
  onCopy,
  notice,
  onDismissNotice,
  onRenameAsset,
}: {
  source: string;
  block: FindingBlock;
  applySource: (compute: (current: string) => string) => void;
  onBack: () => void;
  onShowInCode: () => void;
  /** Jump the preview to this block again. */
  onShowInPreview: () => void;
  /** Whether the code editor follows this selection (false: opened with the preview locked). */
  codeShown: boolean;
  onRetag: (s: FindingStatus) => void;
  onSeverity: (s: UiSeverity | null) => void;
  focusTitle: boolean;
  onTitleFocused: () => void;
  onDelete: () => void;
  onCopy: () => void;
  notice: string | null;
  onDismissNotice: () => void;
  onRenameAsset: (asset: TypstAsset, stem: string) => void;
}) {
  // What to show, from the schema and the report's own #finding signature.
  const signature = useMemo(() => parseFindingSignature(source), [source]);
  const argNamesKey = block.args.map((a) => a.name ?? '').join(',');
  const plan = useMemo(
    () => findingFormPlan(signature, block.args.map((a) => a.name).filter((n): n is string => n !== null)),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [signature, argNamesKey],
  );
  const fields = useMemo(() => readFindingFields(source, block, plan.generic), [source, block, plan.generic]);
  const get = useCallback(
    (name: string): DecodedField => fields[name] ?? { value: null, expression: null },
    [fields],
  );
  const ref = { id: block.id, index: block.index };

  // Write one argument to the live source: re-find the block first, so a
  // teammate adding a finding above it does not redirect the write. `prepare`
  // runs on the whole source first (adding a helper definition the new
  // value needs), and the block is located after it.
  const writeArg = useCallback((name: string, literal: (src: string, live: FindingBlock) => string | null, prepare?: (src: string) => string) => {
    applySource((current) => {
      const src = prepare ? prepare(current) : current;
      const ensured = ensureFindingMarker(src, locateFinding(src, ref) ?? block);
      const live = locateFinding(ensured.source, { id: ensured.id, index: block.index });
      if (!live) return current;
      return setFindingArg(ensured.source, live, name, literal(ensured.source, live));
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applySource, block, ref.id, ref.index]);

  const write = useCallback((name: string, kind: FieldKind, value: FieldValue | null, prepare?: (src: string) => string) => {
    writeArg(name, (src, live) => (value === null ? null : encodeField(value, kind, argIndent(src, live))), prepare);
  }, [writeArg]);

  const writeExploitation = useCallback((markup: string, needs: StepNeeds) => {
    write('exploitation', 'content', markup, (src) => {
      let next = src;
      if (needs.width) next = ensureHelperWidth(next).source;
      else if (needs.slot) next = ensureHelper(next).source;
      if (needs.cmd) next = ensureCmdHelper(next).source;
      return next;
    });
  }, [write]);

  const severity = (get('level').value as Severity | null) ?? block.severity;
  const noSeverity = severity === null && isNoSeverity(source, block);
  // A report-defined #finding that indexes its colours by level cannot draw
  // `level: none`; say so instead of writing a value that fails to compile.
  const acceptsNone = useMemo(() => findingAcceptsNoSeverity(source), [source]);
  const canTeach = useMemo(() => !acceptsNone && allowNoSeverity(source) !== null, [acceptsNone, source]);
  const [noneHelp, setNoneHelp] = useState(false);
  const pickNone = () => {
    if (acceptsNone) { setNoneHelp(false); onSeverity(null); }
    else setNoneHelp(true);
  };
  const teachNone = () => {
    applySource((src) => allowNoSeverity(src) ?? src);
    setNoneHelp(false);
    onSeverity(null);
  };

  const showLevel = plan.known.some((f) => f.editor === 'severity');

  // One schema field, in the editor its spec names.
  const renderField = (spec: FindingArgSpec): React.ReactNode => {
    const { name } = spec;
    const field = get(name);
    switch (spec.editor) {
      case 'severity':
        return null;
      case 'text':
        return (
          <TextField
            key={name}
            label={spec.label}
            value={strOf(field)}
            mono={spec.mono}
            onCommit={(v) => write(name, 'string', v)}
            autoFocus={spec.role === 'title' && focusTitle}
            onAutoFocused={spec.role === 'title' ? onTitleFocused : undefined}
          />
        );
      case 'number':
        return (
          <NumberField
            key={name}
            field={field}
            onAuto={() => writeArg(name, () => (field.value === null && field.expression === null ? null : 'auto'))}
            onCustom={(v) => write(name, 'string', v)}
          />
        );
      case 'scope':
        return (
          <ScopeField
            key={name}
            label={spec.label}
            rows={(field.value as ScopeRow[] | null) ?? []}
            expression={field.expression}
            onCommit={(rows) => write(name, 'scope', rows)}
          />
        );
      case 'checkbox':
        return <Checkbox key={name} checked={field.value === true} onChange={(v) => write(name, 'bool', v)} label={spec.label} />;
      case 'content':
        return <ContentField key={name} label={spec.label} field={field} onCommit={(v) => write(name, 'content', v)} rows={spec.rows ?? 3} />;
      case 'list':
        return (
          <ArrayField
            key={name}
            label={spec.label}
            field={field}
            onCommit={(v) => write(name, spec.kind, v)}
            placeholder={spec.placeholder}
            addLabel={spec.addLabel ?? 'Add item'}
            content={spec.kind === 'contents'}
          />
        );
      case 'exploitation':
        return <ExploitationField key={name} field={field} source={source} onCommit={writeExploitation} onRenameAsset={onRenameAsset} />;
      case 'remediation':
        return <RemediationField key={name} field={field} source={source} onCommit={(v) => write(name, 'content', v)} />;
    }
  };

  // A parameter only the report's definition knows, edited by its default's shape.
  const renderGeneric = (g: GenericField): React.ReactNode => {
    const field = get(g.name);
    if (g.kind === 'content') return <ContentField key={g.name} label={g.label} field={field} onCommit={(v) => write(g.name, 'content', v)} rows={3} />;
    if (g.kind === 'bool') return <Checkbox key={g.name} checked={field.value === true} onChange={(v) => write(g.name, 'bool', v)} label={g.label} />;
    if (g.kind === 'strings') return <ArrayField key={g.name} label={g.label} field={field} onCommit={(v) => write(g.name, 'strings', v)} addLabel="Add item" />;
    if (field.expression) {
      return (
        <div key={g.name}>
          <FieldLabel>{g.label}</FieldLabel>
          <Expression text={field.expression} onReplace={(v) => write(g.name, 'string', v)} />
        </div>
      );
    }
    return <TextField key={g.name} label={g.label} value={strOf(field)} onCommit={(v) => write(g.name, 'string', v)} />;
  };

  // Schema fields in order, two paired text fields to a row.
  const rows = useMemo(() => {
    const out: FindingArgSpec[][] = [];
    const list = plan.known.filter((f) => f.editor !== 'severity');
    for (let i = 0; i < list.length; i++) {
      const a = list[i]!;
      const b = list[i + 1];
      if (a.pair && b?.pair) { out.push([a, b]); i++; } else out.push([a]);
    }
    return out;
  }, [plan.known]);

  // Focus lands in the form when it opens (the row that was clicked is gone),
  // never in the code editor; a new block's title takes it instead.
  const rootRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (focusTitle) return;
    const el = rootRef.current;
    if (el && !el.contains(document.activeElement)) el.focus({ preventScroll: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [block.id, block.index]);

  return (
    <div ref={rootRef} tabIndex={-1} data-testid="finding-form" className="flex h-full flex-col bg-card outline-none">
      <div className="flex shrink-0 items-center justify-between border-b border-border px-2 py-1.5">
        <Button variant="ghost" size="sm" icon={<ChevronRight size={13} className="rotate-180" />} onClick={onBack}>
          All findings
        </Button>
        <div className="flex items-center gap-1">
          <IconButton label="Show in preview" title="Show in preview: scroll the preview to this block again" size="sm" onClick={onShowInPreview}><Crosshair size={13} /></IconButton>
          <IconButton label="Show in code" size="sm" onClick={onShowInCode}><Code2 size={13} /></IconButton>
          <IconButton label="Copy finding" title="Copy finding: the whole block, to paste into another workspace's Findings rail (or any Typst file)" size="sm" onClick={onCopy}><Copy size={13} /></IconButton>
          <IconButton label="Delete finding" size="sm" tone="danger" onClick={onDelete}><Trash2 size={13} /></IconButton>
        </div>
      </div>

      {notice && (
        <Banner tone="neutral" flush className="shrink-0 items-center" actions={<IconButton label="Dismiss" onClick={onDismissNotice}><X size={13} /></IconButton>}>
          <span className="text-caption">{notice}</span>
        </Banner>
      )}
      <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-3">
        {!codeShown && (
          <p data-testid="finding-lock-hint" className="flex items-center gap-1.5 text-caption text-muted-foreground">
            <Lock size={11} className="shrink-0" />
            Preview locked: only the preview jumped here, the code is left alone. Show in code opens it.
          </p>
        )}
        {/* Severity + status */}
        <div className="grid grid-cols-2 gap-2">
          {showLevel && (
          <div>
            <FieldLabel>Severity</FieldLabel>
            <div className="flex flex-wrap gap-1">
              {UI_SEVERITIES.map((s) => (
                <ToggleChip
                  key={s}
                  pressed={severity === s}
                  onClick={() => { setNoneHelp(false); onSeverity(s); }}
                  className={severity === s ? cn('font-bold', SEV_CLASS[s].chip) : undefined}
                >
                  {SEVERITY_LABEL[s]}
                </ToggleChip>
              ))}
              <ToggleChip
                pressed={noSeverity}
                onClick={pickNone}
                title={acceptsNone ? 'No severity: written as level: none, listed after Low' : "This report's #finding needs a level"}
              >
                No severity
              </ToggleChip>
            </div>
            {noneHelp && !acceptsNone && (
              <div role="note" className="mt-1 space-y-1 rounded border border-border bg-muted/50 p-2 text-caption text-muted-foreground">
                <p>This report&apos;s <code className="font-mono">#finding</code> needs a level: it looks its colours up by level, so a finding with no severity would not compile.</p>
                {canTeach ? (
                  <Button variant="outline" size="sm" onClick={teachNone}>Let #finding draw no severity</Button>
                ) : (
                  <p>Add a branch for <code className="font-mono">level == none</code> to its definition to allow it.</p>
                )}
              </div>
            )}
            {severity === 'info' && (
              <p className="mt-1 text-caption text-muted-foreground">
                Written as level &quot;info&quot; in the source and listed under Low. Pick a severity to change it.
              </p>
            )}
          </div>
          )}
          <div>
            <FieldLabel>Status</FieldLabel>
            <div className="flex flex-wrap gap-1">
              {STATUSES.map((s) => (
                <ToggleChip key={s} pressed={block.status === s} onClick={() => onRetag(s)}>
                  {STATUS_LABEL[s]}
                </ToggleChip>
              ))}
            </div>
          </div>
        </div>

        {rows.map((row) => (row.length === 2
          ? <div key={row[0]!.name} className="grid grid-cols-2 gap-2">{row.map(renderField)}</div>
          : renderField(row[0]!)))}

        {plan.generic.length > 0 && (
          <div data-testid="finding-template-fields" className="space-y-3 border-t border-border pt-3">
            <p className="text-caption text-muted-foreground">Fields this report&apos;s <code className="font-mono">#finding</code> adds:</p>
            {plan.generic.map(renderGeneric)}
          </div>
        )}

        {plan.unused.length > 0 && (
          <div data-testid="finding-unused-fields" className="space-y-1 border-t border-border pt-3">
            <FieldLabel>Unused by this template</FieldLabel>
            <p className="text-caption text-muted-foreground">
              This block passes {plan.unused.length === 1 ? 'an argument' : 'arguments'} the report&apos;s <code className="font-mono">#finding</code> does not declare. {plan.unused.length === 1 ? 'It is' : 'They are'} kept as written.
            </p>
            {plan.unused.map((name) => {
              const raw = findingArgRaw(source, block, name) ?? '';
              return (
                <code key={name} className="block overflow-x-auto whitespace-pre-wrap break-all rounded bg-muted/40 p-1.5 font-mono text-caption text-foreground">
                  {name}: {raw.length > 160 ? raw.slice(0, 160) + '…' : raw}
                </code>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
});
