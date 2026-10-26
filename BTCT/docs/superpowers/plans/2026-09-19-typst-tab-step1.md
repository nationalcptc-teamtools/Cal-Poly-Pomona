# Typst Tab, Step 1 (flag, tab on Yjs, ZIP entry, measurements) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the Typst report tab back into BTCT behind a runtime `ENABLE_TYPST` flag, stored in Yjs, so a flag-off box pays nothing but idle disk.

**Architecture:** The server reads `ENABLE_TYPST` and reports it as `features.typst` on `GET /api/settings`. The client keeps it in the theme store and renders the `typst` TabKind and its entry points only when true; the tab is a `lazy()` import, so the wasm, fonts and editor code stay in chunks nobody requests. The port is a hybrid: Yjs-wired shells (`TypstView`, `TypstEditor`) are restored from `8a549fb^`, while the pure libs, the worker compiler, the preview, the search panel and the place-screenshot dialog come from Typst Studio.

**Tech Stack:** Bun, Vite, React 19, Zustand, Yjs + `y-codemirror.next`, CodeMirror 6, `@myriaddreamin/typst.ts` 0.7.0 (wasm, in a Web Worker), Vitest.

**Spec:** `docs/superpowers/specs/2026-09-18-typst-tab-design.md`

## Global Constraints

- `TS` below means `C:/Users/rober/Desktop/university-tools/advanced-typst-editor` (Git Bash: `/c/Users/rober/Desktop/university-tools/advanced-typst-editor`). `OLD` means git revision `8a549fb^` in this repo.
- Never add Claude as author or co-author to any commit. No `Co-Authored-By` trailer, no "Generated with" line.
- No em dashes anywhere you write (docs, comments, commit messages). Check with `grep -c "$(printf '\342\200\224')" <file>`; the only allowed hit in the repo is the style table in `CLAUDE.md`.
- The compile gate is `bun run build` (`tsc -b && vite build`). It typechecks tests too. Two test failures are baseline on this branch; record them in Task 1 and do not count them against later tasks.
- Files are CRLF on this checkout. A Git Bash heredoc eats backslashes; write files with an editor tool, not `cat <<EOF`.
- Report source key is exactly `textKey('typst', workspaceId, 'source')`. One report per workspace.
- Programmatic `Y.Text` rewrites use `replaceYTextContent` (invariant #3b). New `Y.Text`s are created with `getOrInitYText` (invariant #1).
- Store reads use a selector or `useShallow`, never bare `useAppStore()` (invariant #8).
- No native `confirm`/`prompt`/`alert`; use `src/components/ui/ConfirmDialog.tsx` (invariant #14).
- BTCT's `src/lib/blur-math.ts`, `crop-math.ts`, `assets.ts`, `asset-folders.ts`, `pane-resize.ts` and `src/components/assets/FigureViewport.tsx` win over Typst Studio's copies. Do not overwrite them.
- Transfer between machines is server backup + restore, not the workspace ZIP. The ZIP does not carry asset records or bytes; this plan does not change that.
- Every task ends by updating `README.md` and `CLAUDE.md` for what it changed, per the repo's "Keep the docs in sync" rule. Task 8 does the final pass.

## File Structure

| File | Responsibility |
|---|---|
| `server/index.mjs` (modify) | Read `ENABLE_TYPST`, add `features` to `GET /api/settings` |
| `docker-compose.yml`, `docker-compose.preview.yml` (modify) | Pass `ENABLE_TYPST` through |
| `src/lib/features.ts` (create) | Pure `resolveFeatures(payload)`; the only place that parses the flag |
| `src/stores/theme-store.ts` (modify) | Hold `features`, filled by the existing `loadTheme` fetch |
| `src/lib/typst-*.ts` (create) | Pure libs and the worker compiler, from `TS` |
| `scripts/fonts.ts` (create), `.gitignore` (modify) | Stage the 17 default faces under `public/fonts/` |
| `vite.config.ts` (modify) | `optimizeDeps.exclude`, `worker.format: 'es'` |
| `src/components/typst/*` (create) | The tab: view and editor from `OLD`, preview, search, dialog, bridge from `TS` |
| `src/components/assets/AssetsPanel.tsx` (modify) | Optional `typst` prop: insert and place actions, off by default |
| `src/types/index.ts`, `SplitContainer.tsx`, `TabBar.tsx`, `app-store.ts` (modify) | The `typst` TabKind |
| `LeftSidebar.tsx`, `CommandPalette.tsx`, `WorkspaceOverview.tsx` (modify) | Entry points, rendered only when the flag is on |
| `src/export/workspace-zip.ts`, `ExportDialog.tsx` (modify) | `report.typ` in and out of the ZIP |
| `docs/typst-tab-2026-09.md` (create) | Measured bloat budget |

---

### Task 1: The feature flag, server to store

**Files:**
- Modify: `server/index.mjs` (the `GET /api/settings` branch, near line 521)
- Modify: `docker-compose.yml`, `docker-compose.preview.yml` (the `environment:` block)
- Create: `src/lib/features.ts`
- Modify: `src/stores/theme-store.ts` (`loadTheme`, near line 134)
- Test: `src/test/features.test.ts`

**Interfaces:**
- Produces: `interface Features { typst: boolean }`, `resolveFeatures(payload: unknown): Features`, `DEFAULT_FEATURES`, all from `@/lib/features`; store field `features: Features` on `useThemeStore`, read as `useThemeStore((s) => s.features.typst)`.

- [ ] **Step 1: Record the baseline**

Run: `bun run test 2>&1 | tail -15` and `bun run build 2>&1 | tail -5`.
Write down the names of the failing tests (memory says two). Later tasks compare against this list.

- [ ] **Step 2: Write the failing test**

`src/test/features.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { resolveFeatures, DEFAULT_FEATURES } from '@/lib/features';

describe('resolveFeatures', () => {
  it('is all-off by default', () => {
    expect(DEFAULT_FEATURES).toEqual({ typst: false });
  });
  it('reads features.typst === true', () => {
    expect(resolveFeatures({ features: { typst: true } })).toEqual({ typst: true });
  });
  it('treats anything but literal true as off', () => {
    for (const bad of [undefined, null, {}, { features: null }, { features: { typst: 'true' } }, { features: { typst: 1 } }, 'x']) {
      expect(resolveFeatures(bad)).toEqual({ typst: false });
    }
  });
});
```

- [ ] **Step 3: Run it and see it fail**

Run: `bun run test -- src/test/features.test.ts`
Expected: FAIL, cannot resolve `@/lib/features`.

- [ ] **Step 4: Implement `src/lib/features.ts`**

```ts
// Server-decided feature switches, as served under `features` by
// GET /api/settings. Env-driven on the server (ENABLE_TYPST), so a small box
// cannot be switched on from the UI. Anything but a literal `true` is off.

export interface Features {
  typst: boolean;
}

export const DEFAULT_FEATURES: Features = { typst: false };

export function resolveFeatures(payload: unknown): Features {
  if (!payload || typeof payload !== 'object') return { ...DEFAULT_FEATURES };
  const f = (payload as { features?: unknown }).features;
  if (!f || typeof f !== 'object') return { ...DEFAULT_FEATURES };
  return { typst: (f as { typst?: unknown }).typst === true };
}
```

- [ ] **Step 5: Run the test, expect PASS**

Run: `bun run test -- src/test/features.test.ts`

- [ ] **Step 6: Store field**

In `src/stores/theme-store.ts`: import `{ DEFAULT_FEATURES, resolveFeatures, type Features }` from `@/lib/features`; add `features: Features;` to the state interface and `features: DEFAULT_FEATURES,` to the initial state. In `loadTheme`, change the parse and add one line:

```ts
      const data = (await res.json()) as PublicThemeSettings & PublicBlurSettings;
      get().applyServerTheme(data);
      get().applyServerBlur(data);
      set({ features: resolveFeatures(data) });
```

The `catch` branch leaves `features` at the default (off).

- [ ] **Step 7: Server**

In `server/index.mjs`, next to the other env reads at the top of the file:

```js
// Feature switch for the Typst report tab. Env only, never a setting: a small
// box must not be switchable from the UI.
const ENABLE_TYPST = process.env.ENABLE_TYPST === '1' || process.env.ENABLE_TYPST === 'true';
```

Change the route:

```js
    if (req.method === 'GET' && req.url === '/api/settings') {
      return sendJson(res, 200, { ...publicThemeSettings(), features: { typst: ENABLE_TYPST } });
    }
```

`features` is not written to `settingsPublic`; it cannot change while the process runs.

In both compose files add under `environment:`:

```yaml
      # "1" turns on the Typst report tab. Leave off on a small box.
      ENABLE_TYPST: "${ENABLE_TYPST:-0}"
```

`docker-compose.yml` has an uncommitted port change by the user (`4747:8080`). Stage with `git add -p docker-compose.yml` and take only the `ENABLE_TYPST` hunk.

- [ ] **Step 8: Verify**

Run: `bun build ./server/index.mjs --target=bun --external ws --external yjs --external y-websocket --external y-leveldb --external lib0 --external y-protocols --outfile "$TEMP/x.js"` (expect no error), then `bun run build`.

- [ ] **Step 9: Docs and commit**

README: env var table row for `ENABLE_TYPST`, and `features` in the `GET /api/settings` API row. CLAUDE.md: one sentence in the `theme-store.ts` bullet that the same fetch carries `features`.

```bash
git add src/lib/features.ts src/test/features.test.ts src/stores/theme-store.ts server/index.mjs docker-compose.preview.yml README.md CLAUDE.md
git add -p docker-compose.yml
git commit -m "Add ENABLE_TYPST feature flag, exposed as features.typst"
```

---

### Task 2: Dependencies, fonts and Vite config

**Files:**
- Modify: `package.json`, `bun.lock`, `vite.config.ts`, `.gitignore`, `Dockerfile`
- Create: `scripts/fonts.ts`, `src/lib/typst-default-fonts.ts`

**Interfaces:**
- Produces: `DEFAULT_FONT_FILES: string[]`, `DEFAULT_FONT_URL_PREFIX = '/fonts/'` from `@/lib/typst-default-fonts`; fonts on disk under `public/fonts/`.

- [ ] **Step 1: Install the three packages, pinned as Typst Studio pins them**

```bash
bun add @myriaddreamin/typst.ts@0.7.0 @myriaddreamin/typst-ts-web-compiler@0.7.0 @myriaddreamin/typst-ts-renderer@0.7.0
```

- [ ] **Step 2: Copy the font list and the staging script**

```bash
cp "$TS/src/lib/typst-default-fonts.ts" src/lib/typst-default-fonts.ts
mkdir -p scripts && cp "$TS/scripts/fonts.ts" scripts/fonts.ts
```

Edit `scripts/fonts.ts`: delete the `LOCAL` constant and the two lines that use it (`const local = ...` and the `if (fs.existsSync(local))` line). It pointed at a folder on one machine. The CDN fetch with the skip-if-present check stays.

- [ ] **Step 3: Ignore the staged fonts, add the script**

Append `public/fonts/` to `.gitignore`. In `package.json` scripts add `"fonts": "bun scripts/fonts.ts"`. Run `bun run fonts`; expect `fonts: 17 files in ...public/fonts`.

- [ ] **Step 4: Vite**

In `vite.config.ts` add to the top-level config object:

```ts
  // The typst.ts packages ship wasm-pack shims + large wasm that esbuild's dep
  // pre-bundler mishandles; they are loaded lazily via dynamic import + `?url`.
  optimizeDeps: { exclude: ['@myriaddreamin/typst.ts', '@myriaddreamin/typst-ts-web-compiler', '@myriaddreamin/typst-ts-renderer'] },
  // The compiler worker uses dynamic imports; Vite's default iife worker
  // format cannot code-split.
  worker: { format: 'es' },
```

If `optimizeDeps` or `worker` already exists, merge instead of duplicating the key.

- [ ] **Step 5: Dockerfile**

In the client-build stage, `scripts/` must exist before the build and fonts must be staged. After `COPY src ./src` add `COPY scripts ./scripts`, and change `RUN bun run build` to `RUN bun scripts/fonts.ts && bun run build`. The existing gzip line already covers `*.wasm`. Font files (`.otf`, `.ttf`) are not in that `find`; add `-o -name '*.otf' -o -name '*.ttf'` to it, and confirm `tryServeStatic`'s MIME table in `server/index.mjs` has `.otf` (`font/otf`) and `.ttf` (`font/ttf`); add them if absent. `.wasm` must stay.

- [ ] **Step 6: Verify and commit**

Run: `bun run build`. Expected: passes; `dist/fonts/` has 17 files; no wasm in `dist/assets/` yet (nothing imports the compiler).

```bash
git add package.json bun.lock vite.config.ts .gitignore Dockerfile scripts/fonts.ts src/lib/typst-default-fonts.ts server/index.mjs
git commit -m "Add typst.ts packages, font staging and worker build config"
```

---

### Task 3: Pure Typst libs and their tests

**Files:**
- Create (copied from `TS/src/lib/`): `typst-placeholders.ts`, `typst-source-map.ts`, `typst-search.ts`, `typst-pages.ts`, `typst-geometry.ts`, `typst-language.ts`
- Create (copied from `TS/src/test/`): `typst-placeholders.test.ts`, `typst-source-map.test.ts`, `typst-search.test.ts`, `typst-geometry.test.ts`, plus any `typst-pages*.test.ts` that does not render a component
- Create: `src/lib/typst-template.ts`

**Interfaces:**
- Produces: the same exports `OLD` had for placeholders, source-map, search, geometry and language (verified identical), and the new `typst-pages` API: `splitTypstPages`, `extractTextRuns`, `reconcileDefs`, `splitSharedStyle`, `SplitTypstSvg`, `TypstPageFragment`. `DEFAULT_TYPST_TEMPLATE: string` from `@/lib/typst-template`.

- [ ] **Step 1: Copy**

```bash
for f in typst-placeholders typst-source-map typst-search typst-pages typst-geometry typst-language; do cp "$TS/src/lib/$f.ts" "src/lib/$f.ts"; done
for f in typst-placeholders typst-source-map typst-search typst-geometry; do cp "$TS/src/test/$f.test.ts" "src/test/$f.test.ts"; done
ls "$TS/src/test" | grep -i pages
```

Copy each listed `typst-pages*.test.ts`. Leave `typst-preview-pages.test.tsx` for Task 5.

- [ ] **Step 2: The starter template**

`TS/src/template.ts` holds the starter document. Copy it to `src/lib/typst-template.ts` and make sure the exported name is `DEFAULT_TYPST_TEMPLATE` (that is the name `OLD`'s `TypstView` imports). If `TS` exports it under another name, rename the export in the copy, not the importers.

- [ ] **Step 3: Fix imports**

Run: `bun run build`. Any unresolved import in the copied files points at a Typst Studio module. Expected cases and their fix: `@/types` for `TypstAsset`/`CropRect` already resolves in BTCT (`src/types/index.ts`); a `FileEntry` import means the file belongs to the file-based model and should not have been copied. Nothing else is expected.

- [ ] **Step 4: Run the suites**

Run: `bun run test -- src/test/typst-placeholders.test.ts src/test/typst-source-map.test.ts src/test/typst-search.test.ts src/test/typst-geometry.test.ts`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/lib/typst-*.ts src/test/typst-*.test.ts
git commit -m "Port the pure Typst libs and their tests from Typst Studio"
```

---

### Task 4: The worker compiler

**Files:**
- Create (copied from `TS/src/lib/`): `typst-compiler.ts`, `typst-compiler.driver.ts`, `typst-compiler.worker.ts`, `typst-compiler-types.ts`
- Test (copied): `src/test/typst-compiler-client.test.ts`

**Interfaces:**
- Produces: from `@/lib/typst-compiler`, the client API the view and preview call (compile to SVG, `setTypstShadowFiles`, fonts install, `getFontInfo`, PDF export); types `TypstDiagnostic`, `TypstShadowFile`, `TypstSvgResult` from `@/lib/typst-compiler-types`. Note `getFontInfo` is synchronous in this version and was `async` in `OLD`.

- [ ] **Step 1: Copy**

```bash
for f in typst-compiler typst-compiler.driver typst-compiler.worker typst-compiler-types; do cp "$TS/src/lib/$f.ts" "src/lib/$f.ts"; done
cp "$TS/src/test/typst-compiler-client.test.ts" src/test/
```

- [ ] **Step 2: Remove Typst Studio-only imports**

Run: `grep -n -E "@/lib/perf|switchTrace|@/api/|workspace-cache" src/lib/typst-compiler*.ts`.
For each `switchTrace.mark(...)` call and its import: delete both. It is a timing probe for Typst Studio's workspace switcher and has no BTCT counterpart. Any `@/api/` or `workspace-cache` hit is a bug in this plan: stop and report it.

- [ ] **Step 3: Verify**

Run: `bun run test -- src/test/typst-compiler-client.test.ts` (expect PASS) and `bun run build`.
Expected: the build passes and `dist/assets/` still has no wasm, because nothing reachable from `main.tsx` imports the compiler yet.

- [ ] **Step 4: Commit**

```bash
git add src/lib/typst-compiler*.ts src/test/typst-compiler-client.test.ts
git commit -m "Port the Typst worker compiler"
```

---

### Task 5: The tab's components

**Files:**
- Create from `OLD`: `src/components/typst/TypstView.tsx`, `src/components/typst/TypstEditor.tsx`
- Create from `TS`: `src/components/typst/TypstPreview.tsx`, `TypstSearchPanel.tsx`, `PlaceScreenshotDialog.tsx`
- Modify: `src/components/assets/AssetsPanel.tsx`
- Test (copied): `src/test/typst-preview-pages.test.tsx`

**Interfaces:**
- Consumes: Task 3 libs, Task 4 compiler, `resolveAssetBytes(asset: TypstAsset): Promise<Uint8Array>`, `assetPath`, `fetchAssetBytes` from `@/lib/assets`; `getSharedDoc`, `getOrInitYText`, `textKey` from `@/realtime/shared-doc`; `replaceYTextContent` from `@/realtime/use-y-text`.
- Produces: `export function TypstView({ workspaceId }: { workspaceId: ID })`; from `TypstEditor.tsx`: `TypstEditor({ ytext }: { ytext: Y.Text })`, `revealTypstRange`, `getTypstCaret`, `insertAtTypstCursor`, `setTypstSearchRequest`; `AssetsPanel` gains optional prop `typst?: { onInsert: (asset: TypstAsset) => void }`.

Why the split: `TS`'s `TypstView` and `TypstEditor` are built on a file API (`useWorkspaceFile`, `DiskChangeBar`, `value`/`onChange`), while `OLD`'s are already bound to a `Y.Text` with `yCollab`, which keeps live cursors. `TypstPreview`, the search panel and the dialog have no storage dependency, so the newer copies are taken.

- [ ] **Step 1: Restore the Yjs-wired shells**

```bash
mkdir -p src/components/typst
git show 8a549fb^:src/components/typst/TypstView.tsx   > src/components/typst/TypstView.tsx
git show 8a549fb^:src/components/typst/TypstEditor.tsx > src/components/typst/TypstEditor.tsx
```

- [ ] **Step 2: Take the newer leaf components**

```bash
cp "$TS/src/components/typst/TypstPreview.tsx" "$TS/src/components/typst/TypstSearchPanel.tsx" "$TS/src/components/typst/PlaceScreenshotDialog.tsx" src/components/typst/
cp "$TS/src/test/typst-preview-pages.test.tsx" src/test/
```

- [ ] **Step 3: Repoint imports in all five files**

Apply these renames (they reflect `8a549fb`'s own renames):

| Old import | New import |
|---|---|
| `@/lib/typst-assets` | `@/lib/assets` |
| `@/db/typst-asset-repo` | `@/db/asset-repo` |
| `./TypstAssetsPanel` | `@/components/assets/AssetsPanel` (component name `AssetsPanel`) |
| `./FigureViewport` | `@/components/assets/FigureViewport` |
| `DEFAULT_TYPST_TEMPLATE` source | `@/lib/typst-template` |
| `typst-editor-bridge` functions (in the three `TS` files) | the same-named exports of `./TypstEditor` |

`TS`'s leaf components call `resolveAssetBytes(asset, workspaceId)`; BTCT's takes one argument. Drop the second argument at each call site.

- [ ] **Step 4: Match the new preview's props**

`TS`'s `TypstView` renders:

```tsx
<TypstPreview source={source} revision={assetRevision} mainPath={`/${file}`} docKey={docKey} ready={!loading && assetsReady} onRevealSource={revealSource} onRevealImage={revealImage} />
```

In the restored `TypstView`, pass `mainPath="/main.typ"`, `docKey={workspaceId}` and `ready={ytext !== null && assetsReady}`. `assetsReady` is a `useState(false)` set to `true` at the end of the view's asset-sync effect (the effect that calls `setTypstShadowFiles`), and reset to `false` when `workspaceId` changes. Replace the `separateTypstPages` import, if the restored view uses it, with `splitTypstPages`; the new preview owns page splitting, so prefer deleting the view's call over adapting it.

- [ ] **Step 5: `getFontInfo` is now synchronous**

Run: `grep -rn "getFontInfo" src/components`. Remove `await` at each call and any `async` that existed only for it.

- [ ] **Step 6: Give `AssetsPanel` its insert hook back**

`OLD`'s panel took `onInsert` and rendered an insert button per row and the `PlaceScreenshotDialog`. See exactly what was cut:

```bash
git diff 8a549fb^ 8a549fb -M -- src/components/typst/TypstAssetsPanel.tsx src/components/assets/AssetsPanel.tsx
```

Re-add those pieces behind one optional prop, `typst?: { onInsert: (asset: TypstAsset) => void }`: the insert button and the dialog render only when `typst` is set. `PlaceScreenshotDialog` is a `lazy()` import inside the panel, so the Assets Manager tab, which never passes `typst`, never loads it. `TypstView` passes `typst={{ onInsert }}`, where `onInsert` builds the `#image(...)` text the way `OLD` line 626 did and calls `insertAtTypstCursor`.

- [ ] **Step 7: Verify**

Run: `bun run build`, then `bun run test -- src/test/typst-preview-pages.test.tsx src/test/viewport-drag.test.tsx`.
Expected: build passes; both suites PASS; failures elsewhere match the Task 1 baseline. Nothing renders `TypstView` yet, so there is still no wasm in `dist/assets/`.

- [ ] **Step 8: Commit**

```bash
git add src/components/typst src/components/assets/AssetsPanel.tsx src/test/typst-preview-pages.test.tsx
git commit -m "Restore the Yjs-bound Typst view and editor with the newer preview, search and place dialog"
```

---

### Task 6: The `typst` TabKind, gated entry points

**Files:**
- Modify: `src/types/index.ts:135`, `src/components/ui/SplitContainer.tsx` (lines 5-11, 250-256, 337), `src/components/ui/TabBar.tsx:135`, `src/stores/app-store.ts:495`
- Modify: `src/components/sidebar/LeftSidebar.tsx` (near 209), `src/components/ui/CommandPalette.tsx` (near 74), `src/components/ui/WorkspaceOverview.tsx` (near 41)
- Test: `src/test/typst-flag.test.tsx`

**Interfaces:**
- Consumes: `useThemeStore((s) => s.features.typst)`, `TypstView`.
- Produces: `TabKind` includes `'typst'`; a Typst tab is `{ kind: 'typst', entityId: <workspaceId>, title: 'Report' }`.

- [ ] **Step 1: Write the failing test**

`src/test/typst-flag.test.tsx`:

```tsx
import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { useThemeStore } from '@/stores/theme-store';
import { WorkspaceOverview } from '@/components/ui/WorkspaceOverview';

describe('Typst entry points follow features.typst', () => {
  beforeEach(() => useThemeStore.setState({ features: { typst: false } }));

  it('hides the report action when the flag is off', () => {
    render(<WorkspaceOverview />);
    expect(screen.queryByText('Write the report')).toBeNull();
  });

  it('shows it when the flag is on', () => {
    useThemeStore.setState({ features: { typst: true } });
    render(<WorkspaceOverview />);
    expect(screen.getByText('Write the report')).toBeTruthy();
  });
});
```

If `WorkspaceOverview` needs store state to render at all, seed it the way the nearest existing `src/test/*.test.tsx` that renders a store-backed component does.

- [ ] **Step 2: Run it, expect FAIL** (`Write the report` not found in the second case)

Run: `bun run test -- src/test/typst-flag.test.tsx`

- [ ] **Step 3: TabKind and rendering**

`src/types/index.ts`:

```ts
export type TabKind = 'page' | 'nmap' | 'nmap-machine' | 'cmdlog' | 'history' | 'assets' | 'shortcuts' | 'typst';
```

`SplitContainer.tsx`, with the other lazies:

```tsx
const TypstView = lazy(() => import('@/components/typst/TypstView').then((m) => ({ default: m.TypstView })));
```

and with the other branches:

```tsx
        {activeTab?.kind === 'typst' && <TypstView workspaceId={activeTab.entityId} />}
```

In the two icon ternaries (`SplitContainer.tsx:337`, `TabBar.tsx:135`) add `tab.kind === 'typst' ? <FileType size={N} /> :` before the final `<Keyboard />` fallback, importing `FileType` from `lucide-react`, with `N` matching that line's other icons (9 and 11).

`app-store.ts:495` lists kinds that survive `reconcileTabs` without an entity. A Typst tab's `entityId` is a workspace id, so it must be pruned when that workspace is deleted: do not add `'typst'` to that list. Add a case beside the others in that `switch`: `case 'typst': return workspaceIds.has(t.entityId);`, using whatever the function already calls its set of live workspace ids (build one from `get().workspaces` if it has none).

- [ ] **Step 4: Entry points, all behind the flag**

In each of the three files read the flag with `const typstOn = useThemeStore((s) => s.features.typst);` and wrap the new element in `{typstOn && ...}`.

`WorkspaceOverview.tsx`, beside the assets action, reusing its `open` helper:

```tsx
{typstOn && activeWorkspaceId && (
  <button className="op-action" onClick={() => open('typst', activeWorkspaceId, 'Report')}><FileType size={18} /><span><strong>Write the report</strong><small>Typst, with your screenshots as figures</small></span><ArrowUpRight size={14} /></button>
)}
```

`LeftSidebar.tsx` and `CommandPalette.tsx`: copy the adjacent Assets entry and change it to `openTab({ id: uuidv4(), kind: 'typst', entityId: activeWorkspaceId, title: 'Report' })`, label `Report`. Before opening, reuse an existing Typst tab for that workspace if one is open, the same way the Assets entry avoids duplicates (if it does not, match its behaviour).

- [ ] **Step 5: Run the test, expect PASS; then the gate**

Run: `bun run test -- src/test/typst-flag.test.tsx` then `bun run build`.
Expected: `dist/assets/` now contains `typst_ts_web_compiler_bg-*.wasm` and a `TypstView-*.js` chunk. Confirm the entry bundle did not absorb them: `grep -l "typst_ts_web_compiler" dist/assets/index-*.js` prints nothing.

- [ ] **Step 6: Manual check**

Start the server with `ENABLE_TYPST=1` on a throwaway DB and serve `dist/` (see the repo's verify-headless notes; use `127.0.0.1`). Open the Report tab, type, see the preview compile, place one screenshot with a blur, export PDF in the browser, and confirm the blur is in the PDF. Open a second browser profile and confirm both cursors show in the editor. Restart without the env var and confirm no Report entry appears anywhere.

- [ ] **Step 7: Commit**

```bash
git add src/types/index.ts src/components/ui src/components/sidebar/LeftSidebar.tsx src/stores/app-store.ts src/test/typst-flag.test.tsx
git commit -m "Add the typst TabKind with flag-gated entry points"
```

---

### Task 7: `report.typ` in the workspace ZIP

**Files:**
- Modify: `src/export/workspace-zip.ts` (`WorkspaceExportData`, `exportWorkspaceZip`, `parseWorkspaceZip`)
- Modify: `src/components/ui/ExportDialog.tsx` (export near line 92, import near line 170)
- Test: `src/test/workspace-zip-report.test.ts`

**Interfaces:**
- Produces: `WorkspaceExportData.typstSource?: string | null`.

This runs with the flag off too: a range box must be able to export a report someone wrote earlier, and reading a `Y.Text` loads no Typst code.

- [ ] **Step 1: Write the failing test**

```ts
import { describe, it, expect } from 'vitest';
import { exportWorkspaceZip, parseWorkspaceZip, type WorkspaceExportData } from '@/export';

const base = (): WorkspaceExportData => ({
  schemaVersion: 2, exportedAt: 1, workspace: { id: 'w1', name: 'W' } as WorkspaceExportData['workspace'],
  pages: [], changeLogs: [], nmapScans: [], nmapMachines: [], pageSnapshots: [], pageYjsUpdates: {},
});

describe('workspace zip: report.typ', () => {
  it('round-trips the Typst source', async () => {
    const out = await parseWorkspaceZip(await exportWorkspaceZip({ ...base(), typstSource: '= Report\n#lorem(3)' }));
    expect(out.typstSource).toBe('= Report\n#lorem(3)');
  });
  it('omits the file and parses to null when there is no source', async () => {
    const out = await parseWorkspaceZip(await exportWorkspaceZip(base()));
    expect(out.typstSource ?? null).toBeNull();
  });
});
```

- [ ] **Step 2: Run, expect FAIL** (`typstSource` is undefined after the round trip)

Run: `bun run test -- src/test/workspace-zip-report.test.ts`

- [ ] **Step 3: Implement in `workspace-zip.ts`**

Add to `WorkspaceExportData`:

```ts
  /** The workspace's Typst report source, or null/absent when none was written. */
  typstSource?: string | null;
```

In `exportWorkspaceZip`, after the `pageSnapshots.json` line:

```ts
  if (data.typstSource) zip.file('report.typ', data.typstSource);
```

In `parseWorkspaceZip`, before the returned object, and add `typstSource` to that object:

```ts
  const typstSource = (await zip.file('report.typ')?.async('string')) ?? null;
```

- [ ] **Step 4: Run, expect PASS**

- [ ] **Step 5: Wire `ExportDialog.tsx`**

Import `getSharedDoc, getOrInitYText, textKey` from `@/realtime/shared-doc` and `replaceYTextContent` from `@/realtime/use-y-text`.

Export, inside the `exportWorkspaceZip({ ... })` argument:

```ts
        typstSource: (getSharedDoc().doc.getMap('texts').get(textKey('typst', activeWorkspaceId, 'source')) as { toString(): string } | undefined)?.toString() ?? null,
```

A direct `get` is deliberate: `getOrInitYText` would create an empty report in every exported workspace.

Import, right after `restoreRetired(...)`:

```ts
        if (data.typstSource) {
          replaceYTextContent(getOrInitYText(textKey('typst', importedWsId, 'source'), ''), data.typstSource);
        }
```

The key uses `importedWsId`, so "import as new" lands under the remapped workspace. In "replace" mode the same call overwrites the old report with a minimal delta.

- [ ] **Step 6: Verify and commit**

Run: `bun run build`.

```bash
git add src/export/workspace-zip.ts src/components/ui/ExportDialog.tsx src/test/workspace-zip-report.test.ts
git commit -m "Carry the Typst report source in the workspace ZIP as report.typ"
```

---

### Task 8: Measure the bloat, finish the docs

**Files:**
- Create: `docs/typst-tab-2026-09.md`
- Modify: `README.md`, `CLAUDE.md`

- [ ] **Step 1: Before numbers**

Use a worktree at the spec commit so the working tree (and the user's uncommitted `docker-compose.yml` change) is untouched. Never stash or check out over it.

```bash
git worktree add ../btct-before 5113732
(cd ../btct-before && bun install && bun run build && gzip -9 -c dist/assets/index-*.js | wc -c && du -sb dist)
docker build -t btct:before ../btct-before && docker images btct:before --format '{{.Size}}'
```

- [ ] **Step 2: After numbers**

Same three commands in this tree, image tag `btct:after`. Then remove the worktree: `git worktree remove ../btct-before`.

- [ ] **Step 3: Flag-off runtime**

Bring up the preview stack (1 GB, 2 CPU) on each image with `ENABLE_TYPST` unset: `docker compose --env-file .env.preview -f docker-compose.preview.yml up -d --build`. After two idle minutes record `docker stats --no-stream` memory for the container. Then, on `btct:after`, load `http://127.0.0.1:8081`, log in, open a page, type, open the Assets tab, and read the network log (claude-in-chrome `read_network_requests`, or devtools). Record every request whose URL matches `wasm|/fonts/|Typst`.

- [ ] **Step 4: Write `docs/typst-tab-2026-09.md`**

A short first-person record: what was measured, how, and the table below with real numbers in every cell.

| Metric | Before | After | Pass condition | Result |
|---|---|---|---|---|
| Entry bundle, gzipped bytes | | | within 1 KB | |
| Flag-off idle RSS | | | no measurable change | |
| Flag-off requests for wasm, fonts, Typst chunks | n/a | | zero | |
| `dist/` bytes | | | recorded | |
| Image size | | | recorded | |

If a gated row fails, stop and report; the feature does not ship to the range box until it passes.

- [ ] **Step 5: Docs pass**

README:
- Feature tour: a "Report (Typst)" section and its Table of Contents anchor. Say that it needs `ENABLE_TYPST=1`, that compilation runs in the browser, and that the first open downloads about 11 MB once.
- A "Moving an engagement between machines" section: Admin panel, Backups, run; copy `backups/<name>` to the other host; `docker compose stop btct && docker compose run --rm btct bun server/restore.mjs /backups/<name> --yes && docker compose start btct`. State plainly that restore replaces the target's data, and that the workspace ZIP is not a substitute because it carries no screenshots, command log or page history.
- Commands: `bun run fonts`. Key files map: `src/components/typst/`, `src/lib/typst-*.ts`, `src/lib/features.ts`, `scripts/fonts.ts`. Shortcuts table: any editor shortcuts `TypstEditor` binds.

CLAUDE.md:
- "Retired features": remove the Typst report tab from the list of removed features.
- "Performance": the sentence saying the three `@myriaddreamin/typst*` packages were removed now says they are back, reachable only through the lazy `typst` tab behind `ENABLE_TYPST`, with a link to `docs/typst-tab-2026-09.md`.
- Tabs/panes bullet: the `typst` TabKind, and that its `entityId` is a workspace id pruned by `reconcileTabs`.
- A new invariant: **the Typst tab stays unreachable from the entry bundle.** Every import of `@/components/typst/*` or `@/lib/typst-compiler*` from outside those folders is a `lazy()` or dynamic import, and every entry point is wrapped in `features.typst`. `AssetsPanel` loads `PlaceScreenshotDialog` lazily and only when given its `typst` prop.

Run `grep -c "$(printf '\342\200\224')" README.md CLAUDE.md docs/typst-tab-2026-09.md`. Expect `0`, `1` (the style table), `0`.

- [ ] **Step 6: Final gate and commit**

Run: `bun run build && bun run test`. Failures must equal the Task 1 baseline.

```bash
git add docs/typst-tab-2026-09.md README.md CLAUDE.md
git commit -m "Record Typst tab bloat measurements and sync the docs"
```
