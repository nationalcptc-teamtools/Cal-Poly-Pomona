export type ID = string;

// ---- Workspace ----
export interface Workspace {
  id: ID;
  name: string;
  description: string;
  createdAt: number;
  updatedAt: number;
}

// ---- Page ----
export interface Page {
  id: ID;
  workspaceId: ID;
  parentId: ID | null;
  title: string;
  slug: string;
  icon: string;
  tags: string[];
  /** Markdown source for the page body. Legacy BlockNote JSON arrays are
   *  accepted and auto-converted to markdown at load time (see
   *  normalizePageContent). At runtime, reads from pageRepo always return a
   *  string; the array shape exists only for legacy seed/fixture compatibility. */
  content: PartialBlockContent;
  sortOrder: number;
  /** Legacy: pages auto-created for retired graph nodes. Always false for new
   *  pages; kept so archived workspaces still round-trip through import. */
  isGraphPage: boolean;
  createdAt: number;
  updatedAt: number;
}

// Legacy alias: any code path still passing BlockNote arrays is accepted
// by pageRepo.create/update and converted to markdown before persistence.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type PartialBlockContent = string | readonly Record<string, any>[];

// ---- Typst assets (report screenshots + custom fonts) ----

export type TypstAssetKind = 'image' | 'font';

/**
 * A crop rectangle in *normalized* coordinates (0..1, relative to the
 * original image). Normalized rather than pixels so the rect stays correct
 * if the same record is ever reused at a different resolution, and so the
 * cropper UI can work in whatever display size it happens to be laid out at.
 */
export interface CropRect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** How a blur region hides its pixels. */
export type BlurStyle = 'gaussian' | 'pixelate';

/**
 * One blurred (redacted) rectangle, in normalized coordinates relative to
 * the *original* image: the same space as `CropRect`, but always inside the
 * unit square: blurring pixels that don't exist is meaningless. Regions are
 * anchored to the upload rather than the crop so re-framing a figure never
 * moves a redaction off its secret.
 *
 * `style` and `strength` are optional so records written before they existed
 * stay valid: absent means gaussian at strength 1 (the original behavior).
 * Strength is a multiplier clamped to `MIN_STRENGTH`..`MAX_STRENGTH` in
 * `lib/blur-math.ts`.
 */
export interface BlurRegion {
  x: number;
  y: number;
  w: number;
  h: number;
  style?: BlurStyle;
  strength?: number;
}

/**
 * Metadata for one uploaded asset. The bytes live on the server (see
 * server/assets.mjs); this record is what syncs through the shared Yjs doc.
 *
 * `filename` doubles as the path inside the Typst virtual filesystem: an
 * image called `login-bypass.png` is referenced as
 * `#image("/assets/login-bypass.png")`.
 *
 * `crop` is applied at render time by re-encoding the image through a canvas
 * before it's handed to the compiler. The upload is never modified, so a
 * crop is always undoable and can be widened again later.
 */
export interface TypstAsset {
  id: ID;
  workspaceId: ID;
  kind: TypstAssetKind;
  filename: string;
  mime: string;
  size: number;
  /** Natural pixel dimensions. Images only; absent until first decode. */
  width?: number | null;
  height?: number | null;
  /** Normalized crop rect, or null/absent for "use the whole image". */
  crop?: CropRect | null;
  /**
   * Blurred (redacted) regions, or null/absent for none. Applied at render
   * time like `crop`; anchored to the original image, not the crop.
   */
  blurs?: BlurRegion[] | null;
  /** Family name parsed from the font file: what you pass to `#set text(font:)`. */
  fontFamily?: string | null;
  /** Folder this asset sits in (`assetFolders` id), or null/absent for the root. */
  folderId?: ID | null;
  /** Set when the asset was retired (removed from a note): hidden from the manager, bytes kept until the retention window prunes it. */
  deletedAt?: number | null;
  createdAt: number;
  updatedAt: number;
}

/**
 * A folder in the Typst assets panel's hierarchy. Organizational only: the
 * asset's compiler path stays the flat `/assets/<filename>`, so folder
 * operations never touch a document. Plain LWW JSON, no Y.Text fields
 * (renames go through a dialog, like `typstAssets`).
 */
export interface AssetFolder {
  id: ID;
  workspaceId: ID;
  name: string;
  parentId: ID | null;
  createdAt: number;
  updatedAt: number;
}

// ---- UI State Types ----
export type TabKind = 'page' | 'nmap' | 'nmap-machine' | 'cmdlog' | 'history' | 'assets' | 'shortcuts' | 'typst' | 'web-scan';

export interface TabItem {
  id: string;
  kind: TabKind;
  entityId: ID;
  title: string;
}

// ---- Split Pane Layout ----
export type SplitDirection = 'horizontal' | 'vertical';

export interface LeafPane {
  type: 'leaf';
  id: string;
  tabIds: string[];
  activeTabId: string | null;
}

export interface SplitPane {
  type: 'split';
  id: string;
  direction: SplitDirection;
  children: [PaneNode, PaneNode];
  ratio: number;
}

export type PaneNode = LeafPane | SplitPane;

export type DropPosition = 'center' | 'left' | 'right' | 'top' | 'bottom';

// ---- Change Log ----
export type ChangeAction = 'create' | 'update' | 'delete' | 'restore';
export type ChangeTarget = 'page' | 'workspace';

export interface ChangeLogEntry {
  id: ID;
  workspaceId: ID;
  action: ChangeAction;
  target: ChangeTarget;
  targetId: ID;
  summary: string;
  timestamp: number;
  // Author attribution. Optional for backward-compat with logs written
  // before the history feature landed.
  userId?: number | null;
  userName?: string | null;
  userColor?: string | null;
  // Field-level delta. Set for `update` entries on a single field, OR
  // for `delete` entries where prevValue is the full entity JSON.
  // Strings are JSON.stringify-encoded so any value shape can roundtrip.
  field?: string | null;
  prevValue?: string | null;
  newValue?: string | null;
  // Reversible entries get a Restore button in the UI. true when we have
  // enough state captured (prevValue for update, full entity JSON for
  // delete) to put the entity back.
  reversible?: boolean;
}

// ---- Command Log ----
// One whitelisted pentest command captured by a btct-cmdlog agent on an
// operator's box. Written ONLY by the server ingest endpoint (never by a
// client repo) into both SQLite (durable archive) and the shared doc's
// `commandLogs` map (bounded live window). No Y.Text fields: every field is
// plain LWW JSON, so invariant #1 does not apply. Optional fields are declared
// `?: T | null` because a record may predate a field or the agent may omit it.
export interface CommandLogEntry {
  id: ID;                      // agent-generated; the idempotency key end to end
  workspaceId: ID;
  operator: string;            // self-asserted --operator name
  command: string;             // redacted unless the agent ran --no-redact
  tool: string;                // matched whitelist entry
  cwd?: string | null;
  host?: string | null;        // hostname of the operator's box
  localUser?: string | null;
  shellPid?: number | null;
  startedAt: number;           // agent clock (epoch ms)
  receivedAt: number;          // server clock (epoch ms)
  exitCode?: number | null;    // null while the command is still running
  durationMs?: number | null;
  redacted?: boolean;
}

// Page-body snapshot: Yjs encodeStateAsUpdate bytes of a per-page Y.Doc
// captured at a point in time. Stored in the shared doc so every client
// can browse + restore. Bytes are base64 to fit cleanly in JSON.
export interface PageSnapshot {
  id: ID;
  pageId: ID;
  workspaceId: ID;
  timestamp: number;
  userId?: number | null;
  userName?: string | null;
  userColor?: string | null;
  label?: string | null;       // human label when user explicitly named the version
  updateBase64: string;        // Y.encodeStateAsUpdate(pageDoc) -> base64
  byteLength: number;          // for UI display
}

// ---- Page version history (server-side, see server/history.mjs) ----
export type PageVersionTrigger = 'auto' | 'named' | 'restore' | 'import';

export interface PageVersion {
  id: ID;
  pageId: ID;
  workspaceId: ID | null;
  createdAt: number;
  trigger: PageVersionTrigger;
  name: string | null;
  createdBy: number | null;
  /** Accounts whose edits landed between the previous version and this one (0 = unknown). */
  changedBy: number[];
  /** True when the version is a twin snapshot (renders with per-user changes); false for imports. */
  diffable: boolean;
  size: number;
}

export interface PageVersionUser {
  id: number;
  username: string;
  color: string;
}

// ---- Nmap Scan ----
export type MachineOS = 'windows' | 'linux' | 'attacker' | 'unknown';

export interface NmapScriptResult {
  id: string;
  output: string;
}

export interface NmapPort {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string;
  scripts?: NmapScriptResult[];
}

export type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/**
 * A result from a web/app tool (gobuster, sqlmap, sstimap, dalfox, ...),
 * uploaded through the scan-ingest API and attached to the machine whose IP it
 * targets. Plain LWW JSON on the machine record (like `ports`), so it carries
 * no Y.Text and needs no invariant #1 wiring.
 */
export interface ToolFinding {
  id: ID;
  tool: string;
  title: string;
  severity: FindingSeverity;
  url?: string;
  port?: number;
  details?: Record<string, string | number | boolean>;
  evidence?: string;
  createdAt: number;
}

export interface NmapMachine {
  id: ID;
  scanId: ID;
  ip: string;
  hostname: string;
  os: MachineOS;
  ports: NmapPort[];
  toolFindings?: ToolFinding[];
  linkedNodeId?: ID;
  createdAt: number;
  updatedAt: number;
}

export interface NmapScan {
  id: ID;
  workspaceId: ID;
  name: string;
  importedAt: number;
  rawXml?: string;
}
