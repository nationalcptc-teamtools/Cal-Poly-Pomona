# Demo video: shot script and build plan

Working document for the re-record. Nothing here is recorded yet except the
"already done" list in section 3, which describes the current 1600x1000 cut.

## 1. Output spec

| | Current cut | Re-record |
|---|---|---|
| Resolution | 1600x1000 | **1920x1080** |
| Frame rate | 25 fps | 30 fps |
| Codec | h264, crf 21, yuv420p | same |
| Length | 1:42 | target 2:30 to 3:00 |
| Master | `blog/media/btct-demo.mp4` | same path, replaced |
| Inline GIF | 800x500, 10 fps, 4.5 MB | derive at 960x540, 10 fps |

1080p changes one thing structurally: at 1920 wide, a split pane with the
Properties rail collapsed is about 760px instead of 425px. The command log table
was illegible in a half pane at 1600 and forced the split segment to the end.
At 1080p it fits, so split screen can appear earlier and be used as a real
working layout rather than a closing flourish.

The GIF stays at 960px. A 1080p GIF of a three minute clip would be 30 MB or
more, which is too heavy for a README.

## 2. The Fake Company Environment

A new, deliberately small seed workspace, separate from the existing 37 node
ACME demo. The ACME set is too dense to read at video size. Everything below is
sized so that no screen in the video needs squinting.

**Naming (decided).** The workspace is named **Fake Company**, on screen and
everywhere else.

**Scope fiction:** internal assessment, `172.16.40.0/24`, domain
`fakecompany.local` (NetBIOS `FAKECOMPANY`), three operators. Hosts use an `fc-`
prefix so the footage stays obviously fictional.

**How it gets seeded (decided).** From outside the app, over a Yjs websocket
client, writing records straight into the shared doc. `Page.content` holds
markdown source and `PageEditor` seeds an empty per-page doc from it on first
open, so pages can be authored as plain markdown strings. This needs no change to
`src/` and no `dist` rebuild, which matters because `dist/` is git-tracked.
Repo `create()` rules still apply: pre-seed a `Y.Text` for every collaborative
field (page title and slug, node and edge labels, graph and workspace names).

### 2.1 Pages (4, short)

| Page | Contents |
|---|---|
| Engagement Notes | Scope, rules of engagement, 3 day timeline. About 150 words. |
| Recon | One `bash` fenced block of the scan commands, a short host table. |
| MF-SQL01 write-up | The SQLi to `xp_cmdshell` path, one code block, one figure reference. |
| Findings Summary | Four sentences. Deliberately thin so the Findings tab does the work. |

### 2.2 nmap XML (`blog/example-data/fake-company.xml`)

Five hosts up, one down so the parser visibly skips it. Roughly 20 ports total,
which fits one screen in the host detail view.

| IP | Hostname | OS | Ports of interest |
|---|---|---|---|
| 172.16.40.10 | fc-dc01 | Windows Server 2022 | 53, 88, 135, 389, 445, 3389 |
| 172.16.40.20 | fc-web01 | Ubuntu 24.04 | 22, 80, 443 (nginx 1.24, shipment portal) |
| 172.16.40.30 | fc-file01 | Windows Server 2019 | 139, 445 (SMB signing disabled) |
| 172.16.40.40 | fc-sql01 | Windows Server 2019 | 445, 1433 (MSSQL 2019) |
| 172.16.40.99 | fc-jump01 | Windows 11 | 3389, 5985 |
| 172.16.40.55 | none | down | skipped by the parser |

NSE output on a few ports (`smb-os-discovery`, `ms-sql-info`, `http-title`,
`ssh-hostkey`) so the expandable script rows have something in them.

### 2.3 The chart (attack narrative)

Ten nodes. Small enough that Auto Layout produces something readable without
zooming back in, which was a visible wart in the current cut.

- **Hosts (4):** FC-WEB01, FC-SQL01, FC-FILE01, FC-DC01
- **Services (2):** nginx 1.24 on 80, MSSQL 2019 on 1433
- **Credentials (2):** `svc_shipping`, `FAKECOMPANY\svc_backup`
- **Pivot (1):** WEB01 to SQL01 via `xp_cmdshell`
- **Findings (4):** see below

Edges use all five types at least once: `Exploits`, `HasSession`, `AdminTo`,
`PivotsTo`, `MemberOf`.

### 2.4 Findings (4, one per severity band)

| Severity | CVSS | Title |
|---|---|---|
| Critical | 9.8 | DCSync rights on `svc_backup` |
| High | 8.6 | SQL injection in the shipment portal |
| Medium | 5.9 | SMB signing disabled on MF-FILE01 |
| Low | 3.1 | DNS zone transfer allowed |

One of each band means the Findings tab shows every colour without scrolling.

### 2.5 Command log

Eight rows seeded before recording, spread over the previous six hours, from
three operators. Four more pushed live during the shot. Two of the seeded rows
carry `«REDACTED»` so the redaction is visible without narration.

## 3. Status

### Already recorded (current 1600x1000 cut)

- [x] Notes page open and scroll
- [x] Type ` ```bash ` fence, watch it become a highlighted CodeMirror block
- [x] Command palette on `Ctrl+K`
- [x] Attack graph, wheel zoom, **Auto Layout**
- [x] nmap: create group, name it, import XML, open a host, scroll its ports
- [x] Findings collector, scroll
- [x] Command log at full width, five commands arriving live (counter 14 to 19)
- [x] Split screen via tab drag, Properties rail collapsed first
- [x] Typst tab, wasm compile, rendered report
- [x] Final frame held 3s so the render is readable

### Done (re-record shipped 2026-08-08)

- [x] Wrote `blog/example-data/fake-company.xml` (5 up, 1 down, 18 ports, 13 NSE)
- [x] Wrote the external Yjs seeder (`scratchpad/seed-fakeco.mjs`): workspace,
      4 pages, 13-node graph, all 5 edge types, 4 findings (one per band)
- [x] Bumped the recorder to 1920x1080 at 30 fps (`scratchpad/record-1080.mjs`)
- [x] Created a `jnguyen` account + second browser profile for the live shot
- [x] Staged `blog/images/nmap-host.png` for the Typst figure placement
- [x] Re-cut the GIF at 960x540 from the new master

Shipped as `blog/media/btct-demo.mp4` (1920x1080, 2:42, 5.1 MB) and
`blog/images/btct-demo.gif` (960x540, 5.1 MB). All 14 shots verified frame by
frame.

**Two deviations from the plan, both deliberate:**

1. **Node properties are shown via the finding's graph page, not the canvas
   sidebar.** React Flow v12's XYDrag swallows synthetic node clicks, so a scripted
   click selects the node (ring appears) but never fires `onNodeClick`, so the
   sidebar editor never opens. The finding's linked graph page renders the exact
   same `FindingFields` editor inline and opens from a normal DOM button in the
   Findings collector. It's a better shot anyway: full width, every field visible.
2. **The command log shows 4 rows arriving live, not a pre-seeded backlog.** The
   live-arrival, redaction, three operators, and growing tool-filter chips are all
   visible. If you want a fuller log, seed history with `scratchpad/seed-cmdlog.mjs`
   (retargeted at the Fake Company workspace) before recording and it will already
   be on screen when shot 12 opens.

## 4. Shot list

Times are targets, not hard cuts. Everything is driven by the CDP recorder with
the synthetic cursor overlay, same as the current cut.

| # | Shot | Target | What happens on screen |
|---|---|---|---|
| 1 | Cold open | 0:00 to 0:08 | Land on Engagement Notes. Scroll the page once. Establishes that this is a notes app before anything clever happens. |
| 2 | Typing and highlighting | 0:08 to 0:25 | Caret to end, type ` ```bash `, block converts, type a four line scan loop. Comment, keywords and strings colour in as it goes. |
| 3 | **Live collaboration** | 0:25 to 0:45 | **New.** Second browser joins as a different user. Their coloured cursor and name tag appear in the same paragraph and text arrives character by character while our cursor sits still. This is the headline feature and it is missing from the current cut. |
| 4 | Command palette | 0:45 to 0:53 | `Ctrl+K`, palette opens, dismiss by clicking outside. Never press Escape twice, see section 6. |
| 5 | nmap import | 0:53 to 1:15 | Create group "Meridian internal /24", type the name, drop `meridian-internal.xml`, 5 hosts land, one is skipped. Open MF-DC01, expand one NSE script row. |
| 6 | **Link host to graph node** | 1:15 to 1:28 | **New.** Bind the scanned MF-SQL01 to the Host node on the canvas, show ports syncing across, use *Go to Nmap* to jump back. Ties the two halves of the app together. |
| 7 | Graph and Auto Layout | 1:28 to 1:45 | Open the narrative, wheel zoom, click **Auto Layout**. With 10 nodes the result stays readable and the re-zoom hack is no longer needed. |
| 8 | **Node properties** | 1:45 to 1:58 | **New.** Click the Critical finding node. Right sidebar shows CVSS, vector, MITRE mapping, remediation. Makes the "structured data, not a title" claim visible. |
| 9 | **Attack chain and path** | 1:58 to 2:12 | **New.** Select two nodes, **Highlight Path**, gold route lights up. Then right click, *Add to Attack Chain*, chain appears in the sidebar. |
| 10 | Findings collector | 2:12 to 2:20 | Four findings, one per severity band, no scrolling needed. |
| 11 | Command log with live rows | 2:20 to 2:38 | Full width. Four commands arrive from three operators, counter ticks, tool chips grow, one row shows `«REDACTED»`. |
| 12 | **Typst figure placement** | 2:38 to 2:55 | **New.** Drag a screenshot onto the assets rail, the crop window opens, pick a figure slot, *Place in figure*. The grey placeholder box becomes the real figure in the preview. This is the most distinctive feature in the app and it is entirely absent today. |
| 13 | Split screen finale | 2:55 to 3:05 | Report on the left, command log on the right, both legible at 1080p. Hold 3s. |

## 5. Capabilities not yet showcased

Ranked by how much they would add against how hard they are to film.

### Approved for this cut

These five are locked in. They are the reason the cut grows from 1:42 to roughly
3:00, and they are worth the extra minute.

1. **Live multi-user editing.** Two cursors in one paragraph, name tags,
   character by character merge. This is the entire premise of the tool and the
   current video does not show it once. **Shot 3.**
2. **Typst figure slots and the crop window.** Nothing else on the market places
   screenshots this way, and the empty grey box in the PDF is the part people
   remember. **Shot 12.**
3. **Node property editor.** Turns "typed nodes carry structured data" from a
   claim into something visible. **Shot 8.**
4. **Nmap host to graph node linking.** The only shot that connects recon to
   narrative. **Shot 6.**
5. **Attack chains and Highlight Path.** **Shot 9.**

Build notes for the five:

- Shot 3 needs a second Chrome profile, a second CDP connection, and a second
  BTCT account so the remote cursor carries a different name and colour. Create
  `operator2` in the admin panel during setup. Record browser A, drive typing in
  browser B. Both point at the same page id.
- Shot 6 needs the nmap host and the graph Host node to exist with matching
  hostnames before the take, so the bind is one click rather than a search.
- Shot 8 wants the Critical finding node selected, because its property panel has
  the most filled in fields (CVSS, vector, MITRE, remediation).
- Shot 9 needs two nodes that are genuinely two hops apart, otherwise the
  highlighted path is too short to read. FC-WEB01 to FC-DC01 is three hops.
- Shot 12 needs a real image staged on disk. Use one of the existing
  `blog/images/*.png` screenshots so the crop window has something recognisable
  in it, and place it into a slot captioned "Proof of exploitation".

### Worth adding if length allows

6. **Attack Timeline** with *Copy as Markdown*. It has a screenshot in the post
   but never appears in the video, and "your narrative section, drafted" is a
   strong claim to show rather than state.
7. **Page version history.** Save a named version, edit, restore, watch it roll
   back. Sells the safety net.
8. **Export.** One click to PDF from Typst, or the workspace ZIP. Short and
   concrete.
9. **Typst find and replace** across the whole document, and click to source
   from the preview back to the code.
10. **Presence and follow** on `Mod+Shift+U`. Follow a teammate and have your
    view mirror theirs. Pairs naturally with shot 3 if that shot goes well.

### Probably skip

11. **AI assistant.** Needs your Anthropic key, costs money per run, and the
    streaming response is slow on camera. If you want it, the admin panel config
    plus one short question is about 20 seconds. Tell me and I will use a key you
    provide.
12. **MCP from Claude Code.** Impressive to engineers, but it means filming a
    terminal next to the app and doubles the setup.
13. **Admin panel, themes, workspaces, keybinds dialog, block selection,
    backlinks, tags and sidebar search.** All real, none of them worth screen
    time against the list above.

## 6. Technical notes for the re-record

Carried over from the last five takes, all of which cost a full re-record when
missed.

- **Never send two Escapes.** The first leaves text editing, the second drops
  Milkdown into block selection mode, and every later click is swallowed.
  Dismiss the palette by clicking outside it.
- **Typst goes late.** Once CodeMirror has focus, `Ctrl+K` is eaten by its own
  keymap and tab chip clicks stop landing.
- **Dropping a tab into a pane remounts the Typst preview** and the wasm
  compiler re-initialises. Wait for the SVG again before ending.
- **Prime the browser profile first.** A fresh profile re-seeds a brand new
  workspace before websocket sync lands, which orphans the command log rows.
  Prime once, seed the log, then record with the same profile.
- **Clear `localStorage['btct.ui.v1']`** at startup or the run begins with
  whatever pane layout the last take ended in.
- **`YPERSISTENCE` did not survive a server restart** in practice. Treat the
  shared doc as gone after any restart and re-seed.
- **Code blocks need ` ```bash ` with a trailing space.** The input rule fires on
  the space, and a bare fence has no language so nothing colours.
- **Pick the smallest matching element** when clicking a card in a grid. The last
  match is an outer wrapper whose centre is empty space.

## 7. Open questions

1. ~~Workspace display name.~~ Decided: **Fake Company**.
2. Keep the existing ACME demo seed as well, or replace it? Default if you say
   nothing: keep it. The new environment is seeded externally, so `src/db/seed.ts`
   is untouched and the ACME demo still auto-seeds for anyone starting fresh.
3. Target length. The shot list above lands near 3:05. Shots 6, 8 and 9 are the
   easiest to cut if you want closer to 2:00.
4. Do you want the AI assistant shot, and if so will you supply a key?
5. `blog/media/btct-demo.mp4` is currently orphaned in the post since the caption
   under the GIF was removed. Re-link it under the new video, or drop the file?
