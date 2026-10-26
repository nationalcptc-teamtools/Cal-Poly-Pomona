# We ran a whole engagement out of one Google Doc

*Been There, Conquered That: a real-time notes and reporting workspace for a
collegiate pentest competition.*

<video src="media/btct-demo.mp4" controls muted loop playsinline width="960">
  <img src="images/btct-demo.gif" width="960" alt="BTCT demo: typing a highlighted code block, a second operator editing the same page live, nmap import linked to the graph, a highlighted attack path, structured finding data, the live command log, Typst figure placement, and the split-screen report">
</video>

*Full-quality 1920x1080 clip, one take against a small demo workspace called Fake
Company. The video above plays in most markdown viewers; on GitHub it falls back
to a GIF, and the raw file is [`media/btct-demo.mp4`](media/btct-demo.mp4).*

## Why

All of it went in one Google Doc. Five of us, same document, all day.

To be fair, that mostly works. Docs handles five cursors without complaining and
nothing gets lost. But a few hours in it's a wall of headings somebody else made,
and you're scrolling past two people's scratch notes to find the host you were
on. Somebody asks whether anyone already looked at the file server and the honest
answer is to go read the whole thing.

What actually bothered me is that none of us take notes like that anywhere else.
We all use Notion or Obsidian for our own stuff, with linked pages, tags, a
sidebar you can navigate, code blocks that look like code. Then we'd sit down for
the one weekend of the year that matters and drop straight back to using google docs because that's what we have to use.

We did have one purpose-built tool. We ran
[SLORPIN](https://github.com/nationalcptc-teamtools/Cal-Poly-Pomona/tree/master/SLORPIN),
Cal Poly Pomona's nmap aggregator, which stands for Some Lone Operator Remakes
Program Intended for Nmap. It's a Go and Gin web app that pulls everyone's scan
results into one database behind a login, organized into named operations, so you
can review the team's recon in one place instead of on five separate boxes. That
part was genuinely useful and it's the reason this project exists at all. But it
only covers recon, it doesn't sync in real time, and it wasn't something you
wanted to stare at on hour thirty of a competition.

So why not just build the rest of it? Google Docs is fine. It just isn't built
for this, and there's no rule saying the workflow you use for the
highest-pressure three days of the year has to be the one you're using for class assignments.

BTCT is that build. Recon aggregation like SLORPIN had, plus the note-taking, the
attack narrative, the evidence trail, and the report. All of it in one place, all
of it live, none of it leaving the LAN. One container, one port, one volume on
the engagement network.

## Notes

Pages are a nestable tree with titles, slugs, tags, and icons. The body is a
live-preview markdown editor, so you type markdown and it renders as you go.
There's no source pane and preview pane to keep in sync.

![The page editor with an engagement notes document](images/pages-editor.png)

Type `/` to get a block menu: headings, lists, quotes, tables, code, images.

![The slash menu open in the editor](images/slash-menu.png)

Input rules fire as you type too. Open a fence with ` ```bash ` and the paragraph
becomes a real CodeMirror block with line numbers and live highlighting. That's
the first few seconds of the clip. New code blocks default to `shell`, which is
what you're pasting most of the time anyway.

Select text and a format bar appears with the usual bold, italic, strike, inline
code, block conversions, and a seven-color highlighter. The highlighter marks
are deliberately session-only. CommonMark has no highlight syntax, so keeping
them would mean the exported markdown stops being portable.

## The attack narrative is a graph, not a paragraph

Every engagement gets one or more canvases. Nodes are typed: Host, Credential,
Service, Finding, Pivot. Each one carries real structured data, so a Finding node
holds CVSS and vector, likelihood, impact, exploit steps, MITRE mapping, and
remediation, not just a title. Edges are typed too, with `AdminTo`, `HasSession`,
`MemberOf`, `Exploits` and `PivotsTo`.

![The attack narrative graph for an internal network engagement](images/attack-graph.png)

Every node carries structured data, and you can see it in the clip: opening the
Critical finding brings up an editor with severity, CVSS and vector, likelihood
and impact, exploit steps, the MITRE technique, and remediation. It's a form, not
a paragraph you have to remember to fill in the same way twice.

Right-click one node as the path start and another as the end, and Highlight Path
runs a BFS between them and lights the route gold. In the clip that traces
FC-WEB01 to FC-DC01, three hops through the SQL box and the service account.
`Ctrl+F` fuzzy-searches every field on every node, which matters more than it
sounds once a narrative has a few dozen of them.

Auto Layout re-flows the whole canvas into a dagre hierarchy in one click. You
can watch it snap into a top-down tree, which beats dragging a dozen nodes into
place by hand.

## Findings and the timeline build themselves

The findings list isn't a list you maintain. It's a view over every Finding node
in every narrative, grouped by severity and sorted by CVSS. You maintain the
graph and this falls out of it.

![The findings collector grouped by severity](images/findings.png)

The timeline is the same trick applied to time. Every node in the workspace
ordered by when it was discovered, grouped by day, with each node's incoming
edges shown underneath as lineage. One button copies the lot as a markdown
outline, and that outline is a first draft of your narrative section.

![The attack timeline, grouped by day with edge lineage](images/timeline.png)

## nmap import

Drop nmap XML into a scan group. It pulls hosts, OS detection, ports, service
versions, and NSE script output. Re-import the same IP and the ports merge rather
than duplicating. Then bind a scanned host to its Host node on the graph, and the
open ports sync across the link. In the clip I import the scan, then connect
fc-sql01 to the FC-SQL01 node and jump straight to it on the canvas.

![A parsed nmap host with its open ports and service versions](images/nmap-host.png)

The clip imports
[`example-data/fake-company.xml`](example-data/fake-company.xml), which is in this
folder if you want to reproduce that bit. It's an `nmap -sS -sV -sC -O` run over
the demo network: 5 hosts up, 1 deliberately down so you can see the parser skip
it, 18 ports, 13 NSE script results. Hostnames come from the PTR records and the
OS badge comes from `<osmatch>`, so fc-web01 lands as Linux and everything else
comes through as Windows.

## The command log writes your evidence trail

This is the part I'd want if I only got to keep one feature.

A small Python agent runs on each operator's Kali box. It's standard library
only, no pip install on a competition machine. A shell hook catches whitelisted
commands as they're typed and ships them with the operator name, hostname,
working directory, start time, exit code, and duration. A long scan shows up the
moment it starts and fills in its result when it finishes.

![The command log showing captured commands from three operators](images/command-log.png)

Secrets get redacted before they leave the operator's box. Passwords, hashes,
auth headers and URL credentials become `«REDACTED»`, and the redaction is
tool-aware, so `nmap -p 1-65535` keeps its ports while `mysql -pSECRET` gets
scrubbed. The unredacted line stays in a local log on that machine.

New commands push in live. No reload, no polling. In the clip the log fills in
front of you as three operators' boxes ship `evil-winrm`, `nxc`,
`impacket-secretsdump` and `sqlmap`, two of them showing `«REDACTED»`, and the
tool filter chips grow to match. Filter by operator, tool, host, status or free
text, then export whatever you've filtered to as CSV or JSON for the report
appendix.

Only whitelisted tools are logged. Everything else you type never leaves the box.

## The report is typeset locally

There's a Typst tab: source on the left, the rendered document in the middle,
assets on the right.

![The Typst editor with a live-rendered report preview](images/typst-report.png)

The compiler and the renderer are WebAssembly, bundled into the app, with the
default font set embedded. It renders with no network at all. That was the whole
point. Competition networks are hostile and air-gapped segments are normal, so a
report tool that phones home to typst.app is a report tool you can't use. Export
goes to PDF or SVG.

Screenshots don't get pasted wherever your cursor happens to be. You assign them
to a declared figure slot, which renders as a grey captioned box until something
fills it. An unfinished figure is then visibly unfinished in the PDF instead of
quietly missing, and the caption and figure numbering stay put no matter who
fills it in later. Click anywhere in the rendered preview and the editor jumps to
the matching source line.

## Split panes

Drag any tab to a pane edge. Pages, graphs, findings, the timeline, the Typst
editor, the assistant, all of them.

![The graph and a notes page side by side in split panes](images/split-panes.png)

Attack path on the left, write-up on the right, which is how I actually used it.

## Everything is live, and there's no database

There isn't a traditional database anywhere in this. Every record lives in a Yjs
CRDT document, synced over WebSockets and cached in IndexedDB.

Entity records sit in a `Y.Map` per table, keyed by id. Every collaborative text
field is backed by a `Y.Text`, so page titles, node labels, scan names and
hostnames merge character by character instead of one person's save clobbering
another's. Page bodies get their own per-page document, bound to the editor with
remote cursors and name tags.

Presence rides along with it, so you can follow a teammate and have your view
mirror theirs as they move around. And because IndexedDB caches everything
locally, the UI renders immediately on load and reconciles when the connection
comes back, which is a nicer property than it sounds like on a flaky competition
VLAN.

## Command palette

`Ctrl/⌘+K` for everything. Create a page or a narrative, open the Typst document,
jump to any page or graph by name, ask Claude, flip dark mode.

![The command palette](images/command-palette.png)

## Claude, in both directions

An admin sets an Anthropic API key in the admin panel. The key is stored
server-side and never reaches the browser or the JS bundle.

![Admin panel showing the Claude AI, MCP server, and command log settings](images/admin-ai-mcp.png)

The built-in assistant is a tab like any other. It reads the live workspace,
pages, graphs, findings, nmap results, and in edit mode it can write back:
create a narrative, spawn host and service and credential and finding nodes,
connect them, add findings, turn a scanned nmap host into a graph node. Its tools
run in-process against the shared CRDT, so anything it does appears on everyone
else's canvas immediately and lands in the change log with everything else. There
are no delete tools, on purpose.

The other direction is an MCP server at `POST /mcp`, so an external client like
the Claude Code CLI can read and optionally write the whole workspace. It reuses
the same tool catalog as the in-app assistant, which means the two can't drift
apart. Auth is a bearer token the admin generates.

```bash
claude mcp add btct --transport http http://<host>:8080/mcp \
  --header "Authorization: Bearer <token>"
```

## Stack

Bun everywhere. React 19, Vite and Tailwind on the client. Milkdown and
ProseMirror for the editor, React Flow for the graph, CodeMirror for code,
typst.ts for the report.

The server is deliberately dumb. It's `node:http`, `ws` and `bun:sqlite`, and it
does auth, static hosting and a Yjs relay. It knows nothing about pages or graphs
or findings, and there are only three places where that's not true: the AI
assistant, the asset store, and the command log ingest. Keeping it that way is
the reason the client can work offline at all.
