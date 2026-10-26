from __future__ import annotations

import html
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import config
from .state import Host, State

_PAGE_CSS = """
*{box-sizing:border-box} body{font-family:ui-monospace,Menlo,Consolas,monospace;
background:#0d1117;color:#c9d1d9;margin:0;padding:24px;line-height:1.5}
h1{font-size:20px;color:#58a6ff;margin:0 0 4px} h2{font-size:15px;color:#79c0ff;
margin:28px 0 8px;border-bottom:1px solid #21262d;padding-bottom:4px}
.phase{color:#d29922;font-size:13px;margin-bottom:16px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #21262d;vertical-align:top}
th{color:#8b949e;font-weight:600}
.win{color:#f0883e}.lin{color:#56d364}.unk{color:#8b949e}
.badge{display:inline-block;padding:1px 6px;border-radius:6px;background:#161b22;
margin:1px 2px;font-size:12px}
textarea{width:100%;background:#010409;color:#c9d1d9;border:1px solid #30363d;
border-radius:6px;padding:8px;font-family:inherit;font-size:12px;resize:vertical}
.small{color:#6e7681;font-size:12px}
.cols{display:flex;gap:16px;flex-wrap:wrap}.col{flex:1;min-width:240px}
"""

def _port_badges(host: Host) -> str:
    parts = []
    for p in sorted(host.open_ports(), key=lambda x: x.port):
        label = f"{p.port}/{p.service or '?'}"
        detail = " ".join(x for x in (p.product, p.version) if x)
        title = html.escape(detail) if detail else ""
        web = " ✓web" if p.is_web else ""
        parts.append(f'<span class="badge" title="{title}">'
                     f'{html.escape(label)}{web}</span>')
    return "".join(parts) or '<span class="small">-</span>'

def _os_class(family: str) -> str:
    return {"windows": "win", "linux": "lin"}.get(family, "unk")

def _csv_for(hosts: list[Host]) -> str:
    rows = ["ip,os,hostnames,ports"]
    for h in hosts:
        ports = ";".join(
            f"{p.port}/{p.service or '?'}" for p in sorted(h.open_ports(),
                                                           key=lambda x: x.port))
        names = ";".join(h.hostnames)
        osname = h.os_name or h.os_family
        rows.append(f"{h.ip},{_csv_safe(osname)},{_csv_safe(names)},{_csv_safe(ports)}")
    return "\n".join(rows)

def _csv_safe(value: str) -> str:
    value = value or ""
    if any(c in value for c in (",", '"', "\n")):
        return '"' + value.replace('"', '""') + '"'
    return value

def render(state: State) -> str:
    snap = state.snapshot()
    buckets = state.hosts_by_os()
    host_objs = sorted(state.hosts.values(), key=lambda h: tuple(
        int(x) for x in h.ip.split(".")) if h.ip.count(".") == 3 else (9, 9, 9, 9))

    rows = []
    for h in host_objs:
        cls = _os_class(h.os_family)
        names = ", ".join(h.hostnames) if h.hostnames else "-"
        rows.append(
            f"<tr><td>{html.escape(h.ip)}</td>"
            f'<td class="{cls}">{html.escape(h.os_name or h.os_family)}</td>'
            f"<td>{html.escape(names)}</td>"
            f"<td>{_port_badges(h)}</td></tr>"
        )
    host_table = "".join(rows) or '<tr><td colspan="4" class="small">scanning…</td></tr>'

    all_ips = "\n".join(h.ip for h in host_objs)
    win_ips = "\n".join(h.ip for h in buckets["windows"])
    lin_ips = "\n".join(h.ip for h in buckets["linux"])
    win_csv = _csv_for(buckets["windows"])
    lin_csv = _csv_for(buckets["linux"])

    def box(label, content, rows_n=6):
        return (f'<div class="col"><div class="small">{label}</div>'
                f'<textarea rows="{rows_n}" readonly '
                f'onclick="this.select()">{html.escape(content)}</textarea></div>')

    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="{config.STATUS_REFRESH_SECONDS}">
<title>enumtool status</title><style>{_PAGE_CSS}</style></head><body>
<h1>enumtool — live recon status</h1>
<div class="phase">Phase: {html.escape(snap['phase_label'])} &nbsp;|&nbsp;
hosts up: {len(host_objs)} &nbsp;|&nbsp;
win: {len(buckets['windows'])} &nbsp; linux: {len(buckets['linux'])} &nbsp;
unknown: {len(buckets['unknown'])}</div>

<h2>Discovered hosts</h2>
<table><thead><tr><th>IP</th><th>OS</th><th>Hostnames</th>
<th>Open ports / services</th></tr></thead><tbody>{host_table}</tbody></table>

<h2>Copyable IP lists</h2>
<div class="cols">
{box("All live IPs", all_ips)}
{box("Windows IPs", win_ips)}
{box("Linux IPs", lin_ips)}
</div>

<h2>CSV — Windows</h2>
<textarea rows="{max(3, len(buckets['windows']) + 1)}" readonly
onclick="this.select()">{html.escape(win_csv)}</textarea>

<h2>CSV — Linux</h2>
<textarea rows="{max(3, len(buckets['linux']) + 1)}" readonly
onclick="this.select()">{html.escape(lin_csv)}</textarea>

<p class="small">auto-refreshes every {config.STATUS_REFRESH_SECONDS}s</p>
</body></html>"""

class _Handler(BaseHTTPRequestHandler):
    state: State

    def do_GET(self):
        body = render(self.state).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return

class StatusServer:
    def __init__(self, state: State, host: str = "0.0.0.0",
                 port: int = config.STATUS_WEB_PORT) -> None:
        self.state = state
        self.host = host
        self.port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        _Handler.state = self.state
        self._server = ThreadingHTTPServer((self.host, self.port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
