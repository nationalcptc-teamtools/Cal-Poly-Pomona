from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from . import btct, installer, util
from .btct import BTCTClient

VALID_TOOLS = ("sqlmap", "sstimap", "dalfox")

_MAPPERS = {
    "sqlmap": btct.sqlmap_findings,
    "dalfox": btct.dalfox_findings,
    "sstimap": btct.sstimap_findings,
}

@dataclass
class RawRequest:
    method: str = "GET"
    scheme: str = "http"
    host: str = ""
    port: int = 80
    path: str = "/"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: str = ""
    body: str = ""

    @property
    def url(self) -> str:
        default = (self.scheme == "http" and self.port == 80) or \
                  (self.scheme == "https" and self.port == 443)
        hostport = self.host if default else f"{self.host}:{self.port}"
        return f"{self.scheme}://{hostport}{self.path}"

def parse_request(path: str, scheme: str = "http") -> Optional[RawRequest]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as exc:
        util.log(f"cannot read request file {path}: {exc}", level="err")
        return None

    head, _, body = raw.replace("\r\n", "\n").partition("\n\n")
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        util.log("request file appears empty / malformed", level="err")
        return None

    req = RawRequest(scheme=scheme, body=body.strip())
    first = lines[0].split()
    if len(first) >= 2:
        req.method = first[0].upper()
        req.path = first[1]

    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep:
            continue
        name = name.strip()
        value = value.strip()
        lname = name.lower()
        if lname == "host":
            if ":" in value:
                host, _, p = value.partition(":")
                req.host = host
                req.port = int(p) if p.isdigit() else req.port
            else:
                req.host = value
        elif lname == "cookie":
            req.cookies = value
        else:
            req.headers[name] = value

    if scheme == "https" and req.port == 80:
        req.port = 443
    if not req.host:
        util.log("request file missing Host header", level="err")
        return None
    return req

class VulnRunner:
    def __init__(self, out_dir: str, client: BTCTClient,
                 tool_cmds: dict[str, list[str]]) -> None:
        self.out_dir = util.ensure_dir(os.path.join(out_dir, "vuln"))
        self.client = client
        self.tool_cmds = tool_cmds

    def run(self, tool: str, req: RawRequest, request_file: str) -> dict:
        fn = {
            "sqlmap": self._run_sqlmap,
            "dalfox": self._run_dalfox,
            "sstimap": self._run_sstimap,
        }[tool]
        util.log(f"=== {tool} vs {req.url} ===", level="step")
        result = fn(req, request_file)
        ip = util.resolve_ip(req.host)
        target = {"ip": ip, "port": req.port, "url": req.url}
        if req.host and req.host != ip:
            target["hostname"] = req.host
        findings = _MAPPERS[tool](result)
        self.client.send_tool(tool, target, findings)
        return result

    def _run_sqlmap(self, req: RawRequest, request_file: str) -> dict:
        raw_path = os.path.join(self.out_dir, "sqlmap.txt")
        cmd = [*self.tool_cmds["sqlmap"], "-r", request_file, "--batch",
               "--output-dir", os.path.join(self.out_dir, "sqlmap_out")]
        if req.scheme == "https":
            cmd.append("--force-ssl")
        rc = _run_to_file(cmd, raw_path, timeout=3600)
        findings = _parse_sqlmap(raw_path)
        return {
            "tool": "sqlmap", "target": req.url, "returncode": rc,
            "raw_output": raw_path, "vulnerable": bool(findings),
            "findings": findings,
        }

    def _run_dalfox(self, req: RawRequest, request_file: str) -> dict:
        raw_path = os.path.join(self.out_dir, "dalfox.txt")
        json_path = os.path.join(self.out_dir, "dalfox.json")
        cmd = [*self.tool_cmds["dalfox"], "url", req.url,
               "-X", req.method,
               "--format", "json", "-o", json_path,
               "--skip-bav", "--silence"]
        if req.body:
            cmd += ["-d", req.body]
        if req.cookies:
            cmd += ["-C", req.cookies]
        for name, value in req.headers.items():
            cmd += ["-H", f"{name}: {value}"]
        rc = _run_to_file(cmd, raw_path, timeout=3600)
        findings = _parse_dalfox(json_path)
        return {
            "tool": "dalfox", "target": req.url, "returncode": rc,
            "raw_output": raw_path, "json_output": json_path,
            "vulnerable": bool(findings), "findings": findings,
        }

    def _run_sstimap(self, req: RawRequest, request_file: str) -> dict:
        raw_path = os.path.join(self.out_dir, "sstimap.txt")
        cmd = [*self.tool_cmds["sstimap"], "-u", req.url, "-X", req.method]
        if req.body:
            cmd += ["-d", req.body]
        if req.cookies:
            cmd += ["-c", req.cookies]
        for name, value in req.headers.items():
            cmd += ["-H", f"{name}: {value}"]
        rc = _run_to_file(cmd, raw_path, timeout=3600)
        findings = _parse_sstimap(raw_path)
        return {
            "tool": "sstimap", "target": req.url, "returncode": rc,
            "raw_output": raw_path, "vulnerable": bool(findings),
            "findings": findings,
        }

def _parse_sqlmap(raw_path: str) -> list[dict]:
    findings: list[dict] = []
    if not os.path.exists(raw_path):
        return findings
    current: dict | None = None
    dbms = ""
    param_re = re.compile(r"Parameter:\s*(.+?)\s*\((\w+)\)")
    type_re = re.compile(r"Type:\s*(.+)")
    title_re = re.compile(r"Title:\s*(.+)")
    dbms_re = re.compile(r"back-end DBMS:\s*(.+)", re.IGNORECASE)
    dbms_re2 = re.compile(r"the back-end DBMS is\s*(.+)", re.IGNORECASE)
    with open(raw_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not dbms:
                dm = dbms_re.search(line) or dbms_re2.search(line)
                if dm:
                    dbms = dm.group(1).strip().rstrip(".")
            m = param_re.search(line)
            if m:
                current = {"parameter": m.group(1), "where": m.group(2),
                           "types": [], "titles": []}
                findings.append(current)
            elif current and (t := type_re.search(line)):
                current["types"].append(t.group(1))
            elif current and (t := title_re.search(line)):
                current["titles"].append(t.group(1))
    if dbms:
        for f in findings:
            f["dbms"] = dbms
    return findings

def _parse_dalfox(json_path: str) -> list[dict]:
    if not os.path.exists(json_path):
        return []
    try:
        with open(json_path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read().strip()
        if not text:
            return []
        if text.startswith("["):
            data = json.loads(text)
        else:
            data = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
        return data if isinstance(data, list) else [data]
    except (json.JSONDecodeError, OSError):
        return []

def _parse_sstimap(raw_path: str) -> list[dict]:
    findings: list[dict] = []
    if not os.path.exists(raw_path):
        return findings
    engine_re = re.compile(r"plugin '?(\w+)'? is able to|Rendering engine:\s*(\w+)",
                           re.IGNORECASE)
    with open(raw_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            m = engine_re.search(line)
            if m:
                engine = m.group(1) or m.group(2)
                findings.append({"engine": engine, "detail": line})
    return findings

def _run_to_file(cmd: list[str], raw_path: str, timeout: int) -> int:
    util.log(f"$ {' '.join(cmd)}", level="dim")
    try:
        with open(raw_path, "w", encoding="utf-8") as out:
            proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT,
                                    text=True)
            try:
                return proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                util.log(f"{cmd[0]} timed out after {timeout}s", level="warn")
                return 124
    except FileNotFoundError:
        util.log(f"tool not found: {cmd[0]}", level="err")
        return 127

def resolve_tools(selection: str) -> list[str]:
    if selection.strip().lower() == "all":
        return list(VALID_TOOLS)
    chosen = []
    for raw in selection.split(","):
        name = raw.strip().lower()
        if name in VALID_TOOLS:
            chosen.append(name)
        elif name:
            util.log(f"ignoring unknown tool '{name}'", level="warn")
    return util.dedup(chosen)

def run_vuln_phase(request_file: str, tools_selection: str, out_dir: str,
                   *, scheme: str, btct_url: str, scan_token: str,
                   workspace: str, scan_name: str, do_install: bool) -> None:
    if not os.path.exists(request_file):
        util.log(f"request file not found: {request_file}", level="err")
        return
    tools = resolve_tools(tools_selection)
    if not tools:
        util.log("no valid tools selected", level="err")
        return

    req = parse_request(request_file, scheme=scheme)
    if not req:
        return
    util.log(f"parsed request: {req.method} {req.url} "
             f"({len(req.headers)} headers, body={len(req.body)}B)", level="info")

    tool_cmds = installer.ensure_vuln_tools(tools) if do_install else {
        t: ([t] if util.which(t) else None) for t in tools
    }
    tool_cmds = {t: c for t, c in tool_cmds.items() if c}
    if not tool_cmds:
        util.log("no usable tools (try --install)", level="err")
        return

    client = BTCTClient(btct_url, scan_token, workspace, scan=scan_name,
                        out_dir=out_dir)
    runner = VulnRunner(out_dir, client, tool_cmds)
    for tool in tools:
        if tool not in tool_cmds:
            continue
        result = runner.run(tool, req, request_file)
        verdict = "VULNERABLE" if result.get("vulnerable") else "no findings"
        util.log(f"{tool}: {verdict} ({len(result.get('findings', []))} finding(s))",
                 level="ok" if result.get("vulnerable") else "info")
