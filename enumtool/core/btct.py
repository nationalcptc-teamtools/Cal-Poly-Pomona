from __future__ import annotations

import glob
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from . import util

NMAP_PATH = "/api/scans/nmap"
TOOL_PATH = "/api/scans/tool"

BATCH_MAX_ITEMS = 1000
BATCH_MAX_BYTES = 12_000_000
TITLE_MAX = 512
EVIDENCE_MAX = 65_536
DETAILS_MAX_KEYS = 40
DETAILS_VAL_MAX = 2_048

_SENSITIVE = (
    "admin", "login", "backup", "config", ".git", ".env", ".svn", "upload",
    "phpmyadmin", "dbadmin", "sql", "secret", "private", "dashboard", "console",
    "wp-admin", "server-status", "robots.txt", ".htaccess", "api",
)
_VALID_SEV = ("info", "low", "medium", "high", "critical")
_SUMMARY_KEYS = ("added", "updated", "deduped", "skipped", "matched",
                 "hostsValid", "hostnameSet")

class BTCTClient:
    def __init__(self, base_url: str, token: str = "", workspace: str = "",
                 scan: str = "", out_dir: str | None = None) -> None:
        self.base = (base_url or "").rstrip("/")
        self.token = token
        self.workspace = workspace
        self.scan = scan or default_scan_name()
        self.enabled = bool(self.base)
        self.record_dir = util.ensure_dir(os.path.join(out_dir, "btct")) \
            if out_dir else None
        if self.record_dir:
            try:
                with open(os.path.join(self.record_dir, ".scan"), "w",
                          encoding="utf-8") as fh:
                    fh.write(self.scan)
            except OSError:
                pass

    def _headers(self, content_type: str) -> dict[str, str]:
        headers = {"Content-Type": content_type, "User-Agent": "enumtool/1.0"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _post(self, path: str, body: bytes, content_type: str, label: str) -> bool:
        if not self.enabled:
            util.log(f"[BTCT not configured] {label} saved locally only "
                     f"(set --btct-url to forward)", level="dim")
            return False
        url = self.base + path
        try:
            req = urllib.request.Request(url, data=body, method="POST",
                                         headers=self._headers(content_type))
            with urllib.request.urlopen(req, timeout=20) as resp:
                summary = _summarize(resp.read())
                util.log(f"BTCT <- {label} ({resp.status}){summary}", level="ok")
            return True
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:300]
            except OSError:
                pass
            if exc.code == 409:
                util.log(f"BTCT {label}: workspace '{self.workspace}' not found "
                         f"(409) — create/select it in BTCT, or omit --workspace "
                         f"for the default.", level="err")
            elif exc.code == 413:
                util.log(f"BTCT {label}: rejected as too large (413) — {detail}",
                         level="err")
            else:
                util.log(f"BTCT {label}: HTTP {exc.code} — {detail}", level="warn")
            return False
        except (urllib.error.URLError, OSError) as exc:
            util.log(f"BTCT send failed ({label}): {exc}", level="warn")
            return False

    def _record(self, name: str, data) -> None:
        if not self.record_dir:
            return
        path = os.path.join(self.record_dir,
                            f"{name}_{datetime.now().strftime('%H%M%S')}.json")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except OSError:
            pass

    def _nmap_path(self) -> str:
        params = {"scan": self.scan}
        if self.workspace:
            params["workspace"] = self.workspace
        return NMAP_PATH + "?" + urllib.parse.urlencode(params)

    def send_nmap_xml(self, xml_path: str) -> bool:
        if not xml_path or not os.path.exists(xml_path):
            return False
        try:
            with open(xml_path, "rb") as fh:
                body = fh.read()
        except OSError:
            return False
        return self._post(self._nmap_path(), body, "application/xml",
                          f"nmap xml ({os.path.basename(xml_path)})")

    def send_tool(self, tool: str, target: dict, findings: list[dict]) -> bool:
        if not findings:
            return False
        findings = [_clamp_finding(f) for f in findings]
        ip = target.get("ip")
        batches = list(_batches(findings))
        ok = True
        for i, batch in enumerate(batches):
            payload = _clean({
                "workspace": self.workspace,
                "tool": tool,
                "target": _clean(target),
                "findings": batch,
            })
            self._record(f"{tool}_{ip}_{i}", payload)
            suffix = f" [{i + 1}/{len(batches)}]" if len(batches) > 1 else ""
            ok = self._post(
                TOOL_PATH, json.dumps(payload).encode(), "application/json",
                f"{tool} ({len(batch)} findings -> {ip}){suffix}") and ok
        return ok

    def send_prebuilt_tool(self, payload: dict) -> bool:
        payload = dict(payload)
        if self.workspace:
            payload["workspace"] = self.workspace
        tool = payload.get("tool", "?")
        ip = (payload.get("target") or {}).get("ip")
        n = len(payload.get("findings", []))
        return self._post(TOOL_PATH, json.dumps(payload).encode(),
                          "application/json",
                          f"{tool} ({n} findings -> {ip}) [replay]")

def gobuster_dir_findings(result: dict, port: int | None) -> list[dict]:
    out = []
    for f in result.get("findings", []):
        path = f["path"]
        full = f["base"].rstrip("/") + path
        sev = "low" if any(s in path.lower() for s in _SENSITIVE) else "info"
        details = {"status": f["status"], "size": f["size"]}
        if f.get("redirect"):
            details["redirect"] = f["redirect"]
        out.append(_clean({
            "title": f"{path}  ({f['status']})",
            "severity": sev,
            "url": full,
            "port": port,
            "details": details,
            "evidence": f"{path} (Status: {f['status']}) [Size: {f['size']}]",
        }))
    return out

def gobuster_dns_findings(result: dict) -> list[dict]:
    domain = result.get("domain", "")
    out = []
    for f in result.get("findings", []):
        sub = f["subdomain"]
        out.append(_clean({
            "title": f"subdomain: {sub}",
            "severity": "info",
            "details": {"domain": domain, "subdomain": sub},
        }))
    return out

def sqlmap_findings(result: dict) -> list[dict]:
    url = result.get("target", "")
    out = []
    for f in result.get("findings", []):
        types = f.get("types") or []
        technique = types[0] if types else f.get("where", "")
        details = _clean({
            "parameter": f.get("parameter", ""),
            "where": f.get("where", ""),
            "type": "; ".join(types),
            "dbms": f.get("dbms", ""),
        })
        out.append(_clean({
            "title": f"SQLi: {f.get('parameter', '?')} ({technique})",
            "severity": "high",
            "url": url,
            "details": details,
            "evidence": "\n".join(f.get("titles", [])),
        }))
    return out

def sstimap_findings(result: dict) -> list[dict]:
    url = result.get("target", "")
    out = []
    for f in result.get("findings", []):
        engine = f.get("engine", "")
        out.append(_clean({
            "title": f"SSTI: ({engine})" if engine else "SSTI detected",
            "severity": "high",
            "url": url,
            "details": _clean({"engine": engine}),
            "evidence": f.get("detail", ""),
        }))
    return out

def dalfox_findings(result: dict) -> list[dict]:
    fallback_url = result.get("target", "")
    out = []
    for obj in result.get("findings", []):
        if not isinstance(obj, dict):
            continue
        param = obj.get("param") or obj.get("parameter") or ""
        xtype = obj.get("inject_type") or obj.get("type") or "xss"
        url = obj.get("data") or obj.get("url") or fallback_url
        cwe = obj.get("cwe", "")
        sev = str(obj.get("severity", "medium")).lower()
        if sev not in _VALID_SEV:
            sev = "medium"
        details = _clean({"parameter": param, "type": xtype, "cwe": cwe})
        evidence = obj.get("evidence") or obj.get("poc") or \
            obj.get("message_str", "")
        out.append(_clean({
            "title": f"XSS: {param} ({xtype})" if param else f"XSS ({xtype})",
            "severity": sev,
            "url": url,
            "details": details,
            "evidence": evidence,
        }))
    return out

def read_saved_scan_name(out_dir: str) -> str:
    path = os.path.join(out_dir, "btct", ".scan")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""

def sync_dir(client: BTCTClient, out_dir: str) -> dict:
    counts = {"nmap": 0, "tool": 0, "failed": 0}

    xmls = sorted(glob.glob(os.path.join(out_dir, "nmap_*.xml")),
                  key=lambda p: ("allports" in os.path.basename(p), p))
    for xml in xmls:
        if client.send_nmap_xml(xml):
            counts["nmap"] += 1
        else:
            counts["failed"] += 1

    for path in sorted(glob.glob(os.path.join(out_dir, "btct", "*.json"))):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        if "tool" not in payload or "findings" not in payload:
            continue
        if client.send_prebuilt_tool(payload):
            counts["tool"] += 1
        else:
            counts["failed"] += 1

    util.log(f"sync complete: {counts['nmap']} nmap upload(s), "
             f"{counts['tool']} tool payload(s), {counts['failed']} failed",
             level="ok" if not counts["failed"] else "warn")
    return counts

def default_scan_name() -> str:
    return "enumtool " + datetime.now().strftime("%Y-%m-%d %H:%M")

def _clean(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None and v != ""}

def _clamp_finding(f: dict) -> dict:
    f = dict(f)
    if isinstance(f.get("title"), str):
        f["title"] = f["title"][:TITLE_MAX]
    if isinstance(f.get("evidence"), str):
        f["evidence"] = f["evidence"][:EVIDENCE_MAX]
    details = f.get("details")
    if isinstance(details, dict):
        items = list(details.items())[:DETAILS_MAX_KEYS]
        f["details"] = {
            k: (v[:DETAILS_VAL_MAX] if isinstance(v, str) else v)
            for k, v in items
        }
    return f

def _batches(findings: list[dict], max_items: int = BATCH_MAX_ITEMS,
             max_bytes: int = BATCH_MAX_BYTES):
    batch: list[dict] = []
    size = 0
    for f in findings:
        fb = len(json.dumps(f)) + 1
        if batch and (len(batch) >= max_items or size + fb > max_bytes):
            yield batch
            batch, size = [], 0
        batch.append(f)
        size += fb
    if batch:
        yield batch

def _summarize(raw: bytes) -> str:
    try:
        data = json.loads(raw or b"{}")
    except (json.JSONDecodeError, ValueError):
        return ""
    if not isinstance(data, dict):
        return ""
    parts = [f"{k}={data[k]}" for k in _SUMMARY_KEYS if k in data]
    return f" [{' '.join(parts)}]" if parts else ""
