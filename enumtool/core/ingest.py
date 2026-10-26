from __future__ import annotations

import ipaddress
import json
import os
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from . import util
from .btct import BTCTClient, _clean, _VALID_SEV

VALID_TOOLS = ("openvas", "nuclei", "bbot", "wpscan", "nikto", "gitleaks",
               "secretfinder")

def cvss_to_severity(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "info"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "info"

def _norm_sev(value: str, default: str = "info") -> str:
    v = str(value or "").strip().lower()
    return v if v in _VALID_SEV else default

def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def _first_ip(values) -> str:
    for v in values or []:
        if isinstance(v, str) and _is_ip(v):
            return v
    return ""

def _url_parts(url: str):
    if not url:
        return "", None
    if "://" not in url:
        url = "//" + url
    try:
        s = urlsplit(url)
    except ValueError:
        return "", None
    port = s.port
    if port is None:
        port = {"https": 443, "http": 80}.get(s.scheme)
    return (s.hostname or ""), port

def _group_add(groups: dict, ip: str, finding: dict, hostname: str = "") -> None:
    if not ip:
        return
    g = groups.get(ip)
    if g is None:
        g = {"target": {"ip": ip}, "findings": []}
        groups[ip] = g
    if hostname and "hostname" not in g["target"] and not _is_ip(hostname):
        g["target"]["hostname"] = hostname
    g["findings"].append(_clean(finding))

def parse_nuclei(path: str, default_ip: str = "", **_) -> list[dict]:
    groups: dict[str, dict] = {}
    for line in _iter_lines(path):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info") or {}
        title = info.get("name") or obj.get("template-id") or "nuclei match"
        url = obj.get("matched-at") or obj.get("host") or ""
        host, port = _url_parts(url)
        if obj.get("port"):
            try:
                port = int(obj["port"])
            except (ValueError, TypeError):
                pass
        ip = obj.get("ip") or (host if _is_ip(host) else "") or default_ip
        cls = info.get("classification") or {}
        cve = cls.get("cve-id") or []
        tags = info.get("tags") or []
        details = {
            "template": obj.get("template-id", ""),
            "type": obj.get("type", ""),
            "cve": ", ".join(cve) if isinstance(cve, list) else str(cve),
            "tags": ", ".join(tags) if isinstance(tags, list) else str(tags),
        }
        ev = obj.get("extracted-results") or obj.get("matcher-name") or ""
        if isinstance(ev, list):
            ev = ", ".join(str(x) for x in ev)
        finding = {
            "title": title,
            "severity": _norm_sev(info.get("severity"), "info"),
            "url": url,
            "port": port,
            "details": _clean(details),
            "evidence": ev,
        }
        _group_add(groups, ip, finding, hostname=host)
    return list(groups.values())

def parse_bbot(path: str, default_ip: str = "", include_context: bool = False,
               **_) -> list[dict]:
    groups: dict[str, dict] = {}
    for line in _iter_lines(path):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        etype = ev.get("type", "")
        data = ev.get("data")
        d = data if isinstance(data, dict) else {}
        s = data if isinstance(data, str) else ""
        tags = ev.get("tags")
        tags = ", ".join(tags) if isinstance(tags, list) else (tags or "")
        ip = _first_ip(ev.get("resolved_hosts")) or \
            (d.get("host", "") if _is_ip(d.get("host", "")) else "") or default_ip

        url = d.get("url", "")
        if etype == "VULNERABILITY":
            severity = _norm_sev(d.get("severity"), "info")
            title = d.get("description") or d.get("name") or "vulnerability"
        elif etype == "FINDING":
            severity = "low"
            title = d.get("description") or d.get("name") or s or "finding"
        elif include_context and etype in ("TECHNOLOGY", "DNS_NAME", "OPEN_TCP_PORT"):
            severity = "info"
            if etype == "DNS_NAME":
                title = f"subdomain: {s}" if s else "DNS name"
            elif etype == "OPEN_TCP_PORT":
                title = f"open port: {s}"
            else:
                title = f"tech: {d.get('technology', '')} ({d.get('host', '')})"
        else:
            continue

        details = _clean({"event_type": etype, "module": ev.get("module", ""),
                          "tags": tags})
        evidence = json.dumps(data) if isinstance(data, dict) else s
        finding = {"title": title, "severity": severity, "url": url,
                   "details": details, "evidence": evidence}
        _group_add(groups, ip, finding)
    return list(groups.values())

def parse_openvas(path: str, default_ip: str = "", **_) -> list[dict]:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, FileNotFoundError, OSError) as exc:
        util.log(f"cannot parse OpenVAS XML {path}: {exc}", level="err")
        return []

    groups: dict[str, dict] = {}
    for res in root.iter("result"):
        name = _text(res.find("name"))
        host_el = res.find("host")
        ip = (host_el.text.strip() if host_el is not None and host_el.text else "") \
            or default_ip
        if not _is_ip(ip):
            ip = default_ip
        hostname = _text(res.find("host/hostname"))

        port_raw = _text(res.find("port"))
        port = None
        head = port_raw.split("/", 1)[0]
        if head.isdigit():
            port = int(head)

        nvt = res.find("nvt")
        cvss = _text(res.find("severity")) or (_text(nvt.find("cvss_base"))
                                               if nvt is not None else "")
        oid = nvt.get("oid", "") if nvt is not None else ""
        family = _text(nvt.find("family")) if nvt is not None else ""
        cves = _openvas_cves(nvt)
        if not name and nvt is not None:
            name = _text(nvt.find("name"))

        details = _clean({
            "cvss": _as_num(cvss),
            "cve": ", ".join(cves),
            "oid": oid,
            "family": family,
        })
        finding = {
            "title": name or "OpenVAS result",
            "severity": cvss_to_severity(cvss),
            "port": port,
            "details": details,
            "evidence": _text(res.find("description")),
        }
        _group_add(groups, ip, finding, hostname=hostname)
    return list(groups.values())

def _openvas_cves(nvt) -> list[str]:
    if nvt is None:
        return []
    cves = []
    for ref in nvt.findall("refs/ref"):
        if (ref.get("type") or "").lower() == "cve" and ref.get("id"):
            cves.append(ref.get("id"))
    if not cves:
        raw = _text(nvt.find("cve"))
        if raw and raw.upper() != "NOCVE":
            cves = [c.strip() for c in raw.replace(",", " ").split() if c.strip()]
    return util.dedup(cves)

def parse_wpscan(path: str, default_ip: str = "", **_) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        util.log(f"cannot parse WPScan JSON {path}: {exc}", level="err")
        return []
    base_url = data.get("target_url", "")
    host, _ = _url_parts(base_url)
    ip = default_ip or (host if _is_ip(host) else "")
    groups: dict[str, dict] = {}

    def emit(title, severity, url, details, evidence=""):
        _group_add(groups, ip, {
            "title": title, "severity": severity, "url": url or base_url,
            "details": _clean(details), "evidence": evidence,
        }, hostname=host if not _is_ip(host) else "")

    def vulns(items, vtype, component, version):
        for v in items or []:
            cve = v.get("references", {}).get("cve", []) if isinstance(
                v.get("references"), dict) else []
            cve = ["CVE-" + c if not str(c).upper().startswith("CVE") else c
                   for c in cve]
            emit(v.get("title", "WordPress vulnerability"),
                 _wpscan_sev(v),
                 base_url,
                 {"type": vtype, "component": component, "version": version,
                  "fixed_in": v.get("fixed_in", ""), "cve": ", ".join(cve)},
                 "; ".join(v.get("references", {}).get("url", []))
                 if isinstance(v.get("references"), dict) else "")

    ver = data.get("version") or {}
    if ver.get("number"):
        emit(f"WordPress {ver['number']} identified", "info", base_url,
             {"type": "core", "component": "wordpress", "version": ver["number"]})
    vulns(ver.get("vulnerabilities"), "core", "wordpress", ver.get("number", ""))

    for slug, p in (data.get("plugins") or {}).items():
        pv = (p.get("version") or {}).get("number", "")
        vulns(p.get("vulnerabilities"), "plugin", slug, pv)
    for slug, t in (data.get("themes") or {}).items():
        tv = (t.get("version") or {}).get("number", "")
        vulns(t.get("vulnerabilities"), "theme", slug, tv)

    for f in data.get("interesting_findings") or []:
        emit(f.get("to_s", f.get("type", "interesting finding"))[:200], "info",
             f.get("url", base_url), {"type": "config"},
             "; ".join(f.get("references", {}).values())
             if isinstance(f.get("references"), dict) else "")
    for user in (data.get("users") or {}):
        emit(f"user: {user}", "info", base_url, {"type": "user"})
    return list(groups.values())


def _wpscan_sev(v: dict) -> str:
    cvss = ""
    refs = v.get("references")
    if isinstance(refs, dict):
        cvss = refs.get("cvss") or ""
    if cvss:
        return cvss_to_severity(cvss)
    return "high"  # a listed WPScan vuln is a known advisory


def parse_nikto(path: str, default_ip: str = "", **_) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        util.log(f"cannot parse Nikto JSON {path}: {exc}", level="err")
        return []
    hosts = data if isinstance(data, list) else [data]
    groups: dict[str, dict] = {}
    for h in hosts:
        if not isinstance(h, dict):
            continue
        ip = h.get("ip") or default_ip or ""
        port = _as_num(h.get("port", "")) or None
        hostname = h.get("host", "")
        base = f"http://{hostname}:{port}" if hostname and port else hostname
        for v in h.get("vulnerabilities", []):
            msg = v.get("msg", "") or v.get("id", "nikto finding")
            path_u = v.get("url", "") or ""
            url = (base.rstrip("/") + path_u) if path_u.startswith("/") else \
                (path_u or base)
            _group_add(groups, ip, {
                "title": msg[:200],
                "severity": _nikto_sev(msg),
                "url": url,
                "port": port,
                "details": _clean({"osvdb": v.get("OSVDB", ""),
                                   "method": v.get("method", ""),
                                   "id": v.get("id", "")}),
                "evidence": msg,
            }, hostname=hostname if not _is_ip(hostname) else "")
    return list(groups.values())


_NIKTO_MED = ("admin", "password", "directory indexing", "phpinfo", "backup",
              "config", ".git", "default account", "login")


def _nikto_sev(msg: str) -> str:
    low = msg.lower()
    return "medium" if any(k in low for k in _NIKTO_MED) else "info"


def parse_gitleaks(path: str, default_ip: str = "", **_) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        util.log(f"cannot parse Gitleaks JSON {path}: {exc}", level="err")
        return []
    if not isinstance(data, list):
        return []
    ip = default_ip or ""
    if not ip:
        util.log("gitleaks: no IP to attach to; pass --ip", level="err")
        return []
    groups: dict[str, dict] = {}
    for f in data:
        if not isinstance(f, dict):
            continue
        rule = f.get("RuleID", "")
        file = f.get("File", "")
        line = f.get("StartLine", "")
        _group_add(groups, ip, {
            "title": f.get("Description") or rule or "secret",
            "severity": "high",
            "url": f"repo://{file}#L{line}",
            "details": _clean({
                "rule": rule, "file": file,
                "line": _as_num(str(line)) if str(line) else "",
                "commit": (f.get("Commit", "") or "")[:7],
                "author": f.get("Author") or f.get("Email", ""),
            }),
            "evidence": f.get("Secret") or f.get("Match", ""),
        })
    return list(groups.values())


def parse_secretfinder(path: str, default_ip: str = "", **_) -> list[dict]:
    """SecretFinder has no JSON mode; parse its CLI output (saved to a file).

    Lines look roughly like '[ + ] google_api : AIza...' or
    'google_api -> AIza...'. We pull (type, match).
    """
    ip = default_ip or ""
    groups: dict[str, dict] = {}
    source = ""
    line_re = re.compile(r"^\[?\s*\+?\s*\]?\s*([A-Za-z0-9_ .-]+?)\s*(?:->|:)\s*(\S.+)$")
    url_re = re.compile(r"(https?://\S+)")
    idx = 0
    for raw in _iter_lines(path):
        um = url_re.search(raw)
        if um and ("url" in raw.lower() or raw.strip().startswith(um.group(1))):
            source = um.group(1)
            continue
        m = line_re.match(raw)
        if not m:
            continue
        stype = m.group(1).strip()
        match = m.group(2).strip()
        if not stype or stype.lower() in ("url", "uri"):
            continue
        idx += 1
        _group_add(groups, ip, {
            "title": stype,
            "severity": "medium",
            "url": f"{source}#secret-{idx}" if source else f"js://secret-{idx}",
            "details": _clean({"type": stype, "source": source, "match": match}),
            "evidence": match,
        })
    return list(groups.values())


def run_ingest(tool: str, path: str, client: BTCTClient, *,
               default_ip: str = "", include_context: bool = False) -> None:
    parser = {"openvas": parse_openvas, "nuclei": parse_nuclei,
              "bbot": parse_bbot, "wpscan": parse_wpscan, "nikto": parse_nikto,
              "gitleaks": parse_gitleaks,
              "secretfinder": parse_secretfinder}.get(tool)
    if not parser:
        util.log(f"unknown ingest tool: {tool}", level="err")
        return
    if not os.path.exists(path):
        util.log(f"result file not found: {path}", level="err")
        return

    groups = parser(path, default_ip=default_ip, include_context=include_context)
    if not groups:
        util.log(f"{tool}: no findings parsed from {path} "
                 f"(wrong format, or pass --ip if the file has no host IPs)",
                 level="warn")
        return

    total = sum(len(g["findings"]) for g in groups)
    util.log(f"{tool}: {total} finding(s) across {len(groups)} host(s)",
             level="step")
    for g in groups:
        client.send_tool(tool, g["target"], g["findings"])

def _iter_lines(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield line
    except OSError as exc:
        util.log(f"cannot read {path}: {exc}", level="err")

def _text(el) -> str:
    return (el.text or "").strip() if el is not None else ""

def _as_num(value: str):
    try:
        f = float(value)
        return int(f) if f.is_integer() else f
    except (TypeError, ValueError):
        return ""
