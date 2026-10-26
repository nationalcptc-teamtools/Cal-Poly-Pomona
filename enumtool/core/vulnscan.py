from __future__ import annotations

import glob
import os
import re

from . import ingest, installer, util

def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "target"

class AutoVulnScanner:
    def __init__(self, out_dir: str, proxy_url: str, rate: int,
                 nuclei_severity: str = "low,medium,high,critical",
                 bbot_preset: str = "web-basic",
                 wpscan_api_token: str = "") -> None:
        self.out_dir = util.ensure_dir(os.path.join(out_dir, "vulnscan"))
        self.proxy_url = proxy_url
        self.rate = rate
        self.nuclei_severity = nuclei_severity
        self.bbot_preset = bbot_preset
        self.wpscan_api_token = wpscan_api_token
        self._cmds: dict[str, list[str] | None] = {}

    def _ensure(self, tool: str, resolver) -> bool:
        if tool not in self._cmds:
            self._cmds[tool] = resolver()
        return self._cmds[tool] is not None

    def ensure_nuclei(self) -> bool:
        return self._ensure("nuclei", installer.ensure_nuclei)

    def ensure_bbot(self) -> bool:
        return self._ensure("bbot", installer.ensure_bbot)

    def ensure_nikto(self) -> bool:
        return self._ensure("nikto", installer.ensure_nikto)

    def ensure_wpscan(self) -> bool:
        return self._ensure("wpscan", installer.ensure_wpscan)

    def ensure_secretfinder(self) -> bool:
        return self._ensure("secretfinder", installer.ensure_secretfinder)

    def nuclei(self, url: str, ip: str) -> list[dict]:
        base = self._cmds.get("nuclei")
        if not base:
            return []
        out = os.path.join(self.out_dir, f"nuclei_{_slug(ip)}_{_slug(url)}.jsonl")
        cmd = [
            *base, "-u", url,
            "-jle", out,
            "-silent", "-nc",
            "-duc", "-ni",
            "-proxy", self.proxy_url,
            "-rate-limit", str(self.rate),
            "-timeout", "10", "-retries", "1",
        ]
        if self.nuclei_severity:
            cmd += ["-severity", self.nuclei_severity]
        util.log(f"nuclei: {url}", level="step")
        util.run(cmd, timeout=3600)
        return ingest.parse_nuclei(out, default_ip=ip)

    def bbot(self, target: str, ip: str, include_context: bool = False) -> list[dict]:
        base = self._cmds.get("bbot")
        if not base:
            return []
        name = "bbot_" + _slug(target)
        cmd = [
            *base, "-t", target,
            "-p", self.bbot_preset,
            "-om", "json",
            "-o", self.out_dir, "-n", name,
            "-y", "--silent",
        ]
        util.log(f"bbot: {target} (preset {self.bbot_preset})", level="step")
        util.run(cmd, timeout=5400)
        matches = glob.glob(os.path.join(self.out_dir, name, "output.ndjson")) or \
            glob.glob(os.path.join(self.out_dir, name, "*.ndjson"))
        if not matches:
            util.log(f"bbot produced no NDJSON for {target}", level="warn")
            return []
        return ingest.parse_bbot(matches[0], default_ip=ip,
                                 include_context=include_context)

    def nikto(self, url: str, ip: str) -> list[dict]:
        if not self._cmds.get("nikto"):
            return []
        out = os.path.join(self.out_dir, f"nikto_{_slug(ip)}_{_slug(url)}.json")
        cmd = [
            *self._cmds["nikto"], "-h", url,
            "-Format", "json", "-output", out,
            "-useproxy", self.proxy_url,
            "-ask", "no", "-nointeractive",
        ]
        util.log(f"nikto: {url}", level="step")
        util.run(cmd, timeout=3600)
        return ingest.parse_nikto(out, default_ip=ip)

    def wpscan(self, url: str, ip: str) -> list[dict]:
        if not self._cmds.get("wpscan"):
            return []
        out = os.path.join(self.out_dir, f"wpscan_{_slug(ip)}_{_slug(url)}.json")
        cmd = [
            *self._cmds["wpscan"], "--url", url,
            "--format", "json", "-o", out,
            "--proxy", self.proxy_url,
            "--no-banner", "--disable-tls-checks",
            "--request-timeout", "20",
        ]
        if self.wpscan_api_token:
            cmd += ["--api-token", self.wpscan_api_token]
        util.log(f"wpscan: {url}", level="step")
        util.run(cmd, timeout=3600)
        return ingest.parse_wpscan(out, default_ip=ip)

    def secretfinder(self, url: str, ip: str) -> list[dict]:
        if not self._cmds.get("secretfinder"):
            return []
        out = os.path.join(self.out_dir,
                           f"secretfinder_{_slug(ip)}_{_slug(url)}.txt")
        cmd = [*self._cmds["secretfinder"], "-i", url, "-o", "cli"]
        util.log(f"secretfinder: {url}", level="step")
        rc, text = util.stream(cmd, timeout=600)
        try:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(f"url: {url}\n{text}\n")
        except OSError:
            pass
        return ingest.parse_secretfinder(out, default_ip=ip)


def run_gitleaks(path: str, ip: str, out_dir: str, client) -> None:
    """Run gitleaks on a recovered source directory/repo and forward findings."""
    cmd = installer.ensure_gitleaks()
    if not cmd:
        return
    report = os.path.join(util.ensure_dir(os.path.join(out_dir, "vulnscan")),
                          f"gitleaks_{_slug(ip)}.json")
    # `gitleaks dir` scans plain files; it exits non-zero when leaks are found.
    scan = [*cmd, "dir", "--report-format", "json", "--report-path", report,
            "--exit-code", "0", path]
    util.log(f"gitleaks: {path}", level="step")
    util.run(scan, timeout=3600)
    groups = ingest.parse_gitleaks(report, default_ip=ip)
    total = sum(len(g["findings"]) for g in groups)
    util.log(f"gitleaks: {total} secret(s) in {path}", level="ok")
    for g in groups:
        client.send_tool("gitleaks", g["target"], g["findings"])
