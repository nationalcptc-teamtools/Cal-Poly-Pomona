from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

from . import config, util

_DIR_RE = re.compile(
    r"^(?P<path>/\S*)\s+\(Status:\s*(?P<code>\d+)\)\s*\[Size:\s*(?P<size>\d+)\]"
    r"(?:\s*\[--> \s*(?P<redirect>[^\]]+)\])?")
_DNS_RE = re.compile(r"^Found:\s*(?P<name>\S+)")

class GobusterScanner:
    def __init__(self, out_dir: str, proxy_url: str, *,
                 dir_wordlist: str = config.DIR_WORDLIST,
                 sub_wordlist: str = config.SUBDOMAIN_WORDLIST,
                 rate: int = config.REQUESTS_PER_SECOND,
                 threads: int = 10,
                 depth: int = config.GOBUSTER_RECURSION_DEPTH) -> None:
        self.out_dir = util.ensure_dir(os.path.join(out_dir, "gobuster"))
        self.proxy_url = proxy_url
        self.dir_wordlist = dir_wordlist
        self.sub_wordlist = sub_wordlist
        self.rate = rate
        self.threads = threads
        self.depth = depth
        self.delay_ms = max(1, int(1000 * threads / max(rate, 1)))
        self.bin = util.which("gobuster")

    def available(self) -> bool:
        if not self.bin:
            util.log("gobuster not found on PATH (apt install gobuster)", level="err")
            return False
        return True

    def scan_target(self, url: str) -> dict:
        if not self.available():
            return {"url": url, "findings": [], "error": "gobuster missing"}
        if not os.path.exists(self.dir_wordlist):
            util.log(f"dir wordlist missing: {self.dir_wordlist}", level="err")
            return {"url": url, "findings": [], "error": "wordlist missing"}

        util.log(f"gobuster dir: {url}", level="step")
        all_findings: list[dict] = []
        visited: set[str] = set()

        frontier = [(url.rstrip("/") + "/", 0)]
        while frontier:
            current, level = frontier.pop(0)
            if current in visited or level >= self.depth:
                continue
            visited.add(current)
            findings = self._run_dir(current)
            for f in findings:
                f["depth"] = level
                all_findings.append(f)
                child = self._child_url(current, f)
                if child and self._is_dir_like(f) and child not in visited:
                    frontier.append((child, level + 1))

        return {"url": url, "findings": all_findings}

    def _run_dir(self, url: str) -> list[dict]:
        slug = _slug(url)
        txt_path = os.path.join(self.out_dir, f"dir_{slug}.txt")
        cmd = [
            self.bin, "dir",
            "-u", url,
            "-w", self.dir_wordlist,
            "-t", str(self.threads),
            "--delay", f"{self.delay_ms}ms",
            "--proxy", self.proxy_url,
            "-b", config.GOBUSTER_STATUS_BLACKLIST,
            "-k",
            "-q", "--no-color",
            "-o", txt_path,
            "--no-error",
        ]
        util.run(cmd, timeout=3600)
        return self._parse_dir(txt_path, url)

    @staticmethod
    def _parse_dir(txt_path: str, url: str) -> list[dict]:
        findings: list[dict] = []
        if not os.path.exists(txt_path):
            return findings
        with open(txt_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = _DIR_RE.match(line.strip())
                if not m:
                    continue
                entry = {
                    "base": url,
                    "path": m.group("path"),
                    "status": int(m.group("code")),
                    "size": int(m.group("size")),
                }
                if m.group("redirect"):
                    entry["redirect"] = m.group("redirect").strip()
                findings.append(entry)
        return findings

    @staticmethod
    def _child_url(base: str, finding: dict) -> str:
        path = finding["path"].lstrip("/")
        return base.rstrip("/") + "/" + path + "/"

    @staticmethod
    def _is_dir_like(finding: dict) -> bool:
        if finding["status"] not in config.GOBUSTER_RECURSE_CODES:
            return False
        last = finding["path"].rstrip("/").rsplit("/", 1)[-1]
        return "." not in last

    def scan_subdomains(self, domain: str, resolver_ip: str = "") -> dict:
        if not self.available():
            return {"domain": domain, "findings": [], "error": "gobuster missing"}
        if not os.path.exists(self.sub_wordlist):
            util.log(f"subdomain wordlist missing: {self.sub_wordlist} "
                     f"(apt install seclists)", level="err")
            return {"domain": domain, "findings": [], "error": "wordlist missing"}

        util.log(f"gobuster dns: {domain}", level="step")
        slug = _slug(domain)
        txt_path = os.path.join(self.out_dir, f"dns_{slug}.txt")
        cmd = [
            self.bin, "dns",
            "-d", domain,
            "-w", self.sub_wordlist,
            "-t", str(self.threads),
            "--delay", f"{self.delay_ms}ms",
            "-q", "--no-color",
            "-o", txt_path,
            "--no-error",
        ]
        if resolver_ip:
            cmd += ["-r", f"{resolver_ip}:53"]
        util.run(cmd, timeout=1800)

        findings: list[dict] = []
        if os.path.exists(txt_path):
            with open(txt_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = _DNS_RE.match(line.strip())
                    if m:
                        findings.append({"subdomain": m.group("name")})
        util.log(f"gobuster dns {domain}: {len(findings)} subdomain(s)", level="ok")
        return {"domain": domain, "findings": findings}

def _slug(value: str) -> str:
    s = urlsplit(value)
    raw = (s.netloc + s.path) if s.scheme else value
    return re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("_") or "target"
