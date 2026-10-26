from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import config, installer, nmapscan, util, webdetect
from .btct import BTCTClient, gobuster_dir_findings, gobuster_dns_findings
from .gobusterscan import GobusterScanner
from .state import State
from .throttle import ThrottleProxy
from .vulnscan import AutoVulnScanner
from .webserver import StatusServer

class Orchestrator:
    def __init__(self, args) -> None:
        self.args = args
        self.out_dir = util.ensure_dir(args.out)
        self.state = State()
        self.btct = BTCTClient(args.btct_url, args.scan_token, args.workspace,
                               scan=args.scan_name, out_dir=self.out_dir)
        self.proxy = ThrottleProxy(config.THROTTLE_PROXY_HOST,
                                   config.THROTTLE_PROXY_PORT, args.rate)
        self.web = StatusServer(self.state, port=args.web_port)
        self.scanner = GobusterScanner(
            self.out_dir, self.proxy.proxy_url,
            dir_wordlist=args.wordlist,
            sub_wordlist=args.subdomain_wordlist,
            rate=args.rate,
            depth=args.recursion_depth,
        )
        self._scanned_urls: set[str] = set()
        self._scanned_domains: set[str] = set()

    def run(self) -> None:
        if not installer.ensure_core():
            util.log("core tools missing; aborting", level="err")
            return

        self.web.start()
        self.proxy.start()
        util.log(f"status site: http://127.0.0.1:{self.args.web_port}/", level="ok")

        ranges = self.args.ranges
        live = nmapscan.ping_sweep(ranges, self.out_dir, self.state)
        if not live:
            util.log("no live hosts found; nothing to do", level="warn")
            self._idle()
            return

        common_xml = nmapscan.common_scan(live, self.out_dir, self.state)
        self._send_nmap(common_xml)

        allports_thread = threading.Thread(
            target=self._allports_worker, args=(live,), daemon=True)
        if not self.args.no_allports:
            allports_thread.start()

        self._web_enumeration(live)

        if not self.args.no_allports:
            allports_thread.join()
            self._web_enumeration(live, note="post-allports")

        self._subdomain_enumeration()

        self._auto_vuln()

        self.state.set_phase("done")
        util.log("enumeration complete", level="ok")
        self._idle()

    def _send_nmap(self, xml_path: str | None) -> None:
        if xml_path:
            self.btct.send_nmap_xml(xml_path)

    def _allports_worker(self, live: list[str]) -> None:
        xml = nmapscan.allports_scan(live, self.out_dir, self.state)
        self._send_nmap(xml)

    def _web_enumeration(self, live: list[str], note: str = "") -> None:
        self.state.set_phase("webenum")
        targets = webdetect.detect(live, self.state, add_hosts=self.args.add_hosts)
        todo = [t for t in targets if t["url"] not in self._scanned_urls]
        if not todo:
            return
        util.log(f"web enumeration{(' (' + note + ')') if note else ''}: "
                 f"{len(todo)} target(s)", level="step")
        for t in todo:
            self._scanned_urls.add(t["url"])

        max_workers = max(1, min(len(todo), self.args.web_workers))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self.scanner.scan_target, t["url"]): t
                       for t in todo}
            for fut in as_completed(futures):
                t = futures[fut]
                try:
                    result = fut.result()
                except Exception as exc:
                    util.log(f"gobuster failed on {t['url']}: {exc}", level="warn")
                    continue
                count = len(result.get("findings", []))
                util.log(f"gobuster {t['url']}: {count} path(s)", level="ok")
                findings = gobuster_dir_findings(result, t["port"])
                target = {"ip": t["ip"], "port": t["port"], "url": t["url"]}
                if t.get("host") and t["host"] != t["ip"]:
                    target["hostname"] = t["host"]
                self.btct.send_tool("gobuster", target, findings)

    def _subdomain_enumeration(self) -> None:
        pairs: dict[str, str] = {}
        for host in self.state.hosts.values():
            for name in host.hostnames:
                if "." in name and name not in pairs:
                    pairs[name] = host.ip
        pending = {d: ip for d, ip in pairs.items()
                   if d not in self._scanned_domains}
        if not pending:
            return
        util.log(f"subdomain brute on {len(pending)} domain(s)", level="step")
        if not installer.ensure_seclists():
            return
        for domain, resolver_ip in pending.items():
            self._scanned_domains.add(domain)
            result = self.scanner.scan_subdomains(domain, resolver_ip)
            findings = gobuster_dns_findings(result)
            self.btct.send_tool("gobuster", {"ip": resolver_ip}, findings)

    def _collect_web_targets(self) -> list[dict]:
        seen: set[str] = set()
        out = []
        for host in self.state.hosts.values():
            for url in host.web_targets:
                if url not in seen:
                    seen.add(url)
                    out.append({"ip": host.ip, "url": url})
        return out

    def _auto_vuln(self) -> None:
        if self.args.no_vuln_scan:
            return
        targets = self._collect_web_targets()
        if not targets and not self.args.bbot:
            return
        self.state.set_phase("vulnscan")
        scanner = AutoVulnScanner(
            self.out_dir, self.proxy.proxy_url, self.args.rate,
            nuclei_severity=self.args.nuclei_severity,
            bbot_preset=self.args.bbot_preset,
            wpscan_api_token=self.args.wpscan_api_token,
        )

        # URL-driven scanners, each fanned out across web targets.
        if targets and scanner.ensure_nuclei():
            self._run_web_tool("nuclei", scanner.nuclei, targets)
        if targets and self.args.nikto and scanner.ensure_nikto():
            self._run_web_tool("nikto", scanner.nikto, targets)
        if targets and self.args.wpscan and scanner.ensure_wpscan():
            self._run_web_tool("wpscan", scanner.wpscan, targets)
        if targets and self.args.secretfinder and scanner.ensure_secretfinder():
            self._run_web_tool("secretfinder", scanner.secretfinder, targets)

        if self.args.bbot and scanner.ensure_bbot():
            for host in self.state.hosts.values():
                if not host.open_ports():
                    continue
                target = host.hostnames[0] if host.hostnames else host.ip
                try:
                    groups = scanner.bbot(target, host.ip,
                                          include_context=self.args.bbot_context)
                except Exception as exc:
                    util.log(f"bbot failed on {target}: {exc}", level="warn")
                    continue
                self._send_groups("bbot", groups)

    def _run_web_tool(self, tool: str, fn, targets: list[dict]) -> None:
        util.log(f"auto vuln scan ({tool}) on {len(targets)} web target(s)",
                 level="step")
        workers = max(1, min(len(targets), self.args.web_workers))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(fn, t["url"], t["ip"]): t for t in targets}
            for fut in as_completed(futures):
                t = futures[fut]
                try:
                    groups = fut.result()
                except Exception as exc:  # noqa: BLE001
                    util.log(f"{tool} failed on {t['url']}: {exc}", level="warn")
                    continue
                self._send_groups(tool, groups)

    def _send_groups(self, tool: str, groups: list[dict]) -> None:
        for g in groups:
            count = len(g.get("findings", []))
            util.log(f"{tool} {g['target'].get('ip')}: {count} finding(s)",
                     level="ok")
            self.btct.send_tool(tool, g["target"], g["findings"])

    def _idle(self) -> None:
        util.log("status site still serving — press Ctrl+C to stop", level="info")
        try:
            while True:
                threading.Event().wait(3600)
        except KeyboardInterrupt:
            util.log("shutting down", level="info")
        finally:
            self.proxy.stop()
            self.web.stop()
