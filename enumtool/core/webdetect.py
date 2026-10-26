from __future__ import annotations

import http.client
import os
import ssl
from urllib.parse import urlsplit

from . import config, util
from .state import State

_TLS = ssl.create_default_context()
_TLS.check_hostname = False
_TLS.verify_mode = ssl.CERT_NONE

def _probe(ip: str, port: int, scheme: str, timeout: float = 5.0):
    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=_TLS)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("GET", "/", headers={"User-Agent": "enumtool/1.0",
                                          "Connection": "close"})
        resp = conn.getresponse()
        status = resp.status
        location = resp.getheader("Location", "") or ""
        resp.read(1)
        conn.close()
    except (OSError, http.client.HTTPException, ssl.SSLError):
        return None

    location_host = ""
    if 300 <= status < 400 and location:
        loc = urlsplit(location)
        if loc.hostname and loc.hostname != ip:
            location_host = loc.hostname
    return status, location_host

def _schemes_for(port, nmap_service: str) -> list[str]:
    svc = (nmap_service or "").lower()
    if "ssl" in svc or "https" in svc or port in (443, 8443, 9443, 4443):
        return ["https"]
    if "http" in svc or port in config.KNOWN_WEB_PORTS:
        return ["http"]
    return ["http", "https"]

def detect(ips: list[str], state: State, *, add_hosts: bool = False) -> list[dict]:
    targets: list[dict] = []
    for ip in ips:
        host = state.hosts.get(ip)
        if not host:
            continue
        for p in host.open_ports():
            if p.is_web is False:
                continue
            for scheme in _schemes_for(p.port, p.service):
                if not util.tcp_open(ip, p.port, timeout=3):
                    continue
                result = _probe(ip, p.port, scheme)
                if result is None:
                    continue
                _status, location_host = result

                target_host = ip
                if location_host:
                    util.log(f"{ip}:{p.port} redirects to '{location_host}' "
                             f"-- switching to that vhost", level="info")
                    target_host = location_host
                    if location_host not in host.hostnames:
                        host.hostnames.append(location_host)
                    if add_hosts:
                        add_hosts_entry(location_host, ip)

                url = _build_url(scheme, target_host, p.port)
                state.mark_web(ip, p.port, scheme, url)
                targets.append({
                    "ip": ip, "port": p.port, "scheme": scheme,
                    "host": target_host, "url": url,
                })
                util.log(f"web service: {url}", level="ok")
                break
            else:
                if p.is_web is None:
                    p.is_web = False
    return targets

def _build_url(scheme: str, host: str, port: int) -> str:
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return f"{scheme}://{host}/" if default else f"{scheme}://{host}:{port}/"

def add_hosts_entry(domain: str, ip: str, hosts_path: str = "/etc/hosts") -> bool:
    if not domain or not ip:
        return False
    try:
        existing = ""
        if os.path.exists(hosts_path):
            with open(hosts_path, "r", encoding="utf-8", errors="replace") as fh:
                existing = fh.read()
        for line in existing.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == ip and domain in parts[1:]:
                return True
        with open(hosts_path, "a", encoding="utf-8") as fh:
            fh.write(f"{ip}\t{domain}  {config.HOSTS_MARKER}\n")
        util.log(f"/etc/hosts: {ip} -> {domain}", level="ok")
        return True
    except PermissionError:
        util.log(f"cannot write {hosts_path} (need root); add manually: "
                 f"{ip} {domain}", level="warn")
        return False
    except OSError as exc:
        util.log(f"/etc/hosts update failed: {exc}", level="warn")
        return False

def cleanup_hosts(hosts_path: str = "/etc/hosts") -> None:
    try:
        if not os.path.exists(hosts_path):
            return
        with open(hosts_path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        kept = [ln for ln in lines if config.HOSTS_MARKER not in ln]
        if len(kept) != len(lines):
            with open(hosts_path, "w", encoding="utf-8") as fh:
                fh.writelines(kept)
            util.log("removed enumtool /etc/hosts entries", level="ok")
    except (OSError, PermissionError):
        pass
