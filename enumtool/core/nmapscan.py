from __future__ import annotations

import os
import xml.etree.ElementTree as ET

from . import config, util
from .state import Port, State

def _run_nmap(args: list[str], xml_path: str, timeout: int | None) -> bool:
    nmap = util.which("nmap")
    if not nmap:
        util.log("nmap not found on PATH -- install it (apt install nmap)", level="err")
        return False
    cmd = [nmap, *args, "-oX", xml_path]
    result = util.run(cmd, timeout=timeout)
    if result.returncode not in (0, 124):
        util.log(f"nmap exited {result.returncode}: {result.stderr.strip()[:200]}",
                 level="warn")
    return os.path.exists(xml_path)

def ping_sweep(ranges: list[str], out_dir: str, state: State,
               timeout: int = 900) -> list[str]:
    state.set_phase("ping")
    util.log(f"ping sweep over {len(ranges)} range(s): {', '.join(ranges)}",
             level="step")
    xml_path = os.path.join(out_dir, "nmap_ping.xml")
    args = ["-sn", "-PE", "-n", "--max-retries", "1", *ranges]
    if not _run_nmap(args, xml_path, timeout):
        return []
    live = _parse_hosts(xml_path, state, ports=False)
    util.log(f"discovered {len(live)} live host(s)", level="ok")
    return live

def common_scan(ips: list[str], out_dir: str, state: State,
                timeout: int = 1800) -> str | None:
    if not ips:
        return None
    state.set_phase("common")
    util.log(f"common-port scan on {len(ips)} host(s)", level="step")
    xml_path = os.path.join(out_dir, "nmap_common.xml")
    if util.is_root():
        base = ["-sS", "-sV", "-O", "--top-ports", "1000"]
    else:
        util.log("not root: using TCP connect scan, skipping OS detection",
                 level="warn")
        base = ["-sT", "-sV", "--top-ports", "1000"]
    args = [*base, "-n", "-T4", *ips]
    if not _run_nmap(args, xml_path, timeout):
        return None
    _parse_hosts(xml_path, state, ports=True)
    util.log("common-port scan complete", level="ok")
    return xml_path

def allports_scan(ips: list[str], out_dir: str, state: State,
                  timeout: int = 3600) -> str | None:
    if not ips:
        return None
    state.set_phase("allports")
    util.log(f"full port scan (1-65535) on {len(ips)} host(s)", level="step")
    xml_path = os.path.join(out_dir, "nmap_allports.xml")
    scan_type = "-sS" if util.is_root() else "-sT"
    args = [scan_type, "-sV", "-p-", "-n", "-T4", "--min-rate", "1000", *ips]
    if not _run_nmap(args, xml_path, timeout):
        return None
    _parse_hosts(xml_path, state, ports=True)
    util.log("full port scan complete", level="ok")
    return xml_path

def _parse_hosts(xml_path: str, state: State, *, ports: bool) -> list[str]:
    live: list[str] = []
    try:
        context = ET.iterparse(xml_path, events=("end",))
    except (ET.ParseError, FileNotFoundError) as exc:
        util.log(f"could not parse {xml_path}: {exc}", level="warn")
        return live

    for _event, elem in context:
        if elem.tag != "host":
            continue
        status = elem.find("status")
        if status is not None and status.get("state") != "up":
            elem.clear()
            continue

        ip = ""
        mac = ""
        vendor = ""
        for addr in elem.findall("address"):
            atype = addr.get("addrtype")
            if atype == "ipv4":
                ip = addr.get("addr", "")
            elif atype == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")
        if not ip:
            elem.clear()
            continue

        hostnames = [hn.get("name", "") for hn in elem.findall("hostnames/hostname")
                     if hn.get("name")]
        os_family, os_name = _extract_os(elem)
        host = state.add_host(ip, mac=mac, vendor=vendor)
        if hostnames:
            host.hostnames = util.dedup(host.hostnames + hostnames)
        if os_family != "unknown":
            host.os_family = os_family
            host.os_name = os_name

        if ports:
            family_before = host.os_family
            for port_el in elem.findall("ports/port"):
                p = _extract_port(port_el)
                if p:
                    state.set_port(ip, p)
            if family_before == "unknown":
                guess = _os_from_services(host)
                if guess != "unknown":
                    host.os_family = guess

        live.append(ip)
        elem.clear()
    return live

def _extract_port(port_el: ET.Element) -> Port | None:
    stateel = port_el.find("state")
    if stateel is None or stateel.get("state") != "open":
        return None
    try:
        portid = int(port_el.get("portid", "0"))
    except ValueError:
        return None
    svc = port_el.find("service")
    service = svc.get("name", "") if svc is not None else ""
    product = svc.get("product", "") if svc is not None else ""
    version = svc.get("version", "") if svc is not None else ""
    tunnel = svc.get("tunnel", "") if svc is not None else ""
    if tunnel == "ssl" and service in ("http", "http-alt", "http-proxy"):
        service = "ssl/" + service
    return Port(
        port=portid,
        protocol=port_el.get("protocol", "tcp"),
        state="open",
        service=service,
        product=product,
        version=version,
    )

def _extract_os(host_el: ET.Element) -> tuple[str, str]:
    best_name = ""
    for osmatch in host_el.findall("os/osmatch"):
        best_name = osmatch.get("name", "") or best_name
        for osclass in osmatch.findall("osclass"):
            family = (osclass.get("osfamily") or "").lower()
            if "windows" in family:
                return "windows", best_name
            if "linux" in family:
                return "linux", best_name
        if best_name:
            break
    return "unknown", best_name

def _os_from_services(host) -> str:
    blob = " ".join(
        f"{p.product} {p.version} {p.service}".lower()
        for p in host.ports.values()
    )
    if any(k in blob for k in ("windows", "microsoft", "iis", "win32", "win64")):
        return "windows"
    if any(k in blob for k in ("ubuntu", "debian", "linux", "unix",
                               "apache", "nginx", "openssh")):
        return "linux"
    return "unknown"
