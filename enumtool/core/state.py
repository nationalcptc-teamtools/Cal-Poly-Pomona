from __future__ import annotations

import threading
from dataclasses import dataclass, field, asdict
from typing import Optional

@dataclass
class Port:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    is_web: Optional[bool] = None
    scheme: str = ""

    def as_dict(self) -> dict:
        return asdict(self)

@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostnames: list[str] = field(default_factory=list)
    os_family: str = "unknown"
    os_name: str = ""
    ports: dict[int, Port] = field(default_factory=dict)
    web_targets: list[str] = field(default_factory=list)

    def open_ports(self) -> list[Port]:
        return [p for p in self.ports.values() if p.state == "open"]

    def as_dict(self) -> dict:
        d = asdict(self)
        d["ports"] = [p.as_dict() for p in self.ports.values()]
        return d

class State:

    PHASES = {
        "init": "Initializing",
        "ping": "Host discovery (ICMP ping sweep)",
        "common": "Common-port scan (top 1000 + services + OS)",
        "allports": "Full TCP port scan (1-65535)",
        "webenum": "Web enumeration (gobuster)",
        "vulnscan": "Auto vulnerability scan (nuclei/bbot)",
        "done": "Complete",
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.hosts: dict[str, Host] = {}
        self.phase: str = "init"
        self.started_at: Optional[float] = None
        self.notes: list[str] = []

    def set_phase(self, phase: str) -> None:
        with self._lock:
            self.phase = phase

    def add_note(self, note: str) -> None:
        with self._lock:
            self.notes.append(note)

    def add_host(self, ip: str, **kwargs) -> Host:
        with self._lock:
            host = self.hosts.get(ip)
            if host is None:
                host = Host(ip=ip)
                self.hosts[ip] = host
            for k, v in kwargs.items():
                if v:
                    setattr(host, k, v)
            return host

    def set_port(self, ip: str, port: Port) -> None:
        with self._lock:
            host = self.hosts.setdefault(ip, Host(ip=ip))
            existing = host.ports.get(port.port)
            if existing:
                for attr in ("service", "product", "version"):
                    if getattr(port, attr):
                        setattr(existing, attr, getattr(port, attr))
                existing.state = port.state
            else:
                host.ports[port.port] = port

    def mark_web(self, ip: str, port: int, scheme: str, target_url: str) -> None:
        with self._lock:
            host = self.hosts.get(ip)
            if not host:
                return
            p = host.ports.get(port)
            if p:
                p.is_web = True
                p.scheme = scheme
            if target_url not in host.web_targets:
                host.web_targets.append(target_url)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "phase": self.phase,
                "phase_label": self.PHASES.get(self.phase, self.phase),
                "notes": list(self.notes),
                "hosts": [h.as_dict() for h in sorted(self.hosts.values(),
                                                       key=_ip_sort_key)],
            }

    def live_ips(self) -> list[str]:
        with self._lock:
            return sorted(self.hosts.keys(), key=_ip_sort_key_str)

    def hosts_by_os(self) -> dict[str, list[Host]]:
        with self._lock:
            buckets: dict[str, list[Host]] = {"windows": [], "linux": [], "unknown": []}
            for h in sorted(self.hosts.values(), key=_ip_sort_key):
                key = h.os_family if h.os_family in buckets else "unknown"
                buckets[key].append(h)
            return buckets

def _ip_sort_key(host: Host):
    return _ip_sort_key_str(host.ip)

def _ip_sort_key_str(ip: str):
    try:
        return tuple(int(x) for x in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)
