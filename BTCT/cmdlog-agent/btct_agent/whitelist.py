"""Server-driven whitelist with a local fallback.

The agent fetches the tool list from GET /api/cmdlog/whitelist at startup and
refreshes periodically, so an admin can change what's logged mid-engagement for
everyone at once. If the server is unreachable we keep the last good list, or
fall back to DEFAULT_WHITELIST on a cold start.
"""
from __future__ import annotations

import json
import threading
import urllib.request
from typing import Optional, Set

# Mirrors server/cmdlog.mjs DEFAULT_WHITELIST: used only when the server has
# never been reachable.
DEFAULT_WHITELIST = {
    "nmap", "masscan", "rustscan", "gobuster", "feroxbuster", "ffuf", "dirb", "dirbuster",
    "nikto", "whatweb", "wpscan", "hydra", "medusa", "ncrack", "sqlmap", "crackmapexec",
    "nxc", "netexec", "evil-winrm", "responder", "bloodhound-python", "enum4linux",
    "enum4linux-ng", "smbclient", "smbmap", "rpcclient", "ldapsearch", "kerbrute",
    "impacket-secretsdump", "impacket-psexec", "impacket-wmiexec", "impacket-GetUserSPNs",
    "impacket-GetNPUsers", "secretsdump.py", "psexec.py", "wmiexec.py", "GetUserSPNs.py",
    "GetNPUsers.py", "hashcat", "john", "msfconsole", "msfvenom", "searchsploit", "curl",
    "wget", "ssh", "nc", "ncat", "netcat", "socat", "proxychains", "proxychains4", "ping",
}


class Whitelist:
    """Thread-safe holder for the current tool set."""

    def __init__(self, server: str, token: str) -> None:
        self._url = server.rstrip("/") + "/api/cmdlog/whitelist"
        self._token = token
        self._lock = threading.Lock()
        self._tools: Set[str] = set(DEFAULT_WHITELIST)

    def tools(self) -> Set[str]:
        with self._lock:
            return set(self._tools)

    def refresh(self, timeout: float = 5.0) -> bool:
        """Fetch the server list. Returns True on success, False on any error
        (keeping the previous list)."""
        try:
            req = urllib.request.Request(
                self._url, headers={"Authorization": f"Bearer {self._token}"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            tools = data.get("tools")
            if isinstance(tools, list) and tools:
                clean = {str(t).strip().lower() for t in tools if str(t).strip()}
                with self._lock:
                    self._tools = clean
                return True
        except Exception:
            pass
        return False
