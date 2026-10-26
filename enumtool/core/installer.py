from __future__ import annotations

import os

from . import config, util

TOOLS_DIR = os.path.expanduser("~/.local/share/enumtool/tools")

def _apt() -> str | None:
    return util.which("apt-get") or util.which("apt")

def _sudo_prefix() -> list[str]:
    if util.is_root():
        return []
    if util.which("sudo"):
        return ["sudo", "-n"]
    return []

def apt_install(pkg: str) -> bool:
    apt = _apt()
    if not apt:
        return False
    util.log(f"installing {pkg} via apt…", level="step")
    res = util.run([*_sudo_prefix(), apt, "install", "-y", pkg], timeout=600)
    return res.returncode == 0

def ensure_seclists() -> bool:
    if os.path.exists(config.SUBDOMAIN_WORDLIST):
        return True
    util.log("seclists not found; attempting install", level="warn")
    if apt_install("seclists") and os.path.exists(config.SUBDOMAIN_WORDLIST):
        return True
    util.log(f"seclists unavailable; subdomain scan needs "
             f"{config.SUBDOMAIN_WORDLIST}", level="err")
    return False

def ensure_dir_wordlist() -> bool:
    if os.path.exists(config.DIR_WORDLIST):
        return True
    util.log(f"dir wordlist missing ({config.DIR_WORDLIST}); "
             f"install 'dirbuster' or 'wordlists' package", level="warn")
    apt_install("wordlists")
    return os.path.exists(config.DIR_WORDLIST)

def ensure_core() -> bool:
    ok = True
    for pkg in ("nmap", "gobuster"):
        if not util.which(pkg):
            util.log(f"{pkg} missing; attempting install", level="warn")
            if not apt_install(pkg) or not util.which(pkg):
                util.log(f"{pkg} still missing — install it manually", level="err")
                ok = False
    return ok

def ensure_sqlmap() -> list[str] | None:
    if util.which("sqlmap"):
        return ["sqlmap"]
    if apt_install("sqlmap") and util.which("sqlmap"):
        return ["sqlmap"]
    path = _git_clone("https://github.com/sqlmapproject/sqlmap.git", "sqlmap")
    if path and os.path.exists(os.path.join(path, "sqlmap.py")):
        return ["python3", os.path.join(path, "sqlmap.py")]
    return None

def ensure_dalfox() -> list[str] | None:
    if util.which("dalfox"):
        return ["dalfox"]
    if apt_install("dalfox") and util.which("dalfox"):
        return ["dalfox"]
    go = util.which("go")
    if go:
        util.log("installing dalfox via go…", level="step")
        util.run([go, "install", "github.com/hahwul/dalfox/v2@latest"], timeout=600)
        gobin = os.path.join(os.path.expanduser("~/go/bin"), "dalfox")
        if os.path.exists(gobin):
            return [gobin]
        if util.which("dalfox"):
            return ["dalfox"]
    util.log("dalfox install failed (need apt or go)", level="err")
    return None

def ensure_sstimap() -> list[str] | None:
    if util.which("sstimap"):
        return ["sstimap"]
    path = _git_clone("https://github.com/vladko312/SSTImap.git", "SSTImap")
    if not path:
        return None
    script = os.path.join(path, "sstimap.py")
    if not os.path.exists(script):
        return None
    req = os.path.join(path, "requirements.txt")
    pip = util.which("pip3") or util.which("pip")
    if pip and os.path.exists(req):
        util.run([pip, "install", "--quiet", "-r", req], timeout=600)
    return ["python3", script]

def ensure_nuclei() -> list[str] | None:
    if util.which("nuclei"):
        return ["nuclei"]
    if apt_install("nuclei") and util.which("nuclei"):
        return ["nuclei"]
    go = util.which("go")
    if go:
        util.log("installing nuclei via go…", level="step")
        util.run([go, "install",
                  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
                 timeout=900)
        gobin = os.path.join(os.path.expanduser("~/go/bin"), "nuclei")
        if os.path.exists(gobin):
            return [gobin]
        if util.which("nuclei"):
            return ["nuclei"]
    util.log("nuclei install failed (need apt or go)", level="err")
    return None

def ensure_bbot() -> list[str] | None:
    if util.which("bbot"):
        return ["bbot"]
    pipx = util.which("pipx")
    if pipx:
        util.log("installing bbot via pipx…", level="step")
        util.run([pipx, "install", "bbot"], timeout=1200)
        if util.which("bbot"):
            return ["bbot"]
    pip = util.which("pip3") or util.which("pip")
    if pip:
        util.log("installing bbot via pip…", level="step")
        util.run([pip, "install", "--quiet", "bbot"], timeout=1200)
        if util.which("bbot"):
            return ["bbot"]
    util.log("bbot install failed (need pipx or pip)", level="err")
    return None

def ensure_nikto() -> list[str] | None:
    if util.which("nikto"):
        return ["nikto"]
    if apt_install("nikto") and util.which("nikto"):
        return ["nikto"]
    util.log("nikto install failed (apt install nikto)", level="err")
    return None


def ensure_wpscan() -> list[str] | None:
    if util.which("wpscan"):
        return ["wpscan"]
    if apt_install("wpscan") and util.which("wpscan"):
        return ["wpscan"]
    gem = util.which("gem")
    if gem:
        util.log("installing wpscan via gem…", level="step")
        util.run([*_sudo_prefix(), gem, "install", "wpscan"], timeout=900)
        if util.which("wpscan"):
            return ["wpscan"]
    util.log("wpscan install failed (apt or gem)", level="err")
    return None


def ensure_gitleaks() -> list[str] | None:
    if util.which("gitleaks"):
        return ["gitleaks"]
    if apt_install("gitleaks") and util.which("gitleaks"):
        return ["gitleaks"]
    go = util.which("go")
    if go:
        util.log("installing gitleaks via go…", level="step")
        util.run([go, "install", "github.com/gitleaks/gitleaks/v8@latest"],
                 timeout=900)
        gobin = os.path.join(os.path.expanduser("~/go/bin"), "gitleaks")
        if os.path.exists(gobin):
            return [gobin]
        if util.which("gitleaks"):
            return ["gitleaks"]
    util.log("gitleaks install failed (apt or go)", level="err")
    return None


def ensure_secretfinder() -> list[str] | None:
    if util.which("SecretFinder.py"):
        return ["python3", util.which("SecretFinder.py")]
    path = _git_clone("https://github.com/m4ll0k/SecretFinder.git", "SecretFinder")
    if not path:
        return None
    script = os.path.join(path, "SecretFinder.py")
    if not os.path.exists(script):
        return None
    pip = util.which("pip3") or util.which("pip")
    req = os.path.join(path, "requirements.txt")
    if pip and os.path.exists(req):
        util.run([pip, "install", "--quiet", "-r", req], timeout=600)
    return ["python3", script]


def ensure_vuln_tools(selected: list[str]) -> dict[str, list[str]]:
    resolvers = {
        "sqlmap": ensure_sqlmap,
        "dalfox": ensure_dalfox,
        "sstimap": ensure_sstimap,
    }
    cmds: dict[str, list[str]] = {}
    for tool in selected:
        resolver = resolvers.get(tool)
        if not resolver:
            util.log(f"unknown vuln tool: {tool}", level="warn")
            continue
        cmd = resolver()
        if cmd:
            cmds[tool] = cmd
            util.log(f"{tool} ready: {' '.join(cmd)}", level="ok")
        else:
            util.log(f"{tool} unavailable — skipping", level="err")
    return cmds

def _git_clone(url: str, name: str) -> str | None:
    git = util.which("git")
    if not git:
        util.log("git not available for fallback clone", level="warn")
        return None
    util.ensure_dir(TOOLS_DIR)
    dest = os.path.join(TOOLS_DIR, name)
    if os.path.isdir(dest):
        return dest
    util.log(f"cloning {url} -> {dest}", level="step")
    res = util.run([git, "clone", "--depth", "1", url, dest], timeout=600)
    return dest if res.returncode == 0 else None
