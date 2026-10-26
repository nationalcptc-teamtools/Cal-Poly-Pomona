from __future__ import annotations

import os

DIR_WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
SUBDOMAIN_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

REQUESTS_PER_SECOND = 20

STATUS_WEB_PORT = 8080
STATUS_REFRESH_SECONDS = 5

THROTTLE_PROXY_HOST = "127.0.0.1"
THROTTLE_PROXY_PORT = 8081

KNOWN_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888, 4443, 9443, 3000, 5000}

WEB_SERVICE_NAMES = {
    "http", "https", "http-alt", "http-proxy", "https-alt",
    "ssl/http", "ssl/https", "ssl/http-alt", "sun-answerbook", "http-mgmt",
}

GOBUSTER_RECURSION_DEPTH = 2
GOBUSTER_RECURSE_CODES = {200, 301, 302, 307, 401, 403}
GOBUSTER_STATUS_BLACKLIST = "404"

DEFAULT_OUTPUT_DIR = "./enum_results"
BTCT_URL = os.environ.get("ENUMTOOL_BTCT_URL", os.environ.get("ENUMTOOL_SEND_URL", ""))
SCAN_TOKEN = os.environ.get("ENUMTOOL_SCAN_TOKEN", "")
WORKSPACE = os.environ.get("ENUMTOOL_WORKSPACE", "")

HOSTS_MARKER = "# added-by-enumtool"
