from __future__ import annotations

import argparse
import sys

from . import config

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="HTB/CPTC recon: nmap + gobuster discovery with a live "
                    "status site, auto vuln scanning, and BTCT upload.",
    )
    sub = parser.add_subparsers(dest="command", required=False)

    e = sub.add_parser("enum", help="host discovery, port + web enumeration")
    e.add_argument("ranges", nargs="+",
                   help="IP ranges/CIDRs to scan, e.g. 10.10.10.0/24")
    e.add_argument("--out", default=config.DEFAULT_OUTPUT_DIR,
                   help="output directory (default: %(default)s)")
    e.add_argument("--web-port", type=int, default=config.STATUS_WEB_PORT,
                   help="status website port (default: %(default)s)")
    e.add_argument("--rate", type=int, default=config.REQUESTS_PER_SECOND,
                   help="max HTTP requests/sec per host (default: %(default)s)")
    e.add_argument("--wordlist", default=config.DIR_WORDLIST,
                   help="gobuster directory wordlist")
    e.add_argument("--subdomain-wordlist", default=config.SUBDOMAIN_WORDLIST,
                   help="gobuster DNS/subdomain wordlist")
    e.add_argument("--recursion-depth", type=int,
                   default=config.GOBUSTER_RECURSION_DEPTH,
                   help="gobuster recursion depth (1 = no recursion)")
    e.add_argument("--web-workers", type=int, default=4,
                   help="concurrent gobuster targets (kept low for RAM)")
    e.add_argument("--no-allports", action="store_true",
                   help="skip the full 1-65535 TCP scan")
    e.add_argument("--add-hosts", action="store_true",
                   help="add discovered vhosts to /etc/hosts (needs root)")
    e.add_argument("--no-vuln-scan", action="store_true",
                   help="skip the automatic nuclei vuln scan of web targets")
    e.add_argument("--nuclei-severity", default="low,medium,high,critical",
                   help="nuclei severities to report (default: %(default)s; "
                        "set to include 'info' for tech-detection noise)")
    e.add_argument("--bbot", action="store_true",
                   help="also run bbot per host in the auto phase (heavier; "
                        "auto-installed on first use)")
    e.add_argument("--bbot-preset", default="web-basic",
                   help="bbot preset/flag to run (default: %(default)s)")
    e.add_argument("--bbot-context", action="store_true",
                   help="include bbot TECHNOLOGY/DNS_NAME/OPEN_TCP_PORT as info")
    e.add_argument("--nikto", action="store_true",
                   help="also run nikto on each web target (auto-installed)")
    e.add_argument("--wpscan", action="store_true",
                   help="also run wpscan on each web target (auto-installed)")
    e.add_argument("--wpscan-api-token", default="",
                   help="WPScan API token for vulnerability data (optional)")
    e.add_argument("--secretfinder", action="store_true",
                   help="also run SecretFinder on each web target for JS secrets")
    _add_btct_args(e)

    v = sub.add_parser("vuln", help="run sqlmap/sstimap/dalfox on a request file")
    v.add_argument("--request", "-r", required=True,
                   help="raw HTTP request file (req.txt / request.txt)")
    v.add_argument("--tools", "-t", default="all",
                   help="comma list of sqlmap,sstimap,dalfox or 'all' "
                        "(default: all)")
    v.add_argument("--scheme", default="http", choices=("http", "https"),
                   help="scheme for the request (default: http)")
    v.add_argument("--out", default=config.DEFAULT_OUTPUT_DIR,
                   help="output directory (default: %(default)s)")
    v.add_argument("--install", action="store_true",
                   help="install any missing tools before running")
    _add_btct_args(v)

    s = sub.add_parser("sync",
                       help="re-send a prior run's saved results to BTCT "
                            "(catch-up if --btct-url wasn't set, or a send was "
                            "missed)")
    s.add_argument("--out", default=config.DEFAULT_OUTPUT_DIR,
                   help="results directory to replay from (default: %(default)s)")
    _add_btct_args(s)

    ig = sub.add_parser("ingest",
                        help="forward a saved scanner report to BTCT")
    ig.add_argument("--tool", "-t", required=True,
                    choices=("openvas", "nuclei", "bbot", "wpscan", "nikto",
                             "gitleaks", "secretfinder"),
                    help="which tool produced the file")
    ig.add_argument("--file", "-f", required=True,
                    help="the result file (OpenVAS/GVM XML; nuclei JSONL; bbot "
                         "NDJSON; wpscan/nikto/gitleaks JSON; SecretFinder text)")
    ig.add_argument("--ip",
                    help="attach all findings to this host IP (override; "
                         "otherwise the host IP is read from the file). "
                         "Required for gitleaks/secretfinder reports.")
    ig.add_argument("--include-context", action="store_true",
                    help="bbot only: also send TECHNOLOGY/DNS_NAME/OPEN_TCP_PORT "
                         "events as info findings")
    ig.add_argument("--out", default=config.DEFAULT_OUTPUT_DIR,
                    help="output directory for the local record (default: "
                         "%(default)s)")
    _add_btct_args(ig)

    sec = sub.add_parser("secrets",
                         help="run gitleaks on recovered source and forward "
                              "secrets to BTCT")
    sec.add_argument("--path", "-p", required=True,
                     help="directory or git repo of recovered source to scan")
    sec.add_argument("--ip", required=True,
                     help="host IP these secrets belong to (for BTCT attach)")
    sec.add_argument("--out", default=config.DEFAULT_OUTPUT_DIR,
                     help="output directory (default: %(default)s)")
    _add_btct_args(sec)
    return parser

def _add_btct_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("BTCT scan-ingest")
    g.add_argument("--btct-url", default=config.BTCT_URL,
                   help="BTCT base URL, e.g. http://10.10.14.5:8080 "
                        "(or set ENUMTOOL_BTCT_URL). Omit = save to disk only.")
    g.add_argument("--scan-token", default=config.SCAN_TOKEN,
                   help="BTCT bearer token, if the team set one "
                        "(or set ENUMTOOL_SCAN_TOKEN)")
    g.add_argument("--workspace", default=config.WORKSPACE,
                   help="BTCT workspace id or exact name "
                        "(or set ENUMTOOL_WORKSPACE; omit = default workspace)")
    g.add_argument("--scan-name", default=None,
                   help="BTCT scan-group name; shared across this run's nmap "
                        "uploads so hosts merge. Default: 'enumtool <date>' for "
                        "a new run, or the original run's name when syncing.")

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "enum":
        from .orchestrator import Orchestrator
        Orchestrator(args).run()
        return 0

    if args.command == "sync":
        from .btct import BTCTClient, read_saved_scan_name, sync_dir
        if not args.btct_url:
            print("error: --btct-url (or ENUMTOOL_BTCT_URL) is required to sync",
                  file=sys.stderr)
            return 2
        scan = args.scan_name or read_saved_scan_name(args.out) or None
        client = BTCTClient(args.btct_url, args.scan_token, args.workspace,
                            scan=scan, out_dir=None)
        sync_dir(client, args.out)
        return 0

    if args.command == "ingest":
        from .btct import BTCTClient
        from .ingest import run_ingest
        client = BTCTClient(args.btct_url, args.scan_token, args.workspace,
                            scan=args.scan_name, out_dir=args.out)
        run_ingest(args.tool, args.file, client,
                   default_ip=args.ip or "",
                   include_context=args.include_context)
        return 0

    if args.command == "secrets":
        from .btct import BTCTClient
        from .vulnscan import run_gitleaks
        client = BTCTClient(args.btct_url, args.scan_token, args.workspace,
                            scan=args.scan_name, out_dir=args.out)
        run_gitleaks(args.path, args.ip, args.out, client)
        return 0

    if args.command == "vuln":
        from .vuln import run_vuln_phase
        run_vuln_phase(
            request_file=args.request,
            tools_selection=args.tools,
            out_dir=args.out,
            scheme=args.scheme,
            btct_url=args.btct_url,
            scan_token=args.scan_token,
            workspace=args.workspace,
            scan_name=args.scan_name,
            do_install=args.install,
        )
        return 0

    return 1
