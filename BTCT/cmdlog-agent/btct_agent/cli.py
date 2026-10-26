"""Command-line entry point: install / uninstall / run / status / test-redact."""
from __future__ import annotations

import argparse
import json
import sys

from . import config, installer
from .redactor import redact_line
from .shipper import MAX_BATCH_EVENTS, clamp_batch_size


def _need(cfg: dict, *keys: str) -> None:
    missing = [k for k in keys if not cfg.get(k)]
    if missing:
        sys.exit(f"error: missing required config: {', '.join(missing)} "
                 f"(pass --{missing[0]} or set it in {config.config_file()})")


def cmd_install(args: argparse.Namespace) -> int:
    cfg = config.resolve({
        "server": args.server, "token": args.token,
        "operator": args.operator, "workspace": args.workspace,
        "log_file": args.log_file,
    })
    _need(cfg, "server", "token", "operator")
    config.save_config(cfg)
    touched = installer.install(args.shell)
    print(f"Installed hook into: {', '.join(touched)}")
    print(f"Config saved to: {config.config_file()}")
    print("Open a NEW shell (or `source` your rc), then run the daemon:")
    print(f"  python3 -m btct_agent run")
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    touched = installer.uninstall(args.shell)
    if touched:
        print(f"Removed hook from: {', '.join(touched)}")
        print("Open a new shell for it to take effect.")
    else:
        print("No btct-cmdlog hook found.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from .daemon import Daemon, daemonize
    cfg = config.resolve({
        "server": args.server, "token": args.token,
        "operator": args.operator, "workspace": args.workspace,
        "log_file": args.log_file,
    })
    _need(cfg, "server", "token", "operator")
    batch_size = clamp_batch_size(args.batch_size)
    if batch_size != args.batch_size:
        print(f"btct-agent: --batch-size {args.batch_size} is outside 1 to {MAX_BATCH_EVENTS} "
              f"(the server's cap per POST); using {batch_size}", file=sys.stderr)
    if args.daemonize:
        daemonize()
    d = Daemon(
        cfg, no_redact=args.no_redact, batch_size=batch_size,
        flush_interval=args.flush_interval, max_spool_mb=args.max_spool_mb,
        whitelist_refresh=args.whitelist_refresh, log_file=args.log_file,
    )
    return d.run()


def cmd_status(_args: argparse.Namespace) -> int:
    path = config.state_dir() / "status.json"
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        print("No running daemon (no status file). Start it with `btct_agent run`.")
        return 1
    print(json.dumps(data, indent=2))
    return 0


def cmd_test_redact(args: argparse.Namespace) -> int:
    red, degraded = redact_line(args.command)
    print(red)
    if degraded:
        print("(note: redaction degraded: line could not be fully tokenized)", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="btct_agent", description="BTCT command-log capture agent.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--server", help="BTCT base URL, e.g. http://10.0.0.5:8080")
        sp.add_argument("--token", help="ingest token from BTCT admin → Command Log")
        sp.add_argument("--operator", help="your name, shown in the log")
        sp.add_argument("--workspace", help="target workspace id (optional; server default used otherwise)")
        sp.add_argument("--log-file", help="local unredacted log path")

    ins = sub.add_parser("install", help="install the shell hook + save config")
    common(ins)
    ins.add_argument("--shell", choices=["auto", "bash", "zsh"], default="auto")
    ins.set_defaults(func=cmd_install)

    un = sub.add_parser("uninstall", help="remove the shell hook")
    un.add_argument("--shell", choices=["auto", "bash", "zsh"], default="auto")
    un.set_defaults(func=cmd_uninstall)

    run = sub.add_parser("run", help="run the capture daemon")
    common(run)
    run.add_argument("--no-redact", action="store_true", help="ship commands unredacted (full fidelity)")
    run.add_argument("--batch-size", type=int, default=25,
                     help=f"events per POST, 1 to {MAX_BATCH_EVENTS} (the server's cap; a larger value is clamped)")
    run.add_argument("--flush-interval", type=float, default=2.0)
    run.add_argument("--max-spool-mb", type=float, default=20.0)
    run.add_argument("--whitelist-refresh", type=float, default=60.0)
    run.add_argument("--daemonize", action="store_true", help="detach into the background")
    run.set_defaults(func=cmd_run)

    st = sub.add_parser("status", help="print the running daemon's status")
    st.set_defaults(func=cmd_status)

    tr = sub.add_parser("test-redact", help="print the redacted form of a command (no network)")
    tr.add_argument("command")
    tr.set_defaults(func=cmd_test_redact)

    return p


def main(argv: list | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
