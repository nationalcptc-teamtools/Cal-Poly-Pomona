# btct-cmdlog: BTCT command-log capture agent

A tiny, **stdlib-only** Python 3 agent that captures whitelisted pentest commands
from an operator's shell and ships them to a BTCT server's **Command Log** tab,
so the whole team sees a live, filterable record of who ran what, when, where,
and with what result.

Built for CPTC-style engagements: each operator runs this on their own Kali box;
BTCT runs on one box on the same LAN.

- **No dependencies.** Python 3.8+ standard library only (`urllib`, `threading`,
  `shlex`). Nothing to `pip install`.
- **Transparent.** A shell hook captures commands as you type them normally: no
  wrapper, no prefix.
- **Never freezes your terminal.** The hook appends to a regular file; a dead or
  slow daemon is invisible to you.
- **Redacts secrets** (passwords, hashes, auth headers, URL creds) before they
  leave your box. The local log keeps the unredacted original.

## Quick start

1. In BTCT: **Admin → Command Log → Enabled**. Copy the ingest token.
2. On each Kali box:

   ```bash
   python3 -m btct_agent install --server http://<btct-host>:8080 --token <token> --operator <you>
   ```

   Open a **new shell** (or `source ~/.bashrc`), then run the daemon: ideally in
   a tmux pane so you can see its status line:

   ```bash
   python3 -m btct_agent run
   ```

3. Work normally. Whitelisted commands appear in BTCT's Command Log tab live.

> Tip: put the repo's `cmdlog-agent/` directory on the box (scp it) and run the
> commands from inside it, or add it to `PYTHONPATH`.

## What it captures

For each whitelisted command: the full command line (redacted), the tool, the
operator, hostname, local user, working directory, shell PID, start time, exit
code, and duration. A command shows up **live when it starts** (so long scans are
visible while running) and its exit code + duration fill in when it finishes.

**Only whitelisted tools are logged**: everything else you type is ignored and
never leaves the box. The whitelist lives on the server (Admin → Command Log) and
the agent refreshes it every ~60s, so it can be changed for everyone mid-engagement.

## Redaction

Command lines routinely contain credentials. Before shipping, the agent scrubs:

- password flags, tool-aware: `mysql -pSECRET`, `hydra -p SECRET`, `--password=…`,
  `redis-cli -a …`, impacket `-hashes LM:NT`, etc.
- `Authorization:` / `Cookie:` headers, `--token`/`--api-key`/`--secret` values.
- credentials in URLs (`http://user:pass@host`).

The unredacted line is still written to your **local log** (`~/.local/state/btct-cmdlog/commands.log`).

**Honest limitations** (read these):

- **`-p` is tool-aware on purpose.** `nmap -p 1-65535` is a *port* and is kept;
  `mysql -p…` is a *password* and is redacted. A tool not in the table whose secret
  flag we don't know about **will leak** until it's added to `redactor.py`.
- **Positional secrets have no marker** and are not redacted (`mysql db theP@ss`).
- Shipping re-quotes the command, so its spacing/quoting may differ cosmetically
  from what you typed (the local log preserves the exact original).
- `--no-redact` disables redaction entirely (full fidelity, use only on a trusted
  engagement). Try `python3 -m btct_agent test-redact "<command>"` to preview.

## Commands

```
install    --server URL --token T --operator NAME [--workspace W] [--shell auto|bash|zsh] [--log-file PATH]
uninstall  [--shell auto|bash|zsh]
run        --server URL --token T --operator NAME [--workspace W] [--no-redact]
           [--batch-size 25 (1 to 200)] [--flush-interval 2] [--max-spool-mb 20] [--daemonize]
status     # print the running daemon's status (sent / outbox / dropped / rejected / online)
test-redact "<command line>"   # preview redaction, no network
```

`install` saves config to `~/.config/btct/agent.conf` (mode 0600: it holds the
token), so `run` needs no arguments afterward. Config precedence:
CLI > env (`BTCT_SERVER`/`BTCT_TOKEN`/`BTCT_OPERATOR`/`BTCT_WORKSPACE`) > config file.

## How it works

```
your shell ──hook──▶ spool file ──▶ daemon ──▶ POST /api/cmdlog/events ──▶ BTCT
 (bash/zsh)          (per-PID,        │  whitelist-match → redact → batch
                      never blocks)   └─ local log (unredacted)
```

- **Shell hook** (`hooks/hook.bash`, `hooks/hook.zsh`): appends a `pre` record
  before each command and a `post` record (exit + time) after, to a per-PID file
  under `${XDG_RUNTIME_DIR:-/tmp}/btct-$(id -u)/spool/` (dir mode 0700). The bash
  hook is a hand-rolled DEBUG-trap that arms in a last-in-`PROMPT_COMMAND`
  function so it fires only on the real command (not pipeline sub-commands, not
  completion, not `PROMPT_COMMAND` internals). Swap in `bash-preexec.sh` if you
  prefer; register `__btct_preexec`/`__btct_precmd`.
- **Daemon** (`daemon.py`): tails the spool, correlates `pre`/`post` by event id,
  filters by the whitelist, redacts, writes the local log, and ships in batches.
  Two durability layers mean a command is never lost: the spool file survives a
  daemon restart (offset-tracked), and a bounded on-disk **outbox** survives a
  server outage (retried with backoff, drained oldest-first on recovery). The
  outbox is an append-only `outbox.ndjson` plus an `outbox.ndjson.offset` of
  what was delivered, compacted once the delivered part is half the file.
- **What the server refuses** is not retried forever. Commands are cut to the
  server's 4096-character limit before shipping. A batch refused for its
  content (413, 400 and other 4xx) is split in half until the bad event stands
  alone; that event is dropped and counted as `rejected` in the status line,
  and everything behind it ships. 401, 403, 404, 405, 408, 409, 429, every 5xx
  and network errors are retried, because they say nothing about the events.
- **Batch size** is 1 to 200, the server's cap per POST; `--batch-size` above
  200 is clamped with a warning. The agent also reads the reply's `accepted`
  and `skipped` counts: events past what the server says it read stay queued
  and go in the next POST, and `skipped` ones count as `rejected`. (Before,
  `--batch-size 500` shipped 1000 commands and the server kept 400.)

Uninstall with `python3 -m btct_agent uninstall` (removes only the managed block
from your rc; a one-time `~/.bashrc.btct.bak` backup is kept).

## Security notes

- The ingest token grants ingest: treat it like a password. It's shared across
  the team for the engagement.
- The operator name is **self-asserted** (`--operator`): appropriate for a
  trusted team, not for adversarial auditing.
- The spool dir is 0700, but raw commands and the local log are **plaintext on
  your box**. Clean them up after the engagement if needed.

## Tests

```
python3 -m unittest discover -s tests
```

Covers the pure cores: the whitelist matcher, the redactor (including the
`nmap -p` regression guard), spool parsing + pre/post correlation, and the outbox
ring / retry logic.
