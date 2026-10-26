#!/usr/bin/env bash
# btct.sh: a command-line menu for running BTCT on a Linux box (Kali first).
#
# Run it with no arguments for the menu (whiptail when installed, else a
# numbered text menu), or with a subcommand:
#
#   btct                          the menu
#   btct status                   health, container, URLs, RAM/CPU, backup folder, last backup
#   btct start | stop | restart
#   btct backup-dir [PATH]        set the host folder backups go to, recreate btct, verify it
#   btct backup-dir --show        print the folder .env names and the one the container mounts
#   btct backup                   run a backup now (admin login or BTCT_BACKUP_TOKEN)
#   btct backups                  list backups (from the server when logged in, else the folder)
#   btct schedule [on|off] [--every MIN] [--keep N] [--show]
#   btct restore [NAME] [--keep-browser-caches] [--partial]
#   btct passwords                print /data/initial-passwords.txt (secrets)
#   btct logs [-f] [LINES]        last LINES (100) log lines, or follow them
#   btct update [--branch NAME] [--rebuild]
#                                 pull the latest comp-ready (or NAME), build the new image
#                                 while BTCT runs, stop, snapshot the data volume to
#                                 <backup folder>/pre-update-<stamp>.tgz, start, wait for health
#   btct rollback [--data] [SNAPSHOT]
#                                 run the image from before the last update again (tag
#                                 <image>:previous); --data also puts back a pre-update snapshot
#   btct check                    ./competition-day.sh --check-only
#   btct install | uninstall      the `btct` command and shell alias
#   btct help
#
# Options for any subcommand: -y / --yes answers yes to confirmations (a
# restore still needs --yes or the typed backup name).
#
# Environment: BTCT_USER (login name, default Roberto), BTCT_PASSWORD (for
# scripts; otherwise the password is asked once per run and kept only in
# memory), BTCT_BACKUP_TOKEN (the Admin -> Backups token, enough for backup
# and status), BTCT_PROJECT (compose project, overriding detection),
# BTCT_CONTAINER (container name, default btct, for a second instance whose
# compose override renames it), BTCT_MENU=text (skip whiptail),
# BTCT_HEALTH_TIMEOUT (seconds, 180).

set -u -o pipefail

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
APP_DIR="$(dirname "$SELF")"
ENV_FILE="$APP_DIR/.env"
CNAME="${BTCT_CONTAINER:-btct}" # container_name in docker-compose.yml
ALIAS_MARK="# btct-cli"
LINK_PATH=/usr/local/bin/btct
HEALTH_TIMEOUT="${BTCT_HEALTH_TIMEOUT:-180}"
ASSUME_YES=0

if [ -t 1 ]; then
  C_B=$'\033[1m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_C=$'\033[36m'; C_0=$'\033[0m'
else
  C_B=""; C_G=""; C_Y=""; C_R=""; C_C=""; C_0=""
fi
say()  { printf '%s\n' "$*"; }
info() { printf '%s[btct]%s %s\n' "$C_C" "$C_0" "$*"; }
ok()   { printf '%s[btct]%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '%s[btct]%s %s\n' "$C_Y" "$C_0" "$*" >&2; }
err()  { printf '%s[btct]%s %s\n' "$C_R" "$C_0" "$*" >&2; }

have_tty() { [ -t 0 ]; }

# confirm QUESTION DEFAULT(y|n): yes/no from the terminal; -y answers yes;
# without a terminal the default stands.
confirm() {
  local q=$1 def=${2:-n} ans hint="[y/N]"
  [ "$def" = y ] && hint="[Y/n]"
  if [ "$ASSUME_YES" -eq 1 ]; then return 0; fi
  if ! have_tty; then [ "$def" = y ]; return; fi
  read -r -p "$q $hint " ans || ans=""
  case "$ans" in
    y|Y|yes|YES|Yes) return 0 ;;
    n|N|no|NO|No) return 1 ;;
    *) [ "$def" = y ] ;;
  esac
}

# ── .env ────────────────────────────────────────────────────────────────
# Read KEY the way docker compose does: the last line wins, CR and one pair
# of surrounding quotes are stripped.
env_get() {
  [ -f "$ENV_FILE" ] || return 0
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -n1 | tr -d '\r' \
    | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\\(.*\\)'\$/\\1/"
}

# The host folder compose mounts at /backups for a BACKUP_HOST_DIR value.
resolve_dir() {
  case "$1" in
    "") printf '%s' "$APP_DIR/backups" ;;
    /*) printf '%s' "$1" ;;
    *) printf '%s' "$APP_DIR/${1#./}" ;;
  esac
}
backup_host_dir() { resolve_dir "$(env_get BACKUP_HOST_DIR)"; }

human_kb() { awk -v k="$1" 'BEGIN { if (k >= 1048576) printf "%.1f GB", k / 1048576; else if (k >= 1024) printf "%.1f MB", k / 1024; else printf "%d KB", k }'; }
free_of() { # free space on the disk holding $1 (or its nearest existing parent)
  local p=$1 kb
  while [ ! -e "$p" ] && [ "$p" != / ]; do p="$(dirname "$p")"; done
  kb="$(df -Pk "$p" 2>/dev/null | awk 'NR==2 {print $4}')"
  [ -n "$kb" ] && printf '%s free' "$(human_kb "$kb")"
}

# ── Docker and compose ──────────────────────────────────────────────────
SUDO_PFX=()
DK=()
COMPOSE=()
PFLAG=()
PROJECT=""
PROJECT_FROM=""
DOCKER_READY=0

need_docker() {
  [ "$DOCKER_READY" -eq 1 ] && return 0
  if ! command -v docker >/dev/null 2>&1; then
    err "docker is not installed. Run ./competition-day.sh (Kali) or ./install-btct.sh first."
    return 1
  fi
  if docker info >/dev/null 2>&1; then
    SUDO_PFX=()
  elif [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    if ! sudo -n true 2>/dev/null; then
      info "your user cannot reach the docker daemon (not in the docker group yet), so docker runs through sudo"
    fi
    if ! sudo docker info >/dev/null 2>&1 </dev/null; then
      err "the docker daemon is not answering (sudo docker info failed). Start it: sudo systemctl start docker"
      return 1
    fi
    SUDO_PFX=(sudo)
  else
    err "the docker daemon is not answering (docker info failed). Start it: systemctl start docker"
    return 1
  fi
  DK=("${SUDO_PFX[@]}" docker)
  if "${DK[@]}" compose version >/dev/null 2>&1; then
    COMPOSE=("${DK[@]}" compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=("${SUDO_PFX[@]}" docker-compose)
  else
    err "docker compose is not installed. On Kali: sudo apt install docker-compose"
    return 1
  fi
  detect_project
  DOCKER_READY=1
}

# Kali's sudo runs commands on a pty of their own (Defaults use_pty) and
# relays the terminal to them, which would swallow what the user types next;
# so docker gets the terminal only where it reads it (compose_tty).
dk() { if [ -t 0 ]; then "${DK[@]}" "$@" </dev/null; else "${DK[@]}" "$@"; fi; }
compose() { (cd "$APP_DIR" && if [ -t 0 ]; then "${COMPOSE[@]}" "${PFLAG[@]}" "$@" </dev/null; else "${COMPOSE[@]}" "${PFLAG[@]}" "$@"; fi); }
compose_tty() { (cd "$APP_DIR" && "${COMPOSE[@]}" "${PFLAG[@]}" "$@"); }

# The compose project the running BTCT belongs to: the label on the btct
# container, else COMPOSE_PROJECT_NAME from .env, else compose's default
# (the folder name). Using the wrong one would start a second container
# and a second, empty data volume.
detect_project() {
  local lbl wd
  PROJECT=""; PROJECT_FROM=""
  if [ -n "${BTCT_PROJECT:-}" ]; then
    PROJECT=$BTCT_PROJECT; PROJECT_FROM="BTCT_PROJECT"
  else
    lbl="$(dk inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$CNAME" 2>/dev/null || true)"
    if [ -n "$lbl" ] && [ "$lbl" != "<no value>" ]; then
      PROJECT=$lbl; PROJECT_FROM="the $CNAME container's label"
      wd="$(dk inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$CNAME" 2>/dev/null || true)"
      if [ -n "$wd" ] && [ "$wd" != "<no value>" ] && [ "$(readlink -f "$wd" 2>/dev/null || printf '%s' "$wd")" != "$APP_DIR" ]; then
        warn "the $CNAME container was started from $wd, not $APP_DIR; this menu manages it with the compose file and .env in $APP_DIR"
      fi
    elif [ -n "$(env_get COMPOSE_PROJECT_NAME)" ]; then
      PROJECT="$(env_get COMPOSE_PROJECT_NAME)"; PROJECT_FROM="COMPOSE_PROJECT_NAME in .env"
    fi
  fi
  if [ -n "$PROJECT" ]; then
    PFLAG=(-p "$PROJECT")
  else
    PFLAG=()
    PROJECT="$(basename "$APP_DIR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')"
    PROJECT_FROM="compose default (the folder name)"
  fi
}

c_exists()  { dk inspect "$CNAME" >/dev/null 2>&1; }
c_running() { [ "$(dk inspect -f '{{.State.Running}}' "$CNAME" 2>/dev/null)" = "true" ]; }
mount_source() { dk inspect -f '{{range .Mounts}}{{if eq .Destination "/backups"}}{{.Source}}{{end}}{{end}}' "$CNAME" 2>/dev/null; }

# The host port mapped to the container's 8080.
HOST_PORT=""
host_port() {
  [ -n "$HOST_PORT" ] && { printf '%s' "$HOST_PORT"; return; }
  local p=""
  if c_running; then p="$(compose port btct 8080 2>/dev/null | tail -n1 | sed 's/.*://')"; fi
  if [ -z "$p" ]; then
    p="$(compose config 2>/dev/null | awk '/target: 8080/ {t = 1; next} t && /published:/ {gsub(/[" ]/, ""); sub(/published:/, ""); print; exit}')"
  fi
  if [ -z "$p" ]; then
    p="$(cat "$APP_DIR/docker-compose.yml" "$APP_DIR/docker-compose.override.yml" 2>/dev/null \
          | sed -n 's/^[[:space:]]*-[[:space:]]*"\{0,1\}\([0-9.]*:\)\{0,1\}\([0-9][0-9]*\):8080"\{0,1\}[[:space:]]*$/\2/p' | tail -n1)"
  fi
  HOST_PORT="${p:-8080}"
  printf '%s' "$HOST_PORT"
}

# GET a URL; prints the body. curl when present, else bash /dev/tcp.
http_get() {
  local host=$1 port=$2 path=$3
  if command -v curl >/dev/null 2>&1; then
    curl -sS --max-time 4 "http://$host:$port$path" 2>/dev/null
  else
    timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port && printf 'GET $path HTTP/1.0\r\nHost: $host\r\n\r\n' >&3 && sed '1,/^\r\{0,1\}\$/d' <&3" 2>/dev/null
  fi
}
healthy() { http_get 127.0.0.1 "$(host_port)" /healthz | grep -q '"ok":true'; }

wait_health() {
  local start=$SECONDS el next=10
  info "waiting for http://127.0.0.1:$(host_port)/healthz (up to ${HEALTH_TIMEOUT}s)"
  while :; do
    el=$((SECONDS - start))
    if healthy; then ok "BTCT is up and healthy after ${el}s"; return 0; fi
    if [ "$el" -ge 15 ] && ! c_running; then
      err "the $CNAME container is not running: $(dk inspect -f '{{.State.Status}} (exit {{.State.ExitCode}})' "$CNAME" 2>/dev/null || echo missing)"
      compose logs --tail=30 btct 2>&1 | sed 's/^/    /'
      return 1
    fi
    if [ "$el" -ge "$HEALTH_TIMEOUT" ]; then
      err "/healthz did not answer within ${HEALTH_TIMEOUT}s; last log lines:"
      compose logs --tail=30 btct 2>&1 | sed 's/^/    /'
      return 1
    fi
    if [ "$el" -ge "$next" ]; then info "still waiting (${el}s)"; next=$((next + 10)); fi
    sleep 2
  done
}

lan_ips() {
  if command -v ip >/dev/null 2>&1; then
    ip -4 -o addr show scope global 2>/dev/null \
      | awk '$2 !~ /^(docker|br-|veth|virbr)/ {sub(/\/.*/, "", $4); print $4}'
  elif command -v hostname >/dev/null 2>&1; then
    hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$' | grep -v '^127\.' | grep -v '^172\.17\.'
  fi
}

# ── The admin API ───────────────────────────────────────────────────────
# Requests run inside the container with its own Bun, so the box needs no
# curl or jq, and the token travels on stdin, never on a command line.
# stdin: METHOD, PATH, FORMAT, TOKEN, then the body (for login: user, password).
# Exit: 0 ok, 10 401, 13 403, 11 409, 14 429, 12 other HTTP error, 20 no answer.
read -r -d '' API_JS <<'JS'
const lines = (await Bun.stdin.text()).split('\n');
const [method, path, fmt, token] = lines;
let body = lines.slice(4).join('\n') || undefined;
if (fmt === 'login') body = JSON.stringify({ username: lines[4], password: lines.slice(5).join('\n') });
const headers = { 'content-type': 'application/json' };
if (token) headers.authorization = 'Bearer ' + token;
let res;
try {
  res = await fetch('http://127.0.0.1:' + (process.env.PORT || 8080) + path, { method, headers, body });
} catch (e) {
  console.error('the server did not answer inside the container: ' + (e?.message || e));
  process.exit(20);
}
const text = await res.text();
let j = null;
try { j = JSON.parse(text); } catch {}
if (!res.ok) {
  console.error('HTTP ' + res.status + ': ' + (j?.error || text.slice(0, 200)));
  process.exit({ 401: 10, 403: 13, 409: 11, 429: 14 }[res.status] ?? 12);
}
const size = (b) => (b >= 1073741824 ? (b / 1073741824).toFixed(2) + ' GB' : b >= 1048576 ? (b / 1048576).toFixed(1) + ' MB' : (b / 1024).toFixed(0) + ' KB');
const when = (t) => (t ? new Date(t).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : 'never');
const sched = (c) => (c.enabled ? `on, every ${c.fullIntervalMin} min` : 'off') + `, keep last ${c.keepLast || 'all'}`;
switch (fmt) {
  case 'login':
    if (!j?.token) { console.error('the server sent no token'); process.exit(12); }
    if (!j.user?.isAdmin) console.error('note: ' + j.user?.username + ' is not an admin; backup actions need an admin account');
    process.stdout.write(j.token);
    break;
  case 'run': {
    console.log(`name\t${j.name}`);
    console.log(`size\t${size(j.bytes || 0)}`);
    console.log(`took\t${Math.round((j.durationMs || 0) / 1000)} s, ${j.files ?? '?'} files`);
    if (j.failedRooms?.length) console.log(`missing\t${j.failedRooms.length} room(s) could not be read: ${j.failedRooms.join(', ')}`);
    break;
  }
  case 'status': {
    const lb = j.lastBackup;
    console.log(`last backup\t${lb ? `${lb.name}, ${size(lb.bytes || 0)}, ${when(lb.at)}` : 'none yet'}`);
    console.log(`schedule\t${sched(j)}${j.enabled && j.nextRunAt ? ', next ' + when(j.nextRunAt) : ''}`);
    if (j.lastError) console.log(`last error\t${j.lastError}`);
    if (j.running) console.log(`running\tsince ${when(j.runningSince)}`);
    console.log(`folder\t${j.hostDir} (in the container: ${j.dir}, ${j.dirWritable ? 'writable' : 'NOT writable'})`);
    break;
  }
  case 'config':
    console.log(`schedule\t${sched(j)}`);
    console.log(`folder\t${j.hostDir} (in the container: ${j.dir})`);
    break;
  case 'config-kv':
    console.log(`${j.enabled ? 1 : 0} ${j.fullIntervalMin} ${j.keepLast}`);
    break;
  case 'list': {
    const rows = j.backups || [];
    if (!rows.length) { console.log('  (no backups yet)'); break; }
    for (const b of rows) {
      const flags = [b.format === 'folder' ? 'folder' : '', b.partial ? 'partial' : '', b.failedRooms ? `${b.failedRooms} room(s) missing` : ''].filter(Boolean).join(', ');
      console.log(`  ${b.name.padEnd(36)} ${size(b.bytes || 0).padStart(9)}  ${when(b.createdAt)}${b.trigger ? '  ' + b.trigger : ''}${flags ? '  (' + flags + ')' : ''}`);
    }
    break;
  }
  default:
    console.log(JSON.stringify(j));
}
JS

# api METHOD PATH FORMAT [BODY]: uses API_TOKEN.
api() {
  printf '%s\n%s\n%s\n%s\n%s' "$1" "$2" "$3" "${API_TOKEN:-}" "${4:-}" \
    | dk exec -i "$CNAME" bun -e "$API_JS"
}

SESSION_TOKEN=""
API_TOKEN=""
login() {
  local user pass tok tries=0
  if ! c_running; then err "BTCT is not running (btct start)"; return 1; fi
  while :; do
    if [ -n "${BTCT_PASSWORD:-}" ]; then
      user="${BTCT_USER:-Roberto}"; pass="$BTCT_PASSWORD"
    else
      if ! have_tty; then
        err "logging in needs a terminal; or set BTCT_BACKUP_TOKEN (Admin panel -> Backups) for backup and status"
        return 1
      fi
      read -r -p "BTCT admin username [${BTCT_USER:-Roberto}]: " user || return 1
      user="${user:-${BTCT_USER:-Roberto}}"
      read -r -s -p "Password for $user: " pass || { echo; return 1; }
      echo
    fi
    tok="$(API_TOKEN="" api POST /api/login login "$user"$'\n'"$pass")"
    case $? in
      0) SESSION_TOKEN=$tok; pass=""; ok "logged in as $user (kept in memory for this run only)"; return 0 ;;
      10) tries=$((tries + 1))
          if [ -n "${BTCT_PASSWORD:-}" ] || [ "$tries" -ge 3 ]; then return 1; fi ;;
      *) return 1 ;;
    esac
  done
}

# auth KIND: "token" routes (status, run) accept BTCT_BACKUP_TOKEN; "admin" ones need a login.
auth() {
  if [ -n "$SESSION_TOKEN" ]; then API_TOKEN=$SESSION_TOKEN; return 0; fi
  if [ "$1" = token ] && [ -n "${BTCT_BACKUP_TOKEN:-}" ]; then API_TOKEN=$BTCT_BACKUP_TOKEN; return 0; fi
  login || return 1
  API_TOKEN=$SESSION_TOKEN
}

# api_auth KIND METHOD PATH FORMAT [BODY]: logs in when needed (in this
# shell, so the session is kept), and again once when a session token was
# refused (expired). The output lands in API_OUT, never in a subshell.
API_OUT=""
api_auth() {
  local kind=$1 rc; shift
  API_OUT=""
  auth "$kind" || return 1
  API_OUT="$(api "$@")"; rc=$?
  if [ "$rc" -eq 10 ] && [ -n "$SESSION_TOKEN" ] && [ "$API_TOKEN" = "$SESSION_TOKEN" ]; then
    SESSION_TOKEN=""
    info "the session was refused; log in again"
    auth admin || return 1
    API_OUT="$(api "$@")"; rc=$?
  fi
  return "$rc"
}
print_kv() { [ -n "$1" ] && printf '%s\n' "$1" | while IFS=$'\t' read -r k v; do row "$k" "$v"; done; return 0; }

need_running() {
  need_docker || return 1
  c_running && return 0
  err "BTCT is not running. Start it with: btct start"
  return 1
}

# ── status ──────────────────────────────────────────────────────────────
uptime_of() {
  local s now d h m
  s="$(date -d "$1" +%s 2>/dev/null)" || return 0
  now="$(date +%s)"; d=$((now - s)); [ "$d" -lt 0 ] && d=0
  h=$((d / 3600)); m=$(((d % 3600) / 60))
  if [ "$h" -ge 24 ]; then printf '%dd %dh %dm' $((h / 24)) $((h % 24)) "$m"; else printf '%dh %dm' "$h" "$m"; fi
}

row() { printf '  %-13s %s\n' "$1" "$2"; }

newest_backup_in() {
  local dir=$1
  priv_ls "$dir" | grep -E '^btct-backup-[0-9]{8}-[0-9]{6}(\.zip)?$' | sort | tail -n1
}
# List a folder, through sudo when this user cannot read it.
priv_ls() { ls -1 "$1" 2>/dev/null || { [ "$(id -u)" -ne 0 ] && sudo -n ls -1 "$1" 2>/dev/null; }; }

cmd_status() {
  need_docker || return 1
  local st health port ips ip dir envv mnt stats newest s_state s_health s_started s_image
  port="$(host_port)"
  say "${C_B}BTCT status${C_0}"
  row "checkout" "$APP_DIR (compose project '$PROJECT', from $PROJECT_FROM)"
  if c_exists; then
    st="$(dk inspect -f '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}|{{.State.StartedAt}}|{{.Config.Image}}' "$CNAME" 2>/dev/null)"
    IFS='|' read -r s_state s_health s_started s_image <<<"$st"
    if [ "$s_state" = running ]; then
      row "container" "running, $s_health, up $(uptime_of "$s_started") (image $s_image)"
    else
      row "container" "$s_state (image $s_image). Start it with: btct start"
    fi
  else
    row "container" "not created yet. Start it with: btct start"
  fi
  if c_running; then
    health="$(http_get 127.0.0.1 "$port" /healthz)"
    row "health" "${health:-no answer on 127.0.0.1:$port}"
    row "open" "http://127.0.0.1:$port"
    ips="$(lan_ips || true)"
    for ip in $ips; do row "" "http://$ip:$port  (team LAN)"; done
    stats="$(dk stats --no-stream --format '{{.MemUsage}}|{{.CPUPerc}}' "$CNAME" 2>/dev/null)"
    case "$stats" in
      "") ;;
      0B*) row "resources" "CPU ${stats##*|} (docker reports no memory figure here)" ;;
      *) row "resources" "RAM ${stats%%|*}, CPU ${stats##*|}" ;;
    esac
  fi
  envv="$(env_get BACKUP_HOST_DIR)"
  dir="$(resolve_dir "$envv")"
  row "backups" "$dir ($(free_of "$dir"))${envv:+, BACKUP_HOST_DIR in .env}"
  if c_exists; then
    mnt="$(mount_source)"
    if [ -n "$mnt" ] && [ "$mnt" != "$dir" ] && [ "$mnt" != "$(readlink -f "$dir" 2>/dev/null)" ]; then
      row "" "${C_Y}the container still mounts $mnt; run 'btct backup-dir \"$dir\"' or 'btct start' to apply it${C_0}"
    fi
  fi
  if c_running && { [ -n "$SESSION_TOKEN" ] || [ -n "${BTCT_BACKUP_TOKEN:-}" ]; }; then
    api_auth token GET /api/backup/status status && print_kv "$API_OUT"
  else
    newest="$(newest_backup_in "$dir")"
    row "last backup" "${newest:-none in the folder} (log in, or set BTCT_BACKUP_TOKEN, for the server's view)"
  fi
  return 0
}

# ── start / stop / restart ──────────────────────────────────────────────
cmd_start() {
  need_docker || return 1
  info "running: ${COMPOSE[*]} ${PFLAG[*]} up -d"
  compose up -d || { err "compose up failed"; return 1; }
  wait_health || return 1
  say "  open http://127.0.0.1:$(host_port)"
}
cmd_stop() {
  need_docker || return 1
  c_running || { info "BTCT is not running"; return 0; }
  info "stopping BTCT (it flushes its data first; up to 60 s)"
  compose stop btct && ok "stopped"
}
cmd_restart() {
  need_docker || return 1
  if ! c_exists; then cmd_start; return; fi
  info "restarting BTCT"
  compose restart btct || return 1
  wait_health
}

# ── backup folder ───────────────────────────────────────────────────────
has_dialog() {
  { [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; } || return 1
  command -v zenity >/dev/null 2>&1 || command -v kdialog >/dev/null 2>&1 || command -v yad >/dev/null 2>&1
}

# Check that the running container writes to DIR: the /backups mount and a
# test file written and removed as uid 1000.
verify_backup_mount() {
  local want=$1 mnt real fails=0
  mnt="$(mount_source)"
  real="$(readlink -f "$want" 2>/dev/null || printf '%s' "$want")"
  if [ "$mnt" = "$want" ] || [ "$mnt" = "$real" ]; then
    ok "the container mounts $mnt at /backups"
  else
    err "the container mounts '${mnt:-nothing}' at /backups, not $want"; fails=1
  fi
  # shellcheck disable=SC2016  # expanded by the container's sh
  if dk exec -u 1000 "$CNAME" sh -c 'f=/backups/.btct-write-test.$$ && echo ok > "$f" && rm -f "$f"' 2>/dev/null; then
    ok "write test as uid 1000 in /backups: ok"
  else
    err "uid 1000 cannot write to /backups ($want): check the folder's owner (sudo chown 1000:1000 '$want') and that its disk is not read-only"; fails=1
  fi
  return "$fails"
}

cmd_backup_dir() {
  local show=0 path="" a cur_raw cur new prev_env="" had_env=0 rc
  for a in "$@"; do
    case "$a" in
      --show) show=1 ;;
      -*) err "unknown option for backup-dir: $a"; return 2 ;;
      *) path=$a ;;
    esac
  done
  cur_raw="$(env_get BACKUP_HOST_DIR)"
  cur="$(resolve_dir "$cur_raw")"
  if [ "$show" -eq 1 ]; then
    say "$cur"
    { row "in .env" "BACKUP_HOST_DIR=${cur_raw:-(unset, so ./backups)}"
      row "free" "$(free_of "$cur")"
      if need_docker 2>/dev/null && c_exists; then row "mounted" "$(mount_source) -> /backups"; fi; } >&2
    return 0
  fi
  [ -x "$APP_DIR/choose-backup-folder.sh" ] || { err "choose-backup-folder.sh is missing from $APP_DIR"; return 1; }
  if [ -z "$path" ]; then
    have_tty || { err "no terminal to ask on; pass the folder: btct backup-dir /path/to/folder"; return 1; }
    say "Current backup folder: ${C_B}$cur${C_0} ($(free_of "$cur"))"
    if has_dialog; then
      read -e -r -p "New folder (Tab completes; Enter opens the folder dialog): " path || path=""
    else
      read -e -r -p "New folder (Tab completes; Enter keeps the current one): " path || path=""
      [ -n "$path" ] || { info "kept $cur"; return 0; }
    fi
  fi
  if [ -n "$path" ]; then
    case "$path" in
      "~") path="$HOME" ;;
      \~/*) path="$HOME/${path:2}" ;;
      /*) ;;
      *) path="$PWD/$path"; info "relative path, so using $path" ;;
    esac
  fi
  if [ -f "$ENV_FILE" ]; then had_env=1; prev_env="$(cat "$ENV_FILE")"; fi
  if [ -n "$path" ]; then
    "$APP_DIR/choose-backup-folder.sh" --path "$path" --no-apply; rc=$?
  else
    "$APP_DIR/choose-backup-folder.sh" --no-apply; rc=$?
  fi
  [ "$rc" -eq 0 ] || { err "the backup folder was not changed"; return 1; }
  new="$(backup_host_dir)"

  need_docker || { info "start BTCT later and it will write to $new"; return 0; }
  if ! c_running; then
    info "BTCT is not running; it will write to $new when it starts"
    if confirm "Start BTCT now?" n; then cmd_start || return 1; verify_backup_mount "$new"; fi
    return 0
  fi
  local mnt; mnt="$(mount_source)"
  if [ "$mnt" = "$new" ] || [ "$mnt" = "$(readlink -f "$new" 2>/dev/null)" ]; then
    info "the container already uses $new"
    verify_backup_mount "$new"
    return
  fi
  if ! confirm "Recreate the btct container now so it writes to $new? (data is kept; about 10 s offline)" y; then
    info "not applied yet; run 'btct start' when it suits you"
    return 0
  fi
  info "running: ${COMPOSE[*]} ${PFLAG[*]} up -d (recreates only btct; the data volume is kept)"
  if compose up -d && wait_health && verify_backup_mount "$new"; then
    ok "backups now go to $new"
    return 0
  fi
  err "the new backup folder did not work"
  if confirm "Put the previous folder ($cur) back and recreate the container?" y; then
    if [ "$had_env" -eq 1 ]; then printf '%s\n' "$prev_env" > "$ENV_FILE"; else rm -f "$ENV_FILE"; fi
    compose up -d && wait_health && verify_backup_mount "$cur" && ok "back on $cur"
  fi
  return 1
}

# ── backups ─────────────────────────────────────────────────────────────
cmd_backup() {
  need_running || return 1
  local out name rc dir
  info "asking the server for a backup (a big instance takes a minute)"
  api_auth token POST /api/backup/run run; rc=$?; out=$API_OUT
  case "$rc" in
    0) ;;
    11) warn "a backup is already running; try again when it finishes"; return 1 ;;
    *) err "the backup did not run"; return 1 ;;
  esac
  print_kv "$out"
  name="$(printf '%s\n' "$out" | sed -n 's/^name\t//p')"
  dir="$(backup_host_dir)"
  row "on this box" "$dir/$name"
  if [ -n "$name" ]; then find "$dir" -maxdepth 1 -name "$name" -printf '  %M %u:%g %s bytes %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null; fi
  ok "backup written"
}

list_host_backups() { # name<TAB>bytes<TAB>date, newest first
  local dir=$1
  { find "$dir" -maxdepth 1 -name 'btct-backup-*' -printf '%f\t%s\t%TY-%Tm-%Td %TH:%TM\n' 2>/dev/null \
    || { [ "$(id -u)" -ne 0 ] && sudo -n find "$dir" -maxdepth 1 -name 'btct-backup-*' -printf '%f\t%s\t%TY-%Tm-%Td %TH:%TM\n' 2>/dev/null; }; } \
    | grep -E '^btct-backup-[0-9]{8}-[0-9]{6}(\.zip)?	' | sort -r
}

cmd_backups() {
  local dir; dir="$(backup_host_dir)"
  if [ -z "$SESSION_TOKEN" ] && [ -n "${BTCT_PASSWORD:-}" ] && need_docker && c_running; then login >/dev/null; fi
  if [ -n "$SESSION_TOKEN" ] && need_docker && c_running; then
    say "${C_B}Backups${C_0} (from the server; on this box in $dir)"
    API_TOKEN=$SESSION_TOKEN api GET /api/backup/list list && return 0
  fi
  say "${C_B}Backups in $dir${C_0} (log in from the menu's 'Back up now' or 'Scheduled backups' for the server's view)"
  local rows; rows="$(list_host_backups "$dir")"
  if [ -z "$rows" ]; then say "  (none yet)"; return 0; fi
  printf '%s\n' "$rows" | while IFS=$'\t' read -r n b d; do
    printf '  %-36s %9s  %s\n' "$n" "$(human_kb $((b / 1024)))" "$d"
  done
}

cmd_schedule() {
  need_running || return 1
  local mode="" every="" keep="" show=0 a cur en iv kl body
  while [ $# -gt 0 ]; do
    case "$1" in
      on|off) mode=$1 ;;
      --every) every="${2:-}"; shift ;;
      --keep) keep="${2:-}"; shift ;;
      --show) show=1 ;;
      *) err "usage: btct schedule [on|off] [--every MIN] [--keep N] [--show]"; return 2 ;;
    esac
    shift
  done
  api_auth admin GET /api/backup/config config-kv || { err "could not read the backup settings"; return 1; }
  read -r en iv kl <<<"$API_OUT"
  api_auth admin GET /api/backup/config config && print_kv "$API_OUT"
  [ "$show" -eq 1 ] && return 0
  if [ -z "$mode$every$keep" ]; then
    have_tty || { err "no terminal; pass on|off, --every MIN, --keep N"; return 1; }
    read -r -p "Scheduled backups on? [$([ "$en" = 1 ] && echo Y/n || echo y/N)] " a || a=""
    case "$a" in y|Y|yes) mode=on ;; n|N|no) mode=off ;; *) [ "$en" = 1 ] && mode=on || mode=off ;; esac
    read -r -p "Interval in minutes [$iv]: " every || every=""
    read -r -p "Keep the last N backups, 0 keeps all [$kl]: " keep || keep=""
  fi
  every="${every:-$iv}"; keep="${keep:-$kl}"
  case "$every" in ''|*[!0-9]*) err "the interval must be a whole number of minutes"; return 2 ;; esac
  case "$keep" in ''|*[!0-9]*) err "keep-last must be a whole number (0 keeps all)"; return 2 ;; esac
  [ "$every" -ge 1 ] || { err "the interval must be at least 1 minute"; return 2; }
  [ -n "$mode" ] || { [ "$en" = 1 ] && mode=on || mode=off; }
  body="{\"enabled\":$([ "$mode" = on ] && echo true || echo false),\"fullIntervalMin\":$every,\"keepLast\":$keep}"
  api_auth admin POST /api/backup/config config "$body" || { err "the settings were not saved"; return 1; }
  print_kv "$API_OUT"
  ok "saved"
}

# ── restore ─────────────────────────────────────────────────────────────
restore_msg() {
  case "$1" in
    0) ok "restore done" ;;
    1) err "the restore failed (exit 1); the container stays stopped. Read the output above, then: btct start" ;;
    2) err "the restore was refused (exit 2): the copy did not verify or needs another flag; nothing was changed" ;;
    3) err "the restore was refused (exit 3): the server still holds the data; nothing was changed" ;;
    4) err "the restore was refused (exit 4): not enough free space in the data volume; nothing was changed" ;;
    5) err "the container user (uid 1000) cannot read that copy, so it was not checked (exit 5); nothing was changed. Fix: sudo chown 1000:1000 on the file" ;;
    *) err "the restore ended with exit $1" ;;
  esac
}

cmd_restore() {
  need_docker || return 1
  local name="" flags=() force=0 a dir rows n i pick typed rc
  for a in "$@"; do
    case "$a" in
      --keep-browser-caches|--partial) flags+=("$a") ;;
      -*) err "unknown option for restore: $a"; return 2 ;;
      *) name=$a ;;
    esac
  done
  [ "$ASSUME_YES" -eq 1 ] && force=1
  dir="$(backup_host_dir)"
  if [ -z "$name" ]; then
    have_tty || { err "no terminal; pass the backup name: btct restore btct-backup-YYYYMMDD-HHMMSS.zip"; return 1; }
    rows="$(list_host_backups "$dir")"
    [ -n "$rows" ] || { err "no backups in $dir"; return 1; }
    say "${C_B}Backups in $dir${C_0} (newest first)"
    i=0
    while IFS=$'\t' read -r n b d; do
      i=$((i + 1)); printf '  %2d) %-36s %9s  %s\n' "$i" "$n" "$(human_kb $((b / 1024)))" "$d"
    done <<<"$rows"
    read -r -p "Restore which one (number, Enter cancels)? " pick || pick=""
    case "$pick" in ''|*[!0-9]*) info "cancelled"; return 0 ;; esac
    name="$(printf '%s\n' "$rows" | sed -n "${pick}p" | cut -f1)"
    [ -n "$name" ] || { err "no backup number $pick"; return 1; }
  fi
  name="$(basename "$name")"
  if [ ! -e "$dir/$name" ] && [ -f "$dir/$name.zip" ]; then name="$name.zip"; fi
  if [ ! -e "$dir/$name" ] && ! { [ "$(id -u)" -ne 0 ] && sudo -n test -e "$dir/$name" 2>/dev/null; }; then
    err "no backup $name in $dir"; return 1
  fi

  info "1/4 verifying $name (BTCT keeps running)"
  compose run --rm --no-deps -T btct bun restore.mjs --verify "/backups/$name"; rc=$?
  if [ "$rc" -ne 0 ]; then
    if [ "$rc" -eq 5 ]; then restore_msg 5; else err "verification failed (exit $rc); not restoring this copy"; fi
    return 1
  fi
  ok "$name verified"
  warn "a restore replaces ALL current data with this backup (the current data is kept in /data/pre-restore-<stamp>/ in the volume)"
  if [ "$force" -eq 0 ]; then
    have_tty || { err "no terminal to confirm on; add --yes"; return 1; }
    read -r -p "Type the backup name ($name) to restore it: " typed || typed=""
    [ "$typed" = "$name" ] || [ "$typed" = "${name%.zip}" ] || { info "cancelled; nothing changed"; return 0; }
  fi
  info "2/4 stopping BTCT"
  compose stop btct || { err "could not stop the container"; return 1; }
  info "3/4 restoring $name"
  compose run --rm --no-deps -T btct bun restore.mjs "/backups/$name" --yes "${flags[@]}"; rc=$?
  restore_msg "$rc"
  if [ "$rc" -eq 1 ]; then return 1; fi
  info "4/4 starting BTCT"
  compose start btct || { err "could not start the container"; return 1; }
  wait_health || return 1
  [ "$rc" -eq 0 ] || return 1
  ok "BTCT is back on the data from $name. Open browsers reload themselves."
}

# ── passwords, logs, update, check ──────────────────────────────────────
cmd_passwords() {
  need_running || return 1
  warn "this prints account passwords on the screen"
  confirm "Show them?" n || { have_tty && return 0; }
  dk exec "$CNAME" cat /data/initial-passwords.txt 2>/dev/null \
    || info "no generated passwords (all set in .env, or the file was deleted)"
  say "  (change them after the first login, then delete the file: ${DK[*]} exec $CNAME rm /data/initial-passwords.txt)"
}

cmd_logs() {
  need_docker || return 1
  local follow=0 lines=100 a
  for a in "$@"; do
    case "$a" in -f|--follow) follow=1 ;; [0-9]*) lines=$a ;; *) err "usage: btct logs [-f] [LINES]"; return 2 ;; esac
  done
  if [ "$follow" -eq 1 ]; then
    info "following the log; Ctrl+C stops"
    trap ':' INT
    compose_tty logs -f --tail="$lines" btct
    trap - INT
    echo
  else
    compose logs --tail="$lines" btct
  fi
}

GITC=()
git_c() { "${GITC[@]}" "$@"; }
set_git() {
  local owner; owner="$(stat -c %U "$APP_DIR")"
  if [ "$(id -u)" -eq 0 ] && [ "$owner" != root ] && [ "$owner" != UNKNOWN ]; then
    GITC=(sudo -u "$owner" -H env GIT_TERMINAL_PROMPT=0 git -c safe.directory="$APP_DIR" -C "$APP_DIR")
  else
    GITC=(env GIT_TERMINAL_PROMPT=0 git -C "$APP_DIR")
  fi
}

# ── update and rollback ─────────────────────────────────────────────────
UPDATE_BRANCH=comp-ready        # where `btct update` pulls from unless --branch says otherwise
UPDATE_REMOTE=origin
STATE_FILE="$APP_DIR/.btct-update"  # untracked: built=<commit the running image came from>
SNAP_KEEP=3

state_get() { [ -f "$STATE_FILE" ] && sed -n "s/^$1=//p" "$STATE_FILE" | tail -n1; return 0; }
state_set() { # KEY VALUE: rewrite that one line, keep the rest
  local tmp; tmp="$(mktemp)" || return 0
  { [ -f "$STATE_FILE" ] && grep -v "^$1=" "$STATE_FILE"; printf '%s=%s\n' "$1" "$2"; } > "$tmp"
  cat "$tmp" > "$STATE_FILE" 2>/dev/null || warn "could not write $STATE_FILE"
  rm -f "$tmp"
}

# The image compose builds and runs (image: in the compose file), and the
# tag `btct update` keeps the one it replaces under.
compose_image() {
  local img
  img="$(compose config --images 2>/dev/null | head -n1)"
  [ -n "$img" ] || img="$(compose config 2>/dev/null | awk '$1 == "image:" {print $2; exit}')"
  printf '%s' "${img:-btct:latest}"
}
previous_tag() {
  local img=$1
  case "${img##*/}" in *:*) img="${img%:*}" ;; esac
  printf '%s:previous' "$img"
}
# The named volume mounted at /data (compose names it <project>_btct-data).
data_volume() {
  local v=""
  c_exists && v="$(dk inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' "$CNAME" 2>/dev/null)"
  printf '%s' "${v:-${PROJECT}_btct-data}"
}
free_kb_of() {
  local p=$1
  while [ ! -e "$p" ] && [ "$p" != / ]; do p="$(dirname "$p")"; done
  df -Pk "$p" 2>/dev/null | awk 'NR==2 {print $4}'
}
# Make the snapshot folder exist (docker's --mount does not create it).
ensure_dir() {
  [ -d "$1" ] && return 0
  mkdir -p "$1" 2>/dev/null || as_root mkdir -p "$1" 2>/dev/null || return 1
  [ "$(id -u)" -eq 0 ] && chown 1000:1000 "$1" 2>/dev/null
  return 0
}

# A helper container from IMAGE (the BTCT image itself: it has tar, gzip and
# find, and it is already on the box, so this works offline) running as root
# with the data volume mounted. The server never runs in it.
helper() { # IMAGE VOLUME VOLMODE(ro|rw) DIR DIRTARGET DIRMODE -- script args...
  local img=$1 vol=$2 vmode=$3 dir=$4 dtarget=$5 dmode=$6 vro="" dro=""
  shift 6
  [ "$vmode" = ro ] && vro=",readonly"
  [ "$dmode" = ro ] && dro=",readonly"
  dk run --rm --user 0 --network none --entrypoint sh \
    --mount "type=volume,source=$vol,target=/data$vro" \
    --mount "type=bind,source=$dir,target=$dtarget$dro" \
    "$img" -c "$@"
}

# Snapshot the (stopped) data volume into DIR/pre-update-<stamp>.tgz, keep
# the newest SNAP_KEEP, print the path. A copy of the live LevelDB or SQLite
# would be torn (invariant 12), so the caller stops the container first.
SNAP_PATH=""
take_snapshot() { # VOLUME IMAGE DIR
  local vol=$1 img=$2 dir=$3 name
  name="pre-update-$(date +%Y%m%d-%H%M%S).tgz"
  ensure_dir "$dir" || { err "could not create $dir"; return 1; }
  # shellcheck disable=SC2016  # expanded by the helper's sh
  helper "$img" "$vol" ro "$dir" /out rw '
    set -e
    tar -czf "/out/$1.partial" --numeric-owner -C /data .
    chown 1000:1000 "/out/$1.partial"; chmod 600 "/out/$1.partial"
    mv "/out/$1.partial" "/out/$1"
    ls -1 /out | grep -E "^pre-update-[0-9]{8}-[0-9]{6}\.tgz$" | sort -r | tail -n +$(($2 + 1)) \
      | while read -r old; do rm -f "/out/$old"; done' sh "$name" "$SNAP_KEEP" || return 1
  SNAP_PATH="$dir/$name"
}

newest_snapshot() { priv_ls "$1" | grep -E '^pre-update-[0-9]{8}-[0-9]{6}\.tgz$' | sort | tail -n1; }

rollback_hint() { # PREVIOUS_TAG SNAPSHOT
  say ""
  say "  ${C_B}How to go back${C_0}"
  say "    btct rollback            run the image from before this update again ($1)"
  if [ -n "$2" ]; then
    say "    btct rollback --data     the same, and put the data back to $2"
  fi
  say "  The data volume was not changed by the update; only the image is new."
}

git_auth_hint() {
  say ""
  say "  ${C_B}The repo is private, so this machine needs a GitHub login once.${C_0} Either:"
  say "    a) GitHub CLI:   gh auth login     then     gh auth setup-git"
  say "    b) a fine-grained token (GitHub > Settings > Developer settings > Fine-grained"
  say "       tokens; only this repository; Contents: Read-only), then:"
  say "         git -C $APP_DIR config credential.helper store"
  say "         git -C $APP_DIR fetch $UPDATE_REMOTE"
  say "       and give your GitHub user name, with the token as the password. It is saved"
  say "       in ~/.git-credentials (plain text, mode 600) of the user who runs git."
  say "  Run these as $(stat -c %U "$APP_DIR"), the owner of the checkout, then: btct update"
}

cmd_update() {
  local branch="" rebuild=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --branch) branch="${2:-}"; [ -n "$branch" ] || { err "--branch needs a name"; return 2; }; shift 2 ;;
      --branch=*) branch="${1#--branch=}"; shift ;;
      --rebuild) rebuild=1; shift ;;
      *) err "unknown option for update: $1 (btct update [--branch NAME] [--rebuild] [-y])"; return 2 ;;
    esac
  done
  local target="${branch:-$UPDATE_BRANCH}"
  need_docker || return 1
  command -v git >/dev/null 2>&1 || { err "git is not installed"; return 1; }
  set_git
  git_c rev-parse --git-dir >/dev/null 2>&1 || { err "$APP_DIR is not a git checkout"; return 1; }
  git check-ref-format --branch "$target" >/dev/null 2>&1 || { err "not a branch name: $target"; return 2; }
  git_c remote get-url "$UPDATE_REMOTE" >/dev/null 2>&1 || { err "the checkout has no remote named $UPDATE_REMOTE"; return 1; }

  local dirty cur use switch=0 ref fo n head before built up has_c=0 running=0
  dirty="$(git_c status --porcelain --untracked-files=no)"
  if [ -n "$dirty" ]; then
    err "the checkout has local changes to tracked files, so it is not updated:"
    printf '%s\n' "$dirty" | sed 's/^/    /' >&2
    say "  Set them aside and update:   git -C $APP_DIR stash push -m 'before btct update'  &&  btct update"
    say "  (bring them back later with: git -C $APP_DIR stash pop)"
    say "  Or throw them away:          git -C $APP_DIR checkout -- ."
    say "  Settings belong in .env, which git does not track, so they are never in the way."
    return 1
  fi

  cur="$(git_c symbolic-ref --quiet --short HEAD 2>/dev/null)" || cur=""
  use=$target
  if [ "$cur" != "$target" ]; then
    if [ -n "$cur" ]; then warn "the checkout is on the branch '$cur', not '$target'"
    else warn "the checkout is not on a branch (detached at $(git_c rev-parse --short HEAD))"; fi
    if confirm "Switch it to '$target' and update from there?" y; then
      switch=1
    elif [ -n "$cur" ]; then
      use=$cur; info "staying on '$cur'"
    else
      err "a detached checkout cannot be updated; run btct update again and answer yes"; return 1
    fi
  fi
  ref="$UPDATE_REMOTE/$use"

  info "fetching '$use' from $UPDATE_REMOTE ($(git_c remote get-url "$UPDATE_REMOTE"))"
  if ! fo="$(timeout 120 "${GITC[@]}" fetch --quiet "$UPDATE_REMOTE" "+refs/heads/$use:refs/remotes/$ref" 2>&1)"; then
    [ -n "$fo" ] && printf '%s\n' "$fo" | sed 's/^/    /' >&2
    if printf '%s' "$fo" | grep -qiE "couldn't find remote ref|could not find remote ref"; then
      err "$UPDATE_REMOTE has no branch '$use'; nothing changed"
    elif printf '%s' "$fo" | grep -qiE 'authentication failed|could not read username|could not read password|terminal prompts disabled|permission denied \(publickey|repository not found|invalid username or password|error: 40[13]|requested url returned error: 40[134]'; then
      err "the fetch was refused: this machine has no GitHub login for the repo; nothing changed"
      git_auth_hint
    else
      err "fetch failed (offline, or the remote is unreachable); nothing changed"
    fi
    return 1
  fi

  head="$(git_c rev-parse HEAD)"
  before="$(git_c log -1 --format='%h %s')"
  if [ "$switch" -eq 1 ] && git_c show-ref --verify --quiet "refs/heads/$target" \
     && ! git_c merge-base --is-ancestor "refs/heads/$target" "$ref"; then
    err "the local '$target' has commits that are not on $ref, so it cannot be fast-forwarded; nothing changed"
    return 1
  fi
  if [ "$switch" -eq 0 ] && ! git_c merge-base --is-ancestor HEAD "$ref"; then
    if git_c merge-base --is-ancestor "$ref" HEAD; then
      n=0
    else
      err "'$use' and $ref have both moved on (local commits that are not on the remote); nothing changed"
      return 1
    fi
  else
    n="$(git_c rev-list --count "HEAD..$ref")"
  fi
  if [ "$switch" -eq 0 ]; then
    up="$(git_c rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null)" || up=""
    if [ -z "$up" ]; then
      git_c branch --quiet --set-upstream-to="$ref" "$use" >/dev/null 2>&1 && info "'$use' had no upstream; it now tracks $ref"
    fi
  fi

  say "  now:   $before (${cur:-detached}${up:+, tracking $up})"
  built="$(state_get built)"
  c_exists && has_c=1
  c_running && running=1
  if [ "$switch" -eq 0 ] && [ "$n" -eq 0 ]; then
    if [ "$rebuild" -eq 0 ] && [ "$built" = "$head" ]; then
      ok "already up to date, and the image BTCT runs was built from this commit"
      [ "$running" -eq 1 ] || say "  BTCT is not running; start it with: btct start"
      return 0
    fi
    info "no new commits on $ref"
    if [ "$rebuild" -eq 0 ]; then
      say "  The running image may be older than this checkout (no record that it was built from $(git_c rev-parse --short HEAD))."
      confirm "Rebuild the image from this checkout and restart BTCT (data is kept and snapshotted first)?" n \
        || { info "nothing changed"; return 0; }
    fi
  else
    if [ "$switch" -eq 1 ]; then say "  switch: ${cur:-detached} -> $target"; fi
    say "  $n new commit(s) on $ref:"
    git_c log --oneline "HEAD..$ref" | head -n 20 | sed 's/^/    /'
    [ "$n" -gt 20 ] && say "    ... and $((n - 20)) more"
    confirm "Update to them: build the new image (BTCT keeps running), then stop it for a few seconds to snapshot the data, then start the new version?" n \
      || { info "nothing changed"; return 0; }
  fi

  # Where the data is, where the snapshot goes, and whether it fits. Checked
  # before anything moves, so a "no" leaves everything as it was.
  local img prev vol="" snapdir old_img="" take_snap=0 need_kb free_kb
  img="$(compose_image)"
  prev="$(previous_tag "$img")"
  snapdir="$(backup_host_dir)"
  if [ "$has_c" -eq 1 ]; then
    vol="$(data_volume)"
    old_img="$(dk inspect -f '{{.Image}}' "$CNAME" 2>/dev/null)"
    take_snap=1
    need_kb="$(dk run --rm --user 0 --network none --entrypoint du --mount "type=volume,source=$vol,target=/data,readonly" "$old_img" -sk /data 2>/dev/null | awk '{print $1}')"
    free_kb="$(free_kb_of "$snapdir")"
    if [ -n "$need_kb" ] && [ -n "$free_kb" ] && [ "$free_kb" -lt $((need_kb + 102400)) ]; then
      warn "not enough free space for a pre-update snapshot: the data is $(human_kb "$need_kb"), $snapdir has $(human_kb "$free_kb") free"
      if confirm "Update without a snapshot (the data volume itself is kept either way)?" n; then
        take_snap=0
      else
        info "nothing changed; free some space (or move the backup folder: btct backup-dir) and run btct update again"
        return 1
      fi
    fi
  fi

  # 1. the code
  local gitok=1
  if [ "$switch" -eq 1 ]; then
    if git_c show-ref --verify --quiet "refs/heads/$target"; then
      if ! git_c checkout --quiet "$target" || ! git_c merge --ff-only --quiet "$ref"; then gitok=0; fi
    else
      git_c checkout --quiet -b "$target" --track "$ref" || gitok=0
    fi
    [ "$gitok" -eq 1 ] && git_c branch --quiet --set-upstream-to="$ref" "$target" >/dev/null 2>&1
  elif [ "$n" -gt 0 ]; then
    git_c merge --ff-only --quiet "$ref" || gitok=0
  fi
  if [ "$gitok" -eq 0 ]; then
    if [ "$switch" -eq 1 ]; then git_c checkout --quiet "${cur:-$head}" 2>/dev/null; fi
    err "git could not move the checkout to $ref; nothing changed"
    return 1
  fi
  local after; after="$(git_c log -1 --format='%h %s')"
  say "  before: $before"
  say "  after:  $after"

  # 2. hold on to the image that runs now: with Docker's containerd image
  # store, the image a rebuild takes the tag from is deleted at once, even
  # while its container still runs, so it needs a tag of its own first
  local hold=""
  if [ -n "$old_img" ]; then
    hold="${prev%:previous}:update-hold"
    if ! dk tag "$old_img" "$hold"; then
      if [ "$switch" -eq 1 ]; then git_c checkout --quiet "${cur:-$head}"; else git_c reset --keep --quiet "$head"; fi
      err "could not tag the running image; nothing changed"
      return 1
    fi
  fi

  # 3. build while the old container keeps serving
  info "building the new image while BTCT keeps running (several minutes on a small box)"
  if ! compose build btct; then
    if [ "$switch" -eq 1 ]; then git_c checkout --quiet "${cur:-$head}"
    else git_c reset --keep --quiet "$head"; fi
    [ -n "$hold" ] && dk image rm "$hold" >/dev/null 2>&1
    err "the build failed. The checkout is back on $before and BTCT keeps running the old version; nothing else changed."
    return 1
  fi
  ok "built $img"

  # 4. the image that ran until now becomes <image>:previous, for btct rollback
  if [ -n "$hold" ]; then
    if [ "$running" -eq 1 ] && healthy; then
      dk tag "$hold" "$prev" && info "kept the image that ran until now as $prev"
    elif dk image inspect "$prev" >/dev/null 2>&1; then
      warn "BTCT is not healthy right now, so $prev keeps pointing at the last image that was"
    else
      dk tag "$hold" "$prev" && info "kept the image that ran until now as $prev"
    fi
  fi

  # 5. stop, snapshot, start
  if [ "$has_c" -eq 1 ]; then
    info "stopping BTCT (it flushes its data first)"
    compose stop btct || { err "could not stop the container; BTCT keeps running the old version"; return 1; }
    if [ "$take_snap" -eq 1 ]; then
      info "snapshotting the data volume $vol"
      if take_snapshot "$vol" "$hold" "$snapdir"; then
        ok "snapshot: $SNAP_PATH"
        state_set snapshot "$SNAP_PATH"
      else
        err "the snapshot failed"
        if ! confirm "Start the new version anyway, without a snapshot?" n; then
          info "starting the old version again"
          compose start btct; HOST_PORT=""; wait_health
          say "  The new image is built; run btct update again once the snapshot problem is fixed."
          return 1
        fi
      fi
    fi
  fi
  state_set previous_commit "$head"
  info "starting the new version"
  HOST_PORT=""
  local uprc=0
  compose up -d || uprc=$?
  [ -n "$hold" ] && dk image rm "$hold" >/dev/null 2>&1
  if [ "$uprc" -ne 0 ]; then
    err "compose up failed"
    rollback_hint "$prev" "$SNAP_PATH"
    return 1
  fi
  if ! wait_health; then
    err "the new version did not come up healthy"
    rollback_hint "$prev" "$SNAP_PATH"
    return 1
  fi
  state_set built "$(git_c rev-parse HEAD)"
  ok "updated to $after"
  [ -n "$vol" ] && say "  data: kept in the volume $vol"
  [ -n "$SNAP_PATH" ] && say "  pre-update snapshot: $SNAP_PATH (the newest $SNAP_KEEP are kept)"
  say "  open http://127.0.0.1:$(host_port)"
}

cmd_rollback() {
  local with_data=0 snap="" a
  for a in "$@"; do
    case "$a" in
      --data) with_data=1 ;;
      --no-data) with_data=-1 ;;
      -*) err "unknown option for rollback: $a (btct rollback [--data] [SNAPSHOT])"; return 2 ;;
      *) snap=$a ;;
    esac
  done
  need_docker || return 1
  local img prev dir vol stamp
  img="$(compose_image)"
  prev="$(previous_tag "$img")"
  if ! dk image inspect "$prev" >/dev/null 2>&1; then
    err "there is no $prev image to go back to (btct update keeps one each time it runs)"
    return 1
  fi
  dir="$(backup_host_dir)"
  if [ -n "$snap" ]; then
    snap="$(basename "$snap")"
  else
    snap="$(newest_snapshot "$dir")"
  fi
  say "  go back to: $prev (built $(dk image inspect -f '{{.Created}}' "$prev" | cut -c1-16 | tr T ' '))"
  if [ "$with_data" -eq 0 ] && [ -n "$snap" ] && have_tty && [ "$ASSUME_YES" -eq 0 ]; then
    say "  newest data snapshot: $dir/$snap"
    if confirm "Also put the data back to that snapshot? Everything written since is moved aside, not deleted" n; then with_data=1; fi
  fi
  [ "$with_data" -eq 1 ] || with_data=0
  if [ "$with_data" -eq 1 ]; then
    [ -n "$snap" ] || { err "no pre-update-*.tgz snapshot in $dir"; return 1; }
    priv_ls "$dir" | grep -qxF "$snap" || { err "no snapshot $snap in $dir"; return 1; }
  fi
  confirm "Run the previous version again$([ "$with_data" -eq 1 ] && printf ' with the data from %s' "$snap")?" y \
    || { info "nothing changed"; return 0; }

  dk tag "$prev" "$img" || { err "could not tag $prev as $img"; return 1; }
  ok "$img now points at the previous image"
  if [ "$with_data" -eq 1 ]; then
    vol="$(data_volume)"
    stamp="$(date +%Y%m%d-%H%M%S)"
    info "stopping BTCT (it flushes its data first)"
    compose stop btct || { err "could not stop the container"; return 1; }
    info "putting the data back from $snap (the current data goes to /data/pre-rollback-$stamp/ in the volume)"
    # shellcheck disable=SC2016  # expanded by the helper's sh
    if ! helper "$img" "$vol" rw "$dir" /snap ro '
        set -e
        f="/snap/$1"
        gzip -t "$f"
        tar -tzf "$f" >/dev/null
        aside="/data/pre-rollback-$2"
        mkdir "$aside"; chown 1000:1000 "$aside"
        for e in /data/* /data/.[!.]* /data/..?*; do
          [ -e "$e" ] || continue
          case "${e##*/}" in pre-rollback-*) continue ;; esac
          mv "$e" "$aside/"
        done
        tar -xzpf "$f" --numeric-owner -C /data' sh "$snap" "$stamp"; then
      err "putting the data back failed; the data that was there is in /data/pre-rollback-$stamp/ if that folder was made"
      return 1
    fi
    ok "data put back from $snap"
  fi
  info "starting the previous version"
  HOST_PORT=""
  compose up -d --no-build || { err "compose up failed"; return 1; }
  wait_health || return 1
  state_set built ""
  ok "rolled back. The checkout still has the newer code; the next btct update builds it again."
}

cmd_check() {
  [ -x "$APP_DIR/competition-day.sh" ] || { err "competition-day.sh is missing"; return 1; }
  "$APP_DIR/competition-day.sh" --check-only
}

# ── install / uninstall ─────────────────────────────────────────────────
target_user() {
  if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then printf '%s' "$SUDO_USER"
  else id -un; fi
}
target_home() { getent passwd "$1" 2>/dev/null | cut -d: -f6; }
as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }

# Drop every marked line from a file (in place, keeping owner and mode).
strip_alias() {
  local f=$1 tmp
  [ -f "$f" ] && grep -qF "$ALIAS_MARK" "$f" || return 0
  tmp="$(mktemp)"
  grep -vF "$ALIAS_MARK" "$f" > "$tmp"
  cat "$tmp" > "$f"
  rm -f "$tmp"
}

cmd_install() {
  local u home line f
  u="$(target_user)"; home="$(target_home "$u")"; home="${home:-$HOME}"
  line="alias btct='$SELF'  $ALIAS_MARK"
  chmod +x "$SELF" 2>/dev/null || true
  if [ -L "$LINK_PATH" ] || [ ! -e "$LINK_PATH" ]; then
    if [ "$(readlink "$LINK_PATH" 2>/dev/null)" = "$SELF" ]; then
      ok "$LINK_PATH already points to $SELF"
    elif as_root ln -sfn "$SELF" "$LINK_PATH"; then
      ok "linked $LINK_PATH -> $SELF"
    else
      warn "could not create $LINK_PATH (the shell alias below still works)"
    fi
  else
    warn "$LINK_PATH exists and is not a link; leaving it alone (the shell alias below still works)"
  fi
  for f in "$home/.zshrc" "$home/.bashrc"; do
    if [ -f "$f" ] && grep -qxF "$line" "$f" && [ "$(grep -cF "$ALIAS_MARK" "$f")" -eq 1 ]; then
      ok "$f already has the btct alias"; continue
    fi
    if [ ! -e "$f" ]; then
      : > "$f" || { warn "could not create $f"; continue; }
      [ "$(id -u)" -eq 0 ] && [ "$u" != root ] && chown "$u:" "$f"
    fi
    strip_alias "$f"
    printf '%s\n' "$line" >> "$f" && ok "added the btct alias to $f"
  done
  say ""
  say "Use it now:  source ~/.zshrc   (zsh, the Kali default)  or  source ~/.bashrc"
  say "             or open a new terminal. Then type: btct"
}

cmd_uninstall() {
  local u home f
  u="$(target_user)"; home="$(target_home "$u")"; home="${home:-$HOME}"
  if [ -L "$LINK_PATH" ] && [ "$(basename "$(readlink "$LINK_PATH")")" = btct.sh ]; then
    as_root rm -f "$LINK_PATH" && ok "removed $LINK_PATH"
  else
    info "no btct link in $LINK_PATH"
  fi
  for f in "$home/.zshrc" "$home/.bashrc"; do
    if [ -f "$f" ] && grep -qF "$ALIAS_MARK" "$f"; then strip_alias "$f"; ok "removed the btct alias from $f"; fi
  done
  say "Open a new terminal (or run: unalias btct) to drop it from this one."
}

# ── help and menu ───────────────────────────────────────────────────────
cmd_help() {
  sed -n '2,/^# BTCT_MENU=text/p' "$SELF" | sed -e 's/^# \{0,1\}//'
}

MENU_ITEMS=(
  1 "Status"
  2 "Start"
  3 "Stop"
  4 "Restart"
  5 "Set backup folder"
  6 "Back up now"
  7 "List backups"
  8 "Scheduled backups"
  9 "Restore a backup"
  10 "Show passwords"
  11 "Logs"
  12 "Update to the latest comp-ready (keeps the data)"
  13 "Roll back the last update"
  14 "Competition-day check"
  15 "Install / uninstall the btct command"
  0 "Quit"
)

menu_header() {
  local st="not created" port dir
  if c_exists; then
    st="$(dk inspect -f '{{.State.Status}}{{if .State.Health}}, {{.State.Health.Status}}{{end}}' "$CNAME" 2>/dev/null)"
  fi
  port="$(host_port)"
  dir="$(backup_host_dir)"
  printf 'BTCT %s  |  http://127.0.0.1:%s  |  backups: %s' "$st" "$port" "$dir"
}

run_choice() {
  case "$1" in
    1) cmd_status ;;
    2) cmd_start ;;
    3) cmd_stop ;;
    4) cmd_restart ;;
    5) cmd_backup_dir ;;
    6) cmd_backup ;;
    7) cmd_backups ;;
    8) cmd_schedule ;;
    9) cmd_restore ;;
    10) cmd_passwords ;;
    11) local a; read -r -p "f = follow (Ctrl+C returns here), Enter = last 100 lines: " a || a=""
        if [ "$a" = f ]; then cmd_logs -f; else cmd_logs; fi ;;
    12) cmd_update ;;
    13) cmd_rollback ;;
    14) cmd_check ;;
    15) local a; read -r -p "i = install, u = uninstall: " a || a=""
        case "$a" in i) cmd_install ;; u) cmd_uninstall ;; *) info "nothing changed" ;; esac ;;
    *) err "no such entry: $1" ;;
  esac
}

pause() { local _a; echo; read -r -p "Press Enter to return to the menu " _a || true; }

menu() {
  have_tty || { err "the menu needs a terminal; see: btct help"; return 1; }
  need_docker || warn "docker is not ready; only Install, Check and Quit will work"
  local choice use_wt=0 i
  if [ "${BTCT_MENU:-}" != text ] && [ -n "${TERM:-}" ] && [ "${TERM:-}" != dumb ] && command -v whiptail >/dev/null 2>&1; then use_wt=1; fi
  while :; do
    if [ "$use_wt" -eq 1 ]; then
      choice="$(whiptail --title "BTCT" --cancel-button "Quit" --menu "$(menu_header)" 24 78 16 "${MENU_ITEMS[@]}" 3>&1 1>&2 2>&3)" || choice=0
      clear
    else
      echo
      say "${C_B}$(menu_header)${C_0}"
      for ((i = 0; i < ${#MENU_ITEMS[@]}; i += 2)); do
        printf '  %2s) %s\n' "${MENU_ITEMS[i]}" "${MENU_ITEMS[i + 1]}"
      done
      read -r -p "Choose: " choice || choice=0
    fi
    case "$choice" in
      0|q|Q|quit) return 0 ;;
      "") continue ;;
    esac
    echo
    run_choice "$choice"
    pause
  done
}

main() {
  local args=() a
  for a in "$@"; do
    case "$a" in -y|--yes) ASSUME_YES=1 ;; *) args+=("$a") ;; esac
  done
  set -- "${args[@]+"${args[@]}"}"
  local cmd="${1:-menu}"
  [ $# -gt 0 ] && shift
  case "$cmd" in
    menu) menu ;;
    status) cmd_status ;;
    start) cmd_start ;;
    stop) cmd_stop ;;
    restart) cmd_restart ;;
    backup-dir|backup-folder) cmd_backup_dir "$@" ;;
    backup) cmd_backup ;;
    backups|list) cmd_backups ;;
    schedule) cmd_schedule "$@" ;;
    restore) cmd_restore "$@" ;;
    passwords) cmd_passwords ;;
    logs) cmd_logs "$@" ;;
    update) cmd_update "$@" ;;
    rollback) cmd_rollback "$@" ;;
    check) cmd_check ;;
    install) cmd_install ;;
    uninstall) cmd_uninstall ;;
    help|-h|--help) cmd_help ;;
    *) err "unknown command: $cmd"; cmd_help >&2; return 2 ;;
  esac
}

# One line, so bash has read all of it before main runs: `btct update` can
# replace this file while it runs.
{ main "$@"; exit $?; }
