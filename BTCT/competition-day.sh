#!/usr/bin/env bash
# competition-day.sh: get BTCT running on a Kali (or other Debian-family) box
# as fast as possible, checking everything it needs on the way.
#
# It runs ten labelled steps and ends with a PASS/WARN/FAIL table:
#    1. Preflight: root, OS, internet, disk, RAM/CPU, clock
#    2. apt-get update (UPDATE ONLY: this script never upgrades the system)
#    3. Base tools: git curl openssl ca-certificates iproute2 (only missing ones)
#    4. Docker: engine, compose, daemon running, docker group
#    5. BTCT code: this checkout, or a clone of $BTCT_REPO in $BTCT_DIR
#    6. Image: load btct-image.tar.gz when present, else build
#    7. Config: .env AUTH_SECRET, backup folder, host port, optional limits
#    8. Launch: docker compose up -d, wait for /healthz
#    9. Hand-off: LAN URLs, accounts, passwords, backups, reminders
#   10. Summary table
#
# Safe to re-run: every step checks before it acts. It never runs
# apt-get upgrade, dist-upgrade or full-upgrade, never discards local git
# changes, never prints AUTH_SECRET and never touches the btct-data volume.
# Packages are installed with --no-upgrade, so a package that is already
# installed is left at its version (apt may still have to pull a newer
# library a new package depends on; step 3 and 4 list those first, and
# --no-dep-upgrades refuses them instead).
#
# Usage:
#   ./competition-day.sh                    # full run
#   ./competition-day.sh --check-only       # report every step, change nothing
#   ./competition-day.sh --offline --image /media/usb/btct-image.tar.gz
#
# Options:
#   --check-only       report only: no apt update, no installs, no launch
#   --offline          skip every network step (no apt update, no git pull, no build)
#   --image PATH       image tarball made by save-btct-image.sh (default:
#                      btct-image.tar.gz next to this script or in the repo)
#   --no-build         never build the image; use a tarball or the existing btct:latest
#   --limits           cap the container at 1 GB RAM and 2 CPUs (writes
#                      docker-compose.override.yml)
#   --show-passwords   print /data/initial-passwords.txt at the end
#   --no-dep-upgrades  refuse an install that would upgrade an installed package
#   -h, --help         this text
#
# Environment:
#   BTCT_REPO         git URL     (default https://github.com/rocast560/BTCT.git)
#   BTCT_BRANCH       branch      (default comp-ready, the branch `btct update` follows)
#   BTCT_DIR          clone path  (default /opt/btct), used outside a checkout
#   HEALTH_TIMEOUT    seconds to wait for /healthz (default 180)
#   APT_LOCK_TIMEOUT  seconds to wait for another apt/dpkg to finish (default 300)
#
# Exit code: 0 when no step failed, 1 when at least one did, 2 for a bad option.

# Steps are called through run_step, which shellcheck cannot follow.
# shellcheck disable=SC2317
set -euo pipefail

BTCT_REPO="${BTCT_REPO:-https://github.com/rocast560/BTCT.git}"
BTCT_BRANCH="${BTCT_BRANCH:-comp-ready}"
BTCT_DIR="${BTCT_DIR:-/opt/btct}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-180}"
APT_LOCK_TIMEOUT="${APT_LOCK_TIMEOUT:-300}"
IMAGE_NAME="btct:latest"
ACCOUNTS="Roberto, Warren, Ryan, Anthony, Jesse, Darren"
TOTAL_STEPS=10

CHECK_ONLY=0
FORCE_OFFLINE=0
IMAGE_ARG=""
NO_BUILD=0
LIMITS=0
SHOW_PASSWORDS=0
NO_DEP_UPGRADES=0

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]:-$0}")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"

usage() { sed -n '2,/^# Exit code/p' "$SCRIPT_PATH" | sed 's/^# \{0,1\}//'; }

ORIG_ARGS=("$@")
while [ $# -gt 0 ]; do
  case "$1" in
    --check-only) CHECK_ONLY=1 ;;
    --offline) FORCE_OFFLINE=1 ;;
    --image) [ $# -ge 2 ] || { echo "--image needs a path" >&2; exit 2; }; IMAGE_ARG="$2"; shift ;;
    --image=*) IMAGE_ARG="${1#--image=}" ;;
    --no-build) NO_BUILD=1 ;;
    --limits) LIMITS=1 ;;
    --show-passwords) SHOW_PASSWORDS=1 ;;
    --no-dep-upgrades) NO_DEP_UPGRADES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done
if [ -n "$IMAGE_ARG" ]; then
  IMAGE_ARG="$(readlink -f -- "$IMAGE_ARG" 2>/dev/null || printf '%s' "$IMAGE_ARG")"
fi

# ── Root: re-run through sudo, keeping the settings that matter ─────────
# sudo resets the environment, so the few variables this script reads are
# handed over explicitly. sudo itself sets SUDO_USER.
if [ "$(id -u)" -ne 0 ]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "competition-day.sh needs root: run it as root, or install sudo" >&2
    exit 1
  fi
  keep=()
  for v in DISPLAY WAYLAND_DISPLAY XAUTHORITY XDG_RUNTIME_DIR BTCT_REPO BTCT_BRANCH BTCT_DIR \
           HEALTH_TIMEOUT APT_LOCK_TIMEOUT BACKUP_HOST_DIR NO_COLOR TERM; do
    [ -n "${!v:-}" ] && keep+=("$v=${!v}")
  done
  echo "[competition-day] not root; re-running with sudo"
  exec sudo env "${keep[@]}" bash "$SCRIPT_PATH" "${ORIG_ARGS[@]}"
fi
TARGET_USER="${SUDO_USER:-root}"
export DEBIAN_FRONTEND=noninteractive

# ── Output helpers ───────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_B=$'\033[1m'; C_G=$'\033[1;32m'; C_Y=$'\033[1;33m'; C_R=$'\033[1;31m'; C_C=$'\033[1;36m'; C_0=$'\033[0m'
else
  C_B=""; C_G=""; C_Y=""; C_R=""; C_C=""; C_0=""
fi
now_ms() { date +%s%3N; }
fmt_ms() { local ms=$1; printf '%d.%01ds' $((ms / 1000)) $(((ms % 1000) / 100)); }

STATUS="PASS"     # status of the step that is running
NOTE=""           # first WARN/FAIL message of that step, for the table
declare -a S_TITLE=() S_STATUS=() S_TIME=() S_NOTE=()

ok()   { printf '      %sok%s    %s\n' "$C_G" "$C_0" "$*"; }
info() { printf '      %sinfo%s  %s\n' "$C_C" "$C_0" "$*"; }
hint() { printf '      %shint%s  %s\n' "$C_C" "$C_0" "$*"; }
warn() {
  printf '      %sWARN%s  %s\n' "$C_Y" "$C_0" "$*"
  [ "$STATUS" = "PASS" ] && STATUS="WARN"
  [ -z "$NOTE" ] && NOTE="$*"
  return 0
}
fail() {
  printf '      %sFAIL%s  %s\n' "$C_R" "$C_0" "$*"
  if [ "$STATUS" != "FAIL" ]; then STATUS="FAIL"; NOTE="$*"; fi
  return 0
}
skip() { STATUS="SKIP"; NOTE="$*"; printf '      skip  %s\n' "$*"; }

# run_step N "Title" function: prints the header, runs the step, records the
# result. A step reports through ok/warn/fail; a command that fails inside it
# is checked explicitly, so one broken step never hides the summary.
run_step() {
  local n=$1 title=$2 fn=$3 t0 rc=0
  printf '\n%s[%d/%d] %s%s\n' "$C_B" "$n" "$TOTAL_STEPS" "$title" "$C_0"
  STATUS="PASS"; NOTE=""
  t0=$(now_ms)
  "$fn" || rc=$?
  [ "$rc" -ne 0 ] && fail "step stopped unexpectedly (exit $rc)"
  S_TITLE[n]="$title"; S_STATUS[n]="$STATUS"; S_TIME[n]=$(( $(now_ms) - t0 )); S_NOTE[n]="$NOTE"
}
step_ok() { [ "${S_STATUS[$1]:-FAIL}" = "PASS" ] || [ "${S_STATUS[$1]:-FAIL}" = "WARN" ]; }

# Run a command as the owner of a directory (git credentials and file
# ownership stay with the operator, not root).
as_owner() {
  local dir=$1; shift
  local owner
  owner="$(stat -c %U "$dir" 2>/dev/null || echo root)"
  if [ "$owner" = "root" ] || [ "$owner" = "UNKNOWN" ]; then
    "$@"
  else
    sudo -u "$owner" -H "$@"
  fi
}
# A terminal may prompt for a GitHub token; a script without one must not hang.
GIT_PROMPT=0; [ -t 0 ] && GIT_PROMPT=1
git_in() { local d=$1; shift; as_owner "$d" env GIT_TERMINAL_PROMPT="$GIT_PROMPT" git -c safe.directory="$d" -C "$d" "$@"; }

# TCP reachability with a short timeout and no dependency on curl.
reachable() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1; }

# GET a URL and succeed only on HTTP 200 (curl when present, else /dev/tcp).
http_ok() {
  local host=$1 port=$2 path=$3
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 3 -o /dev/null "http://$host:$port$path" 2>/dev/null
  else
    timeout 4 bash -c "exec 3<>/dev/tcp/$host/$port && printf 'GET $path HTTP/1.0\r\n\r\n' >&3 && read -r l <&3 && [[ \$l == *' 200 '* ]]" 2>/dev/null
  fi
}

free_kb() { df -Pk "$1" 2>/dev/null | awk 'NR==2 {print $4}'; }
existing_parent() { local p=$1; while [ ! -e "$p" ]; do p="$(dirname "$p")"; done; printf '%s' "$p"; }

# ── Shared state ─────────────────────────────────────────────────────────
OFFLINE=0
NET_APT=0; NET_GITHUB=0; NET_DOCKER=0; NET_REGISTRY=0
APT_HOST=""; APT_PORT=""
OS_ID=""; OS_LIKE=""; OS_CODENAME=""; OS_PRETTY=""
DOCKER_OK=0
COMPOSE=()
APP_DIR=""
IMAGE_READY=0
HOST_PORT=8080
BACKUP_DIR_SHOWN=""
LAUNCHED=0
RUN_START=$(now_ms)

# The compose project of an existing BTCT container (its label), so a box
# started from a folder with another name (e.g. BTCT-latest with -p btct)
# is reused instead of colliding on container_name btct. Empty when none.
compose_project() {
  docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' btct 2>/dev/null || true
}
compose() {
  local proj; proj="$(compose_project)"
  if [ -n "$proj" ]; then (cd "$APP_DIR" && "${COMPOSE[@]}" -p "$proj" "$@")
  else (cd "$APP_DIR" && "${COMPOSE[@]}" "$@"); fi
}

# ════════════════════════════════════════════════════════════════════════
# 1. Preflight
# ════════════════════════════════════════════════════════════════════════
apt_mirror() {
  # First http(s) apt source that is not Docker's, as "host port".
  local uri
  uri="$( { grep -hsE '^[[:space:]]*deb[[:space:]]' /etc/apt/sources.list /etc/apt/sources.list.d/*.list \
              | sed -E 's/\[[^]]*\]//' | awk '{print $2}'
            grep -hsiE '^[[:space:]]*URIs:' /etc/apt/sources.list.d/*.sources | awk '{print $2}'
          } | grep -E '^https?://' | grep -v 'download.docker.com' | head -n1 || true)"
  [ -n "$uri" ] || return 1
  local scheme="${uri%%://*}" rest="${uri#*://}"
  local hostport="${rest%%/*}"
  local host="${hostport%%:*}" port
  if [ "$hostport" != "$host" ]; then port="${hostport##*:}"
  elif [ "$scheme" = "https" ]; then port=443
  else port=80; fi
  printf '%s %s' "$host" "$port"
}

step_preflight() {
  ok "running as root (operator: $TARGET_USER)"
  [ "$CHECK_ONLY" -eq 1 ] && info "check-only mode: nothing will be installed, changed or launched"

  # OS
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"; OS_LIKE="${ID_LIKE:-}"; OS_CODENAME="${VERSION_CODENAME:-}"; OS_PRETTY="${PRETTY_NAME:-$OS_ID}"
    case " $OS_ID $OS_LIKE " in
      *" kali "*) ok "OS: $OS_PRETTY" ;;
      *" debian "*|*" ubuntu "*) warn "OS: $OS_PRETTY (Debian family, not Kali; should still work)" ;;
      *) warn "OS: $OS_PRETTY is not Debian-family; apt steps will probably fail" ;;
    esac
  else
    warn "/etc/os-release is missing; cannot tell which distro this is"
  fi
  command -v apt-get >/dev/null 2>&1 || fail "apt-get not found; this script needs a Debian-family system"

  # Internet
  if [ "$FORCE_OFFLINE" -eq 1 ]; then
    OFFLINE=1
    info "offline mode (--offline): no apt update, no git pull, no build"
  else
    local hp
    if hp="$(apt_mirror)"; then
      APT_HOST="${hp% *}"; APT_PORT="${hp#* }"
      if reachable "$APT_HOST" "$APT_PORT"; then NET_APT=1; ok "apt mirror $APT_HOST:$APT_PORT reachable"
      else info "apt mirror $APT_HOST:$APT_PORT not reachable"; fi
    else
      info "no http(s) apt source found in /etc/apt"
    fi
    if reachable github.com 443; then NET_GITHUB=1; ok "github.com reachable"; else info "github.com not reachable"; fi
    if reachable download.docker.com 443; then NET_DOCKER=1; ok "download.docker.com reachable"; else info "download.docker.com not reachable"; fi
    if reachable registry-1.docker.io 443; then NET_REGISTRY=1; ok "registry-1.docker.io reachable (needed to build)"; else info "registry-1.docker.io not reachable (a build needs it)"; fi
    if [ $((NET_APT + NET_GITHUB + NET_DOCKER + NET_REGISTRY)) -eq 0 ]; then
      OFFLINE=1
      warn "no internet: continuing in offline mode (bring btct-image.tar.gz on USB)"
    elif [ $((NET_APT + NET_GITHUB + NET_DOCKER + NET_REGISTRY)) -lt 4 ]; then
      warn "internet is partial; steps that need an unreachable host will be skipped"
    fi
  fi

  # Disk
  local kb gb path
  for path in / /var/lib/docker; do
    local real; real="$(existing_parent "$path")"
    kb="$(free_kb "$real")"; kb="${kb:-0}"
    gb=$(awk -v k="$kb" 'BEGIN { printf "%.1f", k/1048576 }')
    if [ "$kb" -lt 2097152 ]; then fail "only ${gb} GB free on $path (need 2 GB minimum, 5 GB recommended)"
    elif [ "$kb" -lt 5242880 ]; then warn "${gb} GB free on $path (5 GB recommended for the image and data)"
    else ok "${gb} GB free on $path"; fi
  done

  # RAM and CPU
  local mem_kb mem_gb cpus
  mem_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  mem_gb=$(awk -v k="${mem_kb:-0}" 'BEGIN { printf "%.1f", k/1048576 }')
  cpus="$(nproc 2>/dev/null || echo 1)"
  if [ "${mem_kb:-0}" -lt 1000000 ]; then warn "RAM ${mem_gb} GB (BTCT is sized for 1 to 2 GB; under 1 GB it may be killed)"
  else ok "RAM ${mem_gb} GB"; fi
  ok "CPUs: $cpus"

  # Clock: a wrong date breaks TLS and makes apt reject Release files.
  local year; year="$(date +%Y)"
  if [ "$year" -lt 2025 ]; then
    warn "system clock says $(date -u '+%F %T') UTC, which is in the past; fix it: sudo date -s 'YYYY-MM-DD HH:MM:SS'"
  else
    local remote="" skew
    if [ "$OFFLINE" -eq 0 ] && [ "$NET_GITHUB" -eq 1 ] && command -v curl >/dev/null 2>&1; then
      remote="$(curl -sI --max-time 4 https://github.com 2>/dev/null | tr -d '\r' | sed -n 's/^[Dd]ate: //p' | head -n1)"
    fi
    if [ -n "$remote" ] && remote="$(date -d "$remote" +%s 2>/dev/null)"; then
      skew=$(( $(date +%s) - remote )); skew=${skew#-}
      if [ "$skew" -gt 300 ]; then warn "clock is ${skew}s off from github.com; fix NTP (timedatectl set-ntp true) or set the date"
      else ok "clock: $(date -u '+%F %T') UTC (within ${skew}s of github.com)"; fi
    else
      ok "clock: $(date -u '+%F %T') UTC (plausible; not compared online)"
    fi
  fi
}

# ════════════════════════════════════════════════════════════════════════
# 2. apt-get update (never upgrade)
# ════════════════════════════════════════════════════════════════════════
APT_LOCKS=(/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock)

# Processes that have an apt/dpkg lock file open, as "pid name" lines.
lock_holders() {
  local f pid args=()
  for f in "${APT_LOCKS[@]}"; do
    [ "${#args[@]}" -gt 0 ] && args+=(-o)
    args+=(-lname "$f")
  done
  find /proc/[0-9]*/fd -maxdepth 1 \( "${args[@]}" \) 2>/dev/null \
    | cut -d/ -f3 | sort -u | while read -r pid; do
        [ "$pid" = "$$" ] && continue
        printf '%s %s\n' "$pid" "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-80)"
      done
}

wait_for_apt_locks() {
  local waited=0 holders
  while holders="$(lock_holders)" && [ -n "$holders" ]; do
    if [ "$waited" -eq 0 ]; then
      info "apt/dpkg is busy (an unattended job?), waiting up to ${APT_LOCK_TIMEOUT}s. Held by:"
      printf '%s\n' "$holders" | sed 's/^/              pid /'
    fi
    if [ "$waited" -ge "$APT_LOCK_TIMEOUT" ]; then
      fail "apt/dpkg still locked after ${APT_LOCK_TIMEOUT}s by: $(printf '%s' "$holders" | head -n1)"
      hint "wait for it to finish, or raise APT_LOCK_TIMEOUT; do not delete the lock files"
      return 1
    fi
    sleep 5; waited=$((waited + 5))
    [ $((waited % 30)) -eq 0 ] && info "still waiting for the apt lock (${waited}s)"
  done
  [ "$waited" -gt 0 ] && ok "apt lock released after ${waited}s"
  return 0
}

# How old the package lists are: apt's cache file when it keeps one, else
# the newest list file (those carry the mirror's date, so it is approximate).
lists_age() {
  local t=""
  ls /var/lib/apt/lists/*_Packages* >/dev/null 2>&1 || { echo "never"; return; }
  if [ -f /var/cache/apt/pkgcache.bin ]; then t="$(stat -c %Y /var/cache/apt/pkgcache.bin)"
  else t="$(find /var/lib/apt/lists -maxdepth 1 -type f -name '*Release' -printf '%T@\n' | sort -n | tail -n1)"; t="${t%.*}"; fi
  [ -n "$t" ] || { echo "at an unknown time"; return; }
  echo "about $(( ($(date +%s) - t) / 3600 ))h ago"
}

step_apt_update() {
  info "this step runs 'apt-get update' only; it never runs upgrade, dist-upgrade or full-upgrade"
  if [ "$CHECK_ONLY" -eq 1 ]; then
    local holders; holders="$(lock_holders)"
    [ -n "$holders" ] && warn "apt/dpkg is busy right now: $(printf '%s' "$holders" | head -n1)"
    info "package lists last refreshed: $(lists_age)"
    if [ "$OFFLINE" -eq 1 ] || [ "$NET_APT" -eq 0 ]; then warn "apt mirror not reachable: the real run would skip apt-get update"
    else ok "would run apt-get update"; fi
    return 0
  fi
  if [ "$OFFLINE" -eq 1 ] || [ "$NET_APT" -eq 0 ]; then
    warn "skipped: $([ "$OFFLINE" -eq 1 ] && echo offline || echo 'apt mirror not reachable') (package lists refreshed $(lists_age))"
    return 0
  fi
  wait_for_apt_locks || return 0
  local out rc=0
  out="$(mktemp)"
  info "running: apt-get update"
  apt-get -o DPkg::Lock::Timeout="$APT_LOCK_TIMEOUT" update 2>&1 | tee "$out" | sed 's/^/        /' || rc=$?
  if [ "$rc" -eq 0 ] && ! grep -qE '^(W|E|Err):' "$out"; then
    ok "package lists refreshed"
  else
    if [ "$rc" -eq 0 ]; then warn "apt-get update finished with warnings (see above)"
    else fail "apt-get update failed (exit $rc)"; fi
    if grep -qiE 'NO_PUBKEY|EXPKEYSIG|KEYEXPIRED|not signed|signatures (couldn.t|were invalid)|invalid signature' "$out"; then
      hint "the archive signing key looks missing or expired. Kali's documented fix (not run automatically):"
      hint "  sudo wget https://archive.kali.org/archive-keyring.gpg -O /usr/share/keyrings/kali-archive-keyring.gpg"
      hint "then re-run this script"
    fi
    if grep -qi 'not valid yet\|is not valid until' "$out"; then
      hint "the clock is behind; set it (sudo date -s ...) or enable NTP, then re-run"
    fi
    if grep -qiE 'Temporary failure resolving|Could not resolve|Could not connect' "$out"; then
      hint "DNS or network trouble; check /etc/resolv.conf, or re-run with --offline and a USB image"
    fi
  fi
  rm -f "$out"
}

# ════════════════════════════════════════════════════════════════════════
# Package helpers (shared by steps 3 and 4)
# ════════════════════════════════════════════════════════════════════════
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }
pkg_candidate() {
  local c
  c="$(apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/ {print $2; exit}')"
  [ -n "$c" ] && [ "$c" != "(none)" ]
}

# Install only the named missing packages. --no-upgrade keeps installed
# packages where they are. The dry run lists any installed package apt would
# still have to upgrade as a dependency, so nothing changes by surprise.
apt_install_missing() {
  local pkgs=("$@") sim upgrades
  [ "${#pkgs[@]}" -gt 0 ] || return 0
  wait_for_apt_locks || return 1
  sim="$(apt-get -s install -y --no-install-recommends --no-upgrade "${pkgs[@]}" 2>&1)" || {
    printf '%s\n' "$sim" | tail -n 8 | sed 's/^/        /'
    return 1
  }
  # "Inst name [old] (new ...)": the bracket means an installed package changes version.
  upgrades="$(printf '%s\n' "$sim" | sed -n 's/^Inst \([^ ]*\) \[\([^]]*\)\].*/\1 (\2)/p')"
  if [ -n "$upgrades" ]; then
    info "installing ${pkgs[*]} needs newer versions of these installed packages (dependencies, not a system upgrade):"
    printf '%s\n' "$upgrades" | sed 's/^/              /'
    if [ "$NO_DEP_UPGRADES" -eq 1 ]; then
      fail "refused because of --no-dep-upgrades"
      return 1
    fi
    warn "$(printf '%s\n' "$upgrades" | wc -l) installed package(s) upgraded as dependencies of ${pkgs[*]}"
  fi
  info "running: apt-get install -y --no-install-recommends --no-upgrade ${pkgs[*]}"
  apt-get -o DPkg::Lock::Timeout="$APT_LOCK_TIMEOUT" install -y --no-install-recommends --no-upgrade "${pkgs[@]}" 2>&1 \
    | { grep -vE '^(Selecting|Preparing|Unpacking|\(Reading database)' || true; } | sed 's/^/        /'
}

# ════════════════════════════════════════════════════════════════════════
# 3. Base tools
# ════════════════════════════════════════════════════════════════════════
step_base_tools() {
  local p missing=()
  for p in git curl openssl ca-certificates iproute2; do
    if pkg_installed "$p"; then ok "$p installed"; else missing+=("$p"); fi
  done
  [ "${#missing[@]}" -eq 0 ] && return 0
  if [ "$CHECK_ONLY" -eq 1 ]; then warn "missing: ${missing[*]} (a real run installs them)"; return 0; fi
  if [ "$OFFLINE" -eq 1 ] || [ "$NET_APT" -eq 0 ]; then
    warn "missing: ${missing[*]}, and the apt mirror is not reachable; continuing with fallbacks"
    return 0
  fi
  if apt_install_missing "${missing[@]}"; then
    for p in "${missing[@]}"; do
      if pkg_installed "$p"; then ok "$p installed now"; else warn "$p still missing"; fi
    done
  else
    warn "could not install ${missing[*]}; continuing with fallbacks"
  fi
}

# ════════════════════════════════════════════════════════════════════════
# 4. Docker
# ════════════════════════════════════════════════════════════════════════
detect_compose() {
  COMPOSE=()
  if docker compose version >/dev/null 2>&1; then COMPOSE=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1 && docker-compose version >/dev/null 2>&1; then COMPOSE=(docker-compose)
  fi
}

# A live (not zombie) process by exact name, without needing procps.
proc_running() {
  local f
  for f in /proc/[0-9]*/comm; do
    [ "$(cat "$f" 2>/dev/null)" = "$1" ] || continue
    grep -qs '^State:[[:space:]]*Z' "${f%/comm}/status" || return 0
  done
  return 1
}

has_systemd() { command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; }

start_docker_daemon() {
  local i tried=0
  if has_systemd; then
    info "starting docker with systemctl (and enabling it at boot)"
    systemctl enable --now docker >/dev/null 2>&1 || systemctl start docker >/dev/null 2>&1 || true
    tried=1
  elif command -v service >/dev/null 2>&1 && [ -x /etc/init.d/docker ]; then
    info "no systemd; starting docker with 'service docker start'"
    # The init script's cgroup v1 mounts fail inside containers; that noise is harmless.
    service docker start 2>&1 | { grep -vE 'cgroup|dmesg' || true; } | sed 's/^/        /' || true
    tried=1
  fi
  if [ "$tried" -eq 1 ]; then
    for i in $(seq 1 30); do docker info >/dev/null 2>&1 && return 0; sleep 1; done
  fi
  # Last resort, only when there is no init system to ask.
  if ! has_systemd && command -v dockerd >/dev/null 2>&1 && ! proc_running dockerd; then
    info "no init system answered; starting dockerd in the background (log: /var/log/dockerd-btct.log)"
    nohup dockerd >/var/log/dockerd-btct.log 2>&1 </dev/null &
    disown || true
  fi
  for i in $(seq 1 40); do docker info >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

# Docker's own repo has no "kali" codename, so a derivative uses Debian's
# bookworm repo, the way install-btct.sh does.
add_docker_repo() {
  local os="debian" codename="bookworm"
  if [ "$OS_ID" = "ubuntu" ]; then os="ubuntu"; codename="$OS_CODENAME"
  elif [ "$OS_ID" = "debian" ] && [ -n "$OS_CODENAME" ]; then codename="$OS_CODENAME"; fi
  info "adding Docker's apt repository ($os $codename)"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$os/gpg" -o /etc/apt/keyrings/docker.asc || return 1
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$os $codename stable" \
    > /etc/apt/sources.list.d/docker.list
  info "running: apt-get update (Docker's repository only adds packages; nothing is upgraded)"
  apt-get update 2>&1 | tail -n 3 | sed 's/^/        /'
}

install_docker() {
  local pkgs=() p
  # 1st choice: the distro's own packages (Kali ships docker.io).
  if pkg_candidate docker.io; then
    pkg_installed docker.io || pkgs+=(docker.io)
    # Newer Debian/Kali split the client out of docker.io and only recommend
    # it, which --no-install-recommends would skip.
    if pkg_candidate docker-cli && ! pkg_installed docker-cli; then pkgs+=(docker-cli); fi
    for p in docker-compose-plugin docker-compose; do
      if pkg_candidate "$p"; then pkg_installed "$p" || pkgs+=("$p"); break; fi
    done
    for p in docker-buildx-plugin docker-buildx; do
      if pkg_candidate "$p"; then pkg_installed "$p" || pkgs+=("$p"); break; fi
    done
    info "using the distro packages: ${pkgs[*]:-(already installed)}"
    apt_install_missing "${pkgs[@]}" || return 1
    hash -r; detect_compose
    [ "${#COMPOSE[@]}" -gt 0 ] && return 0
    info "the distro packages gave no working compose; trying Docker's repository for the plugin"
  fi
  # 2nd choice: Docker's apt repository.
  [ "$NET_DOCKER" -eq 1 ] || { fail "download.docker.com is not reachable and the distro has no usable docker package"; return 1; }
  command -v curl >/dev/null 2>&1 || { fail "curl is needed to add Docker's repository"; return 1; }
  [ -f /etc/apt/sources.list.d/docker.list ] || add_docker_repo || return 1
  pkgs=()
  if ! command -v docker >/dev/null 2>&1; then pkgs+=(docker-ce docker-ce-cli containerd.io); fi
  pkgs+=(docker-buildx-plugin docker-compose-plugin)
  local want=()
  for p in "${pkgs[@]}"; do pkg_installed "$p" || want+=("$p"); done
  apt_install_missing "${want[@]}" || return 1
  hash -r; detect_compose
}

step_docker() {
  local have_bin=0
  command -v docker >/dev/null 2>&1 && have_bin=1
  [ "$have_bin" -eq 1 ] && detect_compose
  if [ "$have_bin" -eq 1 ]; then ok "docker CLI: $(docker --version 2>/dev/null | head -n1)"; fi
  if [ "${#COMPOSE[@]}" -gt 0 ]; then ok "compose: ${COMPOSE[*]} ($("${COMPOSE[@]}" version --short 2>/dev/null || echo '?'))"; fi

  if [ "$CHECK_ONLY" -eq 1 ]; then
    [ "$have_bin" -eq 1 ] || warn "docker is not installed (a real run installs docker.io from the distro, or Docker's repo)"
    [ "$have_bin" -eq 0 ] || [ "${#COMPOSE[@]}" -gt 0 ] || warn "docker compose is not installed (a real run installs it)"
    if [ "$have_bin" -eq 1 ]; then
      if docker info >/dev/null 2>&1; then DOCKER_OK=1; ok "daemon answers"
      else warn "daemon is not running (a real run starts it)"; fi
    fi
    if [ "$have_bin" -eq 0 ] && { [ "$OFFLINE" -eq 1 ] || [ "$NET_APT" -eq 0 ]; } && [ "$NET_DOCKER" -eq 0 ]; then
      fail "docker is missing and no package source is reachable"
    fi
    return 0
  fi

  if [ "$have_bin" -eq 0 ] || [ "${#COMPOSE[@]}" -eq 0 ]; then
    if [ "$OFFLINE" -eq 1 ]; then
      fail "docker or compose is missing and the box is offline; install docker.io + docker-compose first"
      return 0
    fi
    install_docker || { fail "could not install Docker"; return 0; }
    command -v docker >/dev/null 2>&1 || { fail "docker is still missing after the install"; return 0; }
    ok "installed: $(docker --version 2>/dev/null | head -n1)"
  fi
  if [ "${#COMPOSE[@]}" -eq 0 ]; then
    fail "no docker compose (neither 'docker compose' nor 'docker-compose' works)"
    return 0
  fi

  if docker info >/dev/null 2>&1; then
    ok "daemon answers"
    if has_systemd && ! systemctl is-enabled docker >/dev/null 2>&1; then
      systemctl enable docker >/dev/null 2>&1 && ok "docker enabled at boot"
    fi
  elif start_docker_daemon; then
    ok "daemon started and answers"
  else
    fail "the Docker daemon did not come up"
    hint "check: journalctl -u docker, or /var/log/dockerd-btct.log"
    return 0
  fi
  DOCKER_OK=1
  [ "${COMPOSE[0]}" = "docker-compose" ] && warn "using legacy docker-compose ($("${COMPOSE[@]}" version --short 2>/dev/null)); the v2 plugin is preferred"
  docker buildx version >/dev/null 2>&1 || info "buildx is not installed; a build falls back to the legacy builder"

  if [ "$TARGET_USER" != "root" ] && getent group docker >/dev/null 2>&1; then
    if id -nG "$TARGET_USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
      ok "$TARGET_USER is in the docker group"
    else
      usermod -aG docker "$TARGET_USER" && ok "added $TARGET_USER to the docker group (log out and back in to use docker without sudo; this script uses root)"
    fi
  fi
}

# ════════════════════════════════════════════════════════════════════════
# 5. BTCT code
# ════════════════════════════════════════════════════════════════════════
is_checkout() { [ -f "$1/docker-compose.yml" ] && [ -f "$1/Dockerfile" ]; }

clone_hint() {
  hint "the repository is private. Sign in first, as $TARGET_USER (not root):"
  hint "  gh auth login && gh auth setup-git"
  hint "or make a fine-grained token (this repository only, Contents: Read-only), run"
  hint "  git config --global credential.helper store"
  hint "and clone by hand, pasting the token as the password:"
  hint "  git clone -b $BTCT_BRANCH $BTCT_REPO $BTCT_DIR"
  hint "then re-run this script. No internet? Copy the repo folder from USB instead."
}

# Fast-forward a clean checkout when online; never discard anything.
update_checkout() {
  local d=$1 branch dirty upstream before after
  branch="$(git_in "$d" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
  dirty="$(git_in "$d" status --porcelain --untracked-files=no 2>/dev/null || echo '?')"
  ok "branch $branch at $(git_in "$d" log -1 --format='%h %s' 2>/dev/null | cut -c1-70)"
  if [ "$CHECK_ONLY" -eq 1 ]; then
    [ -n "$dirty" ] && info "local changes present (a real run leaves them and skips the pull)"
    return 0
  fi
  if [ "$OFFLINE" -eq 1 ] || [ "$NET_GITHUB" -eq 0 ]; then info "offline: not pulling"; return 0; fi
  if [ -n "$dirty" ]; then warn "local changes in $d: not pulling (nothing was discarded)"; return 0; fi
  if [ "$branch" != "$BTCT_BRANCH" ]; then
    info "on $branch, not $BTCT_BRANCH; leaving the branch as it is (btct update offers to switch)"
  fi
  upstream="$(git_in "$d" rev-parse --abbrev-ref '@{upstream}' 2>/dev/null || true)"
  if [ -z "$upstream" ]; then info "$branch has no upstream; not pulling"; return 0; fi
  before="$(git_in "$d" rev-parse HEAD)"
  if git_in "$d" pull --ff-only --quiet 2>&1 | sed 's/^/        /'; then
    after="$(git_in "$d" rev-parse HEAD)"
    if [ "$before" = "$after" ]; then ok "up to date with $upstream"
    else
      ok "pulled $(git_in "$d" rev-list --count "$before..$after") new commit(s) from $upstream"
      if [ "$d" = "$SCRIPT_DIR" ] && ! git_in "$d" diff --quiet "$before" "$after" -- competition-day.sh; then
        warn "competition-day.sh itself changed in that pull; re-run it to use the new version"
      fi
    fi
  else
    warn "git pull --ff-only failed (diverged, or no credentials); using the code as it is"
    clone_hint
  fi
}

step_code() {
  if is_checkout "$SCRIPT_DIR"; then
    APP_DIR="$SCRIPT_DIR"
    ok "using the checkout this script lives in: $APP_DIR"
    if ! command -v git >/dev/null 2>&1; then info "git is not installed; using the folder as it is"
    elif git_in "$APP_DIR" rev-parse --git-dir >/dev/null 2>&1; then update_checkout "$APP_DIR"
    else info "not a git checkout (copied folder?); using it as it is"; fi
    return 0
  fi
  if is_checkout "$BTCT_DIR"; then
    APP_DIR="$BTCT_DIR"
    ok "found BTCT in $APP_DIR"
    if command -v git >/dev/null 2>&1 && git_in "$APP_DIR" rev-parse --git-dir >/dev/null 2>&1; then update_checkout "$APP_DIR"; fi
    return 0
  fi
  if [ "$CHECK_ONLY" -eq 1 ]; then
    if [ "$OFFLINE" -eq 1 ] || [ "$NET_GITHUB" -eq 0 ]; then fail "no BTCT checkout in $BTCT_DIR and github.com is not reachable"
    else warn "no BTCT checkout yet; a real run clones $BTCT_REPO ($BTCT_BRANCH) into $BTCT_DIR"; fi
    return 0
  fi
  if [ "$OFFLINE" -eq 1 ] || [ "$NET_GITHUB" -eq 0 ]; then
    fail "no BTCT checkout in $BTCT_DIR and github.com is not reachable"
    hint "copy the repo folder from USB to $BTCT_DIR (or run this script from inside it)"
    return 0
  fi
  command -v git >/dev/null 2>&1 || { fail "git is not installed (step 3)"; return 0; }
  if [ -e "$BTCT_DIR" ] && [ -n "$(ls -A "$BTCT_DIR" 2>/dev/null)" ]; then
    fail "$BTCT_DIR exists, is not empty and is not a BTCT checkout; set BTCT_DIR to another folder"
    return 0
  fi
  mkdir -p "$BTCT_DIR"
  [ "$TARGET_USER" != "root" ] && chown "$TARGET_USER:" "$BTCT_DIR"
  info "cloning $BTCT_REPO ($BTCT_BRANCH) into $BTCT_DIR as $TARGET_USER"
  if as_owner "$BTCT_DIR" env GIT_TERMINAL_PROMPT="$GIT_PROMPT" git clone --branch "$BTCT_BRANCH" "$BTCT_REPO" "$BTCT_DIR" 2>&1 | sed 's/^/        /' \
      && is_checkout "$BTCT_DIR"; then
    APP_DIR="$BTCT_DIR"
    ok "cloned: $(git_in "$APP_DIR" log -1 --format='%h %s' | cut -c1-70)"
  else
    fail "git clone failed"
    clone_hint
  fi
}

# ════════════════════════════════════════════════════════════════════════
# 6. Image
# ════════════════════════════════════════════════════════════════════════
find_image_tar() {
  local c
  if [ -n "$IMAGE_ARG" ]; then printf '%s' "$IMAGE_ARG"; return 0; fi
  for c in "$SCRIPT_DIR/btct-image.tar.gz" "${APP_DIR:+$APP_DIR/btct-image.tar.gz}"; do
    [ -n "$c" ] && [ -f "$c" ] && { printf '%s' "$c"; return 0; }
  done
  return 1
}

verify_tar_sha() {
  local tar=$1 want got
  if [ ! -f "$tar.sha256" ]; then info "no $(basename "$tar").sha256 next to it; not verified"; return 0; fi
  want="$(awk '{print $1; exit}' "$tar.sha256")"
  info "verifying sha256 of $(basename "$tar") ($(du -h "$tar" | cut -f1))"
  got="$(sha256sum "$tar" | awk '{print $1}')"
  if [ "$want" = "$got" ]; then ok "sha256 matches"; return 0; fi
  fail "sha256 mismatch: the tarball is damaged or not the one that was saved (copy it again)"
  return 1
}

step_image() {
  [ "$DOCKER_OK" -eq 1 ] || { [ "$CHECK_ONLY" -eq 1 ] || { skip "Docker is not ready (step 4)"; return 0; }; }
  [ -n "$APP_DIR" ] || { [ "$CHECK_ONLY" -eq 1 ] || { skip "no BTCT code (step 5)"; return 0; }; }
  local tar have_id="" want_id=""
  [ "$DOCKER_OK" -eq 1 ] && have_id="$(docker image inspect -f '{{.Id}}' "$IMAGE_NAME" 2>/dev/null || true)"

  if tar="$(find_image_tar)"; then
    if [ ! -f "$tar" ]; then fail "--image $tar: file not found"; return 0; fi
    ok "image tarball: $tar"
    verify_tar_sha "$tar" || return 0
    [ -f "$tar.id" ] && want_id="$(head -n1 "$tar.id")"
    if [ -n "$have_id" ] && [ -n "$want_id" ] && [ "$have_id" = "$want_id" ]; then
      ok "$IMAGE_NAME already holds this image (${have_id:7:12}); not loading again"
      IMAGE_READY=1
      return 0
    fi
    if [ "$CHECK_ONLY" -eq 1 ]; then ok "a real run loads it with docker load (no build)"; return 0; fi
    info "docker load < $(basename "$tar") (takes a minute)"
    local out loaded
    if ! out="$(docker load -i "$tar" 2>&1)"; then
      printf '%s\n' "$out" | tail -n 5 | sed 's/^/        /'
      fail "docker load failed"
      return 0
    fi
    printf '%s\n' "$out" | sed 's/^/        /'
    loaded="$(printf '%s\n' "$out" | sed -n 's/^Loaded image: //p' | tail -n1)"
    if [ -n "$loaded" ] && [ "$loaded" != "$IMAGE_NAME" ]; then
      docker tag "$loaded" "$IMAGE_NAME" && info "tagged $loaded as $IMAGE_NAME"
    elif [ -z "$loaded" ]; then
      loaded="$(printf '%s\n' "$out" | sed -n 's/^Loaded image ID: //p' | tail -n1)"
      [ -n "$loaded" ] && docker tag "$loaded" "$IMAGE_NAME" && info "tagged $loaded as $IMAGE_NAME"
    fi
    if docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
      ok "loaded $IMAGE_NAME; launching without a build"
      IMAGE_READY=1
    else
      fail "the tarball loaded but $IMAGE_NAME is not there"
    fi
    return 0
  fi

  info "no btct-image.tar.gz next to the script or in the repo"
  local can_build=1
  { [ "$OFFLINE" -eq 1 ] || [ "$NET_REGISTRY" -eq 0 ]; } && can_build=0
  if [ "$NO_BUILD" -eq 1 ] || [ "$can_build" -eq 0 ]; then
    if [ -n "$have_id" ]; then
      warn "using the $IMAGE_NAME already on this box (built $(docker image inspect -f '{{.Created}}' "$IMAGE_NAME" | cut -c1-16)); it may be older than the code"
      IMAGE_READY=1
    elif [ "$NO_BUILD" -eq 1 ]; then
      fail "--no-build, but there is no image tarball and no $IMAGE_NAME on this box"
    else
      fail "offline and no image: bring btct-image.tar.gz (made by save-btct-image.sh) and pass --image PATH"
    fi
    return 0
  fi
  if [ "$CHECK_ONLY" -eq 1 ]; then
    warn "a real run builds the image (several minutes; a USB image is faster)"
    return 0
  fi
  info "building $IMAGE_NAME with ${COMPOSE[*]} build (first build: several minutes)"
  # compose interpolates the whole file even to build; .env is written in step
  # 7, so lend it a placeholder that only lives for this command.
  if (cd "$APP_DIR" && AUTH_SECRET="${AUTH_SECRET:-build-only-placeholder}" "${COMPOSE[@]}" build btct) 2>&1 \
      | sed 's/^/        /'; then
    ok "built $IMAGE_NAME"
    IMAGE_READY=1
  else
    fail "image build failed (see the output above)"
  fi
}

# ════════════════════════════════════════════════════════════════════════
# 7. Config
# ════════════════════════════════════════════════════════════════════════
env_value() { tr -d '\r' | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\\(.*\\)'\$/\\1/"; }
env_get() { [ -f "$APP_DIR/.env" ] && sed -n "s/^$1=//p" "$APP_DIR/.env" | tail -n1 | env_value; return 0; }

committed_secrets() {
  git_in "$APP_DIR" rev-parse --git-dir >/dev/null 2>&1 || return 0
  git_in "$APP_DIR" log -p --all --format= -- .env 2>/dev/null | sed -n 's/^[-+]AUTH_SECRET=//p' | env_value
}

new_secret() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 32
  else od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; fi
}

check_env() {
  local cur reason="" hist owner
  cur="$(env_get AUTH_SECRET)"
  if [ ! -f "$APP_DIR/.env" ]; then reason="there is no .env"
  elif [ -z "$cur" ]; then reason=".env has no AUTH_SECRET"
  elif [ "$cur" = "replace-me-with-64-random-hex-chars" ]; then reason=".env holds the example placeholder"
  else
    hist="$(committed_secrets)" || hist=""
    if [ -n "$hist" ] && grep -qxF -- "$cur" <<<"$hist"; then
      reason="the AUTH_SECRET in .env was committed to git, so it is public"
    fi
    unset hist
  fi
  if [ -z "$reason" ]; then
    ok ".env has a private AUTH_SECRET (not shown)"
  elif [ "$CHECK_ONLY" -eq 1 ]; then
    warn "$reason; a real run writes a fresh AUTH_SECRET"
  else
    (
      umask 077
      if [ -f "$APP_DIR/.env" ]; then grep -v '^AUTH_SECRET=' "$APP_DIR/.env" || true; fi > "$APP_DIR/.env.new"
      printf 'AUTH_SECRET=%s\n' "$(new_secret)" >> "$APP_DIR/.env.new"
      mv -f "$APP_DIR/.env.new" "$APP_DIR/.env"
    )
    ok "wrote a fresh AUTH_SECRET to .env ($reason)"
    [ -n "$cur" ] && warn "everyone signed in with the old secret is logged out"
  fi
  unset cur
  if [ "$CHECK_ONLY" -eq 0 ] && [ -f "$APP_DIR/.env" ]; then
    chmod 600 "$APP_DIR/.env"
    owner="$(stat -c %U "$APP_DIR")"
    [ "$owner" != "root" ] && chown "$owner:" "$APP_DIR/.env"
  fi
  if [ -f "$APP_DIR/.env" ] && [ "$(stat -c %a "$APP_DIR/.env")" != "600" ]; then
    warn ".env is mode $(stat -c %a "$APP_DIR/.env"), should be 600"
  fi
}

check_backup_folder() {
  local dir
  dir="${BACKUP_HOST_DIR:-$(env_get BACKUP_HOST_DIR)}"
  if [ -z "$dir" ] && [ "$CHECK_ONLY" -eq 0 ] && [ -f "$APP_DIR/choose-backup-folder.sh" ] \
     && { [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; }; then
    info "no backup folder chosen yet; opening the folder chooser (choose-backup-folder.sh)"
    if sh "$APP_DIR/choose-backup-folder.sh" --no-apply 2>&1 | sed 's/^/        /'; then
      dir="$(env_get BACKUP_HOST_DIR)"
    else
      warn "the folder chooser did not save a folder; keeping the default"
    fi
  fi
  if [ -z "$dir" ]; then
    dir="./backups"
    if [ -f "$APP_DIR/choose-backup-folder.sh" ]; then
      info "backups go to the default folder; run ./choose-backup-folder.sh to pick another"
    fi
  fi
  case "$dir" in /*) BACKUP_DIR_SHOWN="$dir" ;; *) BACKUP_DIR_SHOWN="$APP_DIR/${dir#./}" ;; esac
  if [ ! -d "$BACKUP_DIR_SHOWN" ]; then
    if [ "$CHECK_ONLY" -eq 1 ]; then info "backup folder $BACKUP_DIR_SHOWN does not exist yet (a real run creates it)"; return 0; fi
    mkdir -p "$BACKUP_DIR_SHOWN"
  fi
  # The container runs as uid 1000 and must be able to write here.
  local uid mode
  uid="$(stat -c %u "$BACKUP_DIR_SHOWN")"; mode="$(stat -c %a "$BACKUP_DIR_SHOWN")"
  if [ "$uid" != "1000" ] && [ $((8#$mode & 2)) -eq 0 ]; then
    if [ "$CHECK_ONLY" -eq 1 ]; then warn "backup folder $BACKUP_DIR_SHOWN is not writable by the container (uid 1000)"
    else chown 1000:1000 "$BACKUP_DIR_SHOWN" && info "made $BACKUP_DIR_SHOWN writable by the container user (uid 1000)"; fi
  fi
  ok "backup folder: $BACKUP_DIR_SHOWN"
}

compose_host_port() {
  local p=""
  if [ "${#COMPOSE[@]}" -gt 0 ] && [ "$DOCKER_OK" -eq 1 ]; then
    p="$(compose port btct 8080 2>/dev/null | tail -n1 | sed 's/.*://')"
  fi
  if [ -z "$p" ]; then
    p="$(cat "$APP_DIR/docker-compose.yml" "$APP_DIR/docker-compose.override.yml" 2>/dev/null \
          | sed -n 's/^[[:space:]]*-[[:space:]]*"\{0,1\}\([0-9.]*:\)\{0,1\}\([0-9][0-9]*\):8080"\{0,1\}[[:space:]]*$/\2/p' | tail -n1)"
  fi
  printf '%s' "${p:-8080}"
}

# Who listens on a TCP port: "name(pid)" list, empty when free.
port_holders() {
  local port=$1
  if command -v ss >/dev/null 2>&1; then
    ss -Hltnp "sport = :$port" 2>/dev/null | grep -o 'users:(([^)]*))' \
      | sed -E 's/users:\(\("([^"]*)",pid=([0-9]+).*/\1 (pid \2)/' | sort -u | paste -sd' ' -
    return 0
  fi
  local hex; hex="$(printf ':%04X' "$port")"
  if awk -v h="$hex" '$4=="0A" && $2 ~ h"$"' /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep -q .; then
    echo "unknown process"
  fi
}

port_in_use() {
  if command -v ss >/dev/null 2>&1; then ss -Hltn "sport = :$1" 2>/dev/null | grep -q .
  else [ -n "$(port_holders "$1")" ]; fi
}

btct_owns_port() {
  [ "$DOCKER_OK" -eq 1 ] || return 1
  docker ps --filter name='^btct$' --format '{{.Ports}}' 2>/dev/null | grep -qE "(^|[ ,:])$1->8080/tcp"
}

check_port() {
  HOST_PORT="$(compose_host_port)"
  if ! port_in_use "$HOST_PORT"; then ok "host port $HOST_PORT is free"; return 0; fi
  if btct_owns_port "$HOST_PORT"; then ok "host port $HOST_PORT is held by the running btct container (this run is a restart)"; return 0; fi
  local who; who="$(port_holders "$HOST_PORT")"
  fail "host port $HOST_PORT is in use by ${who:-another process}, not BTCT"
  hint "stop that program, or change the left side of '- \"$HOST_PORT:8080\"' under ports: in $APP_DIR/docker-compose.yml"
}

OVERRIDE_MARK="# Written by competition-day.sh --limits."
check_limits() {
  local f="$APP_DIR/docker-compose.override.yml" cpus owner
  if [ "$LIMITS" -eq 0 ]; then
    if [ -f "$f" ] && grep -qF "$OVERRIDE_MARK" "$f"; then
      info "limits from an earlier --limits run are still on (delete docker-compose.override.yml to drop them)"
    elif [ -f "$f" ]; then
      info "docker-compose.override.yml exists and compose applies it"
    fi
    return 0
  fi
  if [ -f "$f" ] && ! grep -qF "$OVERRIDE_MARK" "$f"; then
    warn "docker-compose.override.yml exists and was not written by this script; not touching it, so --limits is not applied"
    return 0
  fi
  cpus="$(nproc 2>/dev/null || echo 1)"; [ "$cpus" -gt 2 ] && cpus=2
  if [ "$CHECK_ONLY" -eq 1 ]; then ok "a real run writes docker-compose.override.yml (mem_limit 1g, cpus $cpus)"; return 0; fi
  cat > "$f.new" <<EOF
$OVERRIDE_MARK
# Competition limits: the box BTCT is sized for. Delete this file to remove
# them, then run: docker compose up -d
services:
  btct:
    mem_limit: 1g
    cpus: $cpus
EOF
  if [ -f "$f" ] && cmp -s "$f" "$f.new"; then rm -f "$f.new"; ok "limits already set: mem_limit 1g, cpus $cpus"
  else
    mv -f "$f.new" "$f"
    owner="$(stat -c %U "$APP_DIR")"; [ "$owner" != "root" ] && chown "$owner:" "$f"
    ok "wrote docker-compose.override.yml: mem_limit 1g, cpus $cpus"
  fi
}

step_config() {
  [ -n "$APP_DIR" ] || { skip "no BTCT code (step 5)"; return 0; }
  check_env
  check_backup_folder
  check_port
  check_limits
}

# ════════════════════════════════════════════════════════════════════════
# 8. Launch
# ════════════════════════════════════════════════════════════════════════
wait_healthz() {
  local start=$SECONDS el state next=10
  while :; do
    el=$((SECONDS - start))
    if http_ok 127.0.0.1 "$HOST_PORT" /healthz; then ok "/healthz answered 200 after ${el}s"; return 0; fi
    if ! docker ps -q --filter name='^btct$' --filter status=running | grep -q .; then
      state="$(docker inspect -f '{{.State.Status}} (exit {{.State.ExitCode}})' btct 2>/dev/null || echo missing)"
      [ "$el" -ge 10 ] && { fail "the btct container is not running: $state"; return 1; }
    fi
    if [ "$el" -ge "$HEALTH_TIMEOUT" ]; then fail "/healthz did not answer within ${HEALTH_TIMEOUT}s"; return 1; fi
    [ "$el" -ge "$next" ] && next=$((next + 10)) && \
      info "waiting for http://127.0.0.1:$HOST_PORT/healthz (${el}s of ${HEALTH_TIMEOUT}s, health: $(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' btct 2>/dev/null || echo '?'))"
    sleep 2
  done
}

step_launch() {
  if [ "$CHECK_ONLY" -eq 1 ]; then
    if [ "$DOCKER_OK" -eq 0 ] || [ -z "$APP_DIR" ]; then info "nothing to probe yet"; return 0; fi
    HOST_PORT="$(compose_host_port)"
    if docker ps -q --filter name='^btct$' --filter status=running | grep -q .; then
      if http_ok 127.0.0.1 "$HOST_PORT" /healthz; then ok "btct is running and /healthz answers on port $HOST_PORT"; LAUNCHED=1
      else warn "btct is running but /healthz does not answer on port $HOST_PORT"; fi
    else
      info "btct is not running (a real run starts it)"
    fi
    return 0
  fi
  local s
  for s in 4 5 6 7; do
    step_ok "$s" || { skip "step $s did not pass"; return 0; }
  done
  [ "$IMAGE_READY" -eq 1 ] || { skip "no image (step 6)"; return 0; }
  # The image is ready by now (loaded, built or kept), so up never builds.
  local args=(up -d --no-build)
  info "running: ${COMPOSE[*]} ${args[*]}"
  if ! compose "${args[@]}" 2>&1 | sed 's/^/        /'; then
    fail "${COMPOSE[*]} up failed"
    compose logs --tail=40 btct 2>&1 | sed 's/^/        /' || true
    return 0
  fi
  if wait_healthz; then
    LAUNCHED=1
  else
    info "last 40 log lines:"
    compose logs --tail=40 btct 2>&1 | sed 's/^/        /' || true
  fi
}

# ════════════════════════════════════════════════════════════════════════
# 9. Hand-off
# ════════════════════════════════════════════════════════════════════════
lan_ips() {
  if command -v ip >/dev/null 2>&1; then
    ip -4 -o addr show scope global 2>/dev/null \
      | awk '$2 !~ /^(docker|br-|veth|virbr)/ {sub(/\/.*/, "", $4); print $4}'
  elif command -v hostname >/dev/null 2>&1; then
    hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$' | grep -v '^127\.' | grep -v '^172\.17\.'
  fi
}

step_handoff() {
  if [ "$LAUNCHED" -eq 0 ] && [ "$CHECK_ONLY" -eq 0 ]; then
    skip "BTCT is not up (step 8)"
    return 0
  fi
  [ "$CHECK_ONLY" -eq 1 ] && [ "$LAUNCHED" -eq 0 ] && info "BTCT is not running yet; this is what the team will get:"
  local ips ip dc="${COMPOSE[*]:-docker compose}"
  ips="$(lan_ips || true)"
  printf '\n      %sOpen BTCT%s\n' "$C_B" "$C_0"
  printf '        this box:  http://127.0.0.1:%s\n' "$HOST_PORT"
  if [ -n "$ips" ]; then
    for ip in $ips; do printf '        team LAN:  http://%s:%s\n' "$ip" "$HOST_PORT"; done
  else
    if command -v ip >/dev/null 2>&1; then warn "no LAN IPv4 address found; teammates cannot reach this box yet"
    else warn "cannot list LAN addresses ('ip' is missing; install iproute2)"; fi
  fi
  printf '\n      %sAccounts%s (all admins): %s\n' "$C_B" "$C_0" "$ACCOUNTS"
  local proj; proj="$(compose_project)"
  printf '        generated passwords: cd %s && sudo %s%s exec btct cat /data/initial-passwords.txt\n' "${APP_DIR:-$BTCT_DIR}" "$dc" "${proj:+ -p $proj}"
  printf '        (change them after the first login, then delete that file)\n'
  if [ "$SHOW_PASSWORDS" -eq 1 ] && [ "$LAUNCHED" -eq 1 ]; then
    printf '\n      %sinitial-passwords.txt%s (--show-passwords)\n' "$C_B" "$C_0"
    if ! compose exec -T btct cat /data/initial-passwords.txt 2>/dev/null | sed 's/^/        /'; then
      info "no generated passwords (all set in .env, or the file was deleted)"
    fi
  fi
  printf '\n      %sBackups%s go to: %s\n' "$C_B" "$C_0" "${BACKUP_DIR_SHOWN:-${APP_DIR:-$BTCT_DIR}/backups}"
  printf '\n      %sBefore the clock starts%s\n' "$C_B" "$C_0"
  printf '        - Admin -> Backups: turn on scheduled backups\n'
  printf '        - Firefox: Settings -> General -> Downloads -> "Always ask you where to save files",\n'
  printf '          so exports open the save dialog\n'
  printf '        - logs: cd %s && sudo %s%s logs -f btct\n' "${APP_DIR:-$BTCT_DIR}" "$dc" "${proj:+ -p $proj}"
  printf '        - update later, keeping the data: btct update (pulls comp-ready, snapshots, rebuilds)\n'
  if [ -x /usr/local/bin/btct ]; then printf '        - menu: btct (status, backup folder, backups, restore, logs)\n'
  elif [ -f "${APP_DIR:-$BTCT_DIR}/btct.sh" ]; then printf '        - menu: %s/btct.sh (add a btct command with: ./btct.sh install)\n' "${APP_DIR:-$BTCT_DIR}"; fi
}

# ════════════════════════════════════════════════════════════════════════
# 10. Summary
# ════════════════════════════════════════════════════════════════════════
step_summary() {
  local i st col fails=0 warns=0 total note
  total=$(( $(now_ms) - RUN_START ))
  printf '\n      %-4s %-26s %-6s %8s  %s\n' "Step" "Title" "Result" "Time" "Note"
  printf '      %-4s %-26s %-6s %8s  %s\n' "----" "--------------------------" "------" "--------" "----"
  for i in $(seq 1 9); do
    st="${S_STATUS[$i]:-SKIP}"
    case "$st" in PASS) col="$C_G" ;; WARN) col="$C_Y"; warns=$((warns+1)) ;; FAIL) col="$C_R"; fails=$((fails+1)) ;; *) col="" ;; esac
    note="${S_NOTE[$i]:-}"; [ "${#note}" -gt 60 ] && note="${note:0:57}..."
    printf '      %-4s %-26s %s%-6s%s %8s  %s\n' "$i" "${S_TITLE[$i]:-?}" "$col" "$st" "$C_0" "$(fmt_ms "${S_TIME[$i]:-0}")" "$note"
  done
  printf '\n      total elapsed: %s\n' "$(fmt_ms "$total")"
  if [ "$fails" -gt 0 ]; then
    printf '      %sRESULT: FAIL%s (%d failed, %d warning)\n' "$C_R" "$C_0" "$fails" "$warns"
    STATUS="FAIL"; NOTE="$fails step(s) failed"
  elif [ "$warns" -gt 0 ]; then
    printf '      %sRESULT: PASS with %d warning(s)%s\n' "$C_Y" "$warns" "$C_0"
    STATUS="WARN"
  else
    printf '      %sRESULT: PASS%s\n' "$C_G" "$C_0"
  fi
  [ "$CHECK_ONLY" -eq 1 ] && printf '      (check-only: nothing was changed)\n'
  return 0
}

# ── Main ─────────────────────────────────────────────────────────────────
printf '%sBTCT competition day%s  %s  (%s)\n' "$C_B" "$C_0" "$(date '+%F %T')" "$SCRIPT_PATH"
run_step 1 "Preflight"           step_preflight
run_step 2 "apt-get update"      step_apt_update
run_step 3 "Base tools"          step_base_tools
run_step 4 "Docker"              step_docker
run_step 5 "BTCT code"           step_code
run_step 6 "Image"               step_image
run_step 7 "Config"              step_config
run_step 8 "Launch"              step_launch
run_step 9 "Hand-off"            step_handoff
printf '\n%s[10/%d] Summary%s\n' "$C_B" "$TOTAL_STEPS" "$C_0"
step_summary
[ "$STATUS" = "FAIL" ] && exit 1
exit 0
