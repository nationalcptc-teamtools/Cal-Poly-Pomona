#!/usr/bin/env bash
# install-btct.sh: one-shot installer and launcher for BTCT on Debian-family Linux.
#
# What it does, in order:
#   1. Checks the machine is Debian or a Debian derivative (Ubuntu, Kali, ...).
#   2. Installs git, curl, openssl and ca-certificates if any are missing.
#   3. Installs Docker Engine and the compose plugin from Docker's apt
#      repository if `docker` or `docker compose` is missing, then makes sure
#      the daemon is running and enabled at boot.
#   4. Finds the repo: the folder this script lives in when it holds a
#      docker-compose.yml, otherwise a clone of $BTCT_REPO ($BTCT_BRANCH) in
#      $BTCT_DIR (pulled if it already exists).
#   5. Makes sure .env holds a private AUTH_SECRET: a fresh one is written
#      when .env is missing, has no AUTH_SECRET, holds the example
#      placeholder, or holds any value that was ever committed to this
#      repository's .env (those are public). .env is left mode 600.
#   6. Asks where server backups should go (first install only, or with
#      --choose-backup-folder): choose-backup-folder.sh opens a folder
#      chooser (zenity, kdialog or yad; a typed path over SSH) and writes
#      BACKUP_HOST_DIR to .env. Run that script again any time to move them.
#   7. `docker compose up -d --build`, then polls /healthz until it answers.
#
# Build options come from .env too (docker compose reads it): put
# WITH_REPORT_BINS=0 there to leave out the server-side PDF/Word export tools,
# and WITH_TYPST_CLIENT=0 to also leave out the Report tab's compiler and
# fonts. Both default to 1.
#
# Safe to re-run: every step checks before it acts, and the btct-data volume
# is never touched (only `docker compose down -v` deletes it).
#
# Usage:
#   ./install-btct.sh               # install what's missing, build, launch
#   ./install-btct.sh --no-build    # launch without rebuilding the image
#   ./install-btct.sh --choose-backup-folder   # ask for the backup folder again
#   ./install-btct.sh --skip-backup-folder     # never ask (keeps .env's value or ./backups)
#
# Environment overrides (only used when the script is run outside a checkout):
#   BTCT_REPO    git URL to clone    (default https://github.com/rocast560/BTCT.git)
#   BTCT_BRANCH  branch to check out (default comp-ready, the branch
#                `btct update` follows)
#   BTCT_DIR     where to clone it   (default /opt/btct)
#   HEALTH_TIMEOUT  seconds to wait for /healthz (default 120)
#   BTCT_BACKUP_FOLDER  auto (ask only when .env has no BACKUP_HOST_DIR), ask or skip
#
# The repository is private: sign this machine in to GitHub once before a
# clone (gh auth login, then gh auth setup-git; or a fine-grained read-only
# token with git config credential.helper store). Later updates, keeping the
# data: ./btct.sh update (or btct update after ./btct.sh install).

set -euo pipefail

BTCT_REPO="${BTCT_REPO:-https://github.com/rocast560/BTCT.git}"
BTCT_BRANCH="${BTCT_BRANCH:-comp-ready}"
BTCT_DIR="${BTCT_DIR:-/opt/btct}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-120}"
BUILD_FLAG="--build"
BACKUP_FOLDER="${BTCT_BACKUP_FOLDER:-auto}"   # auto, ask or skip

for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD_FLAG="" ;;
    --choose-backup-folder) BACKUP_FOLDER="ask" ;;
    --skip-backup-folder) BACKUP_FOLDER="skip" ;;
    -h|--help) sed -n '2,48p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;36m[install-btct]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[install-btct]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[install-btct]\033[0m %s\n' "$*" >&2; exit 1; }

# Run as root directly, or through sudo for everything that needs it.
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  command -v sudo >/dev/null 2>&1 || die "run as root, or install sudo first"
  SUDO="sudo"
fi

# ── 1. Debian check ──────────────────────────────────────────────────────
[ -r /etc/os-release ] || die "/etc/os-release not found; is this Linux?"
# shellcheck disable=SC1091
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
  *" debian "*|*" ubuntu "*) ;;
  *) die "this script supports Debian-family distros only (found ID=${ID:-unknown})" ;;
esac
log "detected ${PRETTY_NAME:-$ID}"

APT_UPDATED=0
apt_install() {
  if [ "$APT_UPDATED" -eq 0 ]; then
    $SUDO apt-get update -y
    APT_UPDATED=1
  fi
  $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

# ── 2. Base tools ────────────────────────────────────────────────────────
missing=()
command -v git     >/dev/null 2>&1 || missing+=(git)
command -v curl    >/dev/null 2>&1 || missing+=(curl)
command -v openssl >/dev/null 2>&1 || missing+=(openssl)
[ -f /etc/ssl/certs/ca-certificates.crt ] || missing+=(ca-certificates)
if [ "${#missing[@]}" -gt 0 ]; then
  log "installing: ${missing[*]}"
  apt_install "${missing[@]}"
else
  log "git, curl, openssl and ca-certificates already installed"
fi

# ── 3. Docker Engine + compose plugin ────────────────────────────────────
add_docker_repo() {
  # Docker publishes repos for debian and ubuntu only. A derivative (Kali,
  # Parrot, ...) uses the Debian repo at the stable codename it tracks.
  local os codename
  if [ "${ID:-}" = "ubuntu" ] || { [ "${ID:-}" != "debian" ] && [ -n "${UBUNTU_CODENAME:-}" ]; }; then
    os="ubuntu"; codename="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
  elif [ "${ID:-}" = "debian" ] && [ -n "${VERSION_CODENAME:-}" ]; then
    os="debian"; codename="$VERSION_CODENAME"
  else
    os="debian"; codename="bookworm"
  fi
  log "adding Docker's apt repository ($os $codename)"
  $SUDO install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$os/gpg" | $SUDO tee /etc/apt/keyrings/docker.asc >/dev/null
  $SUDO chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$os $codename stable" \
    | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
  APT_UPDATED=0
}

if ! command -v docker >/dev/null 2>&1; then
  add_docker_repo
  log "installing Docker Engine and the compose plugin"
  apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
elif ! $SUDO docker compose version >/dev/null 2>&1; then
  [ -f /etc/apt/sources.list.d/docker.list ] || add_docker_repo
  log "docker is installed but the compose plugin is not; installing it"
  apt_install docker-compose-plugin
else
  log "docker and docker compose already installed"
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  $SUDO systemctl enable --now docker >/dev/null 2>&1 || $SUDO systemctl start docker
else
  $SUDO service docker start >/dev/null 2>&1 || true
fi
for _ in $(seq 1 30); do
  $SUDO docker info >/dev/null 2>&1 && break
  sleep 1
done
$SUDO docker info >/dev/null 2>&1 || die "the Docker daemon did not come up; check 'journalctl -u docker'"

# Let the invoking user run docker without sudo from their next login on.
TARGET_USER="${SUDO_USER:-$(id -un)}"
if [ "$TARGET_USER" != "root" ] && ! id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx docker; then
  $SUDO usermod -aG docker "$TARGET_USER"
  log "added $TARGET_USER to the docker group (takes effect at next login)"
fi

# ── 4. Repo ──────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
if [ -f "$SCRIPT_DIR/docker-compose.yml" ] && [ -f "$SCRIPT_DIR/Dockerfile" ]; then
  APP_DIR="$SCRIPT_DIR"
  log "using the checkout this script lives in: $APP_DIR"
elif [ -d "$BTCT_DIR/.git" ]; then
  APP_DIR="$BTCT_DIR"
  log "updating existing clone in $APP_DIR"
  # Older commits track .env. A local edit to it would make the pull refuse,
  # and the commit that untracks it would delete it, so set the local copy
  # aside, pull, and put it back. Step 5 then replaces a committed secret.
  ENV_KEEP=""
  if [ -f "$APP_DIR/.env" ] && git -C "$APP_DIR" ls-files --error-unmatch .env >/dev/null 2>&1; then
    ENV_KEEP="$APP_DIR/.env.keep-$$"
    cp -p "$APP_DIR/.env" "$ENV_KEEP"
    git -C "$APP_DIR" checkout -- .env
  fi
  if ! { git -C "$APP_DIR" fetch origin "$BTCT_BRANCH" \
      && git -C "$APP_DIR" checkout "$BTCT_BRANCH" \
      && git -C "$APP_DIR" pull --ff-only origin "$BTCT_BRANCH"; }; then
    [ -n "$ENV_KEEP" ] && cp -p "$ENV_KEEP" "$APP_DIR/.env" && rm -f "$ENV_KEEP"
    die "git update of $APP_DIR failed; your .env is unchanged"
  fi
  if [ -n "$ENV_KEEP" ]; then
    cp -p "$ENV_KEEP" "$APP_DIR/.env"
    rm -f "$ENV_KEEP"
  fi
else
  APP_DIR="$BTCT_DIR"
  log "cloning $BTCT_REPO ($BTCT_BRANCH) into $APP_DIR"
  $SUDO mkdir -p "$APP_DIR"
  $SUDO chown "$TARGET_USER:" "$APP_DIR"
  git clone --branch "$BTCT_BRANCH" "$BTCT_REPO" "$APP_DIR"
fi
cd "$APP_DIR"

# ── 5. .env with AUTH_SECRET ─────────────────────────────────────────────
# Strip CR and surrounding quotes, the way docker compose reads a .env value.
env_value() { tr -d '\r' | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\\(.*\\)'\$/\\1/"; }

# Every AUTH_SECRET value any commit ever put in .env, one per line. Empty
# outside a git checkout. The values are never printed.
committed_secrets() {
  git -c safe.directory="$APP_DIR" -C "$APP_DIR" rev-parse --git-dir >/dev/null 2>&1 || return 0
  git -c safe.directory="$APP_DIR" -C "$APP_DIR" log -p --all --format= -- .env 2>/dev/null \
    | sed -n 's/^[-+]AUTH_SECRET=//p' | env_value
}

CURRENT_SECRET=""
if [ -f .env ]; then
  CURRENT_SECRET="$(sed -n 's/^AUTH_SECRET=//p' .env | tail -n1 | env_value)"
fi
NEW_SECRET_REASON=""
if [ ! -f .env ]; then
  NEW_SECRET_REASON="there is no .env"
elif [ -z "$CURRENT_SECRET" ]; then
  NEW_SECRET_REASON=".env has no AUTH_SECRET"
elif [ "$CURRENT_SECRET" = "replace-me-with-64-random-hex-chars" ]; then
  NEW_SECRET_REASON=".env holds the example placeholder"
else
  HISTORY_SECRETS="$(committed_secrets)" || HISTORY_SECRETS=""
  # A here-string, not a pipe: grep -q exiting early would SIGPIPE the writer
  # and, under pipefail, turn a match into a failure.
  if [ -n "$HISTORY_SECRETS" ] && grep -qxF -- "$CURRENT_SECRET" <<<"$HISTORY_SECRETS"; then
    NEW_SECRET_REASON="the AUTH_SECRET in .env was committed to git, so it is public"
  fi
  unset HISTORY_SECRETS
fi

if [ -n "$NEW_SECRET_REASON" ]; then
  log "writing a fresh AUTH_SECRET to .env ($NEW_SECRET_REASON)"
  [ -n "$CURRENT_SECRET" ] && warn "everyone signed in with the old secret is logged out"
  (
    umask 077
    { [ -f .env ] && grep -v '^AUTH_SECRET=' .env || true; } > .env.new
    printf 'AUTH_SECRET=%s\n' "$(openssl rand -hex 32)" >> .env.new
    mv -f .env.new .env
  )
else
  log ".env already has a private AUTH_SECRET; keeping it"
fi
unset CURRENT_SECRET
chmod 600 .env

# ── 6. Backup folder ─────────────────────────────────────────────────────
# Server backups go to BACKUP_HOST_DIR (docker-compose.yml bind-mounts it at
# /backups; ./backups when unset). Ask once, on the first install; the
# chooser writes the answer to .env, so a re-run does not ask again.
BACKUP_HOST_DIR_NOW="$(sed -n 's/^BACKUP_HOST_DIR=//p' .env | tail -n1 | env_value)"
if [ "$BACKUP_FOLDER" = "ask" ] || { [ "$BACKUP_FOLDER" = "auto" ] && [ -z "$BACKUP_HOST_DIR_NOW" ]; }; then
  if [ -f ./choose-backup-folder.sh ]; then
    log "choosing the folder for server backups (run ./choose-backup-folder.sh again any time to change it)"
    sh ./choose-backup-folder.sh --no-apply || warn "backup folder not changed; backups go to ${BACKUP_HOST_DIR_NOW:-$PWD/backups}"
  else
    warn "choose-backup-folder.sh is missing from $PWD; backups go to ${BACKUP_HOST_DIR_NOW:-$PWD/backups}"
  fi
  BACKUP_HOST_DIR_NOW="$(sed -n 's/^BACKUP_HOST_DIR=//p' .env | tail -n1 | env_value)"
fi
if [ -z "$BACKUP_HOST_DIR_NOW" ]; then
  mkdir -p backups
  BACKUP_HOST_DIR_NOW="$PWD/backups"
fi

# ── 7. Launch ────────────────────────────────────────────────────────────
log "starting the container (docker compose up -d $BUILD_FLAG); a first build takes several minutes"
# shellcheck disable=SC2086
$SUDO docker compose up -d $BUILD_FLAG

HOST_PORT="$($SUDO docker compose port btct 8080 2>/dev/null | tail -n1 | sed 's/.*://')"
HOST_PORT="${HOST_PORT:-8080}"
log "waiting up to ${HEALTH_TIMEOUT}s for http://127.0.0.1:$HOST_PORT/healthz"
for _ in $(seq 1 "$HEALTH_TIMEOUT"); do
  if curl -fsS "http://127.0.0.1:$HOST_PORT/healthz" >/dev/null 2>&1; then
    IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    log "BTCT is up: http://127.0.0.1:$HOST_PORT${IP:+ (LAN: http://$IP:$HOST_PORT)}"
    log "accounts: Roberto, Warren, Ryan, Anthony, Jesse and Darren (all admins) are created when missing; a password not set in .env is generated"
    if $SUDO docker compose exec -T btct test -s /data/initial-passwords.txt 2>/dev/null; then
      log "generated passwords: '${SUDO:+$SUDO }docker compose exec btct cat /data/initial-passwords.txt' (or 'docker compose logs btct | grep \"generated password\"'); change them after the first login, then delete that file"
    fi
    log "backups: Admin panel -> Backups writes one btct-backup-YYYYMMDD-HHMMSS.zip per run into $BACKUP_HOST_DIR_NOW; restore with Restore-BTCT.ps1 or README \"Backups\""
    log "update later (pulls $BTCT_BRANCH, keeps the data): $APP_DIR/btct.sh update   (or btct update after ./btct.sh install)"
    exit 0
  fi
  sleep 1
done

warn "healthz never answered; recent logs:"
$SUDO docker compose logs --tail=80
exit 1
