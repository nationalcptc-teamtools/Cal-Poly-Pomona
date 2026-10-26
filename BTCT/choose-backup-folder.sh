#!/bin/sh
# choose-backup-folder.sh: pick the host folder BTCT writes its backups to.
#
# Scheduled server backups (one btct-backup-YYYYMMDD-HHMMSS.zip per run) are
# written to /backups in the container, which docker-compose.yml bind-mounts
# from BACKUP_HOST_DIR in .env (./backups next to docker-compose.yml when
# unset). This script sets that value:
#
#   1. Opens a native folder chooser: zenity, then kdialog, then yad. With no
#      display (over SSH, say) or none of them installed, it asks for a typed
#      path instead, with the current folder as the default.
#   2. Checks the choice: an absolute path, not a system folder. It creates
#      the folder when missing and makes that one folder (never its contents)
#      writable by uid 1000, the container's bun user.
#   3. Warns when the disk has less than 3 GB free (12 kept runs of a
#      500-screenshot engagement are about 2.3 GB).
#   4. Writes BACKUP_HOST_DIR to .env, leaving every other line as it was and
#      the file mode 600, then offers to run `docker compose up -d`.
#
# Run it any time; install-btct.sh calls it on the first install. Under sudo
# the dialog opens as the desktop user (SUDO_USER) on their display.
#
# Usage:
#   ./choose-backup-folder.sh                  # dialog, or typed prompt
#   ./choose-backup-folder.sh --path /srv/bk   # no dialog, use this folder
#   ./choose-backup-folder.sh --no-dialog      # typed prompt only
#   ./choose-backup-folder.sh --apply          # run `docker compose up -d` after
#   ./choose-backup-folder.sh --no-apply       # leave the container alone (install-btct.sh)
#
# Exit codes: 0 saved (or kept), 1 the folder could not be used, 2 bad option.

set -eu

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${BTCT_ENV_FILE:-$APP_DIR/.env}"
CONTAINER_UID=1000
CONTAINER_GID=1000
MIN_FREE_KB=3145728   # 3 GB
TITLE="BTCT: choose the folder for server backups"

ARG_PATH=""
USE_DIALOG=1
APPLY=ask

while [ $# -gt 0 ]; do
  case "$1" in
    --path) [ $# -ge 2 ] || { echo "--path needs a folder" >&2; exit 2; }; ARG_PATH="$2"; shift ;;
    --path=*) ARG_PATH="${1#--path=}" ;;
    --no-dialog) USE_DIALOG=0 ;;
    --apply) APPLY=yes ;;
    --no-apply) APPLY=never ;;
    -h|--help) sed -n '2,31p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

log()  { printf '\033[1;36m[backup-folder]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[backup-folder]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[backup-folder]\033[0m %s\n' "$*" >&2; }

if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
elif command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  SUDO=""
fi

# A terminal to ask on, even when stdin is a pipe (curl ... | bash).
HAVE_TTY=0
if [ -t 0 ]; then
  TTY_IN=/dev/stdin; HAVE_TTY=1
elif (true </dev/tty) 2>/dev/null; then   # a subshell: a failed redirection must not end the script
  TTY_IN=/dev/tty; HAVE_TTY=1
fi

ask() { # ask PROMPT -> answer on stdout ("" without a terminal)
  if [ "$HAVE_TTY" -eq 1 ]; then
    printf '%s' "$1" >&2
    IFS= read -r _ans <"$TTY_IN" || _ans=""
    printf '%s' "$_ans"
  fi
}

# Read KEY's value from .env the way docker compose does: the last line wins,
# CR and one pair of surrounding quotes are stripped.
env_get() {
  [ -f "$ENV_FILE" ] || return 0
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -n1 | tr -d '\r' \
    | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\\(.*\\)'\$/\\1/"
}

# ── Current and default folder ───────────────────────────────────────────
CURRENT="$(env_get BACKUP_HOST_DIR)"
case "$CURRENT" in
  "") DEFAULT="$APP_DIR/backups" ;;
  /*) DEFAULT="$CURRENT" ;;
  *) DEFAULT="$APP_DIR/${CURRENT#./}" ;;   # compose resolves it next to docker-compose.yml
esac

# ── Dialog ───────────────────────────────────────────────────────────────
# The desktop user the dialog should run as, and their home for "~".
DESK_USER=""
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  DESK_USER="$SUDO_USER"
fi
if [ -n "$DESK_USER" ]; then
  DESK_HOME="$(getent passwd "$DESK_USER" 2>/dev/null | cut -d: -f6)"
else
  DESK_HOME="${HOME:-}"
fi

# sudo usually keeps DISPLAY; when it did not, use the desktop user's :0 if
# that X socket is theirs.
if [ -n "$DESK_USER" ] && [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ] \
   && [ -S /tmp/.X11-unix/X0 ] && [ "$(stat -c %U /tmp/.X11-unix/X0 2>/dev/null)" = "$DESK_USER" ]; then
  DISPLAY=:0
  export DISPLAY
fi

run_dialog() { # run_dialog CMD ARGS... -> chosen path on stdout
  if [ -n "$DESK_USER" ]; then
    _uid="$(id -u "$DESK_USER")"
    # sudo resets PATH, so hand it the tool's full path.
    _cmd="$(command -v "$1")"; shift
    set -- "$_cmd" "$@"
    sudo -H -u "$DESK_USER" env \
      DISPLAY="${DISPLAY:-}" WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" \
      XAUTHORITY="${XAUTHORITY:-$DESK_HOME/.Xauthority}" \
      XDG_RUNTIME_DIR="/run/user/$_uid" \
      DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$_uid/bus}" \
      "$@" 2>/dev/null
  else
    "$@" 2>/dev/null
  fi
}

CHOICE=""
pick_with_dialog() {
  if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    log "no graphical display here (DISPLAY and WAYLAND_DISPLAY are unset), so asking in the terminal"
    return 1
  fi
  _start="$DEFAULT"
  [ -d "$_start" ] || _start="$(dirname "$_start")"
  [ -d "$_start" ] || _start="${DESK_HOME:-/}"
  if command -v zenity >/dev/null 2>&1; then
    log "opening the folder chooser (zenity)"
    CHOICE="$(run_dialog zenity --file-selection --directory --title="$TITLE" --filename="${_start%/}/")" && [ -n "$CHOICE" ] && return 0
  elif command -v kdialog >/dev/null 2>&1; then
    log "opening the folder chooser (kdialog)"
    CHOICE="$(run_dialog kdialog --getexistingdirectory "$_start" --title "$TITLE")" && [ -n "$CHOICE" ] && return 0
  elif command -v yad >/dev/null 2>&1; then
    log "opening the folder chooser (yad)"
    CHOICE="$(run_dialog yad --file --directory --title="$TITLE" --filename="${_start%/}/")" && [ -n "$CHOICE" ] && return 0
  else
    warn "no folder chooser found (zenity, kdialog or yad). On Kali or Debian: sudo apt install zenity"
    return 1
  fi
  CHOICE=""
  log "the chooser closed without a folder"
  return 1
}

# Run a command, through sudo when this user may not.
priv() { "$@" 2>/dev/null || { [ -n "$SUDO" ] && $SUDO "$@"; }; }

# Can uid 1000 write there? Read the folder's own owner and mode: the
# container sees only the mounted folder, so its parents do not matter.
writable_by_container() {
  _o="$(stat -c %u "$1")"; _g="$(stat -c %g "$1")"; _m="$(stat -c %a "$1")"
  _m=$(( 0$_m ))
  if [ "$_o" = "$CONTAINER_UID" ]; then [ $(( _m & 0300 )) -eq 192 ]; return; fi
  if [ "$_g" = "$CONTAINER_GID" ]; then [ $(( _m & 0030 )) -eq 24 ]; return; fi
  [ $(( _m & 0003 )) -eq 3 ]
}

# Check CHOICE, create it when missing and make it writable by uid 1000.
# Prints why and returns 1 when the folder cannot be used.
prepare_folder() {
  case "$CHOICE" in
    "~") CHOICE="$DESK_HOME" ;;
    "~/"*) CHOICE="$DESK_HOME/${CHOICE#"~/"}" ;;
  esac
  # Drop trailing slashes (but keep "/" itself, refused below).
  while [ "${#CHOICE}" -gt 1 ] && [ "${CHOICE%/}" != "$CHOICE" ]; do CHOICE="${CHOICE%/}"; done

  case "$CHOICE" in
    /*) ;;
    *) fail "'$CHOICE' is not an absolute path (it must start with /)"; return 1 ;;
  esac
  case "$CHOICE" in
    *"$NL"*|*"'"*|*'"'*|*'$'*|*'\'*|*'`'*)
      fail "the path holds a quote, \$, backslash, backtick or newline, which .env and docker compose cannot carry; pick another folder"; return 1 ;;
    *:*) fail "the path holds a ':', which a docker bind mount cannot carry; pick another folder"; return 1 ;;
  esac
  case "$CHOICE" in
    /|/bin|/boot|/dev|/etc|/home|/lib|/lib32|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|/var/lib|/run/*|/usr/*|/var/lib/docker/*|/etc/*|/proc/*|/sys/*|/dev/*|/boot/*)
      fail "$CHOICE is a system folder; pick (or create) a folder of its own, e.g. $CHOICE/btct-backups"; return 1 ;;
  esac
  if [ -n "$DESK_HOME" ] && [ "$CHOICE" = "$DESK_HOME" ]; then
    fail "$CHOICE is a home folder; pick (or create) a folder of its own, e.g. $CHOICE/btct-backups"; return 1
  fi
  if [ -e "$CHOICE" ] && [ ! -d "$CHOICE" ]; then
    fail "$CHOICE exists and is not a folder"; return 1
  fi

  if [ ! -d "$CHOICE" ]; then
    priv mkdir -p "$CHOICE" || { fail "could not create $CHOICE"; return 1; }
    log "created $CHOICE"
    # A new folder is the container's own (owner 1000); the ZIPs in it are 0600.
    priv chown "$CONTAINER_UID:$CONTAINER_GID" "$CHOICE" || true
    priv chmod 0755 "$CHOICE" || true
  elif ! writable_by_container "$CHOICE"; then
    _owner="$(stat -c %U "$CHOICE" 2>/dev/null || echo '?')"
    warn "$CHOICE (owner $_owner) is not writable by uid $CONTAINER_UID, the user the server runs as"
    _ans="$(ask "Make uid $CONTAINER_UID the owner of that one folder (its contents are left alone)? [Y/n] ")"
    case "$_ans" in
      n|N|no|NO) ;;
      *) priv chown "$CONTAINER_UID:$CONTAINER_GID" "$CHOICE" && priv chmod u+rwx "$CHOICE" || true ;;
    esac
  fi
  if ! writable_by_container "$CHOICE"; then
    _fs="$(stat -f -c %T "$CHOICE" 2>/dev/null || echo unknown)"
    fail "$CHOICE is not writable by uid $CONTAINER_UID (filesystem: $_fs)."
    case "$_fs" in
      msdos|vfat|exfat|fuseblk|ntfs*) fail "That filesystem keeps no Unix owners: mount it with uid=$CONTAINER_UID,gid=$CONTAINER_GID, or pick a folder on a Linux filesystem." ;;
      *) fail "Fix it with: sudo chown $CONTAINER_UID:$CONTAINER_GID '$CHOICE'" ;;
    esac
    return 1
  fi
  return 0
}

NL='
'
TRIES=0
while :; do
  CHOICE=""
  if [ -n "$ARG_PATH" ]; then
    CHOICE="$ARG_PATH"
  elif [ "$USE_DIALOG" -eq 0 ] || ! pick_with_dialog; then
    if [ "$HAVE_TTY" -eq 1 ]; then
      CHOICE="$(ask "Backup folder [$DEFAULT]: ")"
    else
      log "no terminal to ask on; keeping $DEFAULT"
    fi
  fi
  [ -n "$CHOICE" ] || CHOICE="$DEFAULT"
  prepare_folder && break
  TRIES=$((TRIES + 1))
  # A fixed --path, or nobody to ask, gets one try; a person gets three.
  if [ -n "$ARG_PATH" ] || [ "$HAVE_TTY" -eq 0 ] || [ "$TRIES" -ge 3 ]; then
    fail "BACKUP_HOST_DIR left unchanged"
    exit 1
  fi
  log "try again (Enter keeps $DEFAULT)"
done

FREE_KB="$(df -Pk "$CHOICE" 2>/dev/null | awk 'NR==2 {print $4}')"
if [ -n "$FREE_KB" ]; then
  FREE_GB="$(awk -v k="$FREE_KB" 'BEGIN { printf "%.1f", k / 1048576 }')"
  if [ "$FREE_KB" -lt "$MIN_FREE_KB" ]; then
    warn "only $FREE_GB GB free on that disk. Each backup is a full copy (about 192 MB for 500 screenshots) and 12 are kept, about 2.3 GB; lower \"keep last\" in Admin panel -> Backups or pick a bigger disk"
  else
    log "$FREE_GB GB free on that disk"
  fi
fi

# ── .env ─────────────────────────────────────────────────────────────────
# Single quotes keep compose from expanding anything; plain paths stay bare.
case "$CHOICE" in
  *[!A-Za-z0-9_./+-]*) VALUE="'$CHOICE'" ;;
  *) VALUE="$CHOICE" ;;
esac
if [ "$CURRENT" = "$CHOICE" ]; then
  log "BACKUP_HOST_DIR is already $CHOICE; .env unchanged"
  CHANGED=0
else
  TMP="$ENV_FILE.new.$$"
  (
    umask 077
    if [ -f "$ENV_FILE" ]; then
      # Replace the first BACKUP_HOST_DIR line in place and drop later ones;
      # every other line is copied byte for byte.
      awk -v line="BACKUP_HOST_DIR=$VALUE" '
        /^BACKUP_HOST_DIR=/ { if (!done) { print line; done = 1 } ; next }
        { print }
        END { if (!done) print line }
      ' "$ENV_FILE" > "$TMP"
      chown --reference="$ENV_FILE" "$TMP" 2>/dev/null || true
    else
      printf 'BACKUP_HOST_DIR=%s\n' "$VALUE" > "$TMP"
      [ -n "$DESK_USER" ] && chown "$DESK_USER:" "$TMP" 2>/dev/null || true
    fi
    chmod 600 "$TMP"
    mv -f "$TMP" "$ENV_FILE"
  ) || { rm -f "$TMP"; fail "could not write $ENV_FILE"; exit 1; }
  log "saved BACKUP_HOST_DIR=$VALUE in $ENV_FILE"
  CHANGED=1
fi

# ── Apply ────────────────────────────────────────────────────────────────
[ "$APPLY" != never ] || exit 0
[ "$CHANGED" -eq 1 ] || [ "$APPLY" = yes ] || exit 0
if [ "$APPLY" = ask ]; then
  ANS="$(ask "Run 'docker compose up -d' now so the container uses it? [y/N] ")"
  case "$ANS" in y|Y|yes|YES) APPLY=yes ;; *) APPLY=no ;; esac
fi
if [ "$APPLY" = yes ]; then
  if docker info >/dev/null 2>&1; then DOCKER="docker"; else DOCKER="$SUDO docker"; fi
  (cd "$APP_DIR" && $DOCKER compose up -d) || { fail "docker compose up -d failed"; exit 1; }
  log "done: new backups land in $CHOICE"
else
  log "run 'docker compose up -d' in $APP_DIR to apply it (the container is recreated; data in the btct-data volume is kept)"
fi
