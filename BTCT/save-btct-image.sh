#!/usr/bin/env bash
# save-btct-image.sh: save the BTCT Docker image to a file for a USB stick,
# the day before a competition, so competition-day.sh can load it instead of
# building (minutes faster, and it works with no internet).
#
# What it does:
#   1. Uses the image btct:latest when this box has it, or builds it with
#      docker compose (always with --build; first build takes minutes).
#   2. docker save | gzip into btct-image.tar.gz (written under a .partial
#      name and renamed, so an interrupted run leaves nothing to trust).
#   3. Writes btct-image.tar.gz.sha256 (sha256sum format) and
#      btct-image.tar.gz.id (the image ID, so a re-run of competition-day.sh
#      skips a load it already did).
#
# Copy all three files next to competition-day.sh (or into the repo folder)
# on the competition box; competition-day.sh verifies the sha256.
#
# Usage:
#   ./save-btct-image.sh                  # existing btct:latest, else build
#   ./save-btct-image.sh --build          # rebuild first, even if it exists
#   ./save-btct-image.sh --out /media/usb/btct-image.tar.gz
#   ./save-btct-image.sh --image NAME     # save another tag (default btct:latest)
#
# Build options come from .env as usual (WITH_REPORT_BINS=0 and
# WITH_TYPST_CLIENT=0 make a smaller image). The file never contains .env or
# AUTH_SECRET: the secret is passed at run time, not baked into the image.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]:-$0}")")" && pwd)"
IMAGE="btct:latest"
OUT="$SCRIPT_DIR/btct-image.tar.gz"
BUILD=0

while [ $# -gt 0 ]; do
  case "$1" in
    --build) BUILD=1 ;;
    --out) [ $# -ge 2 ] || { echo "--out needs a path" >&2; exit 2; }; OUT="$2"; shift ;;
    --out=*) OUT="${1#--out=}" ;;
    --image) [ $# -ge 2 ] || { echo "--image needs a name" >&2; exit 2; }; IMAGE="$2"; shift ;;
    --image=*) IMAGE="${1#--image=}" ;;
    -h|--help) sed -n '2,29p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

log()  { printf '\033[1;36m[save-image]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[save-image]\033[0m %s\n' "$*" >&2; exit 1; }

# docker directly when this user may, else through sudo.
DOCKER=(docker)
if ! docker info >/dev/null 2>&1; then
  if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
    DOCKER=(sudo docker)
  else
    die "cannot reach the Docker daemon (is it running? are you in the docker group?)"
  fi
fi
COMPOSE=("${DOCKER[@]}" compose)
"${COMPOSE[@]}" version >/dev/null 2>&1 || {
  if command -v docker-compose >/dev/null 2>&1; then
    if [ "${DOCKER[0]}" = "sudo" ]; then COMPOSE=(sudo docker-compose); else COMPOSE=(docker-compose); fi
  else COMPOSE=(); fi
}

if [ "$BUILD" -eq 1 ] || ! "${DOCKER[@]}" image inspect "$IMAGE" >/dev/null 2>&1; then
  [ "$IMAGE" = "btct:latest" ] || die "$IMAGE does not exist, and only btct:latest can be built here"
  [ -f "$SCRIPT_DIR/docker-compose.yml" ] || die "no docker-compose.yml next to this script; run it from the BTCT checkout"
  [ "${#COMPOSE[@]}" -gt 0 ] || die "docker compose is not installed"
  log "building $IMAGE (first build takes several minutes)"
  # compose interpolates the whole file even to build; the placeholder only
  # satisfies that check and is not part of the image.
  (cd "$SCRIPT_DIR" && AUTH_SECRET="${AUTH_SECRET:-build-only-placeholder}" "${COMPOSE[@]}" build btct)
else
  log "using the existing $IMAGE (pass --build to rebuild first)"
fi

ID="$("${DOCKER[@]}" image inspect -f '{{.Id}}' "$IMAGE")"
CREATED="$("${DOCKER[@]}" image inspect -f '{{.Created}}' "$IMAGE" | cut -c1-19)"
log "image $IMAGE ${ID:7:12}, created $CREATED"

OUT_DIR="$(dirname "$OUT")"
mkdir -p "$OUT_DIR"
NEED_KB=$(( $("${DOCKER[@]}" image inspect -f '{{.Size}}' "$IMAGE") / 1024 / 2 ))
FREE_KB="$(df -Pk "$OUT_DIR" | awk 'NR==2 {print $4}')"
if [ "${FREE_KB:-0}" -lt "$NEED_KB" ]; then
  die "only $((FREE_KB / 1024)) MB free in $OUT_DIR; the file needs about $((NEED_KB / 1024)) MB"
fi

GZ=(gzip -6)
command -v pigz >/dev/null 2>&1 && GZ=(pigz -6)
log "saving to $OUT (docker save | ${GZ[0]}; a minute or two)"
PART="$OUT.partial"
trap 'rm -f "$PART"' EXIT
"${DOCKER[@]}" save "$IMAGE" | "${GZ[@]}" > "$PART"
gzip -t "$PART" || die "the compressed file does not test clean"
mv -f "$PART" "$OUT"
trap - EXIT

(cd "$OUT_DIR" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256")
printf '%s\n' "$ID" > "$OUT.id"

log "done: $OUT ($(du -h "$OUT" | cut -f1))"
log "      $OUT.sha256"
log "      $OUT.id"
log "copy all three to the USB stick, then on the competition box put them next to"
log "competition-day.sh (or pass --image /path/to/btct-image.tar.gz)"
