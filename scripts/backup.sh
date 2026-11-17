#!/usr/bin/env bash
# Back up the DefectDojo and SonarQube databases (pg_dump custom format) plus DefectDojo media.
#
# Usage: scripts/backup.sh [--keep N]
# Output: ${LABSEC_BACKUP_DIR:-<data root>/backups}/<UTC timestamp>/   (mode 700); the data root is described in
# scripts/lib/paths.sh (Linux/WSL2 ~/.local/share/labsecurity, macOS ~/Library/Application Support/LabSecurity, $LABSEC_HOME).
# If the lab is stopped, the backup is skipped (exit 0) and the reason is logged:
# the lab is meant to be stopped when unused, so a stopped lab is not an error.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/paths.sh
. "$ROOT/scripts/lib/paths.sh"
labsec_resolve_paths
BACKUP_ROOT="${LABSEC_BACKUP_DIR:-$LABSEC_DATA_DIR/backups}"
KEEP=14
[[ "${1:-}" == "--keep" ]] && KEEP="${2:?--keep needs a number}"

cd "$ROOT"
log() { printf '%s labsecurity-backup: %s\n' "$(date -u +%FT%TZ)" "$*"; }

running() { [[ "$(docker compose ps --status running --services 2>/dev/null | grep -cx "$1")" == 1 ]]; }

if ! running sonar-db || ! running dd-db; then
  log "skipped: lab is not running (start it with: docker compose up -d)"
  exit 0
fi

umask 077
mkdir -p "$BACKUP_ROOT"
chmod 700 "$BACKUP_ROOT"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
dest="$BACKUP_ROOT/$stamp"
mkdir -p "$dest"

docker compose exec -T sonar-db pg_dump -U sonarqube -d sonarqube -Fc >"$dest/sonarqube.dump"
docker compose exec -T dd-db pg_dump -U defectdojo -d defectdojo -Fc >"$dest/defectdojo.dump"
docker run --rm -v labsecurity_dd_media:/media:ro \
  docker.io/library/alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf \
  tar -C /media -czf - . >"$dest/defectdojo-media.tgz"
# sha256sum is GNU; macOS ships `shasum -a 256`, which writes and checks the same format.
if command -v sha256sum >/dev/null 2>&1; then sha256() { sha256sum "$@"; }; else sha256() { shasum -a 256 "$@"; }; fi
(cd "$dest" && sha256 ./*.dump ./*.tgz >SHA256SUMS)

log "ok: $dest ($(du -sh "$dest" | cut -f1))"

# Retention: keep the newest $KEEP backups. Only directories named like our timestamps are touched.
# (No mapfile and no find -regex: macOS has bash 3.2 and BSD find.)
find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -name '[0-9]*T[0-9]*Z' | sort -r | tail -n +"$((KEEP + 1))" |
  while IFS= read -r dir; do
    case "$(basename "$dir")" in
      ????????T??????Z) ;;
      *) continue ;;
    esac
    if command -v gio >/dev/null 2>&1; then gio trash "$dir"; else mv "$dir" "$dir.expired"; fi
    log "rotated: $dir"
  done
