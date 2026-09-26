#!/bin/sh
# Small S3 fixture adapter for the backup/restore E2E. Credentials and
# endpoints come from RCLONE_CONFIG_LOCAL_* or RCLONE_CONFIG_FIXTURE_*.
set -eu

path() {
  case "$1" in
    local/*|fixture/*) printf '%s:%s\n' "${1%%/*}" "${1#*/}" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

command=$1
shift
case "$command" in
  stat)
    remote=$(path "$1")
    rclone lsf --files-only "${remote%/*}" | grep -Fxq "${remote##*/}" ;;
  ls) [ "$1" = --recursive ] && [ "$2" = --json ]; rclone lsjson -R "$(path "$3")" ;;
  cp) rclone copyto --ignore-times "$(path "$1")" "$(path "$2")" ;;
  mirror)
    overwrite=0
    if [ "$1" = --overwrite ]; then overwrite=1; shift; fi
    if [ "$overwrite" = 1 ]; then
      rclone copy --ignore-times "$(path "$1")" "$(path "$2")"
    else
      rclone copy "$(path "$1")" "$(path "$2")"
    fi ;;
  rm) [ "$1" = --recursive ] && [ "$2" = --force ]; rclone purge "$(path "$3")" ;;
  pipe) rclone rcat "$(path "$1")" ;;
  mb) rclone mkdir "$(path "$1")" ;;
  *) echo "unsupported S3 fixture command: $command" >&2; exit 2 ;;
esac
