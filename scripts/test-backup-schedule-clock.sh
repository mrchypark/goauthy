#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' 0 1 2 15
# Load only the production scheduling helpers; never execute the Kind lifecycle.
awk '/^scheduled_backup_(schedule|log_time|now|logs)\(\) \{/ { capture=1 } capture { print } capture && /^\}/ { capture=0 }' \
	"$root/scripts/e2e-kind-backup-restore.sh" >"$work/helpers.sh"
. "$work/helpers.sh"
cluster=clock
# This is the external Docker boundary. Host wall time must not set the slot.
docker() {
	[ "$*" = 'exec clock-control-plane date -u +%s' ] || return 1
	[ "$fake_status" = 0 ] || return 1
	printf '%s\n' "$fake_now"
}
fake_status=0
fake_now=1924991520 # 2030-12-31 23:52:00 UTC
scheduled_backup_outage_profile=0
scheduled_backup_quorum_profile=0
scheduled_backup_rotation_profile=0
scheduled_backup_pause_profile=0
scheduled_backup_schedule
[ "$scheduled_backup_due_epoch" = 1924991820 ]
[ "$scheduled_backup_cron" = '00 57 23 31 12 * 2030' ]
scheduled_backup_outage_profile=1
scheduled_backup_schedule
[ "$scheduled_backup_cron" = '0 00,02 00 01 01 * 2031' ]
[ "$((scheduled_backup_recovery_due_epoch - scheduled_backup_due_epoch))" = 120 ]
[ "$(scheduled_backup_log_time "$scheduled_backup_recovery_due_epoch")" = '2031-01-01T00:02:00.000Z' ]
scheduled_backup_outage_profile=0
scheduled_backup_quorum_profile=1
scheduled_backup_schedule
[ "$scheduled_backup_cron" = '0 00,02 00 01 01 * 2031' ]
scheduled_backup_quorum_profile=0
scheduled_backup_rotation_profile=1
scheduled_backup_schedule
[ "$scheduled_backup_cron" = '0 00,03 00 01 01 * 2031' ]
[ "$((scheduled_backup_recovery_due_epoch - scheduled_backup_due_epoch))" = 180 ]
scheduled_backup_rotation_profile=0
scheduled_backup_pause_profile=1
scheduled_backup_schedule
[ "$scheduled_backup_cron" = '0 00,03 00 01 01 * 2031' ]
[ "$((scheduled_backup_recovery_due_epoch - scheduled_backup_due_epoch))" = 180 ]
scheduled_backup_pause_profile=0
fake_now=invalid
if scheduled_backup_schedule; then echo 'accepted invalid node clock' >&2; exit 1; fi
fake_status=1
if scheduled_backup_schedule; then echo 'accepted unavailable node clock' >&2; exit 1; fi
temp_dir=$work
kind_node=clock-control-plane
source_context=kind-clock
namespace=goauthy
printf '%s' abc123 >"$work/scheduled-quorum-container-0"
docker() {
	[ "$*" = 'exec clock-control-plane crictl logs abc123' ] || return 1
	# crictl preserves container stderr, which carries Go's slog output.
	printf '%s' cri-log >&2
}
kubectl() {
	[ "$*" = '--context kind-clock -n goauthy logs pod/goauthy-0 -c goauthy' ] || return 1
	printf '%s' kubelet-log
}
scheduled_backup_quorum_profile=1
kubelet_stopped=true
[ "$(scheduled_backup_logs 0 2>/dev/null)" = cri-log ]
kubelet_stopped=false
[ "$(scheduled_backup_logs 0)" = kubelet-log ]
printf '%s\n' 'Scheduled backup clock, rollover and stopped-kubelet log checks passed' 
