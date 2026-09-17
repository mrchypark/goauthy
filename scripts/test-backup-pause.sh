#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
cleanup() {
	status=$?
	trap - 0 1 2 15
	rm -rf "$work"
	exit "$status"
}
trap cleanup 0 1 2 15
# Exercise the production holder evidence helpers without a Kind lifecycle.
awk '/^scheduled_backup_(container_pid|holder_is_blocked|holder_state)\(\) \{/ { capture=1 } capture { print } capture && /^}$/ { capture=0 }' \
	"$root/scripts/e2e-kind-backup-restore.sh" >"$work/helpers.sh"
. "$work/helpers.sh"
kind_node=pause-control-plane
catalog_kind_ip=172.19.0.9
holder_pid=4242
scheduled_backup_holder_pid=4242
scratch=yes
socket=yes
docker() {
	[ "$1" = exec ] && [ "$2" = "$kind_node" ] || return 1
	if [ "$3" = sh ] && [ "$4" = -ec ]; then
		case "$5" in
			*find*) [ "$scratch" = yes ] ;;
			*cut*) printf '%s\n' T ;;
			*) return 1 ;;
		esac
		return
	fi
	case "$*" in
		*'crictl inspect -o json deadbeef'*) printf '%s\n' '{"status":{"id":"deadbeef","state":"CONTAINER_RUNNING"},"info":{"pid":4242}}' ;;
		*' nsenter -t 4242 -n ss -Htn state established'*) [ "$socket" = yes ] && printf '%s\n' "ESTAB 0 0 10.244.0.2:45718 $catalog_kind_ip:9000" ;;
		*) return 1 ;;
	esac
}
[ "$(scheduled_backup_container_pid deadbeef)" = 4242 ]
scheduled_backup_holder_is_blocked 4242
[ "$(scheduled_backup_holder_state)" = T ]
socket=no
if scheduled_backup_holder_is_blocked 4242; then
	echo 'holder evidence accepted Create scratch without an actual catalog connection' >&2
	exit 1
fi
socket=yes
scratch=no
if scheduled_backup_holder_is_blocked 4242; then
	echo 'holder evidence accepted a catalog connection without Create scratch' >&2
	exit 1
fi
printf '%s\n' 'Scheduled backup paused-holder evidence checks passed'

# Run the real apply_app renderer over the actual Kustomize input. Kubectl is
# the only stub: this checks rendering and manifest invariants without Kind.
sed -n '/^apply_app() {/,/^assert_no_pvc_application() {/p' "$root/scripts/e2e-kind-backup-restore.sh" | sed '$d' >"$work/apply-app.sh"
. "$work/apply-app.sh"
temp_dir=$work
image=goauthy:e2e
generated_ttl=0
expiry_profile=0
checkpoint_interval=1s
checkpoint_interruption_sidecar=0
checkpoint_block_path=
checkpoint_fault_image=unused
journal_interruption_active=0
journal_interruption_phase=
journal_fault_image=unused
scheduled_backup_outage_profile=0
scheduled_backup_quorum_profile=0
scheduled_backup_rotation_profile=0
scheduled_backup_cron='0 1 2 3 4 * 2026'
catalog_prefix=render-catalog
catalog_kind_ip=192.0.2.1
kubectl() {
	# Rendering wrote the manifest before apply; no Kubernetes API is needed.
	return 0
}
scheduled_backup_pause_profile=1
apply_app render-pause false goauthy-e2e 1
pause_render=$work/render-pause-app.yaml
awk '
	$0 == "        livenessProbe:" { in_liveness = 1; next }
	in_liveness && $0 == "        readinessProbe:" { exit 1 }
	in_liveness && $0 == "          failureThreshold: 120" { found++ }
	END { exit found == 1 ? 0 : 1 }
' "$pause_render"
scheduled_backup_pause_profile=0
apply_app render-default false goauthy-e2e 0
default_render=$work/render-default-app.yaml
if grep -Fqx '          failureThreshold: 120' "$default_render"; then
	echo 'default renderer unexpectedly changed liveness failure threshold' >&2
	exit 1
fi
pause_flow=$(sed -n '/^run_scheduled_backup_paused_holder() {/,/^stop_scheduled_source() {/p' "$root/scripts/e2e-kind-backup-restore.sh")
if printf '%s\n' "$pause_flow" | grep -Fq 'systemctl '; then
	echo 'paused-holder flow must not stop kubelet' >&2
	exit 1
fi
printf '%s\n' 'Scheduled backup paused-holder render guard passed'
