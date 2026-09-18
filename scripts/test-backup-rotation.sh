#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temp_dir=$(mktemp -d)
cleanup() {
	status=$?
	trap - 0 1 2 15
	rm -rf "$temp_dir"
	exit "$status"
}
trap cleanup 0 1 2 15

# Extract the production helpers so the regression covers their real control flow.
extract() {
	awk -v name="$1" '
		$0 == name "() {" { capture=1 }
		capture { print }
		capture && /^}$/ { capture=0 }
	' "$root/scripts/e2e-kind-backup-restore.sh"
}
{
	extract assert_single_kind_node
	extract capture_pod_uid
	extract capture_container_id
	extract create_scheduled_backup_secret
	extract rotate_scheduled_backup_signer
} >"$temp_dir/helpers.sh"
sed '/^\tassert_single_kind_node$/d' "$temp_dir/helpers.sh" >"$temp_dir/helpers-without-node-guard.sh"

cluster=rotation
source_context=kind-rotation
namespace=goauthy
cluster_control_plane=rotation-control-plane
kind_node=
scheduled_backup_rotation_profile=1
scheduled_backup_rotated=0
catalog_private_key=$temp_dir/old-private.pem
catalog_rotated_private_key=$temp_dir/new-private.pem
catalog_trust_bundle=$temp_dir/trust.pem
age_recipient_file=$temp_dir/recipient
catalog_access_key_file=$temp_dir/access
catalog_secret_key_file=$temp_dir/secret
: >"$catalog_private_key"
: >"$catalog_rotated_private_key"
: >"$catalog_trust_bundle"
: >"$age_recipient_file"
: >"$catalog_access_key_file"
: >"$catalog_secret_key_file"
phase=before

pod_ordinal() {
	case "$1" in
		goauthy-0) printf '%s\n' 0 ;;
		goauthy-1) printf '%s\n' 1 ;;
		goauthy-2) printf '%s\n' 2 ;;
		*) return 1 ;;
	esac
}
container_id_for() {
	ordinal=$1
	case "$phase" in
		before) printf '%064d\n' "$((ordinal + 1))" | tr ' ' a ;;
		after) printf '%064d\n' "$((ordinal + 4))" | tr ' ' b ;;
		*) return 1 ;;
	esac
}
uid_for() {
	ordinal=$1
	printf 'uid-%s-%s\n' "$phase" "$ordinal"
}

kind() {
	[ "$*" = 'get nodes --name rotation' ] || return 1
	printf '%s\n' "$cluster_control_plane"
}
docker() {
	case "$1" in
		inspect)
			[ "$2" = --format ] && [ "$4" = "$cluster_control_plane" ] || return 1
			printf '%s\n' true
			;;
		exec)
			[ "$2" = "$cluster_control_plane" ] || return 1
			case "$*" in
				*' sh -ec '*) return 0 ;;
				*' crictl inspect -o json '*)
					container_id=$(printf '%s\n' "$*" | awk '{print $NF}')
					case "$container_id" in ''|*[!0-9a-f]*) return 1;; esac
					printf '{"status":{"id":"%s","state":"CONTAINER_RUNNING"}}\n' "$container_id"
					;;
				*) return 1 ;;
			esac
		;;
		*) return 1 ;;
	esac
}
kubectl() {
	case " $* " in
		*' create secret generic goauthy-backup '*)
			case " $* " in
				*" --from-file=signing-key=$catalog_private_key "*) printf '%s\n' old >"$temp_dir/selected-secret-signer" ;;
				*" --from-file=signing-key=$catalog_rotated_private_key "*) printf '%s\n' new >"$temp_dir/selected-secret-signer" ;;
				*) return 1 ;;
			esac
			printf '%s\n' 'apiVersion: v1'
			;;
		*' apply -f - '*) cat >/dev/null ;;
		*' rollout restart statefulset/goauthy '*) phase=after ;;
		*' rollout status statefulset/goauthy '*) [ "$phase" = after ] ;;
		*' wait --for=condition=ready pod/goauthy-'*) [ "$phase" = after ] ;;
		*' get pod/goauthy-'*)
			case "$*" in
				*'pod/goauthy-0'*) pod=goauthy-0 ;;
				*'pod/goauthy-1'*) pod=goauthy-1 ;;
				*'pod/goauthy-2'*) pod=goauthy-2 ;;
				*) return 1 ;;
			esac
			ordinal=$(pod_ordinal "$pod")
			case "$*" in
				*"jsonpath={.metadata.uid}"*) uid_for "$ordinal" ;;
				*' -o json'*)
					container_id=$(container_id_for "$ordinal")
					printf '{"spec":{"nodeName":"%s"},"status":{"containerStatuses":[{"name":"goauthy","state":{"running":{}},"containerID":"containerd://%s"}]}}\n' "$cluster_control_plane" "$container_id"
					;;
				*) return 1 ;;
			esac
			;;
		*) return 1 ;;
	esac
}

# The old helper has no way to establish kind_node, so its real container
# capture invariant rejects every source voter before a fake rollout can pass.
. "$temp_dir/helpers-without-node-guard.sh"
if rotate_scheduled_backup_signer >/dev/null 2>&1; then
	echo 'rotation helper without the Kind-node guard unexpectedly passed' >&2
	exit 1
fi

# Reload the fixed production helper. It must establish the exact node, select
# the new signing key during Secret replacement, and observe each voter change.
. "$temp_dir/helpers.sh"
scheduled_backup_rotated=0
kind_node=
phase=before
create_scheduled_backup_secret "$source_context"
[ "$(cat "$temp_dir/selected-secret-signer")" = old ]
rotate_scheduled_backup_signer
[ "$kind_node" = "$cluster_control_plane" ]
[ "$phase" = after ]
[ "$scheduled_backup_rotated" = 1 ]
[ "$(cat "$temp_dir/selected-secret-signer")" = new ]
for ordinal in 0 1 2; do
	[ "$(cat "$temp_dir/scheduled-rotation-before-uid-$ordinal")" != "$(cat "$temp_dir/scheduled-rotation-after-uid-$ordinal")" ]
	[ "$(cat "$temp_dir/scheduled-rotation-before-container-$ordinal")" != "$(cat "$temp_dir/scheduled-rotation-after-container-$ordinal")" ]
done
printf '%s\n' 'Scheduled backup rotation Kind-node guard regression check passed'
