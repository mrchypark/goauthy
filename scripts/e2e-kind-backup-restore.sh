#!/bin/sh
# Verifies Rhiza checkpoint/archive backup and clean three-voter restore in
# disposable Kind clusters. The source and restore clusters are deliberately
# separate; only the object-store prefix is carried between them.
set -eu
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/e2e-port-lock.sh"

cluster=${KIND_CLUSTER:-${E2E_INPUT_BACKUP_RESTORE_KIND_CLUSTER:-goauthy-backup-restore-e2e}}
restore_cluster=$cluster-restore
# Kind derives the node hostname from the cluster name; validate the longer
# restore name before creating any resources (DNS label limit is 63 bytes).
restore_node_name=$restore_cluster-control-plane
[ "${#restore_node_name}" -le 63 ] || { echo 'KIND_CLUSTER is too long for the restore node hostname (maximum 41 characters)' >&2; exit 1; }
image=${GOAUTHY_IMAGE:-goauthy:e2e}
namespace=goauthy
port=${E2E_PORT:-18085}
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
umask 077
expiry_profile=${GOAUTHY_E2E_GENERATED_EXPIRY:-0}
case "$expiry_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_GENERATED_EXPIRY must be 0 or 1' >&2; exit 1;; esac
crash_profile=${GOAUTHY_E2E_ALL_VOTERS_CRASH:-0}
case "$crash_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_ALL_VOTERS_CRASH must be 0 or 1' >&2; exit 1;; esac
outage_profile=${GOAUTHY_E2E_OBJECT_STORE_OUTAGE:-0}
case "$outage_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_OBJECT_STORE_OUTAGE must be 0 or 1' >&2; exit 1;; esac
corruption_profile=${GOAUTHY_E2E_ARCHIVE_CORRUPTION:-0}
case "$corruption_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_ARCHIVE_CORRUPTION must be 0 or 1' >&2; exit 1;; esac
missing_blocks_profile=${GOAUTHY_E2E_ARCHIVE_MISSING_BLOCKS:-0}
case "$missing_blocks_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_ARCHIVE_MISSING_BLOCKS must be 0 or 1' >&2; exit 1;; esac
block_corruption_profile=${GOAUTHY_E2E_ARCHIVE_BLOCK_CORRUPTION:-0}
case "$block_corruption_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_ARCHIVE_BLOCK_CORRUPTION must be 0 or 1' >&2; exit 1;; esac
checkpoint_corruption_profile=${GOAUTHY_E2E_CHECKPOINT_CORRUPTION:-0}
case "$checkpoint_corruption_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_CHECKPOINT_CORRUPTION must be 0 or 1' >&2; exit 1;; esac
checkpoint_root_corruption_profile=${GOAUTHY_E2E_CHECKPOINT_ROOT_CORRUPTION:-0}
case "$checkpoint_root_corruption_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_CHECKPOINT_ROOT_CORRUPTION must be 0 or 1' >&2; exit 1;; esac
checkpoint_block_corruption_profile=${GOAUTHY_E2E_CHECKPOINT_BLOCK_CORRUPTION:-0}
case "$checkpoint_block_corruption_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_CHECKPOINT_BLOCK_CORRUPTION must be 0 or 1' >&2; exit 1;; esac
checkpoint_interruption_profile=${GOAUTHY_E2E_CHECKPOINT_INTERRUPTION:-0}
case "$checkpoint_interruption_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_CHECKPOINT_INTERRUPTION must be 0 or 1' >&2; exit 1;; esac
checkpoint_interruption_replace=${GOAUTHY_E2E_CHECKPOINT_INTERRUPTION_REPLACE_PODS:-0}
case "$checkpoint_interruption_replace" in 0|1) ;; *) echo 'GOAUTHY_E2E_CHECKPOINT_INTERRUPTION_REPLACE_PODS must be 0 or 1' >&2; exit 1;; esac
[ "$checkpoint_interruption_replace" = 0 ] || [ "$checkpoint_interruption_profile" = 1 ] || { echo 'pod replacement requires the checkpoint interruption profile' >&2; exit 1; }
journal_interruption_phase=${GOAUTHY_E2E_JOURNAL_INTERRUPTION_PHASE:-}
case "$journal_interruption_phase" in ''|prepared|sqlite-backed-up|graph-installed|sqlite-installed|committed) ;; *) echo 'GOAUTHY_E2E_JOURNAL_INTERRUPTION_PHASE must be empty or a supported restore phase' >&2; exit 1;; esac
journal_interruption_profile=0
[ -z "$journal_interruption_phase" ] || journal_interruption_profile=1
scheduled_backup_profile=${GOAUTHY_E2E_SCHEDULED_BACKUP:-0}
case "$scheduled_backup_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_SCHEDULED_BACKUP must be 0 or 1' >&2; exit 1;; esac
scheduled_backup_outage_profile=${GOAUTHY_E2E_SCHEDULED_BACKUP_OUTAGE:-0}
case "$scheduled_backup_outage_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_SCHEDULED_BACKUP_OUTAGE must be 0 or 1' >&2; exit 1;; esac
[ "$scheduled_backup_outage_profile" = 0 ] || [ "$scheduled_backup_profile" = 1 ] || { echo 'scheduled backup outage requires GOAUTHY_E2E_SCHEDULED_BACKUP=1' >&2; exit 1; }
scheduled_backup_quorum_profile=${GOAUTHY_E2E_SCHEDULED_BACKUP_QUORUM:-0}
case "$scheduled_backup_quorum_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_SCHEDULED_BACKUP_QUORUM must be 0 or 1' >&2; exit 1;; esac
[ "$scheduled_backup_quorum_profile" = 0 ] || [ "$scheduled_backup_profile" = 1 ] || { echo 'scheduled backup quorum requires GOAUTHY_E2E_SCHEDULED_BACKUP=1' >&2; exit 1; }
scheduled_backup_rotation_profile=${GOAUTHY_E2E_SCHEDULED_BACKUP_ROTATION:-0}
case "$scheduled_backup_rotation_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_SCHEDULED_BACKUP_ROTATION must be 0 or 1' >&2; exit 1;; esac
[ "$scheduled_backup_rotation_profile" = 0 ] || [ "$scheduled_backup_profile" = 1 ] || { echo 'scheduled backup rotation requires GOAUTHY_E2E_SCHEDULED_BACKUP=1' >&2; exit 1; }
scheduled_backup_pause_profile=${GOAUTHY_E2E_SCHEDULED_BACKUP_PAUSE_HOLDER:-0}
case "$scheduled_backup_pause_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_SCHEDULED_BACKUP_PAUSE_HOLDER must be 0 or 1' >&2; exit 1;; esac
[ "$scheduled_backup_pause_profile" = 0 ] || [ "$scheduled_backup_profile" = 1 ] || { echo 'scheduled backup paused-holder requires GOAUTHY_E2E_SCHEDULED_BACKUP=1' >&2; exit 1; }
[ $((scheduled_backup_outage_profile + scheduled_backup_quorum_profile + scheduled_backup_rotation_profile + scheduled_backup_pause_profile)) -le 1 ] || { echo 'scheduled backup outage, quorum, rotation, and paused-holder profiles are mutually exclusive' >&2; exit 1; }
backup_expire_all_profile=${GOAUTHY_E2E_BACKUP_EXPIRE_ALL:-0}
case "$backup_expire_all_profile" in 0|1) ;; *) echo 'GOAUTHY_E2E_BACKUP_EXPIRE_ALL must be 0 or 1' >&2; exit 1;; esac
[ $((expiry_profile + crash_profile + outage_profile + corruption_profile + missing_blocks_profile + block_corruption_profile + checkpoint_corruption_profile + checkpoint_root_corruption_profile + checkpoint_block_corruption_profile + checkpoint_interruption_profile + journal_interruption_profile + scheduled_backup_profile + backup_expire_all_profile)) -le 1 ] || {
	echo 'generated expiry, all-voters crash, object-store outage, archive corruption, missing-block, block-corruption, checkpoint-corruption, checkpoint-root-corruption, checkpoint-block-corruption, checkpoint-interruption, journal-interruption, scheduled-backup, and backup-expire-all profiles are mutually exclusive' >&2
	exit 1
}
expiry_ttl=${GOAUTHY_E2E_GENERATED_EXPIRY_TTL_SECONDS:-300}
case "$expiry_ttl" in ''|*[!0-9]*) echo 'GOAUTHY_E2E_GENERATED_EXPIRY_TTL_SECONDS must be decimal' >&2; exit 1;; esac
[ "$expiry_ttl" -ge 180 ] && [ "$expiry_ttl" -le 900 ] || { echo 'generated expiry TTL must be between 180 and 900 seconds' >&2; exit 1; }
generated_ttl=0
[ "$expiry_profile" = 0 ] || generated_ttl=$expiry_ttl
checkpoint_interval=1s
[ "$crash_profile" = 0 ] && [ "$corruption_profile" = 0 ] && [ "$missing_blocks_profile" = 0 ] && [ "$block_corruption_profile" = 0 ] || checkpoint_interval=1h
checkpoint_interruption_sidecar=0
checkpoint_block_path=
checkpoint_fault_image=${GOAUTHY_CHECKPOINT_FAULT_IMAGE:-goauthy-checkpoint-fault:e2e}
journal_interruption_active=0
journal_fault_image=goauthy-journal-fault:e2e
temp_dir=$(mktemp -d)
source_created=false
restore_created=false
forward_pid=
minio_forward_pid=
minio_forward_log=
catalog_container=
catalog_network=
catalog_port=
catalog_prefix=
catalog_kind_ip=
catalog_paused=false
helper_pod=backup-mc
kind_node=
kubelet_stopped=false
scheduled_source_stopped=false
scheduled_backup_cron=
scheduled_backup_due_epoch=
scheduled_backup_recovery_due_epoch=
scheduled_backup_rotated=0
scheduled_backup_holder_container=
scheduled_backup_holder_pid=
scheduled_backup_holder_stopped_at=
scheduled_backup_observer_binary=
scheduled_backup_observer_identity=
scheduled_backup_observer_env=

case "$cluster" in
	goauthy-backup-restore-e2e|goauthy-backup-restore-e2e-*) ;;
	*) echo 'KIND_CLUSTER must start with goauthy-backup-restore-e2e' >&2; exit 1 ;;
esac
valid_cluster_name() {
	name=$1
	[ -n "$name" ] && [ "${#name}" -le 63 ] || return 1
	case "$name" in
		-*|*-|*[!a-z0-9-]*) return 1 ;;
	esac
}
valid_cluster_name "$cluster" || { echo "invalid source Kind cluster name: $cluster" >&2; exit 1; }
valid_cluster_name "$restore_cluster" || { echo "invalid restore Kind cluster name: $restore_cluster" >&2; exit 1; }

cleanup_cluster() {
	cluster_name=$1
	created=$2
	[ "$created" = true ] || return 0
	kind delete cluster --name "$cluster_name" >/dev/null 2>&1 || true
}

dump_cluster() {
	cluster_name=$1
	context=kind-$cluster_name
	kubectl config get-contexts -o name | grep -qx "$context" || return 0
	kubectl --context "$context" -n "$namespace" get all 2>&1 | sed 's/^/[resources] /' || true
	# Keep termination evidence before cleanup without printing logs, env or messages.
	kubectl --context "$context" -n "$namespace" get pods -o 'custom-columns=POD:.metadata.name,CONTAINER:.status.containerStatuses[*].name,RESTARTS:.status.containerStatuses[*].restartCount,LAST_REASON:.status.containerStatuses[*].lastState.terminated.reason,LAST_EXIT:.status.containerStatuses[*].lastState.terminated.exitCode,LAST_SIGNAL:.status.containerStatuses[*].lastState.terminated.signal,CURRENT_REASON:.status.containerStatuses[*].state.terminated.reason,CURRENT_EXIT:.status.containerStatuses[*].state.terminated.exitCode' 2>&1 | sed 's/^/[termination] /' || true
	kubectl --context "$context" -n "$namespace" get events --sort-by=.metadata.creationTimestamp 2>&1 | sed 's/^/[events] /' || true
}

dump_scheduled_pause() {
	[ "$scheduled_backup_pause_profile" = 1 ] && [ -n "$kind_node" ] || return 0
	for diagnostic_ordinal in 0 1 2; do
		diagnostic_file=$temp_dir/scheduled-pause-container-$diagnostic_ordinal
		[ -f "$diagnostic_file" ] || continue
		diagnostic_id=$(cat "$diagnostic_file")
		# Only fixed scheduler diagnostics; never dump environment or raw provider errors.
		docker exec "$kind_node" timeout 5 crictl logs "$diagnostic_id" 2>&1 |
			grep -F 'scheduled backup ' | tail -10 | sed "s/^/[pause-$diagnostic_ordinal] /" || true
		diagnostic_pid=$(docker exec "$kind_node" crictl inspect "$diagnostic_id" 2>/dev/null | jq -er '.info.pid | tonumber | select(. > 1)') || continue
		docker exec "$kind_node" timeout 5 nsenter -t "$diagnostic_pid" -n ss -Huan |
			sed "s/^/[pause-udp-$diagnostic_ordinal] /" || true
	done
}

cleanup() {
	status=$?
	trap - 0 1 2 15
	[ "$status" -eq 0 ] || dump_scheduled_pause
	if [ -n "$forward_pid" ]; then
		kill "$forward_pid" >/dev/null 2>&1 || true
		wait "$forward_pid" 2>/dev/null || true
	fi
	if [ -n "$minio_forward_pid" ]; then
		kill "$minio_forward_pid" >/dev/null 2>&1 || true
		wait "$minio_forward_pid" 2>/dev/null || true
	fi
	if [ "$catalog_paused" = true ] && [ -n "$catalog_container" ]; then
		docker unpause "$catalog_container" >/dev/null 2>&1 || true
	fi
	if [ -n "$scheduled_backup_holder_container" ] && [ -n "$kind_node" ]; then
		docker exec "$kind_node" ctr -n k8s.io tasks kill --signal SIGCONT "$scheduled_backup_holder_container" >/dev/null 2>&1 || true
	fi
	if [ -n "$kind_node" ] && [ -n "$scheduled_backup_observer_binary" ]; then
		docker exec "$kind_node" rm -f "$scheduled_backup_observer_binary" "$scheduled_backup_observer_identity" "$scheduled_backup_observer_env" >/dev/null 2>&1 || true
	fi
	if [ -n "$catalog_container" ]; then
		docker rm -fv "$catalog_container" >/dev/null 2>&1 || true
	fi
	if [ -n "$catalog_network" ]; then
		docker network rm "$catalog_network" >/dev/null 2>&1 || true
	fi
	if [ "$kubelet_stopped" = true ] && [ -n "$kind_node" ] && docker inspect --format '{{.State.Running}}' "$kind_node" 2>/dev/null | grep -qx true; then
		docker exec "$kind_node" systemctl start kubelet >/dev/null 2>&1 || true
	fi
	if [ "$status" -ne 0 ]; then
		dump_cluster "$cluster"
		dump_cluster "$restore_cluster"
	fi
	cleanup_cluster "$restore_cluster" "$restore_created"
	cleanup_cluster "$cluster" "$source_created"
	rm -rf "$temp_dir"
	e2e_port_lock_release
	exit "$status"
}
trap cleanup 0 1 2 15
e2e_port_lock_acquire

for command in cp curl date docker go grep jq kind kubectl kustomize nc openssl sed awk; do
	command -v "$command" >/dev/null 2>&1 || { echo "missing required tool: $command" >&2; exit 1; }
done
	if kind get clusters | grep -Fqx -- "$cluster" || kind get clusters | grep -Fqx -- "$restore_cluster"; then
	echo "refusing to reuse backup/restore Kind cluster" >&2
	exit 1
fi

cd "$root"
./scripts/e2e-preflight.sh host-capacity
bootstrap_user_phc=$(printf '%s\n' correct-horse-browser-staple | go run ./cmd/goauthy-password)
generated_bootstrap_config=$temp_dir/generated-api-keys.json
local_master_key_dir=$temp_dir/master-keys
mkdir -p "$local_master_key_dir"
printf '%s\n' MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY >"$local_master_key_dir/dev-1"
printf '%s\n' '[{"name":"generated-reader","secret":"generate","access":[{"group":"Clients","access_rights":["read"]}]}]' >"$generated_bootstrap_config"
[ "$checkpoint_interruption_profile" = 0 ] || docker build --target checkpoint-fault --tag "$checkpoint_fault_image" .
[ "$journal_interruption_profile" = 0 ] || docker build --target journal-fault --tag "$journal_fault_image" .
docker build --tag "$image" .
go build -trimpath -o "$temp_dir/goauthy-backup" ./cmd/goauthy-backup
cat >"$temp_dir/generate-age-key.go" <<'EOF'
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"strconv"
	"time"

	"filippo.io/age"
)

func main() {
	if len(os.Args) == 6 && os.Args[1] == "fixture-reseed" {
		reseedFixture(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "catalog-key" {
		writeCatalogKey(os.Args[2], os.Args[3])
		return
	}
	if len(os.Args) != 6 || os.Args[1] != "generate" {
		panic("usage: generate identity recipient private public | catalog-key private public | fixture-reseed private entry receipt source-prefix")
	}
	identity, err := age.GenerateHybridIdentity()
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[2], []byte(identity.String()+"\n"), 0600); err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[3], []byte(identity.Recipient().String()+"\n"), 0600); err != nil {
		panic(err)
	}
	writeCatalogKey(os.Args[4], os.Args[5])
}

func writeCatalogKey(privatePath, publicPath string) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		panic(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600); err != nil {
		panic(err)
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0600); err != nil {
		panic(err)
	}
}

func reseedFixture(privatePath, entryPath, receiptPath, sourcePrefix string) {
	pemBytes, err := os.ReadFile(privatePath)
	if err != nil {
		panic(err)
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil || len(rest) != 0 {
		panic("invalid private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		panic("private key is not Ed25519")
	}
	raw, err := os.ReadFile(entryPath)
	if err != nil {
		panic(err)
	}
	var entry map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entry); err != nil || len(entry) != 7 {
		panic("invalid catalog entry")
	}
	for _, name := range []string{"version", "id", "created_at", "source_prefix", "catalog_prefix", "size", "sha256"} {
		if _, ok := entry[name]; !ok {
			panic("invalid catalog entry")
		}
	}
	entry["created_at"] = json.RawMessage(strconv.FormatInt(time.Now().UTC().AddDate(0, 0, -40).Unix(), 10))
	entry["source_prefix"], err = json.Marshal(sourcePrefix)
	if err != nil {
		panic(err)
	}
	raw, err = json.Marshal(entry)
	if err != nil {
		panic(err)
	}
	receipt, err := json.Marshal(struct {
		Entry     json.RawMessage `json:"entry"`
		Signature []byte          `json:"signature"`
	}{raw, ed25519.Sign(private, raw)})
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(receiptPath, receipt, 0600); err != nil {
		panic(err)
	}
}
EOF
age_identity_file=$temp_dir/backup.age-identity
age_recipient_file=$temp_dir/backup.age-recipient
catalog_private_key=$temp_dir/catalog-ed25519-private.pem
catalog_public_key=$temp_dir/catalog-ed25519-public.pem
go run "$temp_dir/generate-age-key.go" generate "$age_identity_file" "$age_recipient_file" "$catalog_private_key" "$catalog_public_key"
catalog_rotated_private_key=$temp_dir/catalog-ed25519-rotated-private.pem
catalog_rotated_public_key=$temp_dir/catalog-ed25519-rotated-public.pem
catalog_trust_bundle=$temp_dir/catalog-ed25519-trust.pem
if [ "$scheduled_backup_rotation_profile" = 1 ]; then
	go run "$temp_dir/generate-age-key.go" catalog-key "$catalog_rotated_private_key" "$catalog_rotated_public_key"
	cat "$catalog_public_key" "$catalog_rotated_public_key" >"$catalog_trust_bundle"
	chmod 0400 "$catalog_trust_bundle"
fi
[ "$expiry_profile" = 0 ] || go build -trimpath -o "$temp_dir/goauthy-bootstrap-secrets" ./cmd/goauthy-bootstrap-secrets

create_secret() {
	context=$1
	kubectl --context "$context" -n "$namespace" create secret generic goauthy-secrets \
		--from-literal=dev-1=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
		--from-literal=oauth-hmac=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY \
		--from-literal=bootstrap-client=correct-horse-battery-staple \
		--from-literal=dcr-registration-token=0123456789abcdef0123456789abcdef \
		--from-literal=bootstrap-user-password-phc="$bootstrap_user_phc" \
		--from-literal=rhiza-admin-token=goauthy-e2e-admin-token \
		--from-literal='rhiza-members=[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-0-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-1-token"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.goauthy.goauthy.svc.cluster.local:8444","token":"goauthy-e2e-voter-2-token"}]' \
		--from-literal=minio-root-user=goauthy-e2e \
		--from-literal=minio-root-password=goauthy-e2e-minio-password \
		--from-file=api-key-bootstrap="$generated_bootstrap_config" \
		--dry-run=client -o yaml | kubectl --context "$context" apply -f -
}

create_scheduled_backup_secret() {
	context=$1
	signing_key=$catalog_private_key
	[ "$scheduled_backup_rotation_profile" = 1 ] && [ "$scheduled_backup_rotated" = 1 ] && signing_key=$catalog_rotated_private_key
	if [ "$scheduled_backup_rotation_profile" = 1 ]; then
		kubectl --context "$context" -n "$namespace" create secret generic goauthy-backup \
			--from-file=recipient="$age_recipient_file" \
			--from-file=signing-key="$signing_key" \
			--from-file=trust-key="$catalog_trust_bundle" \
			--from-file=object-store-access-key="$catalog_access_key_file" \
			--from-file=object-store-secret-key="$catalog_secret_key_file" \
			--dry-run=client -o yaml | kubectl --context "$context" apply -f -
		return
	fi
	kubectl --context "$context" -n "$namespace" create secret generic goauthy-backup \
		--from-file=recipient="$age_recipient_file" \
		--from-file=signing-key="$signing_key" \
		--from-file=object-store-access-key="$catalog_access_key_file" \
		--from-file=object-store-secret-key="$catalog_secret_key_file" \
		--dry-run=client -o yaml | kubectl --context "$context" apply -f -
}

apply_scheduled_catalog_egress() {
	kubectl --context "$source_context" -n "$namespace" apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: scheduled-backup-catalog-egress
  namespace: goauthy
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: goauthy
      app.kubernetes.io/component: object-store-client
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock:
            cidr: ${catalog_kind_ip}/32
      ports:
        - protocol: TCP
          port: 9000
EOF
	kubectl --context "$source_context" -n "$namespace" get networkpolicy scheduled-backup-catalog-egress -o json |
		jq -e --arg cidr "$catalog_kind_ip/32" '.spec.egress == [{"to":[{"ipBlock":{"cidr":$cidr}}],"ports":[{"protocol":"TCP","port":9000}]}]' >/dev/null
}

scheduled_backup_schedule() {
	if [ "$scheduled_backup_outage_profile" = 1 ] || [ "$scheduled_backup_quorum_profile" = 1 ] || [ "$scheduled_backup_rotation_profile" = 1 ] || [ "$scheduled_backup_pause_profile" = 1 ]; then
		now_epoch=$(scheduled_backup_now) || return 1
		# Round to the next whole minute at least five minutes away.
		scheduled_backup_due_epoch=$(( (now_epoch / 60 + 6) * 60 ))
		first_minute=$(( (scheduled_backup_due_epoch / 60) % 60 ))
		slot_gap=120
		[ $((scheduled_backup_rotation_profile + scheduled_backup_pause_profile)) -eq 0 ] || slot_gap=180
		# Keep both finite slots within one UTC hour/date cron expression.
		last_first_minute=$((60 - slot_gap / 60))
		if [ "$first_minute" -ge "$last_first_minute" ]; then
			scheduled_backup_due_epoch=$(( (now_epoch / 3600 + 1) * 3600 ))
		fi
		scheduled_backup_recovery_due_epoch=$((scheduled_backup_due_epoch + slot_gap))
		if scheduled_backup_fields=$(date -u -r "$scheduled_backup_due_epoch" '+%M %H %d %m %Y' 2>/dev/null); then
			:
		else
			scheduled_backup_fields=$(date -u -d "@$scheduled_backup_due_epoch" '+%M %H %d %m %Y')
		fi
		first_minute=$(printf '%s\n' "$scheduled_backup_fields" | awk '{print $1}')
		hour=$(printf '%s\n' "$scheduled_backup_fields" | awk '{print $2}')
		day=$(printf '%s\n' "$scheduled_backup_fields" | awk '{print $3}')
		month=$(printf '%s\n' "$scheduled_backup_fields" | awk '{print $4}')
		year=$(printf '%s\n' "$scheduled_backup_fields" | awk '{print $5}')
		if second_minute=$(date -u -r "$scheduled_backup_recovery_due_epoch" '+%M' 2>/dev/null); then
			:
		else
			second_minute=$(date -u -d "@$scheduled_backup_recovery_due_epoch" '+%M')
		fi
		scheduled_backup_cron="0 $first_minute,$second_minute $hour $day $month * $year"
		return 0
	fi
	now_epoch=$(scheduled_backup_now) || return 1
	scheduled_backup_due_epoch=$((now_epoch + 300))
	if scheduled_backup_cron=$(date -u -r "$scheduled_backup_due_epoch" '+%S %M %H %d %m * %Y' 2>/dev/null); then
		:
	else
		scheduled_backup_cron=$(date -u -d "@$scheduled_backup_due_epoch" '+%S %M %H %d %m * %Y')
	fi
}

scheduled_backup_log_time() {
	epoch=$1
	if date -u -r "$epoch" '+%Y-%m-%dT%H:%M:%S.000Z' 2>/dev/null; then
		return 0
	fi
	date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%S.000Z'
}

scheduled_backup_now() {
	node_now=$(docker exec "$cluster-control-plane" date -u +%s) || return 1
	case "$node_now" in ''|*[!0-9]*) return 1;; esac
	printf '%s\n' "$node_now"
}

normalize_context() {
	context=$1
	api_server=$(kubectl config view --raw -o json | jq -er --arg context "$context" '.clusters[] | select(.name == $context) | .cluster.server')
	case "$api_server" in
		https://0.0.0.0:*) kubectl config set-cluster "$context" --server="$(printf '%s' "$api_server" | sed 's#https://0.0.0.0:#https://127.0.0.1:#')" >/dev/null ;;
	esac
}

apply_object_store() {
	context=$1
	kubectl --context "$context" apply -f deploy/k8s/namespace.yaml
	kubectl --context "$context" apply -f deploy/k8s/serviceaccount.yaml
	create_secret "$context"
	kubectl --context "$context" -n "$namespace" apply -f deploy/k8s/service.yaml -f deploy/k8s/minio.yaml -f deploy/k8s/minio-init.yaml
	kubectl --context "$context" -n "$namespace" rollout status statefulset/minio --timeout=180s
	kubectl --context "$context" -n "$namespace" wait --for=condition=complete job/minio-init --timeout=180s
}

apply_app() {
	context=$1
	wait_ready=${2:-true}
	object_store_prefix=${3:-goauthy-e2e}
	scheduled=${4:-0}
	base_manifest=$temp_dir/$context-base.yaml
	rendered_manifest=$temp_dir/$context-app.yaml
	kustomize build "$root/deploy/e2e-generated-bootstrap" >"$base_manifest"
	awk -v image="$image" -v ttl="$generated_ttl" -v expiry="$expiry_profile" -v checkpoint_interval="$checkpoint_interval" -v interruption="$checkpoint_interruption_sidecar" -v checkpoint_block_path="$checkpoint_block_path" -v checkpoint_fault_image="$checkpoint_fault_image" -v journal_interruption="$journal_interruption_active" -v journal_phase="$journal_interruption_phase" -v journal_fault_image="$journal_fault_image" -v object_store_prefix="$object_store_prefix" -v scheduled="$scheduled" -v scheduled_outage="$scheduled_backup_outage_profile" -v scheduled_quorum="$scheduled_backup_quorum_profile" -v scheduled_rotation="$scheduled_backup_rotation_profile" -v scheduled_pause="$scheduled_backup_pause_profile" -v backup_schedule="$scheduled_backup_cron" -v backup_catalog="$catalog_prefix" -v backup_endpoint="$catalog_kind_ip:9000" '
			$0 == "---" { stateful = 0; goauthy = 0; object_prefix_next = 0 }
			$0 == "kind: StatefulSet" { stateful = 1 }
			stateful && $0 == "  name: goauthy" { goauthy = 1 }
			goauthy && $0 == "      containers:" && expiry == "1" && !sidecar {
				print
				print "      - command:"
				print "        - tail"
				print "        - -f"
				print "        - /dev/null"
				print "        image: busybox:1.36.1"
				print "        imagePullPolicy: IfNotPresent"
				print "        name: bootstrap-artifact"
				print "        resources:"
				print "          limits:"
				print "            cpu: 50m"
				print "            memory: 32Mi"
				print "          requests:"
				print "            cpu: 10m"
				print "            memory: 16Mi"
				print "        securityContext:"
				print "          allowPrivilegeEscalation: false"
				print "          capabilities:"
				print "            drop:"
				print "            - ALL"
				print "          readOnlyRootFilesystem: true"
				print "          runAsGroup: 65532"
				print "          runAsNonRoot: true"
				print "          runAsUser: 65532"
				print "        volumeMounts:"
				print "        - mountPath: /var/lib/goauthy"
				print "          name: data"
				print "          readOnly: true"
				sidecar = 1
				next
			}
			goauthy && $0 == "      initContainers:" && (scheduled == "1" || interruption == "1") {
				print
				if (scheduled == "1") {
					print "      - name: backup-key-copy"
					print "        image: busybox:1.36.1"
					print "        imagePullPolicy: IfNotPresent"
					print "        command:"
					print "        - /bin/sh"
					print "        - -ec"
					print "        - |"
					print "          mkdir -p /var/lib/goauthy/backup-work /var/lib/goauthy/backup-keys"
					print "          cp /run/secrets/backup-input/recipient /var/lib/goauthy/backup-keys/recipient"
					print "          cp /run/secrets/backup-input/signing-key /var/lib/goauthy/backup-keys/signing-key"
					if (scheduled_rotation == "1") print "          cp /run/secrets/backup-input/trust-key /var/lib/goauthy/backup-keys/trust-key"
					print "          chmod 0700 /var/lib/goauthy/backup-work /var/lib/goauthy/backup-keys"
					print "          chmod 0400 /var/lib/goauthy/backup-keys/signing-key"
					if (scheduled_rotation == "1") print "          chmod 0400 /var/lib/goauthy/backup-keys/trust-key"
					print "        securityContext:"
					print "          allowPrivilegeEscalation: false"
					print "          capabilities:"
					print "            drop:"
					print "            - ALL"
					print "          readOnlyRootFilesystem: true"
					print "          runAsGroup: 65532"
					print "          runAsNonRoot: true"
					print "          runAsUser: 65532"
					print "        volumeMounts:"
					print "        - name: data"
					print "          mountPath: /var/lib/goauthy"
					print "        - name: backup-input"
					print "          mountPath: /run/secrets/backup-input"
					print "          readOnly: true"
					backup_key_copy = 1
				}
				if (interruption != "1") next
				# Native sidecar: it must bind the loopback proxy before the app starts.
				print "      - name: checkpoint-fault"
				print "        image: " checkpoint_fault_image
				print "        imagePullPolicy: Never"
				print "        restartPolicy: Always"
				print "        env:"
				print "        - name: BLOCK_PATH"
				print "          value: " checkpoint_block_path
				print "        - name: DATA_DIR"
				print "          value: /var/lib/goauthy"
				print "        - name: UPSTREAM"
				print "          value: http://minio.goauthy.svc.cluster.local:9000"
				print "        securityContext:"
				print "          allowPrivilegeEscalation: false"
				print "          capabilities:"
				print "            drop:"
				print "            - ALL"
				print "          readOnlyRootFilesystem: true"
				print "          runAsGroup: 65532"
				print "          runAsNonRoot: true"
				print "          runAsUser: 65532"
				print "        resources:"
				print "          limits:"
				print "            cpu: 100m"
				print "            memory: 64Mi"
				print "          requests:"
				print "            cpu: 20m"
				print "            memory: 32Mi"
				print "        startupProbe:"
				print "          exec:"
				print "            command:"
				print "            - /goauthy-checkpoint-fault"
				print "            - status"
				print "          periodSeconds: 1"
				print "          failureThreshold: 30"
				print "        volumeMounts:"
				print "        - name: data"
				print "          mountPath: /var/lib/goauthy"
				print "          readOnly: true"
				fault_sidecar = 1
				next
			}
			goauthy && $0 == "        - name: GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT" && interruption == "1" {
				endpoint_replacements++
				print
				getline
				if ($0 != "          value: minio.goauthy.svc.cluster.local:9000") exit 1
				print "          value: 127.0.0.1:9001"
				next
			}
			goauthy && $0 == "        - name: GOAUTHY_RHIZA_OBJECT_STORE_PREFIX" { object_prefix_next = 1; print; next }
			goauthy && object_prefix_next {
				if ($0 != "          value: goauthy-e2e") exit 1
				print "          value: " object_store_prefix
				object_prefix_replacements++
				object_prefix_next = 0
				next
			}
			goauthy && $0 == "        livenessProbe:" { liveness_probe = (scheduled_pause == "1"); print; next }
			goauthy && liveness_probe && $0 == "          periodSeconds: 10" {
				print
				print "          failureThreshold: 120"
				liveness_probe = 0
				pause_liveness_replacements++
				next
			}
			goauthy && $0 == "          failureThreshold: 30" && (interruption == "1" || journal_interruption == "1") {
				startup_budget_replacements++
				print "          failureThreshold: 150"
				next
			}
			goauthy && $0 == "        - name: GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_TTL_SECONDS" {
				ttl_replacements++
				print
				getline
				sub(/value: \"0\"/, "value: \"" ttl "\"")
				print
				next
			}
			goauthy && $0 == "        - name: GOAUTHY_SIGNING_KEY_ROTATION_PERIOD" {
				checkpoint_insertions++
				print "        - name: GOAUTHY_RHIZA_CHECKPOINT_INTERVAL"
				print "          value: " checkpoint_interval
				if (scheduled == "1") {
					print "        - name: GOAUTHY_BACKUP_ENABLED"
					print "          value: \"true\""
					print "        - name: GOAUTHY_BACKUP_SCHEDULE"
					print "          value: \"" backup_schedule "\""
					print "        - name: GOAUTHY_BACKUP_TIMEZONE"
					print "          value: UTC"
					if (scheduled_outage == "1" || scheduled_quorum == "1") {
						print "        - name: GOAUTHY_BACKUP_TIMEOUT"
						print "          value: 10s"
					}
					print "        - name: GOAUTHY_BACKUP_CATALOG_PREFIX"
					print "          value: " backup_catalog
					print "        - name: GOAUTHY_BACKUP_WORK_DIR"
					print "          value: /var/lib/goauthy/backup-work"
					print "        - name: GOAUTHY_BACKUP_RECIPIENT_FILE"
					print "          value: /var/lib/goauthy/backup-keys/recipient"
					print "        - name: GOAUTHY_BACKUP_SIGNING_KEY_FILE"
					print "          value: /var/lib/goauthy/backup-keys/signing-key"
					if (scheduled_rotation == "1") {
						print "        - name: GOAUTHY_BACKUP_TRUST_KEY_FILE"
						print "          value: /var/lib/goauthy/backup-keys/trust-key"
					}
					print "        - name: GOAUTHY_BACKUP_OBJECT_STORE_PROVIDER"
					print "          value: s3"
					print "        - name: GOAUTHY_BACKUP_OBJECT_STORE_ENDPOINT"
					print "          value: " backup_endpoint
					print "        - name: GOAUTHY_BACKUP_OBJECT_STORE_INSECURE"
					print "          value: \"true\""
					print "        - name: GOAUTHY_BACKUP_OBJECT_STORE_BUCKET"
					print "          value: goauthy-backups"
					print "        - name: GOAUTHY_BACKUP_OBJECT_STORE_REGION"
					print "          value: us-east-1"
					print "        - name: GOAUTHY_BACKUP_OBJECT_STORE_ACCESS_KEY"
					print "          valueFrom:"
					print "            secretKeyRef:"
					print "              name: goauthy-backup"
					print "              key: object-store-access-key"
					print "        - name: GOAUTHY_BACKUP_OBJECT_STORE_SECRET_KEY"
					print "          valueFrom:"
					print "            secretKeyRef:"
					print "              name: goauthy-backup"
					print "              key: object-store-secret-key"
					backup_env_insertions++
				}
				if (journal_interruption == "1") {
					journal_phase_insertions++
					print "        - name: GOAUTHY_JOURNAL_PHASE"
					print "          value: " journal_phase
				}
			}
			goauthy && $0 == "        image: goauthy:e2e" { image_replacements++; sub(/goauthy:e2e/, journal_interruption == "1" ? journal_fault_image : image) }
			goauthy && $0 == "      volumes:" && scheduled == "1" {
				print
				print "      - name: backup-input"
				print "        secret:"
				print "          defaultMode: 288"
				print "          secretName: goauthy-backup"
				backup_volume_insertions++
				next
			}
			goauthy && $0 == "        - mountPath: /run/backchannel-ca" && scheduled == "1" {
				print "        - mountPath: /run/secrets/backup-input"
				print "          name: backup-input"
				print "          readOnly: true"
				backup_mount_insertions++
			}
			{ print }
			END {
				if (image_replacements != 1 || ttl_replacements != 1 || checkpoint_insertions != 1 || object_prefix_replacements != 1 || journal_phase_insertions != (journal_interruption == "1") || sidecar != (expiry == "1") || fault_sidecar != (interruption == "1") || endpoint_replacements != (interruption == "1") || startup_budget_replacements != (interruption == "1" || journal_interruption == "1") || backup_key_copy != (scheduled == "1") || backup_env_insertions != (scheduled == "1") || backup_volume_insertions != (scheduled == "1") || backup_mount_insertions != (scheduled == "1") || pause_liveness_replacements != (scheduled_pause == "1")) exit 1
			}
		' "$base_manifest" >"$rendered_manifest" || { echo 'failed to render generated bootstrap application manifest' >&2; return 1; }
	expected_app_image=$image
	[ "$journal_interruption_active" = 0 ] || expected_app_image=$journal_fault_image
	grep -Fqx "        image: $expected_app_image" "$rendered_manifest" || { echo 'rendered GoAuthy image invariant failed' >&2; return 1; }
	grep -A1 -F '        - name: GOAUTHY_BOOTSTRAP_GENERATED_SECRETS_TTL_SECONDS' "$rendered_manifest" | grep -Fqx "          value: \"$generated_ttl\"" || {
		echo 'rendered generated bootstrap TTL invariant failed' >&2
		return 1
	}
	grep -A1 -F '        - name: GOAUTHY_RHIZA_CHECKPOINT_INTERVAL' "$rendered_manifest" | grep -Fqx "          value: $checkpoint_interval" || {
		echo 'rendered Rhiza checkpoint interval invariant failed' >&2
		return 1
	}
	grep -A1 -F '        - name: GOAUTHY_RHIZA_OBJECT_STORE_PREFIX' "$rendered_manifest" | grep -Fqx "          value: $object_store_prefix" || {
		echo 'rendered Rhiza object-store prefix invariant failed' >&2
		return 1
	}
	if [ "$scheduled" = 1 ]; then
		grep -A1 -F '        - name: GOAUTHY_BACKUP_SCHEDULE' "$rendered_manifest" | grep -Fqx "          value: \"$scheduled_backup_cron\"" &&
			grep -Fqx '      - name: backup-key-copy' "$rendered_manifest" &&
			grep -Fqx '      - name: backup-input' "$rendered_manifest" || {
			echo 'rendered scheduled backup profile invariant failed' >&2
			return 1
		}
		if [ "$scheduled_backup_pause_profile" = 1 ]; then
			awk '
				$0 == "        livenessProbe:" { in_liveness = 1; next }
				in_liveness && $0 == "        readinessProbe:" { exit 1 }
				in_liveness && $0 == "          failureThreshold: 120" { found = 1; exit 0 }
				END { exit found ? 0 : 1 }
			' "$rendered_manifest" || { echo 'rendered scheduled paused-holder liveness budget invariant failed' >&2; return 1; }
		fi
		if [ "$scheduled_backup_rotation_profile" = 1 ]; then
			grep -A1 -F '        - name: GOAUTHY_BACKUP_TRUST_KEY_FILE' "$rendered_manifest" | grep -Fqx '          value: /var/lib/goauthy/backup-keys/trust-key' &&
				grep -Fqx '          cp /run/secrets/backup-input/trust-key /var/lib/goauthy/backup-keys/trust-key' "$rendered_manifest" || {
				echo 'rendered scheduled backup rotation trust invariant failed' >&2
				return 1
			}
		fi
	fi
	if [ "$expiry_profile" = 1 ]; then
		grep -Fqx '        name: bootstrap-artifact' "$rendered_manifest" &&
			grep -Fqx '          readOnly: true' "$rendered_manifest" || {
			echo 'rendered bootstrap artifact sidecar invariant failed' >&2
			return 1
		}
	else
		! grep -Fqx '        name: bootstrap-artifact' "$rendered_manifest" || {
			echo 'non-expiry render unexpectedly included the bootstrap artifact sidecar' >&2
			return 1
		}
	fi
	if [ "$checkpoint_interruption_sidecar" = 1 ]; then
		case "$checkpoint_block_path" in
			/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/blocks/[a-f0-9][a-f0-9]*.block) ;;
			*) echo 'checkpoint interruption sidecar received an invalid block path' >&2; return 1 ;;
		esac
		if ! grep -Fqx '      - name: checkpoint-fault' "$rendered_manifest" ||
			! grep -Fqx '        restartPolicy: Always' "$rendered_manifest" ||
			! grep -Fqx '          value: 127.0.0.1:9001' "$rendered_manifest" ||
			! grep -Fqx '          failureThreshold: 150' "$rendered_manifest"; then
			echo 'rendered checkpoint interruption sidecar invariant failed' >&2
			return 1
		fi
	else
		! grep -Fqx '      - name: checkpoint-fault' "$rendered_manifest" || {
			echo 'non-interruption render unexpectedly included the checkpoint fault sidecar' >&2
			return 1
		}
	fi
	if [ "$journal_interruption_active" = 1 ]; then
		if ! grep -A1 -F '        - name: GOAUTHY_JOURNAL_PHASE' "$rendered_manifest" | grep -Fqx "          value: $journal_interruption_phase" ||
			! grep -Fqx '          failureThreshold: 150' "$rendered_manifest"; then
			echo 'rendered journal interruption wrapper invariant failed' >&2
			return 1
		fi
	else
		! grep -Fqx '        - name: GOAUTHY_JOURNAL_PHASE' "$rendered_manifest" || {
			echo 'non-journal render unexpectedly enabled journal interruption' >&2
			return 1
		}
	fi
	kubectl --context "$context" apply -f "$rendered_manifest"
	[ "$wait_ready" = true ] || return 0
	kubectl --context "$context" -n "$namespace" rollout status statefulset/goauthy --timeout=180s
	for pod in goauthy-0 goauthy-1 goauthy-2; do
		kubectl --context "$context" -n "$namespace" wait --for=condition=ready "pod/$pod" --timeout=180s
	done
}

assert_no_pvc_application() {
	context=$1
	kubectl --context "$context" -n "$namespace" get statefulset/goauthy -o json >"$temp_dir/no-pvc-statefulset.json"
	jq -e '(.spec.volumeClaimTemplates // [] | length) == 0 and
		([.spec.template.spec.volumes[] | select(.name == "data" and has("emptyDir"))] | length) == 1 and
		([.spec.template.spec.volumes[] | select(has("persistentVolumeClaim"))] | length) == 0' "$temp_dir/no-pvc-statefulset.json" >/dev/null || {
		echo 'GoAuthy DR requires emptyDir and no application PVC references' >&2
		return 1
	}
	for ordinal in 0 1 2; do
		kubectl --context "$context" -n "$namespace" get "pod/goauthy-$ordinal" -o json >"$temp_dir/no-pvc-pod.json"
		jq -e '([.spec.volumes[] | select(.name == "data" and has("emptyDir"))] | length) == 1 and
			([.spec.volumes[] | select(has("persistentVolumeClaim"))] | length) == 0' "$temp_dir/no-pvc-pod.json" >/dev/null || {
			echo 'running GoAuthy pod unexpectedly depends on a PVC' >&2
			return 1
		}
	done
}

wait_checkpoint() {
	context=$1
	for _ in $(seq 1 60); do
		if kubectl --context "$context" -n "$namespace" exec "$helper_pod" -- \
			mc stat local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/CURRENT >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	echo "checkpoint/CURRENT did not become available" >&2
	return 1
}

assert_archive_without_checkpoint() {
	context=$1
	label=$2
	listing=$temp_dir/$label-archive-listing.jsonl
	errors=$temp_dir/$label-archive-listing.err
	if ! kubectl --context "$context" -n "$namespace" exec -c backup-mc "$helper_pod" -- \
		mc ls --recursive --json local/rhiza/goauthy-e2e/goauthy-e2e >"$listing" 2>"$errors"; then
		echo 'unable to obtain a successful object-store archive listing' >&2
		return 1
	fi
	jq -eRs '
		split("\n") | map(select(length > 0)) as $lines |
		if ($lines | length) == 0 then error("empty listing") else . end |
		[$lines[] | (fromjson |
			if .status == "success" and (.key | type) == "string" then .key
			else error("unexpected mc listing record") end)] as $keys |
		any($keys[]; test("(^|/)archive/head[.]bin$")) and
		all($keys[]; (test("(^|/)checkpoint/CURRENT$") | not))
	' "$listing" >/dev/null || {
		echo 'object-store listing did not prove archive head without checkpoint CURRENT' >&2
		return 1
	}
}

assert_archive_blocks() {
	expected_blocks=$3
	assert_archive_without_checkpoint "$1" "$2"
	jq -es --argjson present "$expected_blocks" '
		if $present then any(.[]; .key | test("(^|/)archive/blocks/[^/]+[.]bin$"))
		else all(.[]; (.key | test("(^|/)archive/blocks/") | not)) end
	' "$listing" >/dev/null || {
		echo 'archive block listing did not match the required fault state' >&2
		return 1
	}
}

assert_checkpoint_with_archive_head() {
	context=$1
	label=$2
	listing=$temp_dir/$label-checkpoint-listing.jsonl
	errors=$temp_dir/$label-checkpoint-listing.err
	if ! kubectl --context "$context" -n "$namespace" exec -c backup-mc "$helper_pod" -- \
		mc ls --recursive --json local/rhiza/goauthy-e2e/goauthy-e2e >"$listing" 2>"$errors"; then
		echo 'unable to obtain a successful object-store checkpoint listing' >&2
		return 1
	fi
	jq -eRs '
		split("\n") | map(select(length > 0)) as $lines |
		if ($lines | length) == 0 then error("empty listing") else . end |
		[$lines[] | (fromjson |
			if .status == "success" and (.key | type) == "string" then .key
			else error("unexpected mc listing record") end)] as $keys |
		any($keys[]; test("(^|/)archive/head[.]bin$")) and
		any($keys[]; test("(^|/)checkpoint/CURRENT$"))
	' "$listing" >/dev/null || {
		echo 'object-store listing did not prove checkpoint CURRENT with archive head' >&2
		return 1
	}
}

capture_pod_uid() {
	context=$1
	pod=$2
	output=$3
	kubectl --context "$context" -n "$namespace" get "pod/$pod" -o jsonpath='{.metadata.uid}' >"$output"
	test -s "$output"
}

capture_container_id() {
	context=$1
	pod=$2
	container=$3
	output=$4
	pod_json=$temp_dir/$pod-$container-pod.json
	kubectl --context "$context" -n "$namespace" get "pod/$pod" -o json >"$pod_json"
	jq -er --arg container "$container" --arg node "$kind_node" '
		[.status.containerStatuses[]?, .status.initContainerStatuses[]? | select(.name == $container)] as $statuses |
		if .spec.nodeName == $node and ($statuses | length) == 1 and
			($statuses[0].state.running != null) and
			($statuses[0].containerID | test("^containerd://[0-9a-f]+$"))
		then $statuses[0].containerID | sub("^containerd://"; "")
		else error("missing running containerd ID on expected node") end
	' "$pod_json" >"$output"
	container_id=$(cat "$output")
	docker exec "$kind_node" crictl inspect -o json "$container_id" >"$temp_dir/container-$container_id-running.inspect.json"
	jq -e --arg id "$container_id" '.status.id == $id and .status.state == "CONTAINER_RUNNING"' \
		"$temp_dir/container-$container_id-running.inspect.json" >/dev/null
}

wait_container_exit_137() {
	container_id=$1
	for _ in $(seq 1 60); do
		inspect=$temp_dir/container-$container_id.inspect.json
		if docker exec "$kind_node" crictl inspect -o json "$container_id" >"$inspect" 2>/dev/null &&
			jq -e --arg id "$container_id" '.status.id == $id and .status.state == "CONTAINER_EXITED" and .status.exitCode == 137' "$inspect" >/dev/null; then
			return 0
		fi
		sleep 1
	done
	echo 'GoAuthy container did not reach exit code 137 after SIGKILL' >&2
	return 1
}

wait_pod_deleted() {
	context=$1
	pod=$2
	for _ in $(seq 1 90); do
		pod_name=$temp_dir/$pod-deletion-check
		kubectl --context "$context" -n "$namespace" get "pod/$pod" --ignore-not-found -o name >"$pod_name" || {
			echo 'cannot inspect killed GoAuthy pod deletion state' >&2
			return 1
		}
		if [ ! -s "$pod_name" ]; then
			return 0
		fi
		sleep 1
	done
	echo 'killed GoAuthy pod was not deleted' >&2
	return 1
}

assert_single_kind_node() {
	kind get nodes --name "$cluster" >"$temp_dir/kind-nodes"
	[ "$(wc -l <"$temp_dir/kind-nodes" | tr -d ' ')" -eq 1 ] || {
		echo 'all-voters crash profile requires exactly one Kind node' >&2
		return 1
	}
	kind_node=$(cat "$temp_dir/kind-nodes")
	[ "$kind_node" = "$cluster-control-plane" ] || {
		echo 'all-voters crash profile found an unexpected Kind node identity' >&2
		return 1
	}
	docker inspect --format '{{.State.Running}}' "$kind_node" | grep -qx true || {
		echo 'Kind control-plane container is not running' >&2
		return 1
	}
	docker exec "$kind_node" sh -ec 'command -v ctr >/dev/null && command -v crictl >/dev/null && command -v systemctl >/dev/null'
}

stop_goauthy_voters_sigkill() {
	context=$1
	label=$2
	assert_single_kind_node
	for ordinal in 0 1 2; do capture_container_id "$context" "goauthy-$ordinal" goauthy "$temp_dir/$label-container-$ordinal"; done
	kubectl --context "$context" -n "$namespace" delete statefulset/goauthy --cascade=orphan --wait=true
	docker exec "$kind_node" systemctl stop kubelet
	kubelet_stopped=true
	: >"$temp_dir/$label-kill-pids"
	for ordinal in 0 1 2; do
		container_id=$(cat "$temp_dir/$label-container-$ordinal")
		docker exec "$kind_node" ctr -n k8s.io tasks kill --signal SIGKILL "$container_id" >"$temp_dir/$label-kill-$ordinal.out" 2>&1 &
		printf '%s\n' "$!" >>"$temp_dir/$label-kill-pids"
	done
	while IFS= read -r kill_pid; do
		wait "$kill_pid" || { echo 'containerd rejected a SIGKILL request' >&2; return 1; }
	done <"$temp_dir/$label-kill-pids"
	for ordinal in 0 1 2; do wait_container_exit_137 "$(cat "$temp_dir/$label-container-$ordinal")"; done
	for ordinal in 0 1 2; do kubectl --context "$context" -n "$namespace" delete "pod/goauthy-$ordinal" --wait=false; done
	docker exec "$kind_node" systemctl start kubelet
	kubelet_stopped=false
	for ordinal in 0 1 2; do wait_pod_deleted "$context" "goauthy-$ordinal"; done
}

run_all_voters_crash_recovery() {
	assert_archive_without_checkpoint "$source_context" source-before-crash
	assert_single_kind_node
	for ordinal in 0 1 2; do
		capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/crash-before-uid-$ordinal"
		capture_container_id "$source_context" "goauthy-$ordinal" goauthy "$temp_dir/crash-container-$ordinal"
	done
	capture_pod_uid "$source_context" minio-0 "$temp_dir/minio-before-uid"
	capture_container_id "$source_context" minio-0 minio "$temp_dir/minio-before-container"

	stop_goauthy_voters_sigkill "$source_context" crash
	# kubelet is running again for exec, but no GoAuthy pod exists and the
	# controller remains orphaned. A checkpoint appearing during the kill fails.
	assert_archive_without_checkpoint "$source_context" source-after-kill

	apply_app "$source_context"
	assert_no_pvc_application "$source_context"
	for ordinal in 0 1 2; do
		capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/crash-after-uid-$ordinal"
		[ "$(cat "$temp_dir/crash-before-uid-$ordinal")" != "$(cat "$temp_dir/crash-after-uid-$ordinal")" ] || {
			echo 'all-voters crash recovery did not replace every GoAuthy pod' >&2
			return 1
		}
		retrieve_generated_bootstrap "$source_context" "goauthy-$ordinal" "$temp_dir/crash-generated-$ordinal.json"
		cmp "$temp_dir/source-generated-0.json" "$temp_dir/crash-generated-$ordinal.json"
		with_pod "$source_context" "goauthy-$ordinal" assert_active "$source_token"
		with_pod "$source_context" "goauthy-$ordinal" assert_generated_key "$temp_dir/generated-auth.conf" "$temp_dir/crash-generated-auth-$ordinal.json"
		assert_generated_log_redaction "$source_context" "goauthy-$ordinal" "$temp_dir/generated-token-patterns" "$temp_dir/crash-generated-log-$ordinal"
	done
	[ "$(cat "$temp_dir/minio-before-uid")" = "$(kubectl --context "$source_context" -n "$namespace" get pod/minio-0 -o jsonpath='{.metadata.uid}')" ] || {
		echo 'MinIO pod identity changed during all-voters crash recovery' >&2
		return 1
	}
	capture_container_id "$source_context" minio-0 minio "$temp_dir/minio-after-container"
	[ "$(cat "$temp_dir/minio-before-container")" = "$(cat "$temp_dir/minio-after-container")" ] || {
		echo 'MinIO container identity changed during all-voters crash recovery' >&2
		return 1
	}
	# A new OAuth access-token session is a persisted Rhiza write; introspection
	# on every voter verifies the recovered request data is served cluster-wide.
	crash_token=$temp_dir/crash-oauth-token
	with_pod "$source_context" goauthy-0 issue_token "$crash_token"
	for ordinal in 0 1 2; do with_pod "$source_context" "goauthy-$ordinal" assert_active "$crash_token"; done
	crash_kid=$(with_pod "$source_context" goauthy-0 jwks_kid)
	[ "$crash_kid" = "$source_kid" ] || { echo 'recovered JWKS kid differs from source' >&2; return 1; }
	echo 'Kind exact-three Rhiza all-voters crash object-store recovery E2E passed'
}

checkpoint_fault_status() {
	context=$1
	pod=$2
	output=$3
	kubectl --context "$context" -n "$namespace" exec "pod/$pod" -c checkpoint-fault -- /goauthy-checkpoint-fault status >"$output"
	jq -e '(.blocked | type) == "boolean" and (.partial_written | type) == "boolean" and (.cancelled | type) == "boolean" and (.released | type) == "boolean"' "$output" >/dev/null
}

wait_checkpoint_download_blocked() {
	context=$1
	for _ in $(seq 1 90); do
		matched=1
		for ordinal in 0 1 2; do
			status_file=$temp_dir/checkpoint-interruption-status-$ordinal.json
			pod_json=$temp_dir/checkpoint-interruption-pod-$ordinal.json
			checkpoint_fault_status "$context" "goauthy-$ordinal" "$status_file" >/dev/null 2>&1 || { matched=0; break; }
			jq -e '.blocked == true and .partial_written == true and .cancelled == false and .released == false' "$status_file" >/dev/null || { matched=0; break; }
			kubectl --context "$context" -n "$namespace" get "pod/goauthy-$ordinal" -o json >"$pod_json" || { matched=0; break; }
			# The fixture is useful only if this is the first main-container attempt;
			# the extended startup probe is test-only waiting room for the SIGKILL.
			jq -e '([.status.conditions[]? | select(.type == "Ready" and .status == "True")] | length) == 0 and
				([.status.containerStatuses[]? | select(.name == "goauthy" and .restartCount == 0 and .state.running != null)] | length) == 1' "$pod_json" >/dev/null || { matched=0; break; }
		done
		[ "$matched" = 1 ] && return 0
		sleep 1
	done
	echo 'checkpoint interruption fixture did not observe a first-attempt partial SQLite download on every voter' >&2
	for ordinal in 0 1 2; do
		status_file=$temp_dir/checkpoint-interruption-final-$ordinal.json
		if checkpoint_fault_status "$context" "goauthy-$ordinal" "$status_file" >/dev/null 2>&1; then
			jq -c --arg pod "goauthy-$ordinal" '{pod: $pod, blocked, partial_written, cancelled, released}' "$status_file" >&2
		fi
	done
	return 1
}

wait_checkpoint_download_cancelled() {
	context=$1
	for _ in $(seq 1 60); do
		matched=1
		for ordinal in 0 1 2; do
			status_file=$temp_dir/checkpoint-interruption-cancelled-$ordinal.json
			checkpoint_fault_status "$context" "goauthy-$ordinal" "$status_file" >/dev/null 2>&1 || { matched=0; break; }
			jq -e '.blocked == false and .cancelled == true and .released == false' "$status_file" >/dev/null || { matched=0; break; }
		done
		[ "$matched" = 1 ] && return 0
		sleep 1
	done
	echo 'checkpoint interruption fixture did not observe cancellation after SIGKILL' >&2
	return 1
}

assert_checkpoint_fault_released() {
	context=$1
	for ordinal in 0 1 2; do
		kubectl --context "$context" -n "$namespace" exec "pod/goauthy-$ordinal" -c checkpoint-fault -- /goauthy-checkpoint-fault release >/dev/null
		status_file=$temp_dir/checkpoint-interruption-released-$ordinal.json
		checkpoint_fault_status "$context" "goauthy-$ordinal" "$status_file"
		jq -e '.blocked == false and .cancelled == true and .released == true' "$status_file" >/dev/null || {
			echo 'checkpoint interruption fixture did not permanently release the blocked request' >&2
			return 1
		}
	done
}

wait_journal_interruption_proof() {
	context=$1
	for _ in $(seq 1 120); do
		matched=1
		for ordinal in 0 1 2; do
			proof=$temp_dir/journal-interruption-proof-$ordinal.json
			pod_json=$temp_dir/journal-interruption-pod-$ordinal.json
			kubectl --context "$context" -n "$namespace" exec "pod/goauthy-$ordinal" -c goauthy -- cat /var/lib/goauthy/.journal-fault/proof.json >"$proof" 2>/dev/null || { matched=0; break; }
			jq -e --arg phase "$journal_interruption_phase" '
				type == "object" and .phase == $phase and .tracee_sigkill == true and
				.before_directory_fsync == true and .layout_valid == true and
				(.pid | type) == "number" and .pid > 1 and (.pid | floor) == .pid
			' "$proof" >/dev/null || { matched=0; break; }
			kubectl --context "$context" -n "$namespace" get "pod/goauthy-$ordinal" -o json >"$pod_json" || { matched=0; break; }
			jq -e '([.status.conditions[]? | select(.type == "Ready" and .status == "True")] | length) == 0 and
				([.status.containerStatuses[]? | select(.name == "goauthy" and .restartCount == 0 and .state.running != null)] | length) == 1
			' "$pod_json" >/dev/null || { matched=0; break; }
		done
		[ "$matched" = 1 ] && return 0
		sleep 1
	done
	echo 'journal interruption wrapper did not prove the requested tracee SIGKILL before directory fsync on every voter' >&2
	return 1
}

assert_last_container_exit_137() {
	context=$1
	pod=$2
	pod_json=$temp_dir/$pod-last-termination.json
	kubectl --context "$context" -n "$namespace" get "pod/$pod" -o json >"$pod_json"
	jq -e '([.status.containerStatuses[]? | select(.name == "goauthy" and .lastState.terminated.exitCode == 137)] | length) == 1' "$pod_json" >/dev/null || {
		echo 'journal wrapper release did not leave GoAuthy container exit 137' >&2
		return 1
	}
}

copy_checkpoint_object() {
	context=$1
	remote=$2
	local=$3
	helper_name=$4
	kubectl --context "$context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp "$remote" "/tmp/backup/$helper_name"
	kubectl --context "$context" -n "$namespace" cp -c archive "$helper_pod:/tmp/backup/$helper_name" "$local"
	test -s "$local"
}

run_checkpoint_download_interruption() {
	wait_checkpoint "$source_context"
	assert_checkpoint_with_archive_head "$source_context" source-before-checkpoint-interruption
	assert_single_kind_node
	for ordinal in 0 1 2; do capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/checkpoint-interruption-source-uid-$ordinal"; done
	capture_pod_uid "$source_context" minio-0 "$temp_dir/checkpoint-interruption-minio-uid"
	capture_container_id "$source_context" minio-0 minio "$temp_dir/checkpoint-interruption-minio-container"

	# Stop every writer before pinning immutable checkpoint metadata. The helper
	# and fixture object store remain live; no GoAuthy data directory is retained.
	stop_goauthy_voters_sigkill "$source_context" checkpoint-interruption-source
	assert_checkpoint_with_archive_head "$source_context" source-stopped-checkpoint-interruption
	checkpoint_current=$temp_dir/checkpoint-interruption-current.json
	copy_checkpoint_object "$source_context" local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/CURRENT "$checkpoint_current" checkpoint-interruption-current.json
	checkpoint_index=$(jq -er 'if (.index | type) == "number" and .index > 0 and (.index | floor) == .index then .index | tostring else error("invalid checkpoint index") end' "$checkpoint_current") || return 1
	case "$checkpoint_index" in ''|*[!0-9]*) echo 'checkpoint interruption CURRENT index was not an unsigned decimal integer' >&2; return 1;; esac
	checkpoint_hash=$(jq -er 'if (.root_hash | type) == "string" and (.root_hash | test("^[a-f0-9]{64}$")) then .root_hash else error("invalid checkpoint root hash") end' "$checkpoint_current") || return 1
	checkpoint_root_name=$(printf '%020d_%s.json' "$checkpoint_index" "$checkpoint_hash")
	checkpoint_root_remote=local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/roots/$checkpoint_root_name
	checkpoint_root=$temp_dir/checkpoint-interruption-root.json
	copy_checkpoint_object "$source_context" "$checkpoint_root_remote" "$checkpoint_root" checkpoint-interruption-root.json
	checkpoint_block=$(jq -er '
		[.files[] | select(.role == "sqlite" and (.blocks | type) == "array" and (.blocks | length) > 0) | .blocks[0]] |
		if length == 1 and (.[0].hash | type) == "string" and (.[0].hash | test("^[a-f0-9]{64}$")) and
			((.[0].generation // 0) | type) == "number" and ((.[0].generation // 0) >= 0) and ((.[0].generation // 0) | floor) == (.[0].generation // 0) and
			(.[0].size | type) == "number" and (.[0].size > 32768) and (.[0].size | floor) == .[0].size
		then .[0] | "\(.hash) \(.generation // 0) \(.size)" else error("invalid SQLite checkpoint block") end
	' "$checkpoint_root") || return 1
	read -r checkpoint_block_hash checkpoint_block_generation checkpoint_block_size <<EOF
$checkpoint_block
EOF
	case "$checkpoint_block_hash" in *[!a-f0-9]*|'') echo 'checkpoint interruption selected invalid SQLite block hash' >&2; return 1;; esac
	case "$checkpoint_block_generation" in ''|*[!0-9]*) echo 'checkpoint interruption selected invalid SQLite block generation' >&2; return 1;; esac
	case "$checkpoint_block_size" in ''|*[!0-9]*) echo 'checkpoint interruption selected invalid SQLite block size' >&2; return 1;; esac
	[ "$checkpoint_block_size" -gt 64 ] || { echo 'checkpoint interruption selected a SQLite block too small for a partial read' >&2; return 1; }
	if [ "$checkpoint_block_generation" -eq 0 ]; then
		checkpoint_block_name=$checkpoint_block_hash.block
	else
		checkpoint_block_name=$(printf '%s_%020d.block' "$checkpoint_block_hash" "$checkpoint_block_generation")
	fi
	case "$checkpoint_block_name" in [a-f0-9][a-f0-9]*.block) ;; *) echo 'checkpoint interruption selected unsafe SQLite block name' >&2; return 1;; esac
	checkpoint_block_path=/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/blocks/$checkpoint_block_name
	checkpoint_block_remote=local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/blocks/$checkpoint_block_name
	checkpoint_block_original=$temp_dir/checkpoint-interruption-block.bin
	copy_checkpoint_object "$source_context" "$checkpoint_block_remote" "$checkpoint_block_original" checkpoint-interruption-block.bin
	archive_head_original=$temp_dir/checkpoint-interruption-head.bin
	copy_checkpoint_object "$source_context" local/rhiza/goauthy-e2e/goauthy-e2e/archive/head.bin "$archive_head_original" checkpoint-interruption-head.bin

	# This profile routes only recovery S3 traffic through the local proxy. Its
	# larger startup budget prevents Kubernetes probes from ending the observed
	# first request before the deliberate container SIGKILL below.
	checkpoint_interruption_sidecar=1
	apply_app "$source_context" false
	assert_no_pvc_application "$source_context"
	wait_checkpoint_download_blocked "$source_context"
	for ordinal in 0 1 2; do
		capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/checkpoint-interruption-fresh-uid-$ordinal"
		[ "$(cat "$temp_dir/checkpoint-interruption-source-uid-$ordinal")" != "$(cat "$temp_dir/checkpoint-interruption-fresh-uid-$ordinal")" ] || { echo 'checkpoint interruption did not create fresh no-PVC pods' >&2; return 1; }
		capture_container_id "$source_context" "goauthy-$ordinal" goauthy "$temp_dir/checkpoint-interruption-main-before-$ordinal"
		capture_container_id "$source_context" "goauthy-$ordinal" checkpoint-fault "$temp_dir/checkpoint-interruption-sidecar-before-$ordinal"
	done
	# No GoAuthy process may have reached Ready while objects remained pinned.
	copy_checkpoint_object "$source_context" local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/CURRENT "$temp_dir/checkpoint-interruption-current-observed.json" checkpoint-interruption-current-observed.json
	copy_checkpoint_object "$source_context" "$checkpoint_root_remote" "$temp_dir/checkpoint-interruption-root-observed.json" checkpoint-interruption-root-observed.json
	copy_checkpoint_object "$source_context" "$checkpoint_block_remote" "$temp_dir/checkpoint-interruption-block-observed.bin" checkpoint-interruption-block-observed.bin
	copy_checkpoint_object "$source_context" local/rhiza/goauthy-e2e/goauthy-e2e/archive/head.bin "$temp_dir/checkpoint-interruption-head-observed.bin" checkpoint-interruption-head-observed.bin
	cmp "$checkpoint_current" "$temp_dir/checkpoint-interruption-current-observed.json"
	cmp "$checkpoint_root" "$temp_dir/checkpoint-interruption-root-observed.json"
	cmp "$checkpoint_block_original" "$temp_dir/checkpoint-interruption-block-observed.bin"
	cmp "$archive_head_original" "$temp_dir/checkpoint-interruption-head-observed.bin"

	# Remove the controller before stopping kubelet in the emptyDir-loss mode.
	# This prevents any replacement from starting before all partial pods are gone.
	if [ "$checkpoint_interruption_replace" = 1 ]; then
		kubectl --context "$source_context" -n "$namespace" delete statefulset/goauthy --cascade=orphan --wait=true
	fi
	docker exec "$kind_node" systemctl stop kubelet
	kubelet_stopped=true
	: >"$temp_dir/checkpoint-interruption-kill-pids"
	for ordinal in 0 1 2; do
		container_id=$(cat "$temp_dir/checkpoint-interruption-main-before-$ordinal")
		docker exec "$kind_node" ctr -n k8s.io tasks kill --signal SIGKILL "$container_id" >"$temp_dir/checkpoint-interruption-kill-$ordinal.out" 2>&1 &
		printf '%s\n' "$!" >>"$temp_dir/checkpoint-interruption-kill-pids"
	done
	while IFS= read -r kill_pid; do wait "$kill_pid" || { echo 'containerd rejected checkpoint interruption SIGKILL' >&2; return 1; }; done <"$temp_dir/checkpoint-interruption-kill-pids"
	for ordinal in 0 1 2; do wait_container_exit_137 "$(cat "$temp_dir/checkpoint-interruption-main-before-$ordinal")"; done
	if [ "$checkpoint_interruption_replace" = 1 ]; then
		for ordinal in 0 1 2; do kubectl --context "$source_context" -n "$namespace" delete "pod/goauthy-$ordinal" --wait=false; done
	fi
	docker exec "$kind_node" systemctl start kubelet
	kubelet_stopped=false
	if [ "$checkpoint_interruption_replace" = 1 ]; then
		for ordinal in 0 1 2; do wait_pod_deleted "$source_context" "goauthy-$ordinal"; done
		# Re-read original object bytes with no GoAuthy writers or partial pods.
		copy_checkpoint_object "$source_context" local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/CURRENT "$temp_dir/interruption-deleted-current" interruption-deleted-current
		copy_checkpoint_object "$source_context" "$checkpoint_root_remote" "$temp_dir/interruption-deleted-root" interruption-deleted-root
		copy_checkpoint_object "$source_context" "$checkpoint_block_remote" "$temp_dir/interruption-deleted-block" interruption-deleted-block
		copy_checkpoint_object "$source_context" local/rhiza/goauthy-e2e/goauthy-e2e/archive/head.bin "$temp_dir/interruption-deleted-head" interruption-deleted-head
		cmp "$checkpoint_current" "$temp_dir/interruption-deleted-current"
		cmp "$checkpoint_root" "$temp_dir/interruption-deleted-root"
		cmp "$checkpoint_block_original" "$temp_dir/interruption-deleted-block"
		cmp "$archive_head_original" "$temp_dir/interruption-deleted-head"
		checkpoint_interruption_sidecar=0
		apply_app "$source_context" false
	else
		wait_checkpoint_download_cancelled "$source_context"
		assert_checkpoint_fault_released "$source_context"
	fi
	kubectl --context "$source_context" -n "$namespace" rollout status statefulset/goauthy --timeout=300s
	for ordinal in 0 1 2; do kubectl --context "$source_context" -n "$namespace" wait --for=condition=ready "pod/goauthy-$ordinal" --timeout=300s; done
	assert_no_pvc_application "$source_context"
	for ordinal in 0 1 2; do
		capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/checkpoint-interruption-ready-uid-$ordinal"
		if [ "$checkpoint_interruption_replace" = 1 ]; then
			[ "$(cat "$temp_dir/checkpoint-interruption-fresh-uid-$ordinal")" != "$(cat "$temp_dir/checkpoint-interruption-ready-uid-$ordinal")" ] || { echo 'interrupted partial-data pod was not replaced' >&2; return 1; }
		else
			cmp "$temp_dir/checkpoint-interruption-fresh-uid-$ordinal" "$temp_dir/checkpoint-interruption-ready-uid-$ordinal"
			capture_container_id "$source_context" "goauthy-$ordinal" checkpoint-fault "$temp_dir/checkpoint-interruption-sidecar-after-$ordinal"
			cmp "$temp_dir/checkpoint-interruption-sidecar-before-$ordinal" "$temp_dir/checkpoint-interruption-sidecar-after-$ordinal"
		fi
		capture_container_id "$source_context" "goauthy-$ordinal" goauthy "$temp_dir/checkpoint-interruption-main-after-$ordinal"
		[ "$(cat "$temp_dir/checkpoint-interruption-main-before-$ordinal")" != "$(cat "$temp_dir/checkpoint-interruption-main-after-$ordinal")" ] || { echo 'checkpoint interruption did not replace the killed main container' >&2; return 1; }
		with_pod "$source_context" "goauthy-$ordinal" assert_active "$source_token"
		retrieve_generated_bootstrap "$source_context" "goauthy-$ordinal" "$temp_dir/checkpoint-interruption-generated-$ordinal.json"
		cmp "$temp_dir/source-generated-0.json" "$temp_dir/checkpoint-interruption-generated-$ordinal.json"
		with_pod "$source_context" "goauthy-$ordinal" assert_generated_key "$temp_dir/generated-auth.conf" "$temp_dir/checkpoint-interruption-generated-auth-$ordinal.json"
		assert_generated_log_redaction "$source_context" "goauthy-$ordinal" "$temp_dir/generated-token-patterns" "$temp_dir/checkpoint-interruption-log-$ordinal"
	done
	checkpoint_interruption_kid=$(with_pod "$source_context" goauthy-0 jwks_kid)
	[ "$checkpoint_interruption_kid" = "$source_kid" ] || { echo 'checkpoint interruption recovery changed JWKS kid' >&2; return 1; }
	for issuer in 0 1 2; do
		checkpoint_interruption_token=$temp_dir/checkpoint-interruption-oauth-token-$issuer
		with_pod "$source_context" "goauthy-$issuer" issue_token "$checkpoint_interruption_token"
		for verifier in 0 1 2; do with_pod "$source_context" "goauthy-$verifier" assert_active "$checkpoint_interruption_token"; done
	done
	[ "$(cat "$temp_dir/checkpoint-interruption-minio-uid")" = "$(kubectl --context "$source_context" -n "$namespace" get pod/minio-0 -o jsonpath='{.metadata.uid}')" ] || { echo 'checkpoint interruption changed MinIO pod identity' >&2; return 1; }
	capture_container_id "$source_context" minio-0 minio "$temp_dir/checkpoint-interruption-minio-after-container"
	cmp "$temp_dir/checkpoint-interruption-minio-container" "$temp_dir/checkpoint-interruption-minio-after-container"
	if [ "$checkpoint_interruption_replace" = 1 ]; then
		echo 'Kind exact-three Rhiza interrupted checkpoint download fresh-pod E2E passed'
	else
		echo 'Kind exact-three Rhiza interrupted checkpoint download E2E passed'
	fi
}

run_journal_interruption() {
	wait_checkpoint "$source_context"
	assert_checkpoint_with_archive_head "$source_context" source-before-journal-interruption
	assert_single_kind_node
	capture_pod_uid "$source_context" minio-0 "$temp_dir/journal-interruption-minio-uid"
	capture_container_id "$source_context" minio-0 minio "$temp_dir/journal-interruption-minio-container"
	for ordinal in 0 1 2; do capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/journal-interruption-source-uid-$ordinal"; done
	stop_goauthy_voters_sigkill "$source_context" journal-interruption-source
	assert_checkpoint_with_archive_head "$source_context" source-stopped-journal-interruption

	journal_current=$temp_dir/journal-interruption-current.json
	copy_checkpoint_object "$source_context" local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/CURRENT "$journal_current" journal-interruption-current.json
	journal_index=$(jq -er 'if (.index | type) == "number" and .index > 0 and (.index | floor) == .index then .index | tostring else error("invalid checkpoint index") end' "$journal_current") || return 1
	case "$journal_index" in ''|*[!0-9]*) echo 'journal interruption CURRENT index was not an unsigned decimal integer' >&2; return 1;; esac
	journal_hash=$(jq -er 'if (.root_hash | type) == "string" and (.root_hash | test("^[a-f0-9]{64}$")) then .root_hash else error("invalid checkpoint root hash") end' "$journal_current") || return 1
	journal_root_name=$(printf '%020d_%s.json' "$journal_index" "$journal_hash")
	journal_root_remote=local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/roots/$journal_root_name
	journal_root=$temp_dir/journal-interruption-root.json
	copy_checkpoint_object "$source_context" "$journal_root_remote" "$journal_root" journal-interruption-root.json
	journal_block=$(jq -er '
		[.files[] | select(.role == "sqlite" and (.blocks | type) == "array" and (.blocks | length) > 0) | .blocks[0]] |
		if length == 1 and (.[0].hash | type) == "string" and (.[0].hash | test("^[a-f0-9]{64}$")) and
			((.[0].generation // 0) | type) == "number" and ((.[0].generation // 0) >= 0) and ((.[0].generation // 0) | floor) == (.[0].generation // 0)
		then .[0] | "\(.hash) \(.generation // 0)" else error("invalid SQLite checkpoint block") end
	' "$journal_root") || return 1
	read -r journal_block_hash journal_block_generation <<EOF
$journal_block
EOF
	case "$journal_block_hash" in *[!a-f0-9]*|'') echo 'journal interruption selected invalid SQLite block hash' >&2; return 1;; esac
	case "$journal_block_generation" in ''|*[!0-9]*) echo 'journal interruption selected invalid SQLite block generation' >&2; return 1;; esac
	if [ "$journal_block_generation" -eq 0 ]; then journal_block_name=$journal_block_hash.block; else journal_block_name=$(printf '%s_%020d.block' "$journal_block_hash" "$journal_block_generation"); fi
	case "$journal_block_name" in [a-f0-9][a-f0-9]*.block) ;; *) echo 'journal interruption selected unsafe SQLite block name' >&2; return 1;; esac
	journal_block_remote=local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/blocks/$journal_block_name
	journal_block_original=$temp_dir/journal-interruption-block.bin
	copy_checkpoint_object "$source_context" "$journal_block_remote" "$journal_block_original" journal-interruption-block.bin
	journal_head_original=$temp_dir/journal-interruption-head.bin
	copy_checkpoint_object "$source_context" local/rhiza/goauthy-e2e/goauthy-e2e/archive/head.bin "$journal_head_original" journal-interruption-head.bin

	journal_interruption_active=1
	apply_app "$source_context" false
	assert_no_pvc_application "$source_context"
	wait_journal_interruption_proof "$source_context"
	for ordinal in 0 1 2; do
		capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/journal-interruption-uid-before-$ordinal"
		journal_source_uid=$(cat "$temp_dir/journal-interruption-source-uid-$ordinal") || return 1
		journal_fresh_uid=$(cat "$temp_dir/journal-interruption-uid-before-$ordinal") || return 1
		[ -n "$journal_source_uid" ] && [ -n "$journal_fresh_uid" ] && [ "$journal_source_uid" != "$journal_fresh_uid" ] || { echo 'journal interruption did not create fresh no-PVC pods' >&2; return 1; }
		capture_container_id "$source_context" "goauthy-$ordinal" goauthy "$temp_dir/journal-interruption-main-before-$ordinal"
	done
	copy_checkpoint_object "$source_context" local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/CURRENT "$temp_dir/journal-interruption-current-observed.json" journal-interruption-current-observed.json
	copy_checkpoint_object "$source_context" "$journal_root_remote" "$temp_dir/journal-interruption-root-observed.json" journal-interruption-root-observed.json
	copy_checkpoint_object "$source_context" "$journal_block_remote" "$temp_dir/journal-interruption-block-observed.bin" journal-interruption-block-observed.bin
	copy_checkpoint_object "$source_context" local/rhiza/goauthy-e2e/goauthy-e2e/archive/head.bin "$temp_dir/journal-interruption-head-observed.bin" journal-interruption-head-observed.bin
	cmp "$journal_current" "$temp_dir/journal-interruption-current-observed.json"
	cmp "$journal_root" "$temp_dir/journal-interruption-root-observed.json"
	cmp "$journal_block_original" "$temp_dir/journal-interruption-block-observed.bin"
	cmp "$journal_head_original" "$temp_dir/journal-interruption-head-observed.bin"

	for ordinal in 0 1 2; do kubectl --context "$source_context" -n "$namespace" exec "pod/goauthy-$ordinal" -c goauthy -- touch /var/lib/goauthy/.journal-fault/release; done
	for ordinal in 0 1 2; do wait_container_exit_137 "$(cat "$temp_dir/journal-interruption-main-before-$ordinal")"; done
	kubectl --context "$source_context" -n "$namespace" rollout status statefulset/goauthy --timeout=300s
	for ordinal in 0 1 2; do kubectl --context "$source_context" -n "$namespace" wait --for=condition=ready "pod/goauthy-$ordinal" --timeout=300s; done
	assert_no_pvc_application "$source_context"
	for ordinal in 0 1 2; do
		capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/journal-interruption-uid-after-$ordinal"
		cmp "$temp_dir/journal-interruption-uid-before-$ordinal" "$temp_dir/journal-interruption-uid-after-$ordinal"
		capture_container_id "$source_context" "goauthy-$ordinal" goauthy "$temp_dir/journal-interruption-main-after-$ordinal"
		[ "$(cat "$temp_dir/journal-interruption-main-before-$ordinal")" != "$(cat "$temp_dir/journal-interruption-main-after-$ordinal")" ] || { echo 'journal interruption did not replace the released wrapper container' >&2; return 1; }
		assert_last_container_exit_137 "$source_context" "goauthy-$ordinal"
		with_pod "$source_context" "goauthy-$ordinal" assert_active "$source_token"
		retrieve_generated_bootstrap "$source_context" "goauthy-$ordinal" "$temp_dir/journal-interruption-generated-$ordinal.json"
		cmp "$temp_dir/source-generated-0.json" "$temp_dir/journal-interruption-generated-$ordinal.json"
		with_pod "$source_context" "goauthy-$ordinal" assert_generated_key "$temp_dir/generated-auth.conf" "$temp_dir/journal-interruption-generated-auth-$ordinal.json"
		assert_generated_log_redaction "$source_context" "goauthy-$ordinal" "$temp_dir/generated-token-patterns" "$temp_dir/journal-interruption-log-$ordinal"
	done
	journal_kid=$(with_pod "$source_context" goauthy-0 jwks_kid)
	[ "$journal_kid" = "$source_kid" ] || { echo 'journal interruption recovery changed JWKS kid' >&2; return 1; }
	for issuer in 0 1 2; do
		journal_token=$temp_dir/journal-interruption-oauth-token-$issuer
		with_pod "$source_context" "goauthy-$issuer" issue_token "$journal_token"
		for verifier in 0 1 2; do with_pod "$source_context" "goauthy-$verifier" assert_active "$journal_token"; done
	done
	[ "$(cat "$temp_dir/journal-interruption-minio-uid")" = "$(kubectl --context "$source_context" -n "$namespace" get pod/minio-0 -o jsonpath='{.metadata.uid}')" ] || { echo 'journal interruption changed MinIO pod identity' >&2; return 1; }
	capture_container_id "$source_context" minio-0 minio "$temp_dir/journal-interruption-minio-after-container"
	cmp "$temp_dir/journal-interruption-minio-container" "$temp_dir/journal-interruption-minio-after-container"
	echo "Kind exact-three Rhiza journal interruption phase $journal_interruption_phase E2E passed"
}

wait_archive_decode_failure() {
	context=$1
	for _ in $(seq 1 90); do
		matched=0
		for ordinal in 0 1 2; do
			pod_json=$temp_dir/corrupt-pod-$ordinal.json
			pod_log=$temp_dir/corrupt-pod-$ordinal.log
			kubectl --context "$context" -n "$namespace" get "pod/goauthy-$ordinal" -o json >"$pod_json" || { matched=0; break; }
			jq -e '([.status.conditions[]? | select(.type == "Ready" and .status == "True")] | length) == 0 and ([.status.containerStatuses[]? | select(.name == "goauthy" and ((.restartCount > 0) or .state.terminated != null or .lastState.terminated != null))] | length) == 1' "$pod_json" >/dev/null || { matched=0; break; }
			kubectl --context "$context" -n "$namespace" logs "pod/goauthy-$ordinal" -c goauthy --previous >"$pod_log" 2>/dev/null || kubectl --context "$context" -n "$namespace" logs "pod/goauthy-$ordinal" -c goauthy >"$pod_log"
			if [ "$missing_blocks_profile" = 1 ]; then
				grep -F 'load shared decision archive: The specified key does not exist.' "$pod_log" >/dev/null || { matched=0; break; }
			elif [ "$checkpoint_root_corruption_profile" = 1 ]; then
				grep -F 'load checkpoint manifest: checkpoint root integrity mismatch' "$pod_log" >/dev/null || { matched=0; break; }
			elif [ "$checkpoint_block_corruption_profile" = 1 ]; then
				grep -F 'restore checkpoint recovery base: checkpoint block integrity mismatch' "$pod_log" >/dev/null || { matched=0; break; }
			elif [ "$checkpoint_corruption_profile" = 1 ]; then
				grep -F 'load checkpoint manifest: invalid CURRENT:' "$pod_log" >/dev/null || { matched=0; break; }
			elif [ "$block_corruption_profile" = 1 ]; then
				grep -F 'load shared decision archive: archive extent integrity mismatch' "$pod_log" >/dev/null || { matched=0; break; }
			else
				grep -F 'load shared decision archive: invalid archive head header' "$pod_log" >/dev/null || { matched=0; break; }
			fi
			matched=$((matched + 1))
		done
		[ "$matched" -eq 3 ] && return 0
		sleep 1
	done
	echo 'corrupted archive did not cause every GoAuthy pod to fail archive decode startup' >&2
	return 1
}

run_archive_corruption() {
	missing_blocks=${1:-0}
	corrupt_blocks=${2:-0}
	corrupt_checkpoint=${3:-0}
	corrupt_checkpoint_root=${4:-0}
	corrupt_checkpoint_blocks=${5:-0}
	checkpoint_fault=0
	if [ "$corrupt_checkpoint" = 1 ] || [ "$corrupt_checkpoint_root" = 1 ] || [ "$corrupt_checkpoint_blocks" = 1 ]; then
		checkpoint_fault=1
	fi
	if [ "$checkpoint_fault" = 1 ]; then
		wait_checkpoint "$source_context"
		assert_checkpoint_with_archive_head "$source_context" source-before-checkpoint-corruption
	else
		assert_archive_without_checkpoint "$source_context" source-before-corruption
	fi
	for ordinal in 0 1 2; do capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/corrupt-source-uid-$ordinal"; done
	capture_pod_uid "$source_context" minio-0 "$temp_dir/corrupt-minio-uid"
	assert_single_kind_node
	capture_container_id "$source_context" minio-0 minio "$temp_dir/corrupt-minio-container"
	stop_goauthy_voters_sigkill "$source_context" corrupt
	if [ "$checkpoint_fault" = 1 ]; then
		assert_checkpoint_with_archive_head "$source_context" source-stopped-checkpoint-corruption
	else
		assert_archive_without_checkpoint "$source_context" source-stopped-corruption
	fi
	head_original=$temp_dir/archive-head-original.bin
	kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp local/rhiza/goauthy-e2e/goauthy-e2e/archive/head.bin /tmp/backup/archive-head-original.bin
	kubectl --context "$source_context" -n "$namespace" cp -c archive "$helper_pod:/tmp/backup/archive-head-original.bin" "$head_original"
	test -s "$head_original"
	if [ "$checkpoint_fault" = 1 ]; then
		checkpoint_original=$temp_dir/checkpoint-current-original.json
		kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/CURRENT /tmp/backup/checkpoint-current-original.json
		kubectl --context "$source_context" -n "$namespace" cp -c archive "$helper_pod:/tmp/backup/checkpoint-current-original.json" "$checkpoint_original"
		test -s "$checkpoint_original"
		jq -e '(.index | type) == "number" and .index > 0 and (.root_hash | type) == "string" and (.root_hash | test("^[a-f0-9]{64}$"))' "$checkpoint_original" >/dev/null || {
			echo 'checkpoint CURRENT did not contain a positive index and 64-hex root hash' >&2
			return 1
		}
		if [ "$corrupt_checkpoint_root" = 1 ] || [ "$corrupt_checkpoint_blocks" = 1 ]; then
			checkpoint_index=$(jq -er '.index as $index | if ($index | type) == "number" and $index > 0 and ($index | floor) == $index then $index | tostring else error("invalid checkpoint index") end' "$checkpoint_original") || return 1
			case "$checkpoint_index" in ''|*[!0-9]*) echo 'checkpoint CURRENT index was not an unsigned decimal integer' >&2; return 1;; esac
			checkpoint_hash=$(jq -er 'if (.root_hash | type) == "string" and (.root_hash | test("^[a-f0-9]{64}$")) then .root_hash else error("invalid checkpoint root hash") end' "$checkpoint_original") || return 1
			checkpoint_root_name=$(printf '%020d_%s.json' "$checkpoint_index" "$checkpoint_hash")
			checkpoint_root_path=local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/roots/$checkpoint_root_name
			checkpoint_root_original=$temp_dir/checkpoint-root-original.json
			kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp "$checkpoint_root_path" /tmp/backup/checkpoint-root-original.json
			kubectl --context "$source_context" -n "$namespace" cp -c archive "$helper_pod:/tmp/backup/checkpoint-root-original.json" "$checkpoint_root_original"
			test -s "$checkpoint_root_original"
			if [ "$corrupt_checkpoint_root" = 1 ]; then
				corrupt_checkpoint_root_file=$temp_dir/checkpoint-root-corrupt.json
				printf '%s' '{"corrupt":true}' >"$corrupt_checkpoint_root_file"
				kubectl --context "$source_context" -n "$namespace" cp -c archive "$corrupt_checkpoint_root_file" "$helper_pod:/tmp/backup/checkpoint-root-corrupt.json"
				kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp /tmp/backup/checkpoint-root-corrupt.json "$checkpoint_root_path"
			else
				jq -er '
					select(.key | test("(^|/)checkpoint/blocks/")) |
					.key as $key |
					if (.size | type) == "number" and .size > 0 and ($key | test("(^|/)checkpoint/blocks/[a-f0-9]{64}([.]block|_[0-9]{20}[.]block)$")) then
						$key | split("/") | last
					else error("unexpected checkpoint block key")
					end
				' "$listing" >"$temp_dir/corrupt-checkpoint-block-keys"
				test -s "$temp_dir/corrupt-checkpoint-block-keys"
				kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc mirror local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/blocks/ /tmp/backup/checkpoint-blocks/
				while IFS= read -r checkpoint_block_key; do
					# shellcheck disable=SC2016 # evaluated in the helper's shell
					kubectl --context "$source_context" -n "$namespace" exec -c archive "$helper_pod" -- sh -ec '
						original=/tmp/backup/checkpoint-blocks/$1
						corrupt=/tmp/backup/checkpoint-blocks-corrupt/$1
						mkdir -p /tmp/backup/checkpoint-blocks-corrupt
						cp "$original" "$corrupt"
						original_size=$(wc -c <"$original")
						[ "$original_size" -gt 0 ]
						first=$(od -An -tu1 -N1 "$corrupt" | tr -d "[:space:]")
						case "$first" in ""|*[!0-9]*) exit 1;; esac
						flipped=$((first ^ 1))
						octal=$(printf "%03o" "$flipped")
						printf "\\$octal" | dd of="$corrupt" bs=1 count=1 conv=notrunc >/dev/null 2>&1
						[ "$original_size" -eq "$(wc -c <"$corrupt")" ]
						if cmp -s "$original" "$corrupt"; then exit 1; else [ "$?" -eq 1 ]; fi
					' sh "$checkpoint_block_key"
					kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp "/tmp/backup/checkpoint-blocks-corrupt/$checkpoint_block_key" "local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/blocks/$checkpoint_block_key"
				done <"$temp_dir/corrupt-checkpoint-block-keys"
			fi
		else
			corrupt_checkpoint_current=$temp_dir/checkpoint-current-corrupt.json
			printf '%s' '{"index":1,"root_hash":"broken"}' >"$corrupt_checkpoint_current"
			kubectl --context "$source_context" -n "$namespace" cp -c archive "$corrupt_checkpoint_current" "$helper_pod:/tmp/backup/checkpoint-current-corrupt.json"
			kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp /tmp/backup/checkpoint-current-corrupt.json local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/CURRENT
		fi
	elif [ "$missing_blocks" = 1 ]; then
		assert_archive_blocks "$source_context" blocks-before-removal true
		kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc mirror local/rhiza/goauthy-e2e/goauthy-e2e/archive/blocks/ /tmp/backup/blocks/
		kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc rm --recursive --force local/rhiza/goauthy-e2e/goauthy-e2e/archive/blocks/
		assert_archive_blocks "$source_context" blocks-after-removal false
	elif [ "$corrupt_blocks" = 1 ]; then
		assert_archive_blocks "$source_context" blocks-before-corruption true
		kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc mirror local/rhiza/goauthy-e2e/goauthy-e2e/archive/blocks/ /tmp/backup/blocks/
		jq -er '
			select(.key | test("(^|/)archive/blocks/")) |
			.key as $key |
			if $key | test("(^|/)archive/blocks/[a-f0-9]{64}_[0-9]{20}[.]bin$") then
				$key | split("/") | last
			else error("unexpected archive block key")
			end
		' "$listing" >"$temp_dir/corrupt-block-keys"
		test -s "$temp_dir/corrupt-block-keys"
		corrupt_block=$temp_dir/archive-block-corrupt.bin
		printf '%s\n' goauthy-e2e-archive-extent-corruption >"$corrupt_block"
		kubectl --context "$source_context" -n "$namespace" cp -c archive "$corrupt_block" "$helper_pod:/tmp/backup/archive-block-corrupt.bin"
		while IFS= read -r block_key; do
			kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp /tmp/backup/archive-block-corrupt.bin "local/rhiza/goauthy-e2e/goauthy-e2e/archive/blocks/$block_key"
		done <"$temp_dir/corrupt-block-keys"
		assert_archive_blocks "$source_context" blocks-after-corruption true
	else
		corrupt_head=$temp_dir/archive-head-corrupt.bin
		printf '%s' corrupt-head >"$corrupt_head"
		kubectl --context "$source_context" -n "$namespace" cp -c archive "$corrupt_head" "$helper_pod:/tmp/backup/archive-head-corrupt.bin"
		kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp /tmp/backup/archive-head-corrupt.bin local/rhiza/goauthy-e2e/goauthy-e2e/archive/head.bin
	fi
	apply_app "$source_context" false
	wait_archive_decode_failure "$source_context"
	assert_no_pvc_application "$source_context"
	for ordinal in 0 1 2; do
		if grep -F -f "$temp_dir/generated-token-patterns" "$temp_dir/corrupt-pod-$ordinal.log" >/dev/null; then
			echo "generated API key leaked in failed recovery logs" >&2
			return 1
		fi
	done
	kubectl --context "$source_context" -n "$namespace" delete statefulset/goauthy --cascade=orphan --wait=true
	for ordinal in 0 1 2; do capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/corrupt-failed-uid-$ordinal"; kubectl --context "$source_context" -n "$namespace" delete "pod/goauthy-$ordinal" --wait=true; done
	for ordinal in 0 1 2; do wait_pod_deleted "$source_context" "goauthy-$ordinal"; done
	kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp local/rhiza/goauthy-e2e/goauthy-e2e/archive/head.bin /tmp/backup/archive-head-observed-corrupt.bin
	kubectl --context "$source_context" -n "$namespace" cp -c archive "$helper_pod:/tmp/backup/archive-head-observed-corrupt.bin" "$temp_dir/archive-head-observed-corrupt.bin"
	if [ "$checkpoint_fault" = 1 ]; then
		cmp "$head_original" "$temp_dir/archive-head-observed-corrupt.bin"
		kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/CURRENT /tmp/backup/checkpoint-current-observed-corrupt.json
		kubectl --context "$source_context" -n "$namespace" cp -c archive "$helper_pod:/tmp/backup/checkpoint-current-observed-corrupt.json" "$temp_dir/checkpoint-current-observed-corrupt.json"
		if [ "$corrupt_checkpoint_root" = 1 ]; then
			cmp "$checkpoint_original" "$temp_dir/checkpoint-current-observed-corrupt.json"
			kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp "$checkpoint_root_path" /tmp/backup/checkpoint-root-observed-corrupt.json
			kubectl --context "$source_context" -n "$namespace" cp -c archive "$helper_pod:/tmp/backup/checkpoint-root-observed-corrupt.json" "$temp_dir/checkpoint-root-observed-corrupt.json"
			cmp "$corrupt_checkpoint_root_file" "$temp_dir/checkpoint-root-observed-corrupt.json"
			kubectl --context "$source_context" -n "$namespace" cp -c archive "$checkpoint_root_original" "$helper_pod:/tmp/restore/checkpoint-root-original.json"
			kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp /tmp/restore/checkpoint-root-original.json "$checkpoint_root_path"
		elif [ "$corrupt_checkpoint_blocks" = 1 ]; then
			cmp "$checkpoint_original" "$temp_dir/checkpoint-current-observed-corrupt.json"
			kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp "$checkpoint_root_path" /tmp/backup/checkpoint-root-observed-corrupt.json
			kubectl --context "$source_context" -n "$namespace" cp -c archive "$helper_pod:/tmp/backup/checkpoint-root-observed-corrupt.json" "$temp_dir/checkpoint-root-observed-corrupt.json"
			cmp "$checkpoint_root_original" "$temp_dir/checkpoint-root-observed-corrupt.json"
			while IFS= read -r checkpoint_block_key; do
				kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp "local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/blocks/$checkpoint_block_key" "/tmp/backup/checkpoint-block-observed-$checkpoint_block_key"
				kubectl --context "$source_context" -n "$namespace" cp -c archive "$helper_pod:/tmp/backup/checkpoint-block-observed-$checkpoint_block_key" "$temp_dir/checkpoint-block-observed-$checkpoint_block_key"
				kubectl --context "$source_context" -n "$namespace" cp -c archive "$helper_pod:/tmp/backup/checkpoint-blocks-corrupt/$checkpoint_block_key" "$temp_dir/checkpoint-block-corrupt-$checkpoint_block_key"
				cmp "$temp_dir/checkpoint-block-corrupt-$checkpoint_block_key" "$temp_dir/checkpoint-block-observed-$checkpoint_block_key"
			done <"$temp_dir/corrupt-checkpoint-block-keys"
			# mirror --overwrite can skip same-size content changes. Copy each saved
			# block explicitly and verify the remote bytes before starting any voter.
			while IFS= read -r checkpoint_block_key; do
				kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp "/tmp/backup/checkpoint-blocks/$checkpoint_block_key" "local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/blocks/$checkpoint_block_key"
				kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp "local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/blocks/$checkpoint_block_key" "/tmp/backup/checkpoint-block-restored-$checkpoint_block_key"
				kubectl --context "$source_context" -n "$namespace" exec -c archive "$helper_pod" -- cmp "/tmp/backup/checkpoint-blocks/$checkpoint_block_key" "/tmp/backup/checkpoint-block-restored-$checkpoint_block_key"
			done <"$temp_dir/corrupt-checkpoint-block-keys"
		else
			cmp "$corrupt_checkpoint_current" "$temp_dir/checkpoint-current-observed-corrupt.json"
			kubectl --context "$source_context" -n "$namespace" cp -c archive "$checkpoint_original" "$helper_pod:/tmp/restore/checkpoint-current-original.json"
			kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp /tmp/restore/checkpoint-current-original.json local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/CURRENT
		fi
		assert_checkpoint_with_archive_head "$source_context" checkpoint-after-restoration
	elif [ "$missing_blocks" = 1 ]; then
		cmp "$head_original" "$temp_dir/archive-head-observed-corrupt.bin"
		assert_archive_blocks "$source_context" blocks-after-failure false
		kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc mirror /tmp/backup/blocks/ local/rhiza/goauthy-e2e/goauthy-e2e/archive/blocks/
		assert_archive_blocks "$source_context" blocks-after-restoration true
	elif [ "$corrupt_blocks" = 1 ]; then
		cmp "$head_original" "$temp_dir/archive-head-observed-corrupt.bin"
		assert_archive_blocks "$source_context" blocks-after-failure true
		while IFS= read -r block_key; do
			kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp "local/rhiza/goauthy-e2e/goauthy-e2e/archive/blocks/$block_key" "/tmp/backup/archive-block-observed-$block_key"
			kubectl --context "$source_context" -n "$namespace" cp -c archive "$helper_pod:/tmp/backup/archive-block-observed-$block_key" "$temp_dir/archive-block-observed-$block_key"
			cmp "$corrupt_block" "$temp_dir/archive-block-observed-$block_key"
		done <"$temp_dir/corrupt-block-keys"
		kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc mirror --overwrite /tmp/backup/blocks/ local/rhiza/goauthy-e2e/goauthy-e2e/archive/blocks/
		assert_archive_blocks "$source_context" blocks-after-restoration true
	else
		cmp "$corrupt_head" "$temp_dir/archive-head-observed-corrupt.bin"
		kubectl --context "$source_context" -n "$namespace" cp -c archive "$head_original" "$helper_pod:/tmp/restore/archive-head-original.bin"
		kubectl --context "$source_context" -n "$namespace" exec -c backup-mc "$helper_pod" -- mc cp /tmp/restore/archive-head-original.bin local/rhiza/goauthy-e2e/goauthy-e2e/archive/head.bin
	fi
	apply_app "$source_context"
	assert_no_pvc_application "$source_context"
	for ordinal in 0 1 2; do
		capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/corrupt-restored-uid-$ordinal"
		[ "$(cat "$temp_dir/corrupt-source-uid-$ordinal")" != "$(cat "$temp_dir/corrupt-failed-uid-$ordinal")" ] && [ "$(cat "$temp_dir/corrupt-failed-uid-$ordinal")" != "$(cat "$temp_dir/corrupt-restored-uid-$ordinal")" ] || return 1
		with_pod "$source_context" "goauthy-$ordinal" assert_active "$source_token"
		retrieve_generated_bootstrap "$source_context" "goauthy-$ordinal" "$temp_dir/corrupt-restored-$ordinal.json"
		cmp "$temp_dir/source-generated-0.json" "$temp_dir/corrupt-restored-$ordinal.json"
		with_pod "$source_context" "goauthy-$ordinal" assert_generated_key "$temp_dir/generated-auth.conf" "$temp_dir/corrupt-restored-auth-$ordinal.json"
		assert_generated_log_redaction "$source_context" "goauthy-$ordinal" "$temp_dir/generated-token-patterns" "$temp_dir/corrupt-restored-log-$ordinal"
	done
	corrupt_kid=$(with_pod "$source_context" goauthy-0 jwks_kid); [ "$corrupt_kid" = "$source_kid" ] || return 1
	for issuer in 0 1 2; do corrupt_token=$temp_dir/corrupt-oauth-token-$issuer; with_pod "$source_context" "goauthy-$issuer" issue_token "$corrupt_token"; for ordinal in 0 1 2; do with_pod "$source_context" "goauthy-$ordinal" assert_active "$corrupt_token"; done; done
	[ "$(cat "$temp_dir/corrupt-minio-uid")" = "$(kubectl --context "$source_context" -n "$namespace" get pod/minio-0 -o jsonpath='{.metadata.uid}')" ] || return 1
	capture_container_id "$source_context" minio-0 minio "$temp_dir/corrupt-minio-after-container"
	cmp "$temp_dir/corrupt-minio-container" "$temp_dir/corrupt-minio-after-container"
	if [ "$corrupt_checkpoint_root" = 1 ]; then
		echo 'Kind exact-three Rhiza checkpoint root corruption E2E passed'
	elif [ "$corrupt_checkpoint_blocks" = 1 ]; then
		echo 'Kind exact-three Rhiza checkpoint block corruption E2E passed'
	elif [ "$corrupt_checkpoint" = 1 ]; then
		echo 'Kind exact-three Rhiza checkpoint corruption E2E passed'
	elif [ "$missing_blocks" = 1 ]; then
		echo 'Kind exact-three Rhiza missing archive blocks E2E passed'
	elif [ "$corrupt_blocks" = 1 ]; then
		echo 'Kind exact-three Rhiza archive block corruption E2E passed'
	else
		echo 'Kind exact-three Rhiza archive corruption E2E passed'
	fi
}

minio_unavailable_once() {
	context=$1
	pods=$temp_dir/minio-outage-pods.json
	endpoints=$temp_dir/minio-outage-endpoints.json
	kubectl --context "$context" -n "$namespace" get pods -l app.kubernetes.io/name=minio -o json >"$pods" || return 2
	jq -e '(.items | type) == "array"' "$pods" >/dev/null || return 2
	jq -e '(.items | length) == 0' "$pods" >/dev/null || return 1
	kubectl --context "$context" -n "$namespace" get endpoints/minio -o json >"$endpoints" || return 2
	jq -e 'if has("subsets") and .subsets != null then (.subsets | type) == "array" else true end' "$endpoints" >/dev/null || return 2
	jq -e '(.subsets // [] | length) == 0' "$endpoints" >/dev/null || return 1
}

wait_minio_unavailable() {
	context=$1
	for _ in $(seq 1 90); do
		if minio_unavailable_once "$context"; then
			return 0
		else
			result=$?
		fi
		[ "$result" -eq 1 ] || { echo 'cannot verify MinIO pods and service endpoints during outage' >&2; return 1; }
		sleep 1
	done
	echo 'MinIO pods or service endpoints remained available during outage' >&2
	return 1
}

assert_outage_oauth_write_failure() {
	base=$1
	output=$2
	errors=$3
	started_at=$(date +%s)
	if http_status=$(curl --silent --show-error --max-time 70 --output "$output" --write-out '%{http_code}' \
		-u goauthy-dev:correct-horse-battery-staple \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		--data 'grant_type=client_credentials&scope=goauthy.read&resource=https%3A%2F%2Fapi.example.test%2Fv1' \
		"$base/oidc/token" 2>"$errors"); then
		:
	else
		echo "object-store outage OAuth write had a client transport failure or timeout after $(($(date +%s) - started_at)) seconds" >&2
		return 1
	fi
	case "$http_status" in 500|503) ;; *) echo "object-store outage OAuth write returned unexpected HTTP $http_status after $(($(date +%s) - started_at)) seconds" >&2; return 1;; esac
	test -s "$output" || { echo 'object-store outage OAuth write did not return a JSON error body' >&2; return 1; }
	jq -e 'type == "object" and (.error == "server_error" or .error == "temporarily_unavailable") and (has("access_token") | not)' "$output" >/dev/null || {
		error_class=$(jq -r 'if type == "object" and (.error == "server_error" or .error == "temporarily_unavailable" or .error == "error" or .error == "invalid_client" or .error == "invalid_request") then .error else "unknown" end' "$output" 2>/dev/null || printf '%s' unknown)
		echo "object-store outage OAuth write returned HTTP $http_status OAuth error class $error_class after $(($(date +%s) - started_at)) seconds" >&2
		return 1
	}
}

run_object_store_outage() {
	for ordinal in 0 1 2; do capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/outage-before-uid-$ordinal"; done
	kubectl --context "$source_context" -n "$namespace" scale statefulset/minio --replicas=0
	wait_minio_unavailable "$source_context"
	for ordinal in 0 1 2; do
		with_pod "$source_context" "goauthy-$ordinal" assert_outage_oauth_write_failure \
			"$temp_dir/outage-write-$ordinal.json" "$temp_dir/outage-write-$ordinal.err"
	done

	kubectl --context "$source_context" -n "$namespace" scale statefulset/minio --replicas=1
	kubectl --context "$source_context" -n "$namespace" rollout status statefulset/minio --timeout=180s
	kubectl --context "$source_context" -n "$namespace" wait --for=condition=ready pod/minio-0 --timeout=180s
	assert_no_pvc_application "$source_context"
	for ordinal in 0 1 2; do
		capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/outage-after-uid-$ordinal"
		[ "$(cat "$temp_dir/outage-before-uid-$ordinal")" = "$(cat "$temp_dir/outage-after-uid-$ordinal")" ] || {
			echo 'object-store outage unexpectedly replaced a GoAuthy pod' >&2
			return 1
		}
		kubectl --context "$source_context" -n "$namespace" wait --for=condition=ready "pod/goauthy-$ordinal" --timeout=180s
	done

	for ordinal in 0 1 2; do
		outage_token=$temp_dir/outage-oauth-token-$ordinal
		with_pod "$source_context" "goauthy-$ordinal" issue_token "$outage_token"
		for verifier in 0 1 2; do with_pod "$source_context" "goauthy-$verifier" assert_active "$outage_token"; done
		outage_kid=$(with_pod "$source_context" "goauthy-$ordinal" jwks_kid)
		[ "$outage_kid" = "$source_kid" ] || { echo 'object-store recovery changed JWKS kid' >&2; return 1; }
		retrieve_generated_bootstrap "$source_context" "goauthy-$ordinal" "$temp_dir/outage-generated-$ordinal.json"
		cmp "$temp_dir/source-generated-0.json" "$temp_dir/outage-generated-$ordinal.json"
		with_pod "$source_context" "goauthy-$ordinal" assert_generated_key "$temp_dir/generated-auth.conf" "$temp_dir/outage-generated-auth-$ordinal.json"
		assert_generated_log_redaction "$source_context" "goauthy-$ordinal" "$temp_dir/generated-token-patterns" "$temp_dir/outage-generated-log-$ordinal"
	done
	echo 'Kind exact-three Rhiza object-store outage E2E passed'
}

start_helper() {
	context=$1
	kubectl --context "$context" -n "$namespace" run "$helper_pod" \
		--image=minio/mc:RELEASE.2025-04-16T18-13-26Z --image-pull-policy=IfNotPresent \
		--restart=Never --labels=app.kubernetes.io/component=object-store-client \
		--overrides='{"spec":{"securityContext":{"fsGroup":1000,"seccompProfile":{"type":"RuntimeDefault"}},"volumes":[{"name":"transfer","emptyDir":{}}],"containers":[{"name":"backup-mc","image":"minio/mc:RELEASE.2025-04-16T18-13-26Z","imagePullPolicy":"IfNotPresent","command":["tail","-f","/dev/null"],"env":[{"name":"MC_CONFIG_DIR","value":"/tmp/.mc"}],"volumeMounts":[{"name":"transfer","mountPath":"/tmp/backup"},{"name":"transfer","mountPath":"/tmp/restore"}],"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"runAsNonRoot":true,"runAsUser":1000,"runAsGroup":1000}},{"name":"archive","image":"busybox:1.36.1","imagePullPolicy":"IfNotPresent","command":["tail","-f","/dev/null"],"volumeMounts":[{"name":"transfer","mountPath":"/tmp/backup"},{"name":"transfer","mountPath":"/tmp/restore"}],"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"runAsNonRoot":true,"runAsUser":1000,"runAsGroup":1000}}]}}' \
		--env=MC_CONFIG_DIR=/tmp/.mc --command -- tail -f /dev/null
	kubectl --context "$context" -n "$namespace" wait --for=condition=ready "pod/$helper_pod" --timeout=180s
	kubectl --context "$context" -n "$namespace" exec "$helper_pod" -- \
		mc alias set local http://minio:9000 goauthy-e2e goauthy-e2e-minio-password >/dev/null
}

wait_forward() {
	log=$1
	for _ in $(seq 1 50); do
		if grep -q '^Forwarding from 127.0.0.1:' "$log"; then return 0; fi
		kill -0 "$forward_pid" 2>/dev/null || { cat "$log" >&2; return 1; }
		sleep 0.1
	done
	cat "$log" >&2
	return 1
}

stop_minio_forward() {
	[ -n "$minio_forward_pid" ] || return 0
	kill "$minio_forward_pid" >/dev/null 2>&1 || true
	wait "$minio_forward_pid" 2>/dev/null || true
	minio_forward_pid=
}

with_minio_operator() {
	context=$1
	prefix=$2
	shift 2
	minio_forward_log=$temp_dir/$context-minio-forward.log
	kubectl --context "$context" -n "$namespace" port-forward --address=127.0.0.1 service/minio 0:9000 >"$minio_forward_log" 2>&1 &
	minio_forward_pid=$!
	for _ in $(seq 1 50); do
		minio_port=$(sed -n 's/^Forwarding from 127[.]0[.]0[.]1:\([0-9][0-9]*\) -> 9000$/\1/p' "$minio_forward_log")
		[ -n "$minio_port" ] && break
		kill -0 "$minio_forward_pid" 2>/dev/null || { cat "$minio_forward_log" >&2; stop_minio_forward; return 1; }
		sleep 0.1
	done
	[ -n "${minio_port:-}" ] || { cat "$minio_forward_log" >&2; stop_minio_forward; return 1; }
	set +e
	GOAUTHY_RHIZA_PROFILE=standalone \
		GOAUTHY_CLUSTER_ID=goauthy-e2e \
		GOAUTHY_NODE_ID=operator \
		GOAUTHY_DATA_DIR="$temp_dir/operator-data" \
		GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE=true \
		GOAUTHY_RHIZA_PEER_ADDR= \
		GOAUTHY_RHIZA_MEMBERS= \
		GOAUTHY_RHIZA_ADMIN_TOKEN= \
		GOAUTHY_RHIZA_PEER_TOKEN= \
		GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER=s3 \
		GOAUTHY_RHIZA_OBJECT_STORE_SESSION_TOKEN= \
		GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT="127.0.0.1:$minio_port" \
		GOAUTHY_RHIZA_OBJECT_STORE_INSECURE=true \
		GOAUTHY_RHIZA_OBJECT_STORE_BUCKET=rhiza \
		GOAUTHY_RHIZA_OBJECT_STORE_PREFIX="$prefix" \
		GOAUTHY_RHIZA_OBJECT_STORE_REGION=us-east-1 \
		GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY=goauthy-e2e \
		GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY=goauthy-e2e-minio-password \
		"$temp_dir/goauthy-backup" "$@"
	status=$?
	set -e
	stop_minio_forward
	return "$status"
}

start_catalog_fixture() {
	fixture=goauthy-backup-catalog-$(openssl rand -hex 6)
	catalog_container=$fixture
	catalog_network=$fixture
	export MINIO_ROOT_USER=goauthy-catalog
	MINIO_ROOT_PASSWORD=$(openssl rand -hex 32)
	export MINIO_ROOT_PASSWORD
	docker network create "$catalog_network" >/dev/null
	docker run -d --name "$catalog_container" --network "$catalog_network" \
		-p 127.0.0.1::9000 -e MINIO_ROOT_USER -e MINIO_ROOT_PASSWORD \
		minio/minio:RELEASE.2025-04-22T22-12-26Z server /data >/dev/null
	catalog_port=$(docker inspect --format '{{(index (index .NetworkSettings.Ports "9000/tcp") 0).HostPort}}' "$catalog_container")
	curl --fail --silent --show-error --retry 30 --retry-all-errors --retry-delay 1 \
		"http://127.0.0.1:$catalog_port/minio/health/ready" >/dev/null
	# The fixture credentials never appear in argv or output.
	MC_HOST_fixture="http://$MINIO_ROOT_USER:$MINIO_ROOT_PASSWORD@$catalog_container:9000"
	export MC_HOST_fixture
	docker run --rm --network "$catalog_network" -e MC_HOST_fixture \
		minio/mc:RELEASE.2025-04-16T18-13-26Z mb fixture/goauthy-backups >/dev/null
	if [ "$scheduled_backup_profile" = 1 ]; then
		docker network connect kind "$catalog_container"
		# The Docker host may reassign an ephemeral published port when attaching
		# another network. Operator clients must use the final mapping.
		catalog_port=$(docker inspect --format '{{(index (index .NetworkSettings.Ports "9000/tcp") 0).HostPort}}' "$catalog_container")
		curl --fail --silent --show-error --retry 30 --retry-all-errors --retry-delay 1 \
			"http://127.0.0.1:$catalog_port/minio/health/ready" >/dev/null
		catalog_kind_ip=$(docker inspect --format '{{with index .NetworkSettings.Networks "kind"}}{{.IPAddress}}{{end}}' "$catalog_container")
		case "$catalog_kind_ip" in
			[0-9]*.[0-9]*.[0-9]*.[0-9]*) ;;
			*) echo 'catalog fixture has no IPv4 address on the Kind Docker network' >&2; return 1 ;;
		esac
		catalog_access_key_file=$temp_dir/catalog-access-key
		catalog_secret_key_file=$temp_dir/catalog-secret-key
		printf '%s' "$MINIO_ROOT_USER" >"$catalog_access_key_file"
		printf '%s' "$MINIO_ROOT_PASSWORD" >"$catalog_secret_key_file"
	fi
}

with_catalog_operator() {
	set +e
	GOAUTHY_RHIZA_PROFILE=standalone \
		GOAUTHY_CLUSTER_ID=goauthy-e2e \
		GOAUTHY_NODE_ID=operator \
		GOAUTHY_DATA_DIR="$temp_dir/catalog-operator-data" \
		GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE=true \
		GOAUTHY_RHIZA_PEER_ADDR= \
		GOAUTHY_RHIZA_MEMBERS= \
		GOAUTHY_RHIZA_ADMIN_TOKEN= \
		GOAUTHY_RHIZA_PEER_TOKEN= \
		GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER=s3 \
		GOAUTHY_RHIZA_OBJECT_STORE_SESSION_TOKEN= \
		GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT="127.0.0.1:$catalog_port" \
		GOAUTHY_RHIZA_OBJECT_STORE_INSECURE=true \
		GOAUTHY_RHIZA_OBJECT_STORE_BUCKET=goauthy-backups \
		GOAUTHY_RHIZA_OBJECT_STORE_PREFIX=goauthy-e2e \
		GOAUTHY_RHIZA_OBJECT_STORE_REGION=us-east-1 \
		GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY="$MINIO_ROOT_USER" \
		GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY="$MINIO_ROOT_PASSWORD" \
		"$temp_dir/goauthy-backup" "$@"
	status=$?
	set -e
	return "$status"
}

catalog_fixture_list() {
	listing=$1
	errors=$2
	if ! docker run --rm --network "$catalog_network" -e MC_HOST_fixture \
		minio/mc:RELEASE.2025-04-16T18-13-26Z ls --recursive --json "fixture/goauthy-backups/" >"$listing" 2>"$errors"; then
		echo 'unable to obtain a successful catalog fixture listing' >&2
		return 1
	fi
}

catalog_fixture_has() {
	listing=$1
	name=$2
	jq -eRs --arg name "$name" '
		split("\n") | map(select(length > 0)) |
		[.[] | (fromjson | if .status == "success" and (.key | type) == "string" then .key else error("unexpected mc listing record") end)] |
		any(.[]; . == $name)
	' "$listing" >/dev/null
}

scheduled_backup_logs() {
	log_ordinal=$1
	if [ "$scheduled_backup_quorum_profile" = 1 ] && [ "$kubelet_stopped" = true ]; then
		# Kubernetes log proxy needs kubelet; CRI remains available during this fault.
		log_prefix=scheduled-quorum
		[ "$scheduled_backup_pause_profile" = 0 ] || log_prefix=scheduled-pause
		log_container_id=$(cat "$temp_dir/$log_prefix-container-$log_ordinal") || return 1
		# CRI preserves stderr (including slog); callers filter this merged stream.
		docker exec "$kind_node" crictl logs "$log_container_id" 2>&1
	else
		kubectl --context "$source_context" -n "$namespace" logs "pod/goauthy-$log_ordinal" -c goauthy
	fi
}

wait_scheduled_backup_at() {
	success_due_epoch=$1
	expected_entries=$2
	expected_scheduled_at=$(scheduled_backup_log_time "$success_due_epoch")
	deadline=$((success_due_epoch + 180))
	while :; do
		scheduled_now=$(scheduled_backup_now) || return 1
		[ "$scheduled_now" -le "$deadline" ] || break
		if with_catalog_operator list -timeout 5s -key-file "$catalog_public_key" -catalog-prefix "$catalog_prefix" >"$catalog_list" 2>/dev/null &&
			jq -e --argjson expected "$expected_entries" 'length == $expected and all(.[]; .id != "" and (.sha256 | test("^[a-f0-9]{64}$")))' "$catalog_list" >/dev/null; then
			for ordinal in 0 1 2; do
				if scheduled_backup_logs "$ordinal" 2>/dev/null |
					grep -F 'scheduled backup completed' | grep -F "scheduled_at=$expected_scheduled_at" >/dev/null; then
					return 0
				fi
			done
		fi
		sleep 1
	done
	echo 'scheduled backup did not publish the expected signed catalog entries and completion marker before deadline' >&2
	return 1
}

wait_scheduled_backup() {
	success_due_epoch=$scheduled_backup_due_epoch
	[ $((scheduled_backup_outage_profile + scheduled_backup_quorum_profile + scheduled_backup_pause_profile)) -eq 0 ] || success_due_epoch=$scheduled_backup_recovery_due_epoch
	wait_scheduled_backup_at "$success_due_epoch" 1
}

wait_scheduled_backup_failure() {
	deadline=$((scheduled_backup_due_epoch + 30))
	expected_scheduled_at=$(scheduled_backup_log_time "$scheduled_backup_due_epoch")
	while :; do
		scheduled_now=$(scheduled_backup_now) || return 1
		[ "$scheduled_now" -le "$deadline" ] || break
		if with_catalog_operator list -timeout 5s -key-file "$catalog_public_key" -catalog-prefix "$catalog_prefix" >"$catalog_list" 2>/dev/null &&
			jq -e 'length == 0' "$catalog_list" >/dev/null; then
			for ordinal in 0 1 2; do
				if scheduled_backup_logs "$ordinal" 2>/dev/null |
					grep -F 'scheduled backup attempt failed' | grep -F "scheduled_at=$expected_scheduled_at" >/dev/null; then
					return 0
				fi
			done
		fi
		sleep 1
	done
	echo 'scheduled backup chaos did not produce a failed server attempt with an empty catalog' >&2
	return 1
}

stop_scheduled_backup_quorum() {
	assert_single_kind_node
	for ordinal in 0 1 2; do
		capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/scheduled-quorum-uid-$ordinal"
		capture_container_id "$source_context" "goauthy-$ordinal" goauthy "$temp_dir/scheduled-quorum-container-$ordinal"
	done
	docker exec "$kind_node" systemctl stop kubelet
	kubelet_stopped=true
	: >"$temp_dir/scheduled-quorum-kill-pids"
	for ordinal in 1 2; do
		container_id=$(cat "$temp_dir/scheduled-quorum-container-$ordinal")
		docker exec "$kind_node" ctr -n k8s.io tasks kill --signal SIGKILL "$container_id" >"$temp_dir/scheduled-quorum-kill-$ordinal.out" 2>&1 &
		printf '%s\n' "$!" >>"$temp_dir/scheduled-quorum-kill-pids"
	done
	while IFS= read -r kill_pid; do wait "$kill_pid" || { echo 'containerd rejected a scheduled quorum SIGKILL request' >&2; return 1; }; done <"$temp_dir/scheduled-quorum-kill-pids"
	for ordinal in 1 2; do wait_container_exit_137 "$(cat "$temp_dir/scheduled-quorum-container-$ordinal")"; done
}

recover_scheduled_backup_quorum() {
	docker exec "$kind_node" systemctl start kubelet
	kubelet_stopped=false
	while :; do
		scheduled_now=$(scheduled_backup_now) || return 1
		[ "$scheduled_now" -le "$scheduled_backup_recovery_due_epoch" ] || { echo 'scheduled quorum voters did not restart before the second backup slot' >&2; return 1; }
		restarted=true
		for ordinal in 1 2; do
			if capture_container_id "$source_context" "goauthy-$ordinal" goauthy "$temp_dir/scheduled-quorum-restart-container-$ordinal" 2>/dev/null &&
				! cmp -s "$temp_dir/scheduled-quorum-container-$ordinal" "$temp_dir/scheduled-quorum-restart-container-$ordinal"; then
				:
			else
				restarted=false
			fi
		done
		[ "$restarted" = true ] && break
		sleep 1
	done
	for ordinal in 0 1 2; do kubectl --context "$source_context" -n "$namespace" wait --for=condition=ready "pod/goauthy-$ordinal" --timeout=30s; done
	for ordinal in 0 1 2; do
		capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/scheduled-quorum-after-uid-$ordinal"
		cmp "$temp_dir/scheduled-quorum-uid-$ordinal" "$temp_dir/scheduled-quorum-after-uid-$ordinal"
		capture_container_id "$source_context" "goauthy-$ordinal" goauthy "$temp_dir/scheduled-quorum-after-container-$ordinal"
		if [ "$ordinal" = 0 ]; then
			cmp "$temp_dir/scheduled-quorum-container-$ordinal" "$temp_dir/scheduled-quorum-after-container-$ordinal"
		else
			if cmp -s "$temp_dir/scheduled-quorum-container-$ordinal" "$temp_dir/scheduled-quorum-after-container-$ordinal"; then
				echo 'scheduled quorum recovery did not replace a killed voter container' >&2
				return 1
			fi
		fi
	done
}

rotate_scheduled_backup_signer() {
	assert_single_kind_node
	for ordinal in 0 1 2; do
		capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/scheduled-rotation-before-uid-$ordinal"
		capture_container_id "$source_context" "goauthy-$ordinal" goauthy "$temp_dir/scheduled-rotation-before-container-$ordinal"
	done
	scheduled_backup_rotated=1
	create_scheduled_backup_secret "$source_context"
	kubectl --context "$source_context" -n "$namespace" rollout restart statefulset/goauthy
	kubectl --context "$source_context" -n "$namespace" rollout status statefulset/goauthy --timeout=180s
	for ordinal in 0 1 2; do
		kubectl --context "$source_context" -n "$namespace" wait --for=condition=ready "pod/goauthy-$ordinal" --timeout=180s
		capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/scheduled-rotation-after-uid-$ordinal"
		if cmp -s "$temp_dir/scheduled-rotation-before-uid-$ordinal" "$temp_dir/scheduled-rotation-after-uid-$ordinal"; then
			echo 'scheduled signer rotation did not replace a voter pod' >&2
			return 1
		fi
		capture_container_id "$source_context" "goauthy-$ordinal" goauthy "$temp_dir/scheduled-rotation-after-container-$ordinal"
		if cmp -s "$temp_dir/scheduled-rotation-before-container-$ordinal" "$temp_dir/scheduled-rotation-after-container-$ordinal"; then
			echo 'scheduled signer rotation did not replace a voter container' >&2
			return 1
		fi
	done
}

assert_rotation_catalog_trust() {
	rotation_old_list=$temp_dir/scheduled-rotation-old-list.json
	with_catalog_operator list -key-file "$catalog_public_key" -catalog-prefix "$catalog_prefix" >"$rotation_old_list"
	jq -e --arg id "$catalog_first_id" --arg digest "$catalog_first_digest" '
		length == 1 and .[0].id == $id and .[0].sha256 == $digest
	' "$rotation_old_list" >/dev/null || return 1
	with_catalog_operator fetch -file "$temp_dir/scheduled-rotation-first.age" -key-file "$catalog_public_key" \
		-catalog-prefix "$catalog_prefix" -id "$catalog_first_id" -work-dir "$temp_dir" >/dev/null
	rm "$temp_dir/scheduled-rotation-first.age"
	catalog_public_key=$catalog_trust_bundle
}

assert_rotation_mixed_catalog() {
	if with_catalog_operator list -key-file "$temp_dir/catalog-ed25519-public.pem" -catalog-prefix "$catalog_prefix" >"$temp_dir/scheduled-rotation-old-only.out" 2>&1; then
		echo 'old-only trust unexpectedly accepted the mixed scheduled catalog' >&2
		return 1
	else
		status=$?
		[ "$status" -eq 1 ] || { echo 'old-only mixed catalog rejection did not return the expected validation error' >&2; return 1; }
	fi
	if with_catalog_operator list -key-file "$catalog_rotated_public_key" -catalog-prefix "$catalog_prefix" >"$temp_dir/scheduled-rotation-new-only.out" 2>&1; then
		echo 'new-only trust unexpectedly accepted the mixed scheduled catalog' >&2
		return 1
	else
		status=$?
		[ "$status" -eq 1 ] || { echo 'new-only mixed catalog rejection did not return the expected validation error' >&2; return 1; }
	fi
	with_catalog_operator list -key-file "$catalog_trust_bundle" -catalog-prefix "$catalog_prefix" >"$catalog_list"
	jq -e --arg old "$catalog_first_id" '
		length == 2 and ([.[].id] | unique | length) == 2 and
		([.[] | select(.id != $old)] | length) == 1
	' "$catalog_list" >/dev/null || return 1
	catalog_id=$(jq -er --arg old "$catalog_first_id" '.[] | select(.id != $old) | .id' "$catalog_list")
	backup_digest=$(jq -er --arg id "$catalog_id" '.[] | select(.id == $id) | .sha256 | select(test("^[a-f0-9]{64}$"))' "$catalog_list")
	# Prove the new signer directly, not only failure of old-only catalog listing.
	with_catalog_operator fetch -file "$temp_dir/scheduled-rotation-second.age" -key-file "$catalog_rotated_public_key" \
		-catalog-prefix "$catalog_prefix" -id "$catalog_id" -work-dir "$temp_dir" >/dev/null
	rm "$temp_dir/scheduled-rotation-second.age"
}

scheduled_backup_container_pid() {
	container_id=$1
	container_pid=$(docker exec "$kind_node" crictl inspect -o json "$container_id" |
		jq -er --arg id "$container_id" 'select(.status.id == $id and .status.state == "CONTAINER_RUNNING") | (.info.pid // .status.pid) | tonumber | select(. > 1)') || return 1
	printf '%s\n' "$container_pid"
}

scheduled_backup_holder_is_blocked() {
	holder_pid=$1
	docker exec "$kind_node" sh -ec '
		find "/proc/$1/root/var/lib/goauthy/backup-work" -maxdepth 1 -type f -name ".goauthy-create-*" -print -quit | grep -q .
	' sh "$holder_pid" || return 1
	docker exec "$kind_node" nsenter -t "$holder_pid" -n ss -Htn state established |
		grep -F "$catalog_kind_ip:9000" >/dev/null
}

wait_scheduled_backup_holder() {
	deadline=$((scheduled_backup_due_epoch + 90))
	while :; do
		scheduled_now=$(scheduled_backup_now) || return 1
		[ "$scheduled_now" -le "$deadline" ] || break
		for ordinal in 0 1 2; do
			container_id=$(cat "$temp_dir/scheduled-pause-container-$ordinal")
			if holder_pid=$(scheduled_backup_container_pid "$container_id") && scheduled_backup_holder_is_blocked "$holder_pid"; then
				[ -z "$scheduled_backup_holder_container" ] || { echo 'more than one scheduled paused-holder candidate observed' >&2; return 1; }
				scheduled_backup_holder_container=$container_id
				scheduled_backup_holder_pid=$holder_pid
				scheduled_backup_holder_ordinal=$ordinal
				return 0
			fi
		done
		sleep 1
	done
	echo 'scheduled paused-holder profile did not observe a blocked catalog request after backup Create began' >&2
	return 1
}

scheduled_backup_holder_state() {
	docker exec "$kind_node" sh -ec 'test -r "/proc/$1/stat" && cut -d " " -f 3 "/proc/$1/stat"' sh "$scheduled_backup_holder_pid"
}

copy_scheduled_backup_observer_file() {
	# Stream through the running mount namespace: docker cp can target the
	# underlying rootfs instead of Kind's /tmp tmpfs on the Dory runtime.
	docker exec -i "$kind_node" sh -ec 'umask 077; cat > "$1"' sh "$2" <"$1"
}

prepare_scheduled_backup_watermark_observer() {
	source_minio_ip=$(kubectl --context "$source_context" -n "$namespace" get pod/minio-0 -o jsonpath='{.status.podIP}')
	case "$source_minio_ip" in [0-9]*.[0-9]*.[0-9]*.[0-9]*) ;; *) echo 'scheduled watermark observer found no source MinIO pod IPv4 address' >&2; return 1;; esac
	node_arch=$(docker exec "$kind_node" uname -m)
	case "$node_arch" in x86_64) observer_arch=amd64;; aarch64|arm64) observer_arch=arm64;; *) echo 'unsupported Kind node architecture for scheduled watermark observer' >&2; return 1;; esac
	observer_local=$temp_dir/backup-watermark
	CGO_ENABLED=0 GOOS=linux GOARCH=$observer_arch go build -trimpath -o "$observer_local" ./scripts/testdata/backup-watermark
	observer_identity_local=$temp_dir/backup-watermark-identity.json
	jq -nc --arg source_endpoint minio.goauthy.svc.cluster.local:9000 --arg destination_endpoint "$catalog_kind_ip:9000" --arg catalog "$catalog_prefix" \
		'["goauthy-e2e", "s3", $source_endpoint, "rhiza", "goauthy-e2e", "s3", $destination_endpoint, "goauthy-backups", $catalog]' >"$observer_identity_local"
	observer_env_local=$temp_dir/backup-watermark.env
	(umask 077; cat >"$observer_env_local" <<EOF
GOAUTHY_CLUSTER_ID=goauthy-e2e
GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT=$source_minio_ip:9000
GOAUTHY_RHIZA_OBJECT_STORE_BUCKET=rhiza
GOAUTHY_RHIZA_OBJECT_STORE_PREFIX=goauthy-e2e
GOAUTHY_RHIZA_OBJECT_STORE_REGION=us-east-1
GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY=goauthy-e2e
GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY=goauthy-e2e-minio-password
EOF
)
	observer_token=$(openssl rand -hex 8)
	scheduled_backup_observer_binary=/usr/local/bin/goauthy-backup-watermark-$observer_token
	scheduled_backup_observer_identity=/tmp/goauthy-backup-watermark-identity-$observer_token.json
	scheduled_backup_observer_env=/tmp/goauthy-backup-watermark-$observer_token.env
	copy_scheduled_backup_observer_file "$observer_local" "$scheduled_backup_observer_binary"
	copy_scheduled_backup_observer_file "$observer_identity_local" "$scheduled_backup_observer_identity"
	copy_scheduled_backup_observer_file "$observer_env_local" "$scheduled_backup_observer_env"
	docker exec "$kind_node" chmod 0700 "$scheduled_backup_observer_binary"
	docker exec "$kind_node" chmod 0400 "$scheduled_backup_observer_identity" "$scheduled_backup_observer_env"
	# Fail before injecting a fault if the observer cannot execute.
	docker exec "$kind_node" "$scheduled_backup_observer_binary" -h >/dev/null 2>&1
}

assert_scheduled_backup_watermark() {
	watermark_due=$1
	watermark_label=$2
	docker exec "$kind_node" sh -ec '
		set -a
		. "$1"
		set +a
		exec "$2" -identity-file "$3" -due "$4"
	' sh "$scheduled_backup_observer_env" "$scheduled_backup_observer_binary" "$scheduled_backup_observer_identity" "$watermark_due" >"$temp_dir/scheduled-pause-watermark-$watermark_label.json"
	jq -e --argjson due "$watermark_due" '.due == $due and (.applied_slot | type == "number" and . > 0)' "$temp_dir/scheduled-pause-watermark-$watermark_label.json" >/dev/null
}

capture_scheduled_pause_voters() {
	for ordinal in 0 1 2; do
		capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/scheduled-pause-uid-$ordinal"
		capture_container_id "$source_context" "goauthy-$ordinal" goauthy "$temp_dir/scheduled-pause-container-$ordinal"
		scheduled_backup_container_pid "$(cat "$temp_dir/scheduled-pause-container-$ordinal")" >"$temp_dir/scheduled-pause-pid-$ordinal"
	done
}

assert_scheduled_pause_voters_unchanged() {
	for ordinal in 0 1 2; do
		capture_pod_uid "$source_context" "goauthy-$ordinal" "$temp_dir/scheduled-pause-current-uid-$ordinal"
		cmp "$temp_dir/scheduled-pause-uid-$ordinal" "$temp_dir/scheduled-pause-current-uid-$ordinal" || {
			echo "scheduled paused-holder replaced goauthy-$ordinal pod" >&2
			return 1
		}
		capture_container_id "$source_context" "goauthy-$ordinal" goauthy "$temp_dir/scheduled-pause-current-container-$ordinal"
		cmp "$temp_dir/scheduled-pause-container-$ordinal" "$temp_dir/scheduled-pause-current-container-$ordinal" || {
			echo "scheduled paused-holder replaced goauthy-$ordinal container" >&2
			return 1
		}
		scheduled_backup_container_pid "$(cat "$temp_dir/scheduled-pause-current-container-$ordinal")" >"$temp_dir/scheduled-pause-current-pid-$ordinal"
		cmp "$temp_dir/scheduled-pause-pid-$ordinal" "$temp_dir/scheduled-pause-current-pid-$ordinal" || {
			echo "scheduled paused-holder changed goauthy-$ordinal container PID" >&2
			return 1
		}
	done
}

assert_scheduled_pause_cluster_health() {
	kubectl --context "$source_context" get node "$kind_node" -o json |
		jq -e 'any(.status.conditions[]?; .type == "Ready" and .status == "True")' >/dev/null || {
			echo 'scheduled paused-holder made the Kind node NotReady' >&2
			return 1
		}
	kubectl --context "$source_context" -n "$namespace" get endpoints/minio -o json |
		jq -e 'any(.subsets[]?.addresses[]?; (.ip | type) == "string" and length > 0)' >/dev/null || {
			echo 'scheduled paused-holder made the source MinIO Service have no ready endpoint' >&2
			return 1
		}
	kubectl --context "$source_context" -n "$namespace" exec "$helper_pod" -- \
		mc stat local/rhiza/goauthy-e2e/goauthy-e2e/checkpoint/CURRENT >/dev/null || {
			echo 'scheduled paused-holder could not reach source MinIO through its Service' >&2
			return 1
		}
}

assert_scheduled_pause_catalog_set() {
	jq -e --slurpfile expected "$temp_dir/scheduled-pause-successors.json" '
		def entries: map({id, sha256}) | sort_by(.id);
		entries == ($expected[0] | entries)
	' "$catalog_list" >/dev/null || { echo 'paused-holder catalog entry set changed after successor completion' >&2; return 1; }
}

run_scheduled_backup_paused_holder() {
	assert_single_kind_node
	docker exec "$kind_node" sh -ec 'command -v nsenter >/dev/null && command -v ss >/dev/null'
	prepare_scheduled_backup_watermark_observer
	capture_scheduled_pause_voters
	docker pause "$catalog_container" >/dev/null
	catalog_paused=true
	wait_scheduled_backup_holder
	docker exec "$kind_node" ctr -n k8s.io tasks kill --signal SIGSTOP "$scheduled_backup_holder_container"
	[ "$(scheduled_backup_holder_state)" = T ] || { echo 'scheduled backup holder did not enter SIGSTOP state' >&2; return 1; }
	scheduled_backup_holder_stopped_at=$(scheduled_backup_now) || return 1
	# Kubernetes stays healthy while the owner is stopped. The rendered test-only
	# liveness budget prevents kubelet from restarting this one process.
	pause_expiry=$((scheduled_backup_holder_stopped_at + 65))
	while :; do
		scheduled_now=$(scheduled_backup_now) || return 1
		[ "$scheduled_now" -gt "$pause_expiry" ] && break
		sleep 1
	done
	assert_scheduled_pause_voters_unchanged
	assert_scheduled_pause_cluster_health
	docker unpause "$catalog_container" >/dev/null
	catalog_paused=false
	with_catalog_operator list -key-file "$catalog_public_key" -catalog-prefix "$catalog_prefix" >"$catalog_list"
	jq -e 'length == 0' "$catalog_list" >/dev/null || { echo 'paused holder published a first-slot catalog completion' >&2; return 1; }
	scheduled_now=$(scheduled_backup_now) || return 1
	[ "$scheduled_now" -lt "$scheduled_backup_recovery_due_epoch" ] || { echo 'paused-holder preparation did not finish before successor slot' >&2; return 1; }
}

resume_scheduled_backup_holder() {
	docker exec "$kind_node" ctr -n k8s.io tasks kill --signal SIGCONT "$scheduled_backup_holder_container"
	[ "$(scheduled_backup_holder_state)" != T ] || { echo 'scheduled backup holder remained stopped after SIGCONT' >&2; return 1; }
	capture_container_id "$source_context" "goauthy-$scheduled_backup_holder_ordinal" goauthy "$temp_dir/scheduled-pause-holder-after"
	cmp "$temp_dir/scheduled-pause-container-$scheduled_backup_holder_ordinal" "$temp_dir/scheduled-pause-holder-after"
	return 0
}

wait_scheduled_backup_holder_settled() {
	settlement_started=$(scheduled_backup_now) || return 1
	deadline=$((settlement_started + 90))
	expected_scheduled_at=$(scheduled_backup_log_time "$scheduled_backup_due_epoch")
	while :; do
		scheduled_now=$(scheduled_backup_now) || return 1
		[ "$scheduled_now" -le "$deadline" ] || break
		if docker exec "$kind_node" crictl logs "$scheduled_backup_holder_container" 2>&1 |
			grep -F 'scheduled backup attempt failed' | grep -F "scheduled_at=$expected_scheduled_at" >/dev/null &&
			! docker exec "$kind_node" sh -ec 'find "/proc/$1/root/var/lib/goauthy/backup-work" -maxdepth 1 -type f -name ".goauthy-create-*" -print -quit | grep -q .' sh "$scheduled_backup_holder_pid"; then
			break
		fi
		sleep 1
	done
	[ "$scheduled_now" -le "$deadline" ] || { echo 'resumed scheduled holder did not fail and remove its Create scratch before deadline' >&2; return 1; }
	with_catalog_operator list -key-file "$catalog_public_key" -catalog-prefix "$catalog_prefix" >"$catalog_list"
	jq -e --arg successor "$catalog_successor_id" '
		length >= 1 and length <= 2 and any(.[]; .id == $successor) and
		all(.[]; .id != "" and (.sha256 | test("^[a-f0-9]{64}$")))
	' "$catalog_list" >/dev/null || { echo 'resumed holder catalog did not preserve the successor entry within the bounded two-slot set' >&2; return 1; }
	jq -r '.[].id' "$catalog_list" | while IFS= read -r listed_id; do
		with_catalog_operator fetch -file "$temp_dir/scheduled-pause-$listed_id.age" -key-file "$catalog_public_key" \
			-catalog-prefix "$catalog_prefix" -id "$listed_id" -work-dir "$temp_dir" >/dev/null
		rm "$temp_dir/scheduled-pause-$listed_id.age"
	done
	cp "$catalog_list" "$temp_dir/scheduled-pause-successors.json"
	assert_scheduled_backup_watermark "$scheduled_backup_recovery_due_epoch" after-resume
	assert_scheduled_pause_voters_unchanged
	assert_scheduled_pause_cluster_health
}

stop_scheduled_source() {
	kubectl --context "$source_context" -n "$namespace" delete statefulset/goauthy --cascade=orphan --wait=true
	for ordinal in 2 1 0; do kubectl --context "$source_context" -n "$namespace" delete "pod/goauthy-$ordinal" --wait=true; done
	scheduled_source_stopped=true
}

with_pod() {
	context=$1
	pod=$2
	shift 2
	log=$temp_dir/$context-$pod-forward.log
	kubectl --context "$context" -n "$namespace" port-forward --address=127.0.0.1 "pod/$pod" "$port:8080" >"$log" 2>&1 &
	forward_pid=$!
	wait_forward "$log"
	set +e
	command=$1
	shift
	"$command" "http://127.0.0.1:$port" "$@"
	status=$?
	set -e
	kill "$forward_pid" >/dev/null 2>&1 || true
	wait "$forward_pid" 2>/dev/null || true
	forward_pid=
	return "$status"
}

issue_token() {
	base=$1
	output=$2
	curl --fail --silent --show-error --max-time 30 -u goauthy-dev:correct-horse-battery-staple \
		-H 'Content-Type: application/x-www-form-urlencoded' \
		--data 'grant_type=client_credentials&scope=goauthy.read&resource=https%3A%2F%2Fapi.example.test%2Fv1' \
		"$base/oidc/token" | jq -jr '.access_token' >"$output"
}

assert_active() {
	base=$1
	token_file=$2
	payload=$(curl --fail --silent --show-error --max-time 30 -u goauthy-dev:correct-horse-battery-staple \
		-H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "token@$token_file" \
		"$base/oidc/introspect")
	[ "$(printf '%s' "$payload" | jq -er '.active')" = true ]
	[ "$(printf '%s' "$payload" | jq -er '.client_id')" = goauthy-dev ]
	[ "$(printf '%s' "$payload" | jq -er '.scope')" = goauthy.read ]
}

retrieve_generated_bootstrap() {
	context=$1
	pod=$2
	output=$3
	kubectl --context "$context" -n "$namespace" exec "pod/$pod" -c goauthy -- /goauthy-bootstrap-secrets \
		-file /var/lib/goauthy/generated-bootstrap.secrets -key-dir /run/secrets/master-keys >"$output"
	jq -e 'length == 1 and .[0].kind == "api-key" and .[0].id == "generated-reader" and .[0].field == "token" and (. [0].value | startswith("generated-reader$"))' "$output" >/dev/null
}

assert_generated_key() {
	base=$1
	config=$2
	output=$3
	curl --fail --silent --show-error --max-time 30 --config "$config" "$base/auth/v1/api_keys/generated-reader/test" >"$output"
	jq -e '.name == "generated-reader"' "$output" >/dev/null
}

assert_generated_log_redaction() {
	context=$1
	pod=$2
	patterns=$3
	output=$4
	kubectl --context "$context" -n "$namespace" logs "pod/$pod" -c goauthy >"$output"
	if grep -F -f "$patterns" "$output" >/dev/null; then
		echo 'generated API-key token appeared in a pod log' >&2
		return 1
	fi
}

assert_generated_export_absent() {
	context=$1
	pod=$2
	output=$3
	err=$4
	if kubectl --context "$context" -n "$namespace" exec "pod/$pod" -c goauthy -- /goauthy-bootstrap-secrets \
		-file /var/lib/goauthy/generated-bootstrap.secrets -key-dir /run/secrets/master-keys >"$output" 2>"$err"; then
		echo 'expired shared generated export was unexpectedly retrievable' >&2
		return 1
	else
		status=$?
	fi
	[ "$status" -eq 1 ] || { echo 'generated export absence retrieval returned an unexpected status' >&2; return 1; }
	[ ! -s "$output" ] || { echo 'generated export absence retrieval emitted plaintext' >&2; return 1; }
	grep -F 'goauthy-bootstrap-secrets: read API-key bootstrap file: open /var/lib/goauthy/generated-bootstrap.secrets: no such file or directory' "$err" >/dev/null || {
		echo 'generated export absence retrieval was not an authenticated missing-artifact result' >&2
		return 1
	}
}

wait_original_export_expiry() {
	artifact=$1
	floor=$2
	deadline=$3
	output=$temp_dir/source-expired.json
	err=$temp_dir/source-expired.err
	while [ "$(date +%s)" -le "$deadline" ]; do
		if "$temp_dir/goauthy-bootstrap-secrets" -file "$artifact" -key-dir "$local_master_key_dir" >"$output" 2>"$err"; then
			sleep 1
			continue
		else
			status=$?
		fi
		[ "$status" -eq 1 ] || { echo 'source generated export retrieval returned an unexpected status' >&2; return 1; }
		[ ! -s "$output" ] || { echo 'source generated export expiry retrieval emitted plaintext' >&2; return 1; }
		grep -F 'goauthy-bootstrap-secrets: generated bootstrap secret container expired' "$err" >/dev/null || {
			echo 'source generated export retrieval was not an authenticated expiry result' >&2
			return 1
		}
		[ "$(date +%s)" -ge "$floor" ] || { echo 'source generated export expired before its original deadline floor' >&2; return 1; }
		return 0
	done
	echo 'source generated export did not expire by its original deadline' >&2
	return 1
}

jwks_kid() {
	base=$1
	curl --fail --silent --show-error --max-time 30 "$base/oidc/jwks.json" | jq -er '.keys[0].kid'
}

source_context=kind-$cluster
restore_context=kind-$restore_cluster

./scripts/e2e-preflight.sh host-capacity
kind create cluster --name "$cluster" --wait 120s
source_created=true
./scripts/e2e-preflight.sh kind-inotify --cluster "$cluster"
normalize_context "$source_context"
kind load docker-image "$image" --name "$cluster"
[ "$checkpoint_interruption_profile" = 0 ] || {
	docker image inspect "$checkpoint_fault_image" >/dev/null
	kind load docker-image "$checkpoint_fault_image" --name "$cluster"
}
[ "$journal_interruption_profile" = 0 ] || {
	docker image inspect "$journal_fault_image" >/dev/null
	kind load docker-image "$journal_fault_image" --name "$cluster"
}
if [ "$scheduled_backup_profile" = 1 ]; then
	start_catalog_fixture
	catalog_prefix=goauthy-e2e-catalog-$(date -u +%Y%m%dT%H%M%SZ)
	scheduled_backup_schedule
fi
apply_object_store "$source_context"
[ "$scheduled_backup_profile" = 0 ] || {
	create_scheduled_backup_secret "$source_context"
	apply_scheduled_catalog_egress
}
[ "$expiry_profile" = 0 ] || expiry_started_at=$(date +%s)
apply_app "$source_context" true goauthy-e2e "$scheduled_backup_profile"
assert_no_pvc_application "$source_context"
[ "$expiry_profile" = 0 ] || expiry_ready_at=$(date +%s)
start_helper "$source_context"

source_token=$temp_dir/source-oauth-token
with_pod "$source_context" goauthy-0 issue_token "$source_token"
with_pod "$source_context" goauthy-1 assert_active "$source_token"
with_pod "$source_context" goauthy-2 assert_active "$source_token"
source_kid=$(with_pod "$source_context" goauthy-0 jwks_kid)
[ -n "$source_kid" ]
for ordinal in 0 1 2; do retrieve_generated_bootstrap "$source_context" "goauthy-$ordinal" "$temp_dir/source-generated-$ordinal.json"; done
cmp "$temp_dir/source-generated-0.json" "$temp_dir/source-generated-1.json"
cmp "$temp_dir/source-generated-0.json" "$temp_dir/source-generated-2.json"
jq -r '.[0].value, (.[0].value | split("$")[1])' "$temp_dir/source-generated-0.json" >"$temp_dir/generated-token-patterns"
jq -jr '.[0].value' "$temp_dir/source-generated-0.json" | sed 's/^/header = "Authorization: API-Key /; s/$/"/' >"$temp_dir/generated-auth.conf"
for ordinal in 0 1 2; do
	with_pod "$source_context" "goauthy-$ordinal" assert_generated_key "$temp_dir/generated-auth.conf" "$temp_dir/source-generated-auth-$ordinal.json"
	assert_generated_log_redaction "$source_context" "goauthy-$ordinal" "$temp_dir/generated-token-patterns" "$temp_dir/source-generated-log-$ordinal"
done
if [ "$crash_profile" = 1 ]; then
	run_all_voters_crash_recovery
	exit 0
fi
if [ "$outage_profile" = 1 ]; then
	run_object_store_outage
	exit 0
fi
if [ "$corruption_profile" = 1 ]; then
	run_archive_corruption
	exit 0
fi
if [ "$missing_blocks_profile" = 1 ]; then
	run_archive_corruption 1
	exit 0
fi
if [ "$block_corruption_profile" = 1 ]; then
	run_archive_corruption 0 1
	exit 0
fi
if [ "$checkpoint_corruption_profile" = 1 ]; then
	run_archive_corruption 0 0 1
	exit 0
fi
if [ "$checkpoint_root_corruption_profile" = 1 ]; then
	run_archive_corruption 0 0 0 1
	exit 0
fi
if [ "$checkpoint_block_corruption_profile" = 1 ]; then
	run_archive_corruption 0 0 0 0 1
	exit 0
fi
if [ "$checkpoint_interruption_profile" = 1 ]; then
	run_checkpoint_download_interruption
	exit 0
fi
if [ "$journal_interruption_profile" = 1 ]; then
	run_journal_interruption
	exit 0
fi
[ "$scheduled_backup_profile" = 1 ] || {
	start_catalog_fixture
	catalog_prefix=goauthy-e2e-catalog-$(date -u +%Y%m%dT%H%M%SZ)
}
[ "$expiry_profile" = 0 ] || kubectl --context "$source_context" -n "$namespace" exec -c bootstrap-artifact pod/goauthy-0 -- \
	cat /var/lib/goauthy/generated-bootstrap.secrets >"$temp_dir/source-generated-bootstrap.secrets"
[ "$expiry_profile" = 0 ] || test -s "$temp_dir/source-generated-bootstrap.secrets"

# The scheduled profile uses the real server worker; all three voters and the
# credential fixtures above must exist before its finite UTC slot is due.
wait_checkpoint "$source_context"
backup_bundle=$temp_dir/goauthy-e2e.age
catalog_list=$temp_dir/catalog-list.json
if [ "$scheduled_backup_profile" = 1 ]; then
	for ordinal in 0 1 2; do
		kubectl --context "$source_context" -n "$namespace" wait --for=condition=ready "pod/goauthy-$ordinal" --timeout=30s
	done
	scheduled_now=$(scheduled_backup_now) || exit 1
	[ "$scheduled_now" -lt "$scheduled_backup_due_epoch" ] || { echo 'scheduled backup slot elapsed before all voters were ready' >&2; exit 1; }
	if [ "$scheduled_backup_outage_profile" = 1 ]; then
		kubectl --context "$source_context" -n "$namespace" scale statefulset/minio --replicas=0
		wait_minio_unavailable "$source_context"
		wait_scheduled_backup_failure
		kubectl --context "$source_context" -n "$namespace" scale statefulset/minio --replicas=1
		kubectl --context "$source_context" -n "$namespace" rollout status statefulset/minio --timeout=180s
		kubectl --context "$source_context" -n "$namespace" wait --for=condition=ready pod/minio-0 --timeout=180s
		for ordinal in 0 1 2; do
			kubectl --context "$source_context" -n "$namespace" wait --for=condition=ready "pod/goauthy-$ordinal" --timeout=30s
		done
		assert_no_pvc_application "$source_context"
		wait_checkpoint "$source_context"
		scheduled_now=$(scheduled_backup_now) || exit 1
		[ "$scheduled_now" -lt "$scheduled_backup_recovery_due_epoch" ] || { echo 'source recovery did not finish before the second scheduled backup slot' >&2; exit 1; }
	elif [ "$scheduled_backup_quorum_profile" = 1 ]; then
		stop_scheduled_backup_quorum
		wait_scheduled_backup_failure
		recover_scheduled_backup_quorum
		assert_no_pvc_application "$source_context"
		wait_checkpoint "$source_context"
		scheduled_now=$(scheduled_backup_now) || exit 1
		[ "$scheduled_now" -lt "$scheduled_backup_recovery_due_epoch" ] || { echo 'scheduled quorum recovery did not finish before the second backup slot' >&2; exit 1; }
	elif [ "$scheduled_backup_pause_profile" = 1 ]; then
		run_scheduled_backup_paused_holder
	fi
	if [ "$scheduled_backup_rotation_profile" = 1 ]; then
		wait_scheduled_backup_at "$scheduled_backup_due_epoch" 1
		catalog_first_id=$(jq -er '.[0].id | strings | select(length > 0)' "$catalog_list")
		catalog_first_digest=$(jq -er '.[0].sha256 | strings | select(test("^[a-f0-9]{64}$"))' "$catalog_list")
		assert_rotation_catalog_trust
		rotate_scheduled_backup_signer
		assert_no_pvc_application "$source_context"
		wait_checkpoint "$source_context"
		scheduled_now=$(scheduled_backup_now) || exit 1
		[ "$scheduled_now" -lt "$scheduled_backup_recovery_due_epoch" ] || { echo 'scheduled signer rotation did not finish before the second backup slot' >&2; exit 1; }
		wait_scheduled_backup_at "$scheduled_backup_recovery_due_epoch" 2
		assert_rotation_mixed_catalog
	else
		wait_scheduled_backup
		catalog_id=$(jq -er '.[0].id | strings | select(length > 0)' "$catalog_list")
		backup_digest=$(jq -er '.[0].sha256 | strings | select(test("^[a-f0-9]{64}$"))' "$catalog_list")
	fi
	if [ "$scheduled_backup_pause_profile" = 1 ]; then
		catalog_successor_id=$catalog_id
		catalog_successor_digest=$backup_digest
		assert_scheduled_backup_watermark "$scheduled_backup_recovery_due_epoch" before-resume
		resume_scheduled_backup_holder
		wait_scheduled_backup_holder_settled
	fi
	jq -e --arg id "$catalog_id" --arg source goauthy-e2e/goauthy-e2e '
		any(.[]; .id == $id and .source_prefix == $source)
	' "$catalog_list" >/dev/null || { echo 'scheduled catalog entry has an unexpected source prefix' >&2; exit 1; }
	# A successful worker log is emitted only after its Rhiza completion marker
	# CAS; stop all schedules before the existing one-entry assertions below.
	stop_scheduled_source
else
	catalog_entry=$temp_dir/catalog-entry.json
	(
		export GOAUTHY_BACKUP_OBJECT_STORE_PROVIDER=s3
		export GOAUTHY_BACKUP_OBJECT_STORE_ENDPOINT="127.0.0.1:$catalog_port"
		export GOAUTHY_BACKUP_OBJECT_STORE_INSECURE=true
		export GOAUTHY_BACKUP_OBJECT_STORE_BUCKET=goauthy-backups
		export GOAUTHY_BACKUP_OBJECT_STORE_REGION=us-east-1
		export GOAUTHY_BACKUP_OBJECT_STORE_ACCESS_KEY="$MINIO_ROOT_USER"
		export GOAUTHY_BACKUP_OBJECT_STORE_SECRET_KEY="$MINIO_ROOT_PASSWORD"
		with_minio_operator "$source_context" goauthy-e2e create \
			-recipient-file "$age_recipient_file" -signing-key-file "$catalog_private_key" \
			-catalog-prefix "$catalog_prefix" -work-dir "$temp_dir"
	) >"$catalog_entry"
	catalog_id=$(jq -er '.id | strings | select(length > 0)' "$catalog_entry")
	backup_digest=$(jq -er '.sha256 | strings | select(test("^[a-f0-9]{64}$"))' "$catalog_entry")
	jq -e --arg source goauthy-e2e/goauthy-e2e '
	.source_prefix == $source
	' "$catalog_entry" >/dev/null || { echo 'created catalog entry has an unexpected source prefix' >&2; exit 1; }
fi
catalog_fetch=$temp_dir/catalog-create-fetch.json
with_catalog_operator fetch -file "$backup_bundle" -key-file "$catalog_public_key" \
	-catalog-prefix "$catalog_prefix" -id "$catalog_id" -work-dir "$temp_dir" >"$catalog_fetch"
jq -e --arg id "$catalog_id" --arg digest "$backup_digest" '
	.id == $id and .sha256 == $digest
' "$catalog_fetch" >/dev/null || { echo 'created catalog artifact fetch differs from its entry' >&2; exit 1; }
with_catalog_operator list -key-file "$catalog_public_key" -catalog-prefix "$catalog_prefix" >"$catalog_list"
if [ "$scheduled_backup_rotation_profile" = 1 ]; then
	jq -e --arg old "$catalog_first_id" --arg id "$catalog_id" --arg digest "$backup_digest" '
		length == 2 and any(.[]; .id == $old) and any(.[]; .id == $id and .sha256 == $digest)
	' "$catalog_list" >/dev/null || { echo 'catalog list did not retain both rotation entries' >&2; exit 1; }
elif [ "$scheduled_backup_pause_profile" = 1 ]; then
	assert_scheduled_pause_catalog_set
else
	jq -e --arg id "$catalog_id" --arg digest "$backup_digest" '
		length == 1 and .[0].id == $id and .[0].sha256 == $digest
	' "$catalog_list" >/dev/null || { echo 'catalog list did not return the published ID and digest' >&2; exit 1; }
fi
catalog_old_entry=$temp_dir/catalog-old-entry.json
with_catalog_operator publish -file "$backup_bundle" -key-file "$catalog_private_key" \
	-catalog-prefix "$catalog_prefix" >"$catalog_old_entry"
catalog_old_id=$(jq -er '.id | strings | select(length > 0)' "$catalog_old_entry")
catalog_old_receipt=$temp_dir/catalog-old-receipt.json
catalog_old_source=goauthy-e2e/goauthy-e2e
[ "$backup_expire_all_profile" = 0 ] || catalog_old_source=retired-source
go run "$temp_dir/generate-age-key.go" fixture-reseed "$catalog_private_key" "$catalog_old_entry" "$catalog_old_receipt" "$catalog_old_source"
jq -e --arg id "$catalog_old_id" --arg prefix "$catalog_prefix" --arg source "$catalog_old_source" '
	.entry | .id == $id and .catalog_prefix == $prefix and .source_prefix == $source and .created_at < (now - 30 * 24 * 60 * 60)
' "$catalog_old_receipt" >/dev/null || { echo 'catalog retention fixture receipt was not reseeded' >&2; exit 1; }
docker run --rm -i --network "$catalog_network" -e MC_HOST_fixture \
	minio/mc:RELEASE.2025-04-16T18-13-26Z pipe "fixture/goauthy-backups/$catalog_prefix/completed/$catalog_old_id.json" <"$catalog_old_receipt"
catalog_old_artifact=$catalog_prefix/artifacts/$catalog_old_id.age
catalog_old_completion=$catalog_prefix/completed/$catalog_old_id.json
catalog_fixture_listing=$temp_dir/catalog-retention-before.jsonl
catalog_fixture_errors=$temp_dir/catalog-retention-before.err
catalog_fixture_list "$catalog_fixture_listing" "$catalog_fixture_errors"
catalog_fixture_has "$catalog_fixture_listing" "$catalog_old_artifact" || { echo 'catalog retention dry run fixture artifact is absent' >&2; exit 1; }
catalog_fixture_has "$catalog_fixture_listing" "$catalog_old_completion" || { echo 'catalog retention dry run fixture receipt is absent' >&2; exit 1; }
catalog_prune_plan=$temp_dir/catalog-prune-plan.json
if [ "$backup_expire_all_profile" = 1 ]; then
	catalog_default_prune_plan=$temp_dir/catalog-prune-default-plan.json
	with_catalog_operator prune -key-file "$catalog_public_key" -catalog-prefix "$catalog_prefix" >"$catalog_default_prune_plan"
	jq -e 'length == 0' "$catalog_default_prune_plan" >/dev/null || {
		echo 'catalog keep-latest dry run selected the only retired-source backup' >&2
		exit 1
	}
	with_catalog_operator prune -key-file "$catalog_public_key" -catalog-prefix "$catalog_prefix" -retention-policy expire-all >"$catalog_prune_plan"
else
	with_catalog_operator prune -key-file "$catalog_public_key" -catalog-prefix "$catalog_prefix" >"$catalog_prune_plan"
fi
jq -e --arg id "$catalog_old_id" 'length == 1 and .[0].id == $id' "$catalog_prune_plan" >/dev/null || {
	echo 'catalog retention dry run did not select exactly the expired fixture' >&2
	exit 1
}
catalog_fixture_listing=$temp_dir/catalog-retention-dry-run.jsonl
catalog_fixture_errors=$temp_dir/catalog-retention-dry-run.err
catalog_fixture_list "$catalog_fixture_listing" "$catalog_fixture_errors"
catalog_fixture_has "$catalog_fixture_listing" "$catalog_old_artifact" || { echo 'catalog retention dry run deleted the old artifact' >&2; exit 1; }
catalog_fixture_has "$catalog_fixture_listing" "$catalog_old_completion" || { echo 'catalog retention dry run deleted the old receipt' >&2; exit 1; }
catalog_prune_apply=$temp_dir/catalog-prune-apply.json
if [ "$backup_expire_all_profile" = 1 ]; then
	with_catalog_operator prune -key-file "$catalog_public_key" -catalog-prefix "$catalog_prefix" -retention-policy expire-all -apply >"$catalog_prune_apply"
else
	with_catalog_operator prune -key-file "$catalog_public_key" -catalog-prefix "$catalog_prefix" -apply >"$catalog_prune_apply"
fi
jq -e --arg id "$catalog_old_id" 'length == 1 and .[0].id == $id' "$catalog_prune_apply" >/dev/null || {
	echo 'catalog retention apply did not remove exactly the expired fixture' >&2
	exit 1
}
catalog_fixture_listing=$temp_dir/catalog-retention-after.jsonl
catalog_fixture_errors=$temp_dir/catalog-retention-after.err
catalog_fixture_list "$catalog_fixture_listing" "$catalog_fixture_errors"
if catalog_fixture_has "$catalog_fixture_listing" "$catalog_old_artifact"; then
	echo 'catalog retention left the old artifact behind' >&2
	exit 1
else
	status=$?
	[ "$status" -eq 1 ] || exit "$status"
fi
if catalog_fixture_has "$catalog_fixture_listing" "$catalog_old_completion"; then
	echo 'catalog retention left the old receipt behind' >&2
	exit 1
else
	status=$?
	[ "$status" -eq 1 ] || exit "$status"
fi
with_catalog_operator list -key-file "$catalog_public_key" -catalog-prefix "$catalog_prefix" >"$catalog_list"
if [ "$scheduled_backup_rotation_profile" = 1 ]; then
	jq -e --arg old "$catalog_first_id" --arg id "$catalog_id" --arg digest "$backup_digest" '
		length == 2 and any(.[]; .id == $old) and any(.[]; .id == $id and .sha256 == $digest)
	' "$catalog_list" >/dev/null || { echo 'catalog retention did not preserve both signed rotation entries' >&2; exit 1; }
elif [ "$scheduled_backup_pause_profile" = 1 ]; then
	assert_scheduled_pause_catalog_set
else
	jq -e --arg id "$catalog_id" --arg digest "$backup_digest" '
		length == 1 and .[0].id == $id and .[0].sha256 == $digest
	' "$catalog_list" >/dev/null || { echo 'catalog retention did not preserve the fresh signed entry' >&2; exit 1; }
fi
# The externally published copy is now the restore input; remove only this
# owned local artifact before destroying the source Kind cluster.
rm -f "$backup_bundle"

# Remove the controller so pods can be stopped one-by-one without replacement.
[ "$scheduled_source_stopped" = true ] || {
	kubectl --context "$source_context" -n "$namespace" delete statefulset/goauthy --cascade=orphan --wait=true
	kubectl --context "$source_context" -n "$namespace" delete pod/goauthy-2 --wait=true
	kubectl --context "$source_context" -n "$namespace" delete pod/goauthy-1 --wait=true
	kubectl --context "$source_context" -n "$namespace" delete pod/goauthy-0 --wait=true
}
[ "$expiry_profile" = 0 ] || {
	backup_completed_at=$(date +%s)
	[ "$backup_completed_at" -lt $((expiry_started_at + generated_ttl)) ] || {
		echo 'source backup did not complete before the generated export deadline floor' >&2
		exit 1
	}
}

# The restore cluster receives an unrelated object-store prefix and exact
# member/secret identity. MinIO is an object-store test fixture; GoAuthy starts
# with emptyDir.
kind delete cluster --name "$cluster"
source_created=false
./scripts/e2e-preflight.sh host-capacity
kind create cluster --name "$restore_cluster" --wait 120s
restore_created=true
./scripts/e2e-preflight.sh kind-inotify --cluster "$restore_cluster"
normalize_context "$restore_context"
kind load docker-image "$image" --name "$restore_cluster"
apply_object_store "$restore_context"
start_helper "$restore_context"
backup_bundle=$temp_dir/goauthy-e2e-catalog.age
catalog_fetch=$temp_dir/catalog-fetch.json
with_catalog_operator fetch -file "$backup_bundle" -key-file "$catalog_public_key" \
	-catalog-prefix "$catalog_prefix" -id "$catalog_id" -work-dir "$temp_dir" >"$catalog_fetch"
jq -e --arg id "$catalog_id" --arg digest "$backup_digest" '
	.id == $id and .sha256 == $digest
' "$catalog_fetch" >/dev/null || { echo 'fetched catalog digest differs from exported artifact' >&2; exit 1; }
with_minio_operator "$restore_context" goauthy-dr restore \
	-file "$backup_bundle" -key-file "$age_identity_file" -work-dir "$temp_dir" -sha256 "$backup_digest"
kubectl --context "$restore_context" -n "$namespace" exec "$helper_pod" -- \
	mc stat local/rhiza/goauthy-dr/goauthy-e2e/checkpoint/CURRENT >/dev/null
kubectl --context "$restore_context" -n "$namespace" exec "$helper_pod" -- \
	mc stat local/rhiza/goauthy-dr/goauthy-e2e/goauthy-restore.json >/dev/null
kubectl --context "$restore_context" -n "$namespace" delete pod "$helper_pod" --wait=true
pvc_names=$(kubectl --context "$restore_context" -n "$namespace" get pvc -o name) || { echo 'cannot inspect restore PVCs before application deployment' >&2; exit 1; }
if printf '%s\n' "$pvc_names" | grep -q '^persistentvolumeclaim/data-goauthy-'; then
	echo 'restore cluster unexpectedly has a GoAuthy PVC before application deployment' >&2
	exit 1
fi
[ "$expiry_profile" = 0 ] || wait_original_export_expiry \
	"$temp_dir/source-generated-bootstrap.secrets" "$((expiry_started_at + generated_ttl))" "$((expiry_ready_at + generated_ttl + 30))"
apply_app "$restore_context" true goauthy-dr
assert_no_pvc_application "$restore_context"

with_pod "$restore_context" goauthy-0 assert_active "$source_token"
with_pod "$restore_context" goauthy-1 assert_active "$source_token"
with_pod "$restore_context" goauthy-2 assert_active "$source_token"
for ordinal in 0 1 2; do
	if [ "$expiry_profile" = 1 ]; then
		assert_generated_export_absent "$restore_context" "goauthy-$ordinal" "$temp_dir/restore-absent-$ordinal.json" "$temp_dir/restore-absent-$ordinal.err"
	else
		retrieve_generated_bootstrap "$restore_context" "goauthy-$ordinal" "$temp_dir/restore-generated-$ordinal.json"
	fi
	with_pod "$restore_context" "goauthy-$ordinal" assert_generated_key "$temp_dir/generated-auth.conf" "$temp_dir/restore-generated-auth-$ordinal.json"
	assert_generated_log_redaction "$restore_context" "goauthy-$ordinal" "$temp_dir/generated-token-patterns" "$temp_dir/restore-generated-log-$ordinal"
done
[ "$expiry_profile" = 1 ] || {
	cmp "$temp_dir/source-generated-0.json" "$temp_dir/restore-generated-0.json"
	cmp "$temp_dir/source-generated-0.json" "$temp_dir/restore-generated-1.json"
	cmp "$temp_dir/source-generated-0.json" "$temp_dir/restore-generated-2.json"
}
restore_kid=$(with_pod "$restore_context" goauthy-0 jwks_kid)
[ "$restore_kid" = "$source_kid" ] || {
	echo "restored JWKS kid $restore_kid differs from source $source_kid" >&2
	exit 1
}
restore_token=$temp_dir/restore-oauth-token
with_pod "$restore_context" goauthy-0 issue_token "$restore_token"
with_pod "$restore_context" goauthy-0 assert_active "$restore_token"
with_pod "$restore_context" goauthy-1 assert_active "$restore_token"
with_pod "$restore_context" goauthy-2 assert_active "$restore_token"
if [ "$expiry_profile" = 1 ]; then
	for ordinal in 0 1 2; do
		kubectl --context "$restore_context" -n "$namespace" get "pod/goauthy-$ordinal" -o jsonpath='{.metadata.uid}' >"$temp_dir/restart-before-uid-$ordinal"
	done
	kubectl --context "$restore_context" -n "$namespace" rollout restart statefulset/goauthy
	kubectl --context "$restore_context" -n "$namespace" rollout status statefulset/goauthy --timeout=180s
	for ordinal in 0 1 2; do
		kubectl --context "$restore_context" -n "$namespace" wait --for=condition=ready "pod/goauthy-$ordinal" --timeout=180s
		before_uid=$(cat "$temp_dir/restart-before-uid-$ordinal")
		after_uid=$(kubectl --context "$restore_context" -n "$namespace" get "pod/goauthy-$ordinal" -o jsonpath='{.metadata.uid}')
		[ "$before_uid" != "$after_uid" ] || { echo 'rollout restart did not replace every restored pod' >&2; exit 1; }
		assert_generated_export_absent "$restore_context" "goauthy-$ordinal" "$temp_dir/restart-absent-$ordinal.json" "$temp_dir/restart-absent-$ordinal.err"
		with_pod "$restore_context" "goauthy-$ordinal" assert_generated_key "$temp_dir/generated-auth.conf" "$temp_dir/restart-generated-auth-$ordinal.json"
		assert_generated_log_redaction "$restore_context" "goauthy-$ordinal" "$temp_dir/generated-token-patterns" "$temp_dir/restart-generated-log-$ordinal"
	done
	echo 'Kind exact-three Rhiza expiring backup/restore E2E passed'
else
	echo 'Kind exact-three Rhiza backup/restore E2E passed'
fi
