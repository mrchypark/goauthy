#!/bin/sh
# Focused offline tests for the privacy-safe startup fatal summarizer used by
# the issue #113 native per-pod log path. Self-contained: builds synthetic
# capture-status files and per-pod container logs, exercises the fixed
# error_class enum, the fixed source prefixes, the anchored native record
# start, per-capture fail-closed eligibility, and two direct --summarize
# integration controls. It never runs a cluster, build, campaign, or dispatch.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
summarizer=$script_dir/summarize-saas-isolation-113-startup-fatal.sh
wrapper=$script_dir/run-capacity-113-ci.sh

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok: $1" >&2; }
bad() { fail=$((fail + 1)); echo "not ok: $1" >&2; }

for tool in awk jq mktemp printf grep sed; do
	command -v "$tool" >/dev/null 2>&1 || { echo "required tool missing: $tool" >&2; exit 1; }
done
[ -x "$summarizer" ] || { echo "summarizer not executable: $summarizer" >&2; exit 1; }

# A complete, eligible capture: status file with all six exit=0 entries and six
# empty per-pod logs.
build_capture() {
	dir=$1
	mkdir -p "$dir/failure-capture"
	{
		printf 'captured_at_utc=2026-01-01T00:00:00Z\n'
		printf 'cluster=kind-test\nnamespace=goauthy\n'
		printf 'pods.json_exit=0\njobs.json_exit=0\nevents.json_exit=0\n'
		printf 'capture_json_validation=passed\n'
		for idx in 0 1 2; do
			for phase in current previous; do
				printf 'goauthy-%s-%s.log_exit=0\n' "$idx" "$phase"
			done
		done
	} >"$dir/failure-capture/capture-status.txt"
	for idx in 0 1 2; do
		for phase in current previous; do
			: >"$dir/failure-capture/goauthy-$idx-$phase.log"
		done
	done
}

# One anchored typed-first fatal record.
append_typed() {
	printf '2026-01-01T00:00:00.000000000Z 2026/01/01 00:00:00 ERROR goauthy stopped error_class=%s error="%s"\n' "$2" "$3" >>"$1"
}

# One anchored typed-first record with a raw (quoted or unquoted) error attr.
append_typed_raw() {
	printf '2026-01-01T00:00:00.000000000Z 2026/01/01 00:00:00 ERROR goauthy stopped error_class=%s error=%s\n' "$2" "$3" >>"$1"
}

# One anchored legacy fatal record.
append_legacy() {
	printf '2026-01-01T00:00:00.000000000Z 2026/01/01 00:00:00 ERROR goauthy stopped error="%s"\n' "$2" >>"$1"
}

append_line() {
	printf '%s\n' "$2" >>"$1"
}

# ---------------------------------------------------------------------------
# Typed-first records: all six fixed error_class enums plus unknown.
# ---------------------------------------------------------------------------
c1=$tmp/typed
build_capture "$c1"
f=$c1/failure-capture/goauthy-0-current.log
append_typed "$f" 'write_outcome_unknown' 'private'
append_typed "$f" 'node_not_ready' 'private'
append_typed "$f" 'quorum_unavailable' 'private'
append_typed "$f" 'ack_durability_unavailable' 'private'
append_typed "$f" 'deadline' 'private'
append_typed "$f" 'canceled' 'private'
append_typed "$f" 'some_unsupported_label' 'private'
if out=$("$summarizer" "$c1") && printf '%s' "$out" | jq -e '
	.available == true and .complete == true
	and ([.pods[].index] | sort) == [0, 1, 2]
	and (first(.pods[] | select(.index == 0)).current.fatal_n) == 7
	and (first(.pods[] | select(.index == 0)).current.error_class_counts.write_outcome_unknown) == 1
	and (first(.pods[] | select(.index == 0)).current.error_class_counts.node_not_ready) == 1
	and (first(.pods[] | select(.index == 0)).current.error_class_counts.quorum_unavailable) == 1
	and (first(.pods[] | select(.index == 0)).current.error_class_counts.ack_durability_unavailable) == 1
	and (first(.pods[] | select(.index == 0)).current.error_class_counts.deadline) == 1
	and (first(.pods[] | select(.index == 0)).current.error_class_counts.canceled) == 1
	and (first(.pods[] | select(.index == 0)).current.error_class_counts.unknown) == 1
	and .totals.fatal_n == 7
	and .totals.observed_n == 6
	and .totals.partial == false
' >/dev/null 2>&1; then
	ok "typed-first records classify by fixed error_class enum"
else
	bad "typed-first records classify by fixed error_class enum"
	printf '%s\n' "$out" >&2 || true
fi

# ---------------------------------------------------------------------------
# Legacy records: all eight fixed source prefixes plus unknown.
# ---------------------------------------------------------------------------
c2=$tmp/legacy
build_capture "$c2"
f=$c2/failure-capture/goauthy-0-current.log
append_legacy "$f" 'open rhiza: private'
append_legacy "$f" 'wait for rhiza readiness: private'
append_legacy "$f" 'configure SCIM runtime: private'
append_legacy "$f" 'reserve bootstrap client: private'
append_legacy "$f" 'bootstrap RBAC principal: private'
append_legacy "$f" 'bootstrap API keys: private'
append_legacy "$f" 'fence DCR software-statement trust: private'
append_legacy "$f" 'configure API-key store: private'
append_legacy "$f" 'some other fatal: private'
if out=$("$summarizer" "$c2") && printf '%s' "$out" | jq -e '
	.available == true and .complete == true
	and (first(.pods[] | select(.index == 0)).current.fatal_n) == 9
	and (first(.pods[] | select(.index == 0)).current.counts.rhiza_open) == 1
	and (first(.pods[] | select(.index == 0)).current.counts.rhiza_readiness) == 1
	and (first(.pods[] | select(.index == 0)).current.counts.scim_runtime) == 1
	and (first(.pods[] | select(.index == 0)).current.counts.bootstrap_client) == 1
	and (first(.pods[] | select(.index == 0)).current.counts.bootstrap_rbac) == 1
	and (first(.pods[] | select(.index == 0)).current.counts.api_key_bootstrap) == 1
	and (first(.pods[] | select(.index == 0)).current.counts.dcr_trust) == 1
	and (first(.pods[] | select(.index == 0)).current.counts.storage_config) == 1
	and (first(.pods[] | select(.index == 0)).current.counts.unknown) == 1
	and .totals.fatal_n == 9
' >/dev/null 2>&1; then
	ok "legacy records classify by fixed source prefixes"
else
	bad "legacy records classify by fixed source prefixes"
	printf '%s\n' "$out" >&2 || true
fi

# ---------------------------------------------------------------------------
# Per-capture fail-closed: crashed pod previous valid typed fatal, other two
# previous missing/failed. Typed cause retained, complete false.
# ---------------------------------------------------------------------------
c3=$tmp/failclosed
mkdir -p "$c3/failure-capture"
{
	printf 'captured_at_utc=2026-01-01T00:00:00Z\ncluster=kind-test\nnamespace=goauthy\n'
	printf 'pods.json_exit=0\ncapture_json_validation=passed\n'
	printf 'goauthy-0-current.log_exit=0\n'
	printf 'goauthy-0-previous.log_exit=0\n'
	printf 'goauthy-1-current.log_exit=0\n'
	printf 'goauthy-1-previous.log_exit=1\n'
	printf 'goauthy-2-current.log_exit=0\n'
} >"$c3/failure-capture/capture-status.txt"
: >"$c3/failure-capture/goauthy-0-current.log"
append_typed "$c3/failure-capture/goauthy-0-previous.log" 'node_not_ready' 'private'
: >"$c3/failure-capture/goauthy-1-current.log"
: >"$c3/failure-capture/goauthy-1-previous.log"
: >"$c3/failure-capture/goauthy-2-current.log"
if out=$("$summarizer" "$c3") && printf '%s' "$out" | jq -e '
	.available == true
	and .complete == false
	and (first(.pods[] | select(.index == 0)).previous.available) == true
	and (first(.pods[] | select(.index == 0)).previous.error_class_counts.node_not_ready) == 1
	and (first(.pods[] | select(.index == 1)).previous.available) == false
	and (first(.pods[] | select(.index == 1)).previous.reason) == "capture-failed"
	and (first(.pods[] | select(.index == 1)).previous.counts) == null
	and (first(.pods[] | select(.index == 2)).previous.available) == false
	and (first(.pods[] | select(.index == 2)).previous.reason) == "capture-missing"
	and .totals.fatal_n == 1
	and .totals.observed_n == 4
	and .totals.partial == true
' >/dev/null 2>&1; then
	ok "per-capture fail-closed retains available crashed pod counts"
else
	bad "per-capture fail-closed retains available crashed pod counts"
	printf '%s\n' "$out" >&2 || true
fi

# ---------------------------------------------------------------------------
# Normal all valid: complete true, observed_n 6, partial false.
# ---------------------------------------------------------------------------
c4=$tmp/allvalid
build_capture "$c4"
if out=$("$summarizer" "$c4") && printf '%s' "$out" | jq -e '
	.available == true
	and .complete == true
	and .totals.observed_n == 6
	and .totals.partial == false
	and .totals.fatal_n == 0
' >/dev/null 2>&1; then
	ok "normal all valid captures are complete"
else
	bad "normal all valid captures are complete"
	printf '%s\n' "$out" >&2 || true
fi

# ---------------------------------------------------------------------------
# Duplicated/malformed status capture NOT parsed; other eligible retain counts.
# ---------------------------------------------------------------------------
c5=$tmp/dupstatus
build_capture "$c5"
append_legacy "$c5/failure-capture/goauthy-0-current.log" 'open rhiza: private'
append_legacy "$c5/failure-capture/goauthy-2-current.log" 'deadline: private'
printf 'goauthy-1-current.log_exit=0\n' >>"$c5/failure-capture/capture-status.txt"
if out=$("$summarizer" "$c5") && printf '%s' "$out" | jq -e '
	.available == true
	and .complete == false
	and (first(.pods[] | select(.index == 0)).current.available) == true
	and (first(.pods[] | select(.index == 0)).current.counts.rhiza_open) == 1
	and (first(.pods[] | select(.index == 1)).current.available) == false
	and (first(.pods[] | select(.index == 1)).current.reason) == "capture-invalid"
	and (first(.pods[] | select(.index == 1)).current.counts) == null
	and (first(.pods[] | select(.index == 2)).current.available) == true
	and (first(.pods[] | select(.index == 2)).current.counts.unknown) == 1
	and .totals.fatal_n == 2
	and .totals.observed_n == 5
	and .totals.partial == true
' >/dev/null 2>&1; then
	ok "duplicated status capture not parsed, others retain counts"
else
	bad "duplicated status capture not parsed, others retain counts"
	printf '%s\n' "$out" >&2 || true
fi

# ---------------------------------------------------------------------------
# Unquoted native error= values and forged quoted attributes.
# ---------------------------------------------------------------------------
c6=$tmp/canary
build_capture "$c6"
f=$c6/failure-capture/goauthy-0-current.log
# Typed unknown with an unquoted native error=EOF.
append_typed_raw "$f" 'unknown' 'EOF'
# Typed known class with an unquoted native error=oops.
append_typed_raw "$f" 'quorum_unavailable' 'oops'
# A real typed record whose quoted error value contains a fake typed anchor.
append_typed "$f" 'node_not_ready' 'dial ERROR goauthy stopped error_class=deadline error="fake"'
# A forged quoted attribute with an embedded fake error= must not become known.
append_line "$f" '2026-01-01T00:00:00.000000000Z 2026/01/01 00:00:00 ERROR goauthy stopped error_class="node_not_ready error="fake"'
# A forged quoted class followed by another error_class must not become known.
append_line "$f" '2026-01-01T00:00:00.000000000Z 2026/01/01 00:00:00 ERROR goauthy stopped error_class="deadline" error_class=canceled error="fake"'
# A fake typed record embedded in an unrelated INFO line.
append_line "$f" '2026-01-01T00:00:00.000000000Z 2026/01/01 00:00:00 INFO wrapper ERROR goauthy stopped error_class=deadline error="fake"'
# A TextHandler-style record: no msg= expectation, so never anchored.
append_line "$f" 'time=2026-01-01T00:00:00Z level=ERROR msg="goauthy stopped" error_class=deadline error="fake"'
# A legacy record whose properly quoted error value contains a fake error_class.
append_legacy "$f" 'open rhiza: ERROR goauthy stopped error_class=deadline error=\"fake\"'
if out=$("$summarizer" "$c6") && printf '%s' "$out" | jq -e '
	.available == true
	and (first(.pods[] | select(.index == 0)).current.fatal_n) == 4
	and (first(.pods[] | select(.index == 0)).current.error_class_counts.unknown) == 1
	and (first(.pods[] | select(.index == 0)).current.error_class_counts.quorum_unavailable) == 1
	and (first(.pods[] | select(.index == 0)).current.error_class_counts.node_not_ready) == 1
	and (first(.pods[] | select(.index == 0)).current.error_class_counts.deadline) == 0
	and (first(.pods[] | select(.index == 0)).current.error_class_counts.canceled) == 0
	and (first(.pods[] | select(.index == 0)).current.counts.rhiza_open) == 1
' >/dev/null 2>&1; then
	ok "unquoted error values parse; forged quoted attrs never become known"
else
	bad "unquoted error values parse; forged quoted attrs never become known"
	printf '%s\n' "$out" >&2 || true
fi

# ---------------------------------------------------------------------------
# Legacy source classification requires a whole well-terminated escape-aware
# quoted value. Unquoted, unterminated, malformed, or trailing-forged values
# stay unknown while the anchored fatal is still counted (fatal_n retained).
# ---------------------------------------------------------------------------
check_legacy_unknown() { # DESC TAG RAW_ATTR
	desc=$1; tag=$2; raw=$3
	dir=$tmp/legacy-$tag
	build_capture "$dir"
	printf '2026-01-01T00:00:00.000000000Z 2026/01/01 00:00:00 ERROR goauthy stopped error=%s\n' "$raw" >"$dir/failure-capture/goauthy-0-current.log"
	if out=$("$summarizer" "$dir") && printf '%s' "$out" | jq -e '
		.available == true
		and (first(.pods[] | select(.index == 0)).current.fatal_n) == 1
		and (first(.pods[] | select(.index == 0)).current.counts.unknown) == 1
		and ([.pods[0].current.counts | to_entries[] | select(.key != "unknown") | .value] | add) == 0
	' >/dev/null 2>&1; then
		ok "$desc"
	else
		bad "$desc"
		printf '%s\n' "$out" >&2 || true
	fi
}

check_legacy_known() { # DESC TAG RAW_ATTR CLASS
	desc=$1; tag=$2; raw=$3; class=$4
	dir=$tmp/legacy-$tag
	build_capture "$dir"
	printf '2026-01-01T00:00:00.000000000Z 2026/01/01 00:00:00 ERROR goauthy stopped error=%s\n' "$raw" >"$dir/failure-capture/goauthy-0-current.log"
	if out=$("$summarizer" "$dir") && printf '%s' "$out" | jq -e --arg c "$class" '
		.available == true
		and (first(.pods[] | select(.index == 0)).current.fatal_n) == 1
		and (first(.pods[] | select(.index == 0)).current.counts[$c]) == 1
		and (first(.pods[] | select(.index == 0)).current.counts.unknown) == 0
	' >/dev/null 2>&1; then
		ok "$desc"
	else
		bad "$desc"
		printf '%s\n' "$out" >&2 || true
	fi
}

# Each of the eight known prefixes, unquoted, never becomes known.
i=0
while [ "$i" -lt 8 ]; do
	i=$((i + 1))
	case "$i" in
		1) prefix='open rhiza: ' ;;
		2) prefix='wait for rhiza readiness: ' ;;
		3) prefix='configure SCIM runtime: ' ;;
		4) prefix='reserve bootstrap client: ' ;;
		5) prefix='bootstrap RBAC principal: ' ;;
		6) prefix='bootstrap API keys: ' ;;
		7) prefix='fence DCR software-statement trust: ' ;;
		8) prefix='configure API-key store: ' ;;
	esac
	check_legacy_unknown "unquoted legacy prefix $i never becomes known" "uq$i" "$prefix""probe"
done

# Each of the eight known prefixes, unterminated quoted, never becomes known.
i=0
while [ "$i" -lt 8 ]; do
	i=$((i + 1))
	case "$i" in
		1) prefix='open rhiza: ' ;;
		2) prefix='wait for rhiza readiness: ' ;;
		3) prefix='configure SCIM runtime: ' ;;
		4) prefix='reserve bootstrap client: ' ;;
		5) prefix='bootstrap RBAC principal: ' ;;
		6) prefix='bootstrap API keys: ' ;;
		7) prefix='fence DCR software-statement trust: ' ;;
		8) prefix='configure API-key store: ' ;;
	esac
	check_legacy_unknown "unterminated quoted legacy prefix $i never becomes known" "un$i" "\"$prefix""probe"
done

# An unterminated quoted value whose final quote is escaped stays unknown.
check_legacy_unknown "unterminated quoted with escaped final quote is unknown" "escun" '"open rhiza: probe\"'

# A valid quoted value with escaped quotes and backslashes inside is known.
check_legacy_known "valid quoted legacy with escapes inside is known" "escok" '"open rhiza: dial \"host\" \\ done"' 'rhiza_open'

# An unquoted one-word error is unknown.
check_legacy_unknown "unquoted EOF is unknown" "eof" 'EOF'

# ---------------------------------------------------------------------------
# Invalid native format: a missing RFC3339 prefix is not an anchored record.
# ---------------------------------------------------------------------------
c7=$tmp/no-prefix
build_capture "$c7"
f=$c7/failure-capture/goauthy-0-current.log
append_line "$f" '2026/01/01 00:00:00 ERROR goauthy stopped error_class=node_not_ready error="no-prefix"'
if out=$("$summarizer" "$c7") && printf '%s' "$out" | jq -e '
	.available == true
	and (first(.pods[] | select(.index == 0)).current.fatal_n) == 0
' >/dev/null 2>&1; then
	ok "invalid format without RFC3339 prefix"
else
	bad "invalid format without RFC3339 prefix"
	printf '%s\n' "$out" >&2 || true
fi

# ---------------------------------------------------------------------------
# Fixed counts schema: nine legacy keys, seven typed keys, numeric values.
# ---------------------------------------------------------------------------
c8=$tmp/schema
build_capture "$c8"
append_typed "$c8/failure-capture/goauthy-0-current.log" 'deadline' 'private'
if out=$("$summarizer" "$c8") && printf '%s' "$out" | jq -e '
	(.classes | length) == 10
	and (.error_classes | length) == 7
	and (.pods | length) == 3
	and ([.pods[].index] | sort) == [0, 1, 2]
	and ([.pods[].current.counts | keys[]] | unique | sort) == (["api_key_bootstrap","bootstrap_client","bootstrap_rbac","dcr_trust","rhiza_open","rhiza_readiness","schema_migrate","scim_runtime","storage_config","unknown"] | sort)
	and ([.pods[].current.error_class_counts | keys[]] | unique | sort) == (["ack_durability_unavailable","canceled","deadline","node_not_ready","quorum_unavailable","unknown","write_outcome_unknown"] | sort)
	and ([.pods[].current.counts[] | type] | all(. == "number"))
	and ([.pods[].current.error_class_counts[] | type] | all(. == "number"))
	and ([.totals.counts[] | type] | all(. == "number"))
	and ([.totals.error_class_counts[] | type] | all(. == "number"))
' >/dev/null 2>&1; then
	ok "fixed counts schema for legacy and typed counts"
else
	bad "fixed counts schema for legacy and typed counts"
	printf '%s\n' "$out" >&2 || true
fi

# ---------------------------------------------------------------------------
# Privacy: no captured raw characters, timestamps, pod names, or free strings.
# ---------------------------------------------------------------------------
c9=$tmp/privacy
build_capture "$c9"
canary='PRIVATE_BODY_CANARY_9f3c7a'
append_typed "$c9/failure-capture/goauthy-0-current.log" 'node_not_ready' "$canary https://private.example.test/secret?token=$canary"
append_legacy "$c9/failure-capture/goauthy-0-current.log" "open rhiza: $canary"
if out=$("$summarizer" "$c9") && ! printf '%s' "$out" | grep -q "$canary" &&
	! printf '%s' "$out" | grep -q 'private.example.test' &&
	! printf '%s' "$out" | grep -q 'error_class=' &&
	! printf '%s' "$out" | grep -q 'error=' &&
	! printf '%s' "$out" | grep -q 'msg=' &&
	! printf '%s' "$out" | grep -q '2026/01/01' &&
	! printf '%s' "$out" | grep -q '2026-01-01' &&
	! printf '%s' "$out" | grep -q 'goauthy-0'; then
	ok "privacy redaction"
else
	bad "privacy redaction"
fi

# ---------------------------------------------------------------------------
# Capture eligibility: missing, failed, malformed, out of range, extra equals.
# ---------------------------------------------------------------------------
expect_unavailable() {
	desc=$1; dir=$2; reason=$3
	if out=$("$summarizer" "$dir") && printf '%s' "$out" | jq -e --arg r "$reason" '.available == false and .reason == $r and .complete == false and (.pods | length) == 0 and .totals == null' >/dev/null 2>&1; then
		ok "$desc"
	else
		bad "$desc"
		printf '%s\n' "$out" >&2 || true
	fi
}

c10=$tmp/missing
mkdir -p "$c10"
expect_unavailable "missing capture" "$c10" capture-missing

c11=$tmp/failed
build_capture "$c11"
sed 's/^goauthy-0-current\.log_exit=0$/goauthy-0-current.log_exit=1/' \
	"$c11/failure-capture/capture-status.txt" >"$c11/failure-capture/capture-status.txt.tmp" &&
	mv "$c11/failure-capture/capture-status.txt.tmp" "$c11/failure-capture/capture-status.txt"
if out=$("$summarizer" "$c11") && printf '%s' "$out" | jq -e '
	.available == true
	and .complete == false
	and (first(.pods[] | select(.index == 0)).current.available) == false
	and (first(.pods[] | select(.index == 0)).current.reason) == "capture-failed"
	and (first(.pods[] | select(.index == 0)).current.counts) == null
	and (first(.pods[] | select(.index == 1)).current.available) == true
	and .totals.observed_n == 5
	and .totals.partial == true
' >/dev/null 2>&1; then
	ok "failed capture is per-capture unavailable, others retained"
else
	bad "failed capture is per-capture unavailable, others retained"
	printf '%s\n' "$out" >&2 || true
fi

c12=$tmp/malformed
build_capture "$c12"
printf 'goauthy-0-current.log_exit=abc\n' >>"$c12/failure-capture/capture-status.txt"
if out=$("$summarizer" "$c12") && printf '%s' "$out" | jq -e '
	.available == true
	and .complete == false
	and (first(.pods[] | select(.index == 0)).current.available) == false
	and (first(.pods[] | select(.index == 0)).current.reason) == "capture-invalid"
	and (first(.pods[] | select(.index == 1)).current.available) == true
	and .totals.observed_n == 5
	and .totals.partial == true
' >/dev/null 2>&1; then
	ok "malformed status capture not parsed, others retained"
else
	bad "malformed status capture not parsed, others retained"
	printf '%s\n' "$out" >&2 || true
fi

c13=$tmp/outofrange
build_capture "$c13"
printf 'goauthy-0-current.log_exit=999\n' >>"$c13/failure-capture/capture-status.txt"
if out=$("$summarizer" "$c13") && printf '%s' "$out" | jq -e '
	.available == true
	and .complete == false
	and (first(.pods[] | select(.index == 0)).current.available) == false
	and (first(.pods[] | select(.index == 0)).current.reason) == "capture-invalid"
	and .totals.observed_n == 5
' >/dev/null 2>&1; then
	ok "out of range exit capture not parsed, others retained"
else
	bad "out of range exit capture not parsed, others retained"
	printf '%s\n' "$out" >&2 || true
fi

c14=$tmp/extraequals
build_capture "$c14"
printf 'goauthy-0-current.log_exit=0=secret\n' >>"$c14/failure-capture/capture-status.txt"
if out=$("$summarizer" "$c14") && printf '%s' "$out" | jq -e '
	.available == true
	and .complete == false
	and (first(.pods[] | select(.index == 0)).current.available) == false
	and (first(.pods[] | select(.index == 0)).current.reason) == "capture-invalid"
	and .totals.observed_n == 5
' >/dev/null 2>&1; then
	ok "extra equals in status capture not parsed, others retained"
else
	bad "extra equals in status capture not parsed, others retained"
	printf '%s\n' "$out" >&2 || true
fi

c15=$tmp/nostatus
build_capture "$c15"
rm "$c15/failure-capture/capture-status.txt"
expect_unavailable "status file missing with logs present" "$c15" capture-incomplete

c16=$tmp/nologs
build_capture "$c16"
rm "$c16"/failure-capture/goauthy-*.log
expect_unavailable "logs missing with status present" "$c16" capture-incomplete

# ---------------------------------------------------------------------------
# Direct integration: startup_fatal is a safe sibling in the resource summary.
# ---------------------------------------------------------------------------
c17=$tmp/integration
build_capture "$c17"
append_typed "$c17/failure-capture/goauthy-0-current.log" 'node_not_ready' 'private'
results=$tmp/integration-results
mkdir -p "$results"
if sh "$wrapper" --summarize "$c17" "$results" >/dev/null 2>"$tmp/integration.err"; then
	rc=0
else
	rc=$?
fi
if [ "$rc" -ne 0 ] && jq -e '
	.startup_fatal.available == true
	and .startup_fatal.complete == true
	and (.startup_fatal.classes | length) == 10
	and (.startup_fatal.error_classes | length) == 7
	and ([.startup_fatal.pods[].index] | sort) == [0, 1, 2]
	and (first(.startup_fatal.pods[] | select(.index == 0)).current.fatal_n) == 1
	and (first(.startup_fatal.pods[] | select(.index == 0)).current.error_class_counts.node_not_ready) == 1
	and .startup_fatal.totals.fatal_n == 1
' "$results/resource-summary.json" >/dev/null 2>&1; then
	ok "direct integration keeps a validated startup fatal summary"
else
	bad "direct integration keeps a validated startup fatal summary"
	sed -n '1,3p' "$tmp/integration.err" >&2 || true
fi

# An unavailable startup fatal must not remove the mandatory resource gates.
c18=$tmp/integration-unavailable
mkdir -p "$c18"
results18=$tmp/integration-unavailable-results
mkdir -p "$results18"
if sh "$wrapper" --summarize "$c18" "$results18" >/dev/null 2>"$tmp/integration18.err"; then
	rc=0
else
	rc=$?
fi
if [ "$rc" -ne 0 ] && jq -e '
	.available == false
	and .startup_fatal.available == false
	and .startup_fatal.reason == "capture-missing"
' "$results18/resource-summary.json" >/dev/null 2>&1; then
	ok "an unavailable startup fatal does not remove the mandatory resource gates"
else
	bad "an unavailable startup fatal does not remove the mandatory resource gates"
	sed -n '1,3p' "$tmp/integration18.err" >&2 || true
fi

# Typed records expose only verified source prefixes and count each fatal once.
c=$tmp/typed-source
build_capture "$c"
f=$c/failure-capture/goauthy-0-current.log
append_typed "$f" write_outcome_unknown 'open rhiza: private'
append_typed "$f" write_outcome_unknown 'migrate schema v57: private'
append_typed "$f" node_not_ready 'configure SCIM runtime: private'
if out=$("$summarizer" "$c") && printf '%s' "$out" | jq -e '
	.pods[0].current.fatal_n == 3 and .totals.fatal_n == 3
	and .pods[0].current.error_class_counts.write_outcome_unknown == 2
	and .pods[0].current.error_class_counts.node_not_ready == 1
	and .pods[0].current.counts.rhiza_open == 1
	and .pods[0].current.counts.schema_migrate == 1
	and .pods[0].current.counts.scim_runtime == 1
	and .totals.counts.schema_migrate == 1
	and .totals.error_class_counts.write_outcome_unknown == 2
' >/dev/null 2>&1; then
	ok "typed source prefixes and error classes count each fatal once"
else
	bad "typed source prefixes and error classes count each fatal once"
fi

c=$tmp/typed-source-unknown
build_capture "$c"
f=$c/failure-capture/goauthy-0-current.log
append_typed "$f" write_outcome_unknown 'open rhiza: private'
append_typed_raw "$f" unknown EOF
append_typed_raw "$f" unknown 'open rhiza: private'
append_typed_raw "$f" deadline '"migrate schema v9: private\"'
append_typed_raw "$f" quorum_unavailable '"open rhiza: private" injected=1'
append_typed "$f" canceled 'migrate schema version: private'
append_typed_raw "$f" deadline '"open rhiza: unterminated'
if out=$("$summarizer" "$c") && printf '%s' "$out" | jq -e '
	.pods[0].current.fatal_n == 6 and .totals.fatal_n == 6
	and .pods[0].current.counts.unknown == 5
	and .pods[0].current.counts.rhiza_open == 1
	and .pods[0].current.counts.schema_migrate == 0
	and .pods[0].current.error_class_counts.unknown == 2
	and .pods[0].current.error_class_counts.deadline == 1
	and .pods[0].current.error_class_counts.quorum_unavailable == 1
	and .pods[0].current.error_class_counts.canceled == 1
' >/dev/null 2>&1; then
	ok "typed source rejects unquoted, unterminated, forged and malformed prefixes"
else
	bad "typed source rejects unquoted, unterminated, forged and malformed prefixes"
fi

echo "passed=$pass failed=$fail" >&2
[ "$fail" -eq 0 ]
