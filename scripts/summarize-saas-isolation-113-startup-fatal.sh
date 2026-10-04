#!/bin/sh
# Offline privacy-safe summarizer for the native startup fatal records captured
# by scripts/e2e-kind-saas-isolation-113.sh. Reads the per-pod current/previous
# container logs and the capture status from a diagnostic directory and emits
# safe JSON on stdout. It reads the private raw logs but never emits raw log
# text, timestamps, error strings, URLs, credentials, or container identifiers.
#
# Two record shapes are recognized, both anchored at the exact kubectl
# --timestamps RFC3339 prefix, the standard log.Logger "YYYY/MM/DD HH:MM:SS"
# prefix, and the literal "ERROR goauthy stopped":
#   typed-first:  ... ERROR goauthy stopped error_class=<CLASS> error="..."
#   legacy:       ... ERROR goauthy stopped error="..."
# The native default slog handler is not a TextHandler, so no msg= field is
# expected. Typed records are classified only by the fixed error_class enum;
# legacy records are classified only by the fixed source prefixes. Anything
# else is "unknown". A missing, failed, or malformed capture is never treated
# as proof of no fatal.
set -eu
umask 077

usage() {
	echo "usage: $0 <diagnostic-directory>" >&2
	exit 2
}

[ "$#" -eq 1 ] || usage
dir=$1
case "$dir" in
	/*) ;;
	*) echo "diagnostic directory must be absolute: $dir" >&2; exit 1 ;;
esac
[ -d "$dir" ] || { echo "diagnostic directory not found: $dir" >&2; exit 1; }

capture_dir=$dir/failure-capture
status_file=$capture_dir/capture-status.txt

classes_json='["rhiza_open","rhiza_readiness","scim_runtime","bootstrap_client","bootstrap_rbac","api_key_bootstrap","dcr_trust","storage_config","unknown"]'
eclasses_json='["write_outcome_unknown","node_not_ready","quorum_unavailable","ack_durability_unavailable","deadline","canceled","unknown"]'

emit_unavailable() {
	jq -n --arg reason "$1" --argjson classes "$classes_json" --argjson eclasses "$eclasses_json" '{
		schema_version: 2,
		available: false,
		reason: $reason,
		source: "failure-capture/goauthy-{0,1,2}-{current,previous}.log",
		criterion: "anchored native default-handler fatal records only; fixed error_class and source prefixes; raw log text is never emitted",
		classes: $classes,
		error_classes: $eclasses,
		pods: [],
		totals: null,
		complete: false
	}'
}

# Classify one capture-status entry. Emits exactly one of: ok, failed,
# invalid, missing. "ok" requires exactly one NAME_exit= line whose value is a
# single valid integer in 0..255 equal to 0. Any duplicate, extra "=",
# non-numeric, or out-of-range value is invalid, never a silent zero.
capture_status() {
	awk -v name="$1" '
		BEGIN { FS = "=" }
		$1 == name {
			n++
			if (NF == 2 && $2 ~ /^[0-9]+$/ && $2 + 0 <= 255) { valid++; val = $2 + 0 }
			else { bad++ }
		}
		END {
			if (n == 0) print "missing"
			else if (n == 1 && valid == 1 && bad == 0) { if (val == 0) print "ok"; else print "failed" }
			else print "invalid"
		}
	' "$status_file" 2>/dev/null || true
}

# Per-capture fail-closed reason for an unavailable capture.
per_reason() {
	st=$1
	has_file=$2
	if [ "$st" = invalid ]; then
		printf 'capture-invalid'
	elif [ "$st" = failed ]; then
		printf 'capture-failed'
	elif [ "$st" = ok ] && [ "$has_file" != true ]; then
		printf 'capture-inconsistent'
	elif [ "$st" = missing ] && [ "$has_file" = true ]; then
		printf 'capture-inconsistent'
	else
		printf 'capture-missing'
	fi
}

eligible_n=0
status_n=0
file_n=0
invalid_n=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
: >"$tmp/fatal.tsv"
neg17="-1	-1	-1	-1	-1	-1	-1	-1	-1	-1	-1	-1	-1	-1	-1	-1	-1"

# Bounded scan of one private per-pod log. Only the exact anchored record
# start is matched; typed records are classified by the fixed error_class enum
# and legacy records by the fixed source prefixes. No raw characters are
# printed. Output is one row: fatal_n, nine legacy counts in fixed class order,
# seven typed counts in fixed class order.
scan_jq='
	function typed_class(v) {
		if (v == "write_outcome_unknown") return "write_outcome_unknown"
		if (v == "node_not_ready") return "node_not_ready"
		if (v == "quorum_unavailable") return "quorum_unavailable"
		if (v == "ack_durability_unavailable") return "ack_durability_unavailable"
		if (v == "deadline") return "deadline"
		if (v == "canceled") return "canceled"
		return "unknown"
	}
	function legacy_class(rest) {
		if (index(rest, "open rhiza: ") == 1) return "rhiza_open"
		if (index(rest, "wait for rhiza readiness: ") == 1) return "rhiza_readiness"
		if (index(rest, "configure SCIM runtime: ") == 1) return "scim_runtime"
		if (index(rest, "reserve bootstrap client: ") == 1) return "bootstrap_client"
		if (index(rest, "bootstrap RBAC principal: ") == 1) return "bootstrap_rbac"
		if (index(rest, "bootstrap API keys: ") == 1) return "api_key_bootstrap"
		if (index(rest, "fence DCR software-statement trust: ") == 1) return "dcr_trust"
		if (index(rest, "configure API-key store: ") == 1) return "storage_config"
		return "unknown"
	}
	# Strict whole-attribute typed parse. The class token is either an unquoted
	# token up to the next space or an exactly quoted token; it must be followed
	# by a native " error=" attribute whose value may be quoted or unquoted. No
	# partial or forged value is ever accepted as a known class. Returns the
	# fixed class, "unknown" for an unsupported label, or "" when malformed.
	function typed_parse(rest,   after, cq, sp, val, tail, ev) {
		if (index(rest, "error_class=") != 1) return ""
		after = substr(rest, length("error_class=") + 1)
		if (substr(after, 1, 1) == "\"") {
			cq = index(substr(after, 2), "\"")
			if (cq == 0) return ""
			val = substr(after, 2, cq - 1)
			tail = substr(after, cq + 2)
		} else {
			sp = index(after, " ")
			if (sp == 0) return ""
			val = substr(after, 1, sp - 1)
			tail = substr(after, sp)
		}
		if (substr(tail, 1, 7) != " error=") return ""
		ev = substr(tail, 8)
		if (substr(ev, 1, 1) == "\"") {
			if (index(substr(ev, 2), "\"") == 0) return ""
		} else {
			if (ev == "") return ""
		}
		return typed_class(val)
	}
	function parse_name(   b, rest, a, n) {
		b = FILENAME
		sub(/.*\//, "", b)
		if (b !~ /^goauthy-[0-9]+-(current|previous)\.log$/) { g_valid = 0; return }
		rest = b
		sub(/^goauthy-/, "", rest)
		sub(/\.log$/, "", rest)
		n = split(rest, a, "-")
		if (n != 2) { g_valid = 0; return }
		g_idx = a[1]
		g_phase = a[2]
		g_valid = 1
	}
	BEGIN {
		g_valid = 0
		re = "^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9](\\.[0-9]+)?(Z|[+-][0-9][0-9]:[0-9][0-9])[[:space:]]+[0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9][[:space:]]+[0-9][0-9]:[0-9][0-9]:[0-9][0-9][[:space:]]+ERROR goauthy stopped "
		split("rhiza_open rhiza_readiness scim_runtime bootstrap_client bootstrap_rbac api_key_bootstrap dcr_trust storage_config unknown", order, " ")
		split("write_outcome_unknown node_not_ready quorum_unavailable ack_durability_unavailable deadline canceled unknown", eorder, " ")
	}
	FNR == 1 { parse_name() }
	{
		if (!g_valid) next
		line = $0
		if (!match(line, re)) next
		rest = substr(line, RSTART + RLENGTH)
		if (index(rest, "error_class=") == 1) {
			cls = typed_parse(rest)
			if (cls != "") {
				ecounts[g_idx, g_phase, cls]++
				etotal++
			}
		} else if (index(rest, "error=") == 1) {
			ev = substr(rest, length("error=") + 1)
			if (substr(ev, 1, 1) == "\"") ev = substr(ev, 2)
			cls = legacy_class(ev)
			counts[g_idx, g_phase, cls]++
			total++
		}
	}
	END {
		parse_name()
		if (!g_valid) exit
		printf "%d", total + etotal
		for (j = 1; j <= 9; j++) {
			c = order[j]
			k = g_idx SUBSEP g_phase SUBSEP c
			printf "\t%d", (k in counts ? counts[k] : 0)
		}
		for (j = 1; j <= 7; j++) {
			c = eorder[j]
			k = g_idx SUBSEP g_phase SUBSEP c
			printf "\t%d", (k in ecounts ? ecounts[k] : 0)
		}
		printf "\n"
	}
'

for idx in 0 1 2; do
	for phase in current previous; do
		name="goauthy-$idx-$phase.log"
		file=$capture_dir/$name
		st=$(capture_status "$name"_exit)
		has_file=false
		[ -f "$file" ] && has_file=true
		if [ "$has_file" = true ]; then
			file_n=$((file_n + 1))
		fi
		case "$st" in
			ok|failed|invalid) status_n=$((status_n + 1)) ;;
		esac
		if [ "$st" = invalid ]; then
			invalid_n=$((invalid_n + 1))
		fi
		if [ "$st" = ok ] && [ "$has_file" = true ]; then
			eligible_n=$((eligible_n + 1))
			row=$(awk "$scan_jq" "$file")
			printf '%s\t%s\t1\t\t0\t%s\n' "$idx" "$phase" "$row" >>"$tmp/fatal.tsv"
		else
			reason=$(per_reason "$st" "$has_file")
			printf '%s\t%s\t0\t%s\t-1\t%s\n' "$idx" "$phase" "$reason" "$neg17" >>"$tmp/fatal.tsv"
		fi
	done
done

if [ "$eligible_n" -eq 0 ]; then
	if [ "$status_n" -eq 0 ] && [ "$file_n" -eq 0 ]; then
		emit_unavailable capture-missing
	elif [ "$invalid_n" -gt 0 ]; then
		emit_unavailable capture-invalid
	else
		emit_unavailable capture-incomplete
	fi
	exit 0
fi

jq -n --argjson classes "$classes_json" --argjson eclasses "$eclasses_json" --rawfile raw "$tmp/fatal.tsv" '
	def classes: $classes;
	def eclasses: $eclasses;
	def row($r):
		if ($r[2] == "1") then
			{
				available: true,
				exit: ($r[4] | tonumber),
				fatal_n: ($r[5] | tonumber),
				counts: (reduce range(0; 9) as $i ({}; .[classes[$i]] = ($r[6 + $i] | tonumber))),
				error_class_counts: (reduce range(0; 7) as $i ({}; .[eclasses[$i]] = ($r[15 + $i] | tonumber)))
			}
		else
			{
				available: false,
				reason: (if $r[3] == "" then null else $r[3] end),
				exit: null,
				fatal_n: null,
				counts: null,
				error_class_counts: null
			}
		end;
	($raw | split("\n") | map(select(length > 0)) | map(split("\t"))) as $rows |
	{
		schema_version: 2,
		available: true,
		reason: null,
		source: "failure-capture/goauthy-{0,1,2}-{current,previous}.log",
		criterion: "anchored native default-handler fatal records only; fixed error_class and source prefixes; raw log text is never emitted",
		classes: classes,
		error_classes: eclasses,
		pods: [range(0; 3) as $i |
			([$rows[] | select(.[0] == ($i | tostring) and .[1] == "current")][0]) as $cur |
			([$rows[] | select(.[0] == ($i | tostring) and .[1] == "previous")][0]) as $prev |
			{
				index: $i,
				current: (if $cur == null then null else row($cur) end),
				previous: (if $prev == null then null else row($prev) end)
			}
		],
		totals: {
			fatal_n: ([$rows[] | select(.[2] == "1") | (.[5] | tonumber)] | add // 0),
			observed_n: ([$rows[] | select(.[2] == "1")] | length),
			partial: (([$rows[] | select(.[2] == "1")] | length) < 6),
			counts: (reduce ($rows[] | select(.[2] == "1")) as $r (reduce range(0; 9) as $i ({}; .[classes[$i]] = 0); reduce range(0; 9) as $i (.; .[classes[$i]] += ($r[6 + $i] | tonumber)))),
			error_class_counts: (reduce ($rows[] | select(.[2] == "1")) as $r (reduce range(0; 7) as $i ({}; .[eclasses[$i]] = 0); reduce range(0; 7) as $i (.; .[eclasses[$i]] += ($r[15 + $i] | tonumber))))
		},
		complete: (([$rows[] | select(.[2] == "1")] | length) == 6)
	}
'
