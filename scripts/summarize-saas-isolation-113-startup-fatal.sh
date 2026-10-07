#!/bin/sh
# Offline privacy-safe summarizer for the native startup fatal records captured
# by scripts/e2e-kind-saas-isolation-113.sh. Reads the per-pod current/previous
# container logs and the capture status from a diagnostic directory and emits
# safe JSON on stdout. It reads the private raw logs but never emits raw log
# text, timestamps, error strings, URLs, credentials, or container identifiers.
#
# Fatal and recovery failure records are anchored at the exact kubectl
# --timestamps RFC3339 prefix, the standard log.Logger "YYYY/MM/DD HH:MM:SS"
# prefix, and the literal "ERROR goauthy stopped":
#   typed-first:  ... ERROR goauthy stopped error_class=<CLASS> error="..."
#   legacy:       ... ERROR goauthy stopped error="..."
# The native default slog handler is not a TextHandler, so no msg= field is
# expected. Typed records retain the fixed error_class enum and also classify
# the verified quoted error value by fixed source prefixes, as legacy records do. Anything
# else is "unknown". A missing, failed, or malformed capture is never treated
# as proof of no fatal. Recovery exports only fixed stages/boolean counts;
# migration versions come only from verified quoted values and are bounded.
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

classes_json='["rhiza_open","rhiza_readiness","scim_runtime","bootstrap_client","bootstrap_rbac","api_key_bootstrap","dcr_trust","storage_config","schema_migrate","unknown"]'
eclasses_json='["write_outcome_unknown","node_not_ready","quorum_unavailable","ack_durability_unavailable","deadline","canceled","unknown"]'
recovery_note='Counts of validated recovery failure records only; terminal unknown-or-expired emits no record. Zero observations do not prove cause absence; original and reconciliation flags overlap.'

emit_unavailable() {
	jq -n --arg reason "$1" --arg note "$recovery_note" --argjson classes "$classes_json" --argjson eclasses "$eclasses_json" '{
		schema_version: 2,
		available: false,
		reason: $reason,
		source: "failure-capture/goauthy-{0,1,2}-{current,previous}.log",
		criterion: "anchored native default-handler fatal records only; fixed error_class and source prefixes; raw log text is never emitted",
		classes: $classes,
		error_classes: $eclasses,
		recovery_coverage_note: $note,
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
neg18="-1	-1	-1	-1	-1	-1	-1	-1	-1	-1	-1	-1	-1	-1	-1	-1	-1	-1"

# Bounded scan of one private per-pod log. Only the exact anchored record
# start is matched; typed records are classified by the fixed error_class enum
# and both record shapes by the fixed source prefixes. No raw characters are
# printed. Output is one row: fatal_n, ten source counts in fixed class order,
# seven typed counts in fixed class order.
scan_jq='
	# ponytail: known GoAuthy schema versions 1..110; extend with a new migration.
	function migration_version(val,   v) {
		if (val !~ /^migrate schema v[1-9][0-9]*: /) return 0
		v = val
		sub(/^migrate schema v/, "", v)
		sub(/: .*$/, "", v)
		return length(v) <= 3 && v + 0 <= 110 ? v + 0 : 0
	}
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
		if (rest ~ /^migrate schema v[0-9]+: /) return "schema_migrate"
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
	# Extract the raw content of a whole, well-terminated, escape-aware quoted
	# value. s starts immediately after "error=". Sets g_qok=1 only when s is a
	# quoted value whose closing quote is unescaped and whose only trailing
	# characters are whitespace (a forged trailing attribute is rejected).
	# Backslash escapes are preserved verbatim in the returned content; this is
	# a bounded quoted-value boundary, not a full Go string grammar.
	function quoted_legacy(s,   i, n, ch, esc, closed, out, tail) {
		g_qok = 0
		if (substr(s, 1, 1) != "\"") return ""
		esc = 0
		closed = 0
		out = ""
		n = length(s)
		for (i = 2; i <= n; i++) {
			ch = substr(s, i, 1)
			if (esc) { out = out ch; esc = 0 }
			else if (ch == "\\") { esc = 1; out = out ch }
			else if (ch == "\"") { closed = i; break }
			else { out = out ch }
		}
		if (closed == 0) return ""
		tail = substr(s, closed + 1)
		if (tail ~ /[^[:space:]]/) return ""
		g_qok = 1
		return out
	}
	# Strict whole-attribute typed parse. The class token is either an unquoted
	# token up to the next space or an exactly quoted token; it must be followed
	# by a native " error=" attribute whose value may be quoted or unquoted. No
	# partial or forged value is ever accepted as a known class. Returns the
	# fixed class, "unknown" for an unsupported label, or "" when malformed.
	function typed_parse(rest,   after, cq, sp, val, tail, ev) {
		g_ev = ""
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
		g_ev = ev
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
		split("rhiza_open rhiza_readiness scim_runtime bootstrap_client bootstrap_rbac api_key_bootstrap dcr_trust storage_config schema_migrate unknown", order, " ")
		split("write_outcome_unknown node_not_ready quorum_unavailable ack_durability_unavailable deadline canceled unknown", eorder, " ")
		rrec = re
		sub(/ERROR goauthy stopped $/, "ERROR Rhiza mutation recovery failed ", rrec)
		split("request_status same_request_replay", rorder, " ")
		split("caller_canceled_after_execute caller_deadline_after_execute original_commit_unknown original_node_not_ready original_quorum_unavailable original_durability_unavailable original_deadline original_canceled reconciliation_commit_unknown reconciliation_node_not_ready reconciliation_quorum_unavailable reconciliation_durability_unavailable reconciliation_deadline reconciliation_canceled", bkeys, " ")
	}
	FNR == 1 { parse_name() }
	{
		if (!g_valid) next
		line = $0
		if (match(line, rrec)) {
			n = split(substr(line, RSTART + RLENGTH), fields, " ")
			valid = n == 15 && (fields[1] == "stage=" rorder[1] || fields[1] == "stage=" rorder[2])
			for (j = 1; j <= 14; j++)
				if (fields[j + 1] != bkeys[j] "=true" && fields[j + 1] != bkeys[j] "=false") valid = 0
			if (valid) {
				rec_n++
				rstage[fields[1]]++
				for (j = 1; j <= 14; j++)
					if (fields[j + 1] == bkeys[j] "=true") rflags[bkeys[j]]++
			} else rec_unparsed++
			next
		}
		if (!match(line, re)) next
		rest = substr(line, RSTART + RLENGTH)
		if (index(rest, "error_class=") == 1) {
			cls = typed_parse(rest)
			if (cls != "") {
				ecounts[g_idx, g_phase, cls]++
				etotal++
				val = quoted_legacy(g_ev)
				counts[g_idx, g_phase, g_qok ? legacy_class(val) : "unknown"]++
				if (g_qok && (v = migration_version(val)) > 0) versions[v]++
			}
		} else if (index(rest, "error=") == 1) {
			ev = substr(rest, length("error=") + 1)
			val = quoted_legacy(ev)
			if (g_qok) {
				cls = legacy_class(val)
				if ((v = migration_version(val)) > 0) versions[v]++
			} else {
				cls = "unknown"
			}
			counts[g_idx, g_phase, cls]++
			total++
		}
	}
	END {
		parse_name()
		if (!g_valid) exit
		printf "%d", total + etotal
		for (j = 1; j <= 10; j++) {
			c = order[j]
			k = g_idx SUBSEP g_phase SUBSEP c
			printf "\t%d", (k in counts ? counts[k] : 0)
		}
		for (j = 1; j <= 7; j++) {
			c = eorder[j]
			k = g_idx SUBSEP g_phase SUBSEP c
			printf "\t%d", (k in ecounts ? ecounts[k] : 0)
		}
		printf "\t{"
		sep = ""
		for (v = 1; v <= 110; v++)
			if (v in versions) { printf "%s\"v%d\":%d", sep, v, versions[v]; sep = "," }
		printf "}\t{\"records_n\":%d,\"unparsed\":%d", rec_n, rec_unparsed
		for (j = 1; j <= 2; j++) printf ",\"stage_%s\":%d", rorder[j], rstage["stage=" rorder[j]]
		for (j = 1; j <= 14; j++) printf ",\"%s\":%d", bkeys[j], rflags[bkeys[j]]
		printf "}\n"
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
			printf '%s\t%s\t0\t%s\t-1\t%s\t-1\t-1\n' "$idx" "$phase" "$reason" "$neg18" >>"$tmp/fatal.tsv"
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

jq -n --arg note "$recovery_note" --argjson classes "$classes_json" --argjson eclasses "$eclasses_json" --rawfile raw "$tmp/fatal.tsv" '
	def classes: $classes;
	def eclasses: $eclasses;
	def addcounts($a; $b): reduce ($b | to_entries[]) as $e ($a; .[$e.key] = ((.[$e.key] // 0) + $e.value));
	def row($r):
		if ($r[2] == "1") then
			{
				available: true,
				exit: ($r[4] | tonumber),
				fatal_n: ($r[5] | tonumber),
				counts: (reduce range(0; 10) as $i ({}; .[classes[$i]] = ($r[6 + $i] | tonumber))),
				error_class_counts: (reduce range(0; 7) as $i ({}; .[eclasses[$i]] = ($r[16 + $i] | tonumber))),
				migration_versions: ($r[23] | fromjson),
				recovery: ($r[24] | fromjson)
			}
		else
			{
				available: false,
				reason: (if $r[3] == "" then null else $r[3] end),
				exit: null,
				fatal_n: null,
				counts: null,
				error_class_counts: null,
				migration_versions: null,
				recovery: null
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
		recovery_coverage_note: $note,
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
			counts: (reduce ($rows[] | select(.[2] == "1")) as $r (reduce range(0; 10) as $i ({}; .[classes[$i]] = 0); reduce range(0; 10) as $i (.; .[classes[$i]] += ($r[6 + $i] | tonumber)))),
			error_class_counts: (reduce ($rows[] | select(.[2] == "1")) as $r (reduce range(0; 7) as $i ({}; .[eclasses[$i]] = 0); reduce range(0; 7) as $i (.; .[eclasses[$i]] += ($r[16 + $i] | tonumber)))),
			migration_versions: (reduce ($rows[] | select(.[2] == "1")) as $r ({}; addcounts(.; ($r[23] | fromjson)))),
			recovery: (reduce ($rows[] | select(.[2] == "1")) as $r ({}; addcounts(.; ($r[24] | fromjson))))
		},
		complete: (([$rows[] | select(.[2] == "1")] | length) == 6)
	}
'
