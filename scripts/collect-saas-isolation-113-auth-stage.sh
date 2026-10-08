#!/bin/sh
# Privacy-safe extractor for the GoAuthy authentication-stage metrics.
#
# Reads one Prometheus text exposition stream on stdin (the body served by the
# native per-pod metrics listener) and writes one bounded JSON summary on
# stdout. Only the exact authentication-stage histogram and canceled-completion
# counter families with the fixed issue #113 stage labels are read. Everything
# else is discarded without being copied, so raw exposition never leaves.
#
# Fail closed on malformed known-family data. An absent family is valid and
# yields an empty map; the cancellation counter is a lazy CounterVec.
set -eu
umask 077

usage() {
	echo "usage: $0 POD_INDEX CAPTURED_AT_UNIX_MS < prometheus.txt" >&2
	exit 2
}

[ "$#" -eq 2 ] || usage
pod_index=$1
captured_at=$2
case "$pod_index" in
	0|1|2) ;;
	*) echo "pod index must be 0, 1, or 2" >&2; exit 1 ;;
esac
case "$captured_at" in
	''|*[!0-9]*) echo "captured_at_unix_ms must be a non-negative integer" >&2; exit 1 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

cat >"$tmp/filter.awk" <<'AWK'
function allowed_stage(s) {
	return (s == "credential_lookup" || s == "password_verify" ||
		s == "subject_revalidate" || s == "interaction_consume" ||
		s == "session_rotate" || s == "oauth_issue" ||
		s == "authorize_validate" || s == "authorize_session" ||
		s == "policy_check" || s == "policy_allow" ||
		s == "policy_account_lock" || s == "policy_success")
}
function split_labels(labels, segs,   i, n, c, inq, esc, cnt, cur) {
	n = length(labels); cnt = 0; cur = ""; inq = 0; esc = 0
	for (i = 1; i <= n; i++) {
		c = substr(labels, i, 1)
		if (inq) {
			cur = cur c
			if (esc) esc = 0
			else if (c == "\\") esc = 1
			else if (c == "\"") inq = 0
		} else if (c == "\"") {
			inq = 1; cur = cur c
		} else if (c == ",") {
			cnt++; segs[cnt] = cur; cur = ""
		} else {
			cur = cur c
		}
	}
	cnt++; segs[cnt] = cur
	return cnt
}
function label_value(labels, want,   segs, cnt, i, eqpos, key, val) {
	cnt = split_labels(labels, segs)
	for (i = 1; i <= cnt; i++) {
		eqpos = index(segs[i], "=")
		if (eqpos == 0) continue
		key = substr(segs[i], 1, eqpos - 1)
		if (key != want) continue
		val = substr(segs[i], eqpos + 1)
		if (length(val) >= 2 && substr(val, 1, 1) == "\"" && substr(val, length(val), 1) == "\"") {
			return substr(val, 2, length(val) - 2)
		}
		return ""
	}
	return ""
}
function valid_value(v) {
	return (v ~ /^[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$/)
}
function safe_counter(v,   epos, mantissa, exptext, sign, expdigits, exponent, dotpos, whole, fraction, digits, scale, cut, candidate) {
	if (length(v) > 32) return 0
	if (!valid_value(v)) return 0
	epos = match(v, /[eE]/)
	mantissa = epos ? substr(v, 1, epos - 1) : v
	exptext = epos ? substr(v, epos + 1) : "0"
	sign = 1
	if (substr(exptext, 1, 1) == "-") { sign = -1; exptext = substr(exptext, 2) }
	else if (substr(exptext, 1, 1) == "+") exptext = substr(exptext, 2)
	sub(/^0+/, "", exptext)
	if (exptext == "") exptext = "0"
	if (length(exptext) > 3) return 0
	exponent = sign * (exptext + 0)
	dotpos = index(mantissa, ".")
	if (dotpos) {
		whole = substr(mantissa, 1, dotpos - 1)
		fraction = substr(mantissa, dotpos + 1)
	} else { whole = mantissa; fraction = "" }
	digits = whole fraction
	sub(/^0+/, "", digits)
	if (digits == "") { normalized_counter = "0"; return 1 }
	scale = exponent - length(fraction)
	if (scale >= 0) {
		if (length(digits) + scale > 16) return 0
		candidate = digits (scale ? sprintf("%0*d", scale, 0) : "")
	} else {
		cut = -scale
		if (cut > length(digits)) return 0
		if (substr(digits, length(digits) - cut + 1) ~ /[^0]/) return 0
		candidate = substr(digits, 1, length(digits) - cut)
	}
	sub(/^0+/, "", candidate)
	if (candidate == "") candidate = "0"
	if (length(candidate) > 16 || (length(candidate) == 16 && candidate > "9007199254740991")) return 0
	normalized_counter = candidate
	return 1
}
function valid_le(v) {
	return (v == "+Inf" || v ~ /^[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$/)
}
{
	line = $0
	kind = ""
	if (line ~ /^goauthy_auth_stage_duration_seconds_bucket\{/) kind = "bucket"
	else if (line ~ /^goauthy_auth_stage_duration_seconds_sum\{/) kind = "sum"
	else if (line ~ /^goauthy_auth_stage_duration_seconds_count\{/) kind = "count"
	else if (line ~ /^goauthy_auth_stage_duration_seconds/) {
		print "malformed auth stage family line" > "/dev/stderr"; exit 1
	} else if (line ~ /^goauthy_auth_stage_canceled_completions_total\{/) {
		kind = "canceled"
	} else if (line ~ /^goauthy_auth_stage_canceled_completions_total/) {
		print "malformed auth stage counter family line" > "/dev/stderr"; exit 1
	} else next

	open = index(line, "{")
	if (open == 0) { print "missing auth stage label set" > "/dev/stderr"; exit 1 }
	rest = substr(line, open + 1)
	i = 1; inq = 0; esc = 0; endpos = 0
	while (i <= length(rest)) {
		c = substr(rest, i, 1)
		if (inq) {
			if (esc) esc = 0
			else if (c == "\\") esc = 1
			else if (c == "\"") inq = 0
		} else if (c == "\"") { inq = 1 }
		else if (c == "}") { endpos = i; break }
		i++
	}
	if (endpos == 0) { print "unterminated auth stage label set" > "/dev/stderr"; exit 1 }
	labels = substr(rest, 1, endpos - 1)
	stage = label_value(labels, "stage")
	if (stage == "" || !allowed_stage(stage)) {
		print "unknown or missing auth stage label" > "/dev/stderr"; exit 1
	}
	le = ""
	if (kind == "bucket") {
		le = label_value(labels, "le")
		if (!valid_le(le)) { print "invalid auth stage bucket le label" > "/dev/stderr"; exit 1 }
	}
	ntok = split_labels(labels, segs)
	stage_labels = 0
	for (i = 1; i <= ntok; i++) {
		eqpos = index(segs[i], "=")
		if (eqpos == 0) { print "malformed auth stage label" > "/dev/stderr"; exit 1 }
		key = substr(segs[i], 1, eqpos - 1)
		if (key == "stage") stage_labels++
		if (kind == "bucket") {
			if (key != "stage" && key != "le") { print "unexpected auth stage bucket label" > "/dev/stderr"; exit 1 }
		} else if (key != "stage") {
			print "unexpected auth stage label" > "/dev/stderr"; exit 1
		}
	}
	if (stage_labels != 1 || (kind == "canceled" && ntok != 1)) {
		print "invalid auth stage counter labels" > "/dev/stderr"; exit 1
	}
	tail = substr(rest, endpos + 1)
	gsub(/[ \t]+/, " ", tail); sub(/^ /, "", tail); sub(/ $/, "", tail)
	ntok = split(tail, tok, " ")
	value = ""
	if (ntok == 1) value = tok[1]
	else if (ntok == 2 && tok[2] ~ /^[0-9]+$/) value = tok[1]
	else { print "malformed auth stage value field" > "/dev/stderr"; exit 1 }
	if (kind == "canceled") {
		if (!safe_counter(value)) { print "invalid auth stage counter value" > "/dev/stderr"; exit 1 }
		value = normalized_counter
	} else if (!valid_value(value)) { print "non-numeric auth stage metric value" > "/dev/stderr"; exit 1 }
	key = stage SUBSEP kind SUBSEP le
	if (key in seen) { print "duplicate auth stage series" > "/dev/stderr"; exit 1 }
	seen[key] = 1
	print stage "\t" kind "\t" le "\t" value
}
AWK

awk -f "$tmp/filter.awk" >"$tmp/rows.tsv" || {
	echo "auth stage metrics rejected: malformed or unknown series" >&2
	exit 1
}

jq -R -s --argjson pod "$pod_index" --argjson captured "$captured_at" '
	def nonneg: type == "number" and isfinite and . >= 0;
	def is_int: type == "number" and isfinite and . >= 0 and (floor == .) and . <= 9007199254740991;
	def safe_counter_text:
		type == "string" and test("^[0-9]+$") and
		((ltrimstr("0") | if . == "" then "0" else . end) as $n |
			($n | length) < 16 or (($n | length) == 16 and $n <= "9007199254740991"));
	def allowed: ["credential_lookup","password_verify","subject_revalidate","interaction_consume","session_rotate","oauth_issue","authorize_validate","authorize_session","policy_check","policy_allow","policy_account_lock","policy_success"];
	split("\n") | map(select(length > 0)) | map(split("\t")) |
	map({stage: .[0], kind: .[1], le: .[2], raw_value: .[3], value: (.[3] | tonumber)}) |
	if (map(select((.stage as $s | allowed | index($s)) == null)) | length) > 0
		then error("unknown auth stage label") else . end |
	if (map(select((.value | nonneg) | not)) | length) > 0
		then error("negative or non-finite auth stage value") else . end |
	if ((map(select(.kind == "canceled" and ((.raw_value | safe_counter_text) | not))) | length) > 0)
		then error("invalid or unsafe auth stage counter") else . end |
	. as $rows |
	($rows | map(select(.kind != "canceled")) | group_by(.stage) |
	map(
		.[0].stage as $stage |
		([.[] | select(.kind == "count")] | length) as $counts |
		([.[] | select(.kind == "sum")] | length) as $sums |
		if ($counts != 1 or $sums != 1) then error("stage \($stage) must carry exactly one count and one sum") else . end |
		([.[] | select(.kind == "bucket")]) as $buckets |
		if (($buckets | length) == 0) then error("stage \($stage) has no buckets") else . end |
		([$buckets[] | select(.le == "+Inf")]) as $inf |
		if (($inf | length) != 1) then error("stage \($stage) must carry exactly one +Inf bucket") else . end |
		([.[] | select(.kind == "count")][0].value) as $count |
		if (($count | is_int) | not) then error("stage \($stage) count must be a non-negative integer") else . end |
		if ([$buckets[].value | is_int] | all) then . else error("stage \($stage) bucket values must be non-negative integers") end |
		if ($inf[0].value != $count) then error("stage \($stage) +Inf bucket must equal its count") else . end |
		([.[] | select(.kind == "sum")][0].value) as $sum |
		{
			key: $stage,
			value: {
				count: $count,
				sum: $sum,
				buckets: ([$buckets[] | {le: .le, value: .value}]
					| sort_by(if .le == "+Inf" then 1e300 else (.le | tonumber) end))
			}
		}
	) | from_entries) as $stage_map |
	($rows | map(select(.kind == "canceled") | {key: .stage, value: .value}) | from_entries) as $canceled_map |
	if (([$stage_map | to_entries[] | .value.buckets] | all(. as $b |
		([range(0; (($b | length) - 1)) as $i | ($b[$i].value <= $b[$i + 1].value)] | all))))
		then . else error("auth stage buckets must be non-decreasing") end |
	{
		schema_version: 2,
		family: "goauthy_auth_stage_duration_seconds",
		pod_index: $pod,
		captured_at_unix_ms: $captured,
		stages: $stage_map,
		canceled_completions: $canceled_map
	}
' "$tmp/rows.tsv"
