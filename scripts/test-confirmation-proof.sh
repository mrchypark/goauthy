#!/bin/sh
# Test-only overlays: intercept the real creator request without production hooks.
# Requires Go, awk and jq. Does not edit dependency sources or another checkout.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
# Optional first argument enables only the login E2E diagnostic overlay.
login_e2e_diagnostics=0
if [ "${1-}" = --login-e2e-diagnostics ]; then
	login_e2e_diagnostics=1
	shift
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
baseline_ref=${CONFIRMATION_BASELINE_REF:-}
if [ -n "$baseline_ref" ]; then
	# Pin both production call sites to the same commit for handler measurements.
	git show "$baseline_ref:internal/browser/store.go" > "$tmp/store-source.go"
	git show "$baseline_ref:internal/login/handler.go" > "$tmp/handler.go"
elif [ "${CONFIRMATION_BASELINE:-0}" = 1 ]; then
	git show a4515ac517affedf55f073d625d91c9a3d4b17cc:internal/browser/store.go > "$tmp/store-source.go"
	cp internal/login/handler.go "$tmp/handler.go"
else
	cp internal/browser/store.go "$tmp/store-source.go"
	cp internal/login/handler.go "$tmp/handler.go"
fi
awk '{gsub(/storage.Execute\(ctx, s.db,/, "confirmationExecute(ctx, s.db,"); gsub(/s.db.Query\(ctx,/, "confirmationQuery(ctx, s.db,"); print}' "$tmp/store-source.go" > "$tmp/store.go"
# Leave the import used even if future source changes remove unrelated calls.
printf '\nvar _ = storage.Execute\n' >> "$tmp/store.go"
# Coverage also builds the non-test package. Put the test-only wrappers in the
# virtual production file and remove their duplicate declarations from the test.
awk '/^type confirmationKey / {copy=1} /^func confirmationFixture/ {copy=0} copy {print}' internal/browser/confirmation_overlay_test.go >> "$tmp/store.go"
awk '/^type confirmationKey / {skip=1} /^func confirmationFixture/ {skip=0} !skip {print}' internal/browser/confirmation_overlay_test.go | sed '/^[[:space:]]*"strings"$/d' > "$tmp/confirmation_overlay_test.go"
awk '{gsub(/db.Execute\(ctx, request\)/, "confirmationRecoveryExecute(ctx, db, request)"); print}' internal/storage/migrate.go > "$tmp/migrate.go"
if [ "$login_e2e_diagnostics" = 1 ]; then
	if [ "${CONFIRMATION_RECOVERY_OVERLAY:-0}" = 1 ]; then
		echo "--login-e2e-diagnostics cannot be combined with CONFIRMATION_RECOVERY_OVERLAY=1" >&2
		exit 2
	fi
	awk '
	BEGIN { begin="// BEGIN_E2E_DIAGNOSTIC_HELPERS"; end="// END_E2E_DIAGNOSTIC_HELPERS" }
	$0 == begin { begins++; if (inside) bad=1; inside=1; next }
	$0 == end { ends++; if (!inside) bad=1; inside=0; next }
	inside { print }
	END { if (begins != 1 || ends != 1 || inside || bad) exit 1 }
	' internal/login/end_to_end_cost_test.go > "$tmp/e2e-diagnostic-helpers.go" || {
		echo "expected exactly one well-formed E2E diagnostic helper marker block" >&2
		exit 2
	}
	awk '
	BEGIN { begin="// BEGIN_E2E_DIAGNOSTIC_HELPERS"; end="// END_E2E_DIAGNOSTIC_HELPERS" }
	$0 == begin { begins++; if (inside) bad=1; inside=1; next }
	$0 == end { ends++; if (!inside) bad=1; inside=0; next }
	!inside { print }
	END { if (begins != 1 || ends != 1 || inside || bad) exit 1 }
	' internal/login/end_to_end_cost_test.go > "$tmp/end_to_end_cost_test.go" || {
		echo "expected exactly one well-formed E2E diagnostic helper marker block" >&2
		exit 2
	}
	cat > "$tmp/instrument-login-handler.awk" <<'AWK'
{ source[NR] = $0 }
END {
	function_count = 0
	for (i = 1; i <= NR; i++) {
		if (index(source[i], "func (h *Handler) authenticatePassword(") == 1) {
			auth_start = i
			function_count++
		}
	}
	if (function_count != 1) fail("authenticatePassword function anchor")
	auth_end = NR
	for (i = auth_start + 1; i <= NR; i++) {
		if (index(source[i], "func ") == 1) { auth_end = i - 1; break }
	}

	credential_import_count = 0
	for (i = 1; i <= NR; i++) {
		if (source[i] == "\t\"github.com/mrchypark/goauthy/internal/browser\"") {
			credential_import_line = i
			credential_import_count++
		}
		if (source[i] == "\t\"github.com/mrchypark/goauthy/internal/credential\"") credential_already_imported++
	}
	if (credential_import_count != 1 || credential_already_imported != 0) fail("virtual credential import anchor")
	insert[credential_import_line] = "IMPORT_CREDENTIAL"

	call_line = find_anchor("auth", "auth, err := h.identity.Authenticate(r.Context(), username, []byte(password))")
	invalid_line = find_anchor("auth", "if errors.Is(err, identity.ErrInvalidCredentials) {")
	depth = 0
	invalid_end = 0
	for (i = invalid_line; i <= auth_end; i++) {
		depth += brace_delta(source[i])
		if (i > invalid_line && depth == 0) { invalid_end = i; break }
	}
	if (invalid_end == 0) fail("invalid-credentials branch boundary")
	service_branch_count = 0
	for (i = invalid_end + 1; i + 3 <= auth_end; i++) {
		if (source[i] == "\tif err != nil {" &&
			source[i+1] == "\t\thttp.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)" &&
			source[i+2] == "\t\treturn identity.Authentication{}, \"\", time.Time{}, false" &&
			source[i+3] == "\t}") {
			insert[i] = "CLASSIFY_IDENTITY_ERROR"
			service_branch_count++
		}
	}
	if (service_branch_count != 1) fail("unclassified Authenticate 503 branch")
	if (call_line >= invalid_line || invalid_line >= invalid_end) fail("Authenticate classification order")

	policy_check = find_anchor("auth", "status, err := h.policy.Check(r.Context(), peerIP, h.now().UTC())")
	policy_allow = find_anchor("auth", "allowed, err := h.policy.Allow(r.Context(), peerIP, h.now().UTC())")
	policy_check_guard = find_next(policy_check, policy_allow, "\t\tif err != nil {")
	insert[policy_check_guard] = "RECORD_POLICY_ERROR"
	policy_lock = find_anchor("auth", "locked, remaining, lockErr := h.policy.CheckAccountLock(r.Context(), accountHash, h.now().UTC())")
	policy_allow_guard = find_next(policy_allow, policy_lock, "\t\tif err != nil {")
	insert[policy_allow_guard] = "RECORD_POLICY_ERROR"
	policy_lock_guard = find_next(policy_lock, call_line, "\t\tif lockErr != nil {")
	insert[policy_lock_guard] = "RECORD_POLICY_ERROR"
	policy_failure = find_anchor("auth", "status, policyErr := h.policy.Failure(r.Context(), peerIP, h.now().UTC())")
	policy_account = find_anchor("auth", "if _, _, accountErr := h.policy.RecordAccountFailure(r.Context(), accountHash, peerIP, h.now().UTC()); accountErr != nil {")
	policy_failure_guard = find_next(policy_failure, policy_account, "\t\t\tif policyErr != nil {")
	insert[policy_failure_guard] = "RECORD_POLICY_ERROR_DEEP"
	insert[policy_account] = "RECORD_POLICY_ERROR_DEEP"

	session_line = find_anchor("session", "newSession, err = h.browser.CreatePasswordSession(r.Context(), subject, authMethod, passwordGeneration, authenticationGeneration, h.now().Add(sessionLifetime), peerIP, sessionToken)")
	insert[session_line] = "RECORD_SESSION_ERROR"
	success_line = find_anchor("success", "successErr := h.policy.Success(ctx, peerIP, elapsed)")
	insert[success_line] = "RECORD_SUCCESS_ERROR"

	for (i = 1; i <= NR; i++) {
		print source[i]
		if (insert[i] == "IMPORT_CREDENTIAL") print "\t\"github.com/mrchypark/goauthy/internal/credential\""
		else if (insert[i] == "CLASSIFY_IDENTITY_ERROR") {
			print "\t\tif errors.Is(err, credential.ErrWorkLimit) {"
			print "\t\t\trecordE2EDiagnostic(r.Context(), e2eDiagnosticKDFWorkLimit)"
			print "\t\t} else {"
			print "\t\t\trecordE2EDiagnostic(r.Context(), e2eDiagnosticIdentityOther)"
			print "\t\t}"
		} else if (insert[i] == "RECORD_POLICY_ERROR") print "\t\t\trecordE2EDiagnostic(r.Context(), e2eDiagnosticPolicyError)"
		else if (insert[i] == "RECORD_POLICY_ERROR_DEEP") print "\t\t\t\trecordE2EDiagnostic(r.Context(), e2eDiagnosticPolicyError)"
		else if (insert[i] == "RECORD_SESSION_ERROR") {
			print "\t\tif err != nil { recordE2EDiagnostic(r.Context(), e2eDiagnosticSessionWriteError) }"
		} else if (insert[i] == "RECORD_SUCCESS_ERROR") {
			print "\tif successErr != nil { recordE2EDiagnostic(ctx, e2eDiagnosticPolicyError) }"
		}
	}
	if (failed) exit 2
}
function fail(message) {
	print "login E2E diagnostic overlay anchor mismatch: " message > "/dev/stderr"
	failed = 1
	exit 2
}
function find_anchor(scope, needle,    first,last,count,i) {
	first = scope == "auth" ? auth_start : scope == "session" ? session_start : scope == "success" ? success_start : 1
	last = scope == "auth" ? auth_end : scope == "session" ? session_end : scope == "success" ? success_end : NR
	if (scope == "session" || scope == "success") {
		count = 0
		for (i = 1; i <= NR; i++) {
			if (index(source[i], scope == "session" ? "func (h *Handler) rotateBrowserSessionWithParent(" : "func (h *Handler) recordSuccessfulAuthentication(") == 1) {
				first = i
				count++
			}
		}
		if (count != 1) fail(scope " function anchor")
		last = NR
		for (i = first + 1; i <= NR; i++) {
			if (index(source[i], "func ") == 1) { last = i - 1; break }
		}
	}
	count = 0
	for (i = first; i <= last; i++) if (index(source[i], needle) > 0) { found = i; count++ }
	if (count != 1) fail(scope " anchor count for: " needle)
	return found
}
function find_next(after, before, needle,    count,i) {
	count = 0
	for (i = after + 1; i < before; i++) {
		if (source[i] == needle) { found = i; count++ }
	}
	if (count != 1) fail("error-branch anchor count between lines " after " and " before " for: " needle)
	return found
}
function brace_delta(text,    opened,closed) {
	opened = gsub(/\{/, "&", text)
	closed = gsub(/\}/, "&", text)
	return opened - closed
}
AWK
	awk -f "$tmp/instrument-login-handler.awk" "$tmp/handler.go" > "$tmp/handler.instrumented.go" || exit 2
	mv "$tmp/handler.instrumented.go" "$tmp/handler.go"
	cat "$tmp/e2e-diagnostic-helpers.go" >> "$tmp/handler.go"
fi
jq -n --arg recovery "${CONFIRMATION_RECOVERY_OVERLAY:-0}" --arg diagnostics "$login_e2e_diagnostics" --arg store "$root/internal/browser/store.go" --arg newstore "$tmp/store.go" --arg test "$root/internal/browser/confirmation_overlay_test.go" --arg newtest "$tmp/confirmation_overlay_test.go" --arg handler "$root/internal/login/handler.go" --arg newhandler "$tmp/handler.go" --arg migrate "$root/internal/storage/migrate.go" --arg newmigrate "$tmp/migrate.go" --arg loginTest "$root/internal/login/end_to_end_cost_test.go" --arg newLoginTest "$tmp/end_to_end_cost_test.go" '{Replace: (if $recovery == "1" then {($migrate):$newmigrate} else {($store):$newstore,($test):$newtest,($handler):$newhandler} + (if $diagnostics == "1" then {($loginTest):$newLoginTest} else {} end) end)}' > "$tmp/overlay.json"
go test -overlay="$tmp/overlay.json" -tags=confirmationproof "$@"
