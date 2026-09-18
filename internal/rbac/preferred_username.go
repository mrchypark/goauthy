package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type preferredUsernameRequest struct {
	PreferredUsername *string `json:"preferred_username"`
	ForceOverwrite    *bool   `json:"force_overwrite"`
}

func decodePreferredUsername(w http.ResponseWriter, r *http.Request) (preferredUsernameRequest, error) {
	var input preferredUsernameRequest
	if r.URL.RawQuery != "" || len(r.Header.Values("Content-Type")) != 1 {
		return input, ErrInvalid
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return input, ErrInvalid
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, adminRequestLimit))
	if err != nil || !utf8.Valid(body) || rejectDuplicateJSONFields(body) != nil {
		return input, ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return input, ErrInvalid
	}
	for key := range fields {
		if key != "preferred_username" && key != "force_overwrite" {
			return input, ErrInvalid
		}
	}
	if json.Unmarshal(body, &input) != nil {
		return input, ErrInvalid
	}
	return input, nil
}

// UpdatePreferredUsername accepts self-service sessions as well as Users:update
// keys and administrators. An explicit Authorization header never falls back
// to the ambient cookie, even when its key has insufficient rights.
func (h *Handler) UpdatePreferredUsername(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", http.MethodPut)
		h.methodNotAllowed(w)
		return
	}
	if h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	var actor string
	var key *apikey.Principal
	if apikey.HasAuthorization(r) {
		var ok bool
		actor, key, ok = h.principalFor(w, r, true, "Users", apikey.Update, true)
		if !ok {
			return
		}
	} else {
		name, _ := browser.CookieName(h.issuer)
		cookie, err := r.Cookie(name)
		if err != nil || cookie.Value == "" || browser.ValidateCSRFToken(cookie.Value, r.Header.Get("X-CSRF-Token")) != nil {
			h.genericUnauthorized(w)
			return
		}
		session, err := h.browser.LoadSessionForPeer(r.Context(), cookie.Value, browser.PeerIPFromContext(r.Context()))
		if err != nil || !session.Authenticated() {
			h.genericUnauthorized(w)
			return
		}
		actor = session.Subject
	}
	input, err := decodePreferredUsername(w, r)
	target := r.PathValue("subject")
	if err != nil || !validSubjectID(target) || h.userValuesPolicy.PreferredUsername.ValidateSyntax(input.PreferredUsername) != nil {
		h.badRequest(w)
		return
	}
	if h.beforePreferredUsernameUpdate != nil {
		h.beforePreferredUsernameUpdate()
	}
	guard, args, _ := h.userUpdateGuard(r, actor, key)
	status, err := h.store.updatePreferredUsername(r.Context(), actor, target, input, h.userValuesPolicy.PreferredUsername, guard, args, key != nil)
	if err != nil {
		h.unavailable(w)
		return
	}
	if status != http.StatusOK {
		h.error(w, status, http.StatusText(status))
		return
	}
	w.WriteHeader(http.StatusOK)
}

// The decision and conditional write run in the same Rhiza SQL transaction.
// No application preflight can authorize a stale role, group, name or key.
// Evaluating the same predicate twice is safe: there are no intervening writes.
func (s *Store) updatePreferredUsername(ctx context.Context, actor, target string, input preferredUsernameRequest, policy *identity.PreferredUsernamePolicy, guard string, args []any, api bool) (int, error) {
	if !validSubjectID(target) || strings.TrimSpace(guard) == "" || strings.Contains(guard, ";") {
		return 0, ErrInvalid
	}
	force := input.ForceOverwrite != nil && *input.ForceOverwrite
	decision := `CASE WHEN NOT (` + guard + `) THEN 401 `
	values := append([]any{}, args...)
	if !api {
		if force {
			decision += `WHEN NOT (` + adminGuard() + `) THEN 403 `
			values = append(values, actor)
		}
		decision += `WHEN NOT (?=? OR ` + adminGuard() + ` OR ` + delegatedAdminGuard() + `) THEN 403 `
		values = append(values, actor, target, actor, actor)
	}
	decision += `WHEN NOT EXISTS(SELECT 1 FROM identity_users WHERE subject=?) THEN 404 `
	values = append(values, target)
	if !api {
		decision += `WHEN NOT (?=? OR ` + adminGuard() + `) THEN CASE
		 WHEN EXISTS(SELECT 1 FROM rbac_user_roles m JOIN rbac_roles r ON r.id=m.role_id WHERE m.subject=? AND (r.name='rauthy_admin' OR substr(r.name,1,13)='rauthy_admin:')) THEN 403
		 WHEN NOT EXISTS(SELECT 1 FROM rbac_user_groups tm JOIN rbac_groups g ON g.id=tm.group_id WHERE tm.subject=? AND ` + userUpdateGroupScope("g.name") + `) THEN 428
		 WHEN EXISTS(SELECT 1 FROM identity_user_profiles WHERE subject=? AND preferred_username IS NOT NULL) THEN 403
		 ELSE 200 END ELSE 200 END`
		values = append(values, actor, target, actor, target, target, actor, target)
	} else {
		decision += `ELSE 200 END`
	}
	// Configuration checks apply to every actor, including forced admin edits.
	policyStatus := 200
	if err := policy.ValidateRegistration(input.PreferredUsername); err != nil {
		policyStatus = 400
		if errors.Is(err, identity.ErrPreferredUsernameUnavailable) {
			policyStatus = 406
		}
	}
	var name any
	if input.PreferredUsername != nil && *input.PreferredUsername != "" {
		name = *input.PreferredUsername
	}
	// Legacy accounts can lack a profile and recovery email. Do not invent an
	// email to satisfy the profile constraint; clearing a missing row is a no-op.
	authorityDecision := decision
	decision = `SELECT CASE WHEN status<>200 THEN status
	 WHEN ?<>200 THEN ?
	 WHEN ? AND EXISTS(SELECT 1 FROM identity_user_profiles WHERE subject=? AND preferred_username IS NOT NULL) THEN 400
	 WHEN EXISTS(SELECT 1 FROM identity_user_profiles WHERE preferred_username=? AND subject<>?) THEN 406
	 WHEN ? IS NOT NULL AND NOT EXISTS(SELECT 1 FROM identity_user_profiles WHERE subject=?) AND NOT EXISTS(SELECT 1 FROM identity_recovery_emails WHERE subject=?) THEN 409
	 ELSE 200 END FROM (SELECT ` + authorityDecision + ` AS status)`
	values = append([]any{policyStatus, policyStatus, policy.Immutable() && !force, target, name, target, name, target, target}, values...)
	nonce, err := s.randomID()
	if err != nil {
		return 0, err
	}
	one := int64(1)
	write := `INSERT INTO identity_user_profiles(subject,email,preferred_username)
	 SELECT u.subject,COALESCE(p.email,re.email),? FROM identity_users u
	 LEFT JOIN identity_user_profiles p ON p.subject=u.subject
	 LEFT JOIN identity_recovery_emails re ON re.subject=u.subject
	 WHERE u.subject=? AND (p.subject IS NOT NULL OR re.subject IS NOT NULL) AND (` + decision + `)=200
	 ON CONFLICT(subject) DO UPDATE SET preferred_username=excluded.preferred_username`
	result, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID("preferred-username", target, nonce), Statements: []rhiza.SQLStatement{
		{SQL: decision, Args: values, WantRows: true, ExpectedReturnedRows: &one},
		{SQL: write, Args: append([]any{name, target}, values...)},
	}})
	if err != nil {
		return 0, err
	}
	if len(result.Statements) != 2 || len(result.Statements[0].Rows) != 1 || len(result.Statements[0].Rows[0]) != 1 {
		return 0, errors.New("invalid preferred username result")
	}
	status, ok := result.Statements[0].Rows[0][0].(int64)
	if !ok {
		return 0, errors.New("invalid preferred username status")
	}
	return int(status), nil
}
