package rbac

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
)

// UpdateUser handles the administrator PUT /auth/v1/users/{subject} boundary.
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
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
	actor, key, ok := h.principalFor(w, r, true, "Users", apikey.Update, true)
	if !ok {
		return
	}
	target := r.PathValue("subject")
	if !validSubjectID(target) {
		h.notFound(w)
		return
	}
	input, err := decodeUserUpdate(w, r)
	if err != nil {
		h.badRequest(w)
		return
	}
	if h.userValuesPolicy.ValidateFields(input.GivenName, input.FamilyName, input.UserValues) != nil {
		h.badRequest(w)
		return
	}

	guard, args, api := h.userUpdateGuard(r, actor, key)
	// This preflight intentionally uses only the session/key guard. Mutation
	// authority stays inside UpdateUserWithGuard and is evaluated at commit.
	_, _, status, err := h.store.detailUser(r.Context(), actor, target, guard, args, api)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	if status != http.StatusOK {
		h.error(w, status, http.StatusText(status))
		return
	}

	values := ""
	if input.UserValues != nil {
		encoded, _ := json.Marshal(input.UserValues)
		values = string(encoded)
	}
	update := identity.UserUpdate{
		Email: input.Email, GivenName: input.GivenName, FamilyName: input.FamilyName,
		Language: input.Language, Password: input.Password, Roles: input.Roles,
		Enabled: input.Enabled, EmailVerified: input.EmailVerified,
		UserValuesJSON: values, SourceIP: browser.PeerIPFromContext(r.Context()),
	}
	if input.Groups != nil {
		update.Groups = *input.Groups
	}
	if update.SourceIP == "" {
		update.SourceIP, _ = loginpolicy.PeerIP(r.RemoteAddr)
	}
	if input.UserExpires != nil {
		ms := *input.UserExpires * 1000
		update.UserExpires = &ms
	}

	if h.beforeUserUpdate != nil {
		h.beforeUserUpdate()
	}
	result, err := h.identity.UpdateUserWithGuard(r.Context(), target, update, func() (string, []any) {
		if key != nil {
			return h.store.apiKeys.AuthorizationGuard(*key, "Users", apikey.Update)
		}
		freshGuard, freshArgs := h.userUpdateSessionGuard(r, actor)
		policy, policyArgs := userUpdateAuthority(actor, target, input.Roles, update.Groups)
		return freshGuard + " AND (" + policy + ")", append(freshArgs, policyArgs...)
	})
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrUpdateUnauthorized):
			h.error(w, http.StatusForbidden, "Forbidden")
		case errors.Is(err, identity.ErrUpdateConflict):
			h.error(w, http.StatusConflict, "Conflict")
		case errors.Is(err, identity.ErrInvalidUserUpdate), errors.Is(err, identity.ErrPasswordRejected), errors.Is(err, identity.ErrPasswordReuse):
			h.badRequest(w)
		default:
			h.error(w, http.StatusServiceUnavailable, "Service Unavailable")
		}
		return
	}
	result.User.PasswordExpires = h.identity.PasswordExpiresAt(result.PasswordChanged)
	if h.OnUserUpdated != nil {
		h.OnUserUpdated(r.Context(), result)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result.User)
}

// SetUserValuesPolicy configures both standalone and HA HTTP boundaries before
// serving. Every node must use the same immutable deployment configuration.
func (h *Handler) SetUserValuesPolicy(policy identity.UserValuesPolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	h.userValuesPolicy = policy
	return nil
}

func (h *Handler) userUpdateGuard(r *http.Request, actor string, key *apikey.Principal) (string, []any, bool) {
	if key != nil {
		guard, args := h.store.apiKeys.AuthorizationGuard(*key, "Users", apikey.Update)
		return guard, args, true
	}
	guard, args := h.userUpdateSessionGuard(r, actor)
	return guard, args, false
}

func (h *Handler) userUpdateSessionGuard(r *http.Request, actor string) (string, []any) {
	name, _ := browser.CookieName(h.issuer)
	cookie, err := r.Cookie(name)
	if err != nil {
		return "0", nil
	}
	peer := browser.PeerIPFromContext(r.Context())
	session, err := h.browser.LoadSessionForPeer(r.Context(), cookie.Value, peer)
	if err != nil || !session.Authenticated() || session.Subject != actor {
		return "0", nil
	}
	return h.browser.SessionAuthorizationGuard(session, peer)
}
