package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"time"
	_ "time/tzdata" // Validate IANA zones in the scratch container too.
	"unicode"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/i18n"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/recovery"
)

// UserCreateRequest follows the administrator endpoint, not public signup:
// no PoW, redirect, supplied password, enabled flag or client-chosen subject.
type UserCreateRequest struct {
	Email             string   `json:"email"`
	Language          string   `json:"language"`
	Roles             []string `json:"roles"`
	Groups            []string `json:"groups,omitempty"`
	PreferredUsername *string  `json:"preferred_username,omitempty"`
	GivenName         *string  `json:"given_name,omitempty"`
	FamilyName        *string  `json:"family_name,omitempty"`
	UserExpires       *int64   `json:"user_expires,omitempty"`
	Timezone          *string  `json:"tz,omitempty"`
	Mode              *string  `json:"mode,omitempty"`
}

// BindUserCreation is startup-only. It does not enable public registration.
func (h *Handler) BindUserCreation(service *recovery.Service, ttl time.Duration) error {
	if service == nil || ttl < time.Minute || ttl > 7*24*time.Hour {
		return ErrInvalid
	}
	h.userCreation, h.passwordNewTTL = service, ttl
	return nil
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.methodNotAllowed(w)
		return
	}
	if h.crossSite(r) {
		h.genericUnauthorized(w)
		return
	}
	actor, key, ok := h.principalFor(w, r, true, "Users", apikey.Create, true)
	if !ok {
		return
	}
	input, err := decodeUserCreate(w, r, h.userValuesPolicy.PreferredUsername)
	if err != nil {
		h.badRequest(w)
		return
	}
	if h.userCreation == nil {
		h.error(w, http.StatusServiceUnavailable, "Service Unavailable")
		return
	}
	var guard string
	var args []any
	if key != nil {
		guard, args = h.store.apiKeys.AuthorizationGuard(*key, "Users", apikey.Create)
	} else {
		name, _ := browser.CookieName(h.issuer)
		cookie, err := r.Cookie(name)
		if err != nil {
			h.genericUnauthorized(w)
			return
		}
		peer := browser.PeerIPFromContext(r.Context())
		session, err := h.browser.LoadSessionForPeer(r.Context(), cookie.Value, peer)
		if err != nil || !session.Authenticated() || session.Subject != actor {
			h.genericUnauthorized(w)
			return
		}
		guard, args = h.browser.SessionAuthorizationGuard(session, peer)
		policy, policyArgs := userCreationAuthority(actor, input.Roles, input.Groups)
		guard += " AND (" + policy + ")"
		args = append(args, policyArgs...)
	}
	if h.beforeUserCreate != nil {
		h.beforeUserCreate()
	}
	isPasskeyOnly := input.Mode != nil && *input.Mode == "passkey"
	if isPasskeyOnly && h.passkeyService == nil {
		h.error(w, http.StatusServiceUnavailable, "Service Unavailable")
		return
	}
	if isPasskeyOnly {
		subject, err := h.userCreation.CreatePasskeyOnlyUser(r.Context(), identity.UserCreation{OpenRegistration: identity.OpenRegistration{
			Email: input.Email, Language: input.Language, SourceIP: browser.PeerIPFromContext(r.Context()),
			PreferredUsernamePolicy: h.userValuesPolicy.PreferredUsername,
		}, Roles: input.Roles, Groups: input.Groups}, guard, args)
		if err != nil {
			switch {
			case errors.Is(err, identity.ErrCreateUnauthorized):
				h.error(w, http.StatusForbidden, "Forbidden")
			case errors.Is(err, identity.ErrCreateConflict):
				h.error(w, http.StatusNotAcceptable, "Not Acceptable")
			default:
				h.error(w, http.StatusServiceUnavailable, "Service Unavailable")
			}
			return
		}
		credOpts, _, _, err := h.passkeyService.BeginRegistration(r.Context(), subject, "", "admin-provisioned", "")
		if err != nil {
			h.error(w, http.StatusServiceUnavailable, "Service Unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"subject": subject, "credential_creation_options": credOpts})
		return
	}
	creation := identity.UserCreation{OpenRegistration: identity.OpenRegistration{
		Email: input.Email, Language: input.Language, TTL: h.passwordNewTTL, SourceIP: browser.PeerIPFromContext(r.Context()),
		PreferredUsernamePolicy: h.userValuesPolicy.PreferredUsername,
	}, Roles: input.Roles, Groups: input.Groups}
	if creation.SourceIP == "" {
		creation.SourceIP, _ = loginpolicy.PeerIP(r.RemoteAddr)
	}
	if input.PreferredUsername != nil {
		creation.PreferredUsername = *input.PreferredUsername
	}
	if input.GivenName != nil {
		creation.GivenName = *input.GivenName
	}
	if input.FamilyName != nil {
		creation.FamilyName = *input.FamilyName
	}
	if input.UserExpires != nil {
		ms := *input.UserExpires * 1000
		creation.UserExpires = &ms
	}
	if input.Timezone != nil && *input.Timezone != "UTC" && *input.Timezone != "Etc/UTC" {
		values, _ := json.Marshal(map[string]string{"tz": *input.Timezone})
		creation.UserValuesJSON = string(values)
	}
	result, err := h.userCreation.CreateUser(r.Context(), creation, guard, args)
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrCreateUnauthorized):
			h.error(w, http.StatusForbidden, "Forbidden")
		case errors.Is(err, identity.ErrCreateConflict):
			h.error(w, http.StatusNotAcceptable, "Not Acceptable")
		default:
			h.error(w, http.StatusServiceUnavailable, "Service Unavailable")
		}
		return
	}
	// Users/create includes its own result, even for a key without Users/read.
	user, _, status, err := h.store.detailUser(r.Context(), actor, result.Subject, guard, args, key != nil)
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	if status != http.StatusOK {
		h.error(w, status, http.StatusText(status))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(user)
}

// Snapshot the full input authorization before adding any target memberships.
// A delegated creator needs no roles and at least one existing managed group;
// every requested group must be in scope, including unknown names.
func userCreationAuthority(actor string, roles, groups []string) (string, []any) {
	guard, args := adminGuard(), []any{actor}
	if len(roles) != 0 || len(groups) == 0 {
		return guard, args
	}
	delegated, values := delegatedAdminGuard(), []any{actor}
	delegated += ` AND EXISTS(SELECT 1 FROM rbac_groups WHERE name IN (` + namesPlaceholders(groups) + `))`
	values = append(values, stringsAny(groups)...)
	for _, group := range groups {
		delegated += ` AND EXISTS(SELECT 1 FROM rbac_user_roles m JOIN rbac_roles r ON r.id=m.role_id
		 WHERE m.subject=? AND substr(r.name,1,13)='rauthy_admin:' AND
		 (substr(r.name,14)=? OR (substr(r.name,-1)='*' AND substr(?,1,length(r.name)-14)=substr(r.name,14,length(r.name)-14))))`
		values = append(values, actor, group, group)
	}
	return guard + " OR (" + delegated + ")", append(args, values...)
}

func decodeUserCreate(w http.ResponseWriter, r *http.Request, policy *identity.PreferredUsernamePolicy) (UserCreateRequest, error) {
	var input UserCreateRequest
	if r.URL.RawQuery != "" || len(r.Header.Values("Content-Type")) != 1 {
		return input, ErrInvalid
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return input, ErrInvalid
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminRequestLimit)
	body, err := io.ReadAll(r.Body)
	if err != nil || !utf8.Valid(body) || rejectDuplicateJSONFields(body) != nil {
		return input, ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return input, ErrInvalid
	}
	for key := range fields {
		switch key {
		case "email", "language", "roles", "groups", "preferred_username", "given_name", "family_name", "user_expires", "tz", "mode":
		default:
			return input, ErrInvalid
		}
	}
	for _, key := range []string{"email", "language", "roles"} {
		if len(fields[key]) == 0 || bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) {
			return input, ErrInvalid
		}
	}
	if json.Unmarshal(body, &input) != nil || !i18n.ValidUserLanguage(input.Language) {
		return input, ErrInvalid
	}
	if input.Email, err = identity.CanonicalEmail(input.Email); err != nil {
		return input, ErrInvalid
	}
	if input.Roles, err = canonicalNames(input.Roles, false); err != nil {
		return input, err
	}
	if input.Groups, err = canonicalNames(input.Groups, true); err != nil {
		return input, err
	}
	if input.UserExpires != nil && (*input.UserExpires < 1719784800 || *input.UserExpires > math.MaxInt64/1000) {
		return input, ErrInvalid
	}
	if policy.ValidateSyntax(input.PreferredUsername) != nil {
		return input, ErrInvalid
	}
	for _, value := range []*string{input.GivenName, input.FamilyName} {
		if value != nil && !validCreateName(*value) {
			return input, ErrInvalid
		}
	}
	if input.Timezone != nil {
		zone := *input.Timezone
		if zone == "" || zone == "Local" || len(zone) > 48 {
			return input, ErrInvalid
		}
		if _, err := time.LoadLocation(zone); err != nil {
			return input, ErrInvalid
		}
	}
	return input, nil
}

func validCreateName(value string) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) < 1 || utf8.RuneCountInString(value) > 32 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r >= 'À' && r <= 'ɏ' || r == '-' || r == '\'' || unicode.IsSpace(r) ||
			r >= 0x3041 && r <= 0x3096 || r >= 0x30a0 && r <= 0x30ff || r >= 0x3400 && r <= 0x4db5 || r >= 0x4e00 && r <= 0x9fcb || r >= 0xf900 && r <= 0xfa6a || r >= 0x2e80 && r <= 0x2fd5 || r >= 0xff66 && r <= 0xff9f || r >= 0xffa1 && r <= 0xffdc || r >= 0x31f0 && r <= 0x31ff) {
			return false
		}
	}
	return true
}
