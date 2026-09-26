package login

import (
	"errors"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/i18n"
	"github.com/mrchypark/goauthy/internal/identity"
)

var profilePage = template.Must(template.New("profile").Parse(`<!doctype html><html lang="{{.Language}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="{{.IssuerPath}}/auth/v1/theme/global.css">{{if .ThemeURL}}<link rel="stylesheet" href="{{.ThemeURL}}">{{end}}<title>{{if eq .Language "ko"}}프로필 업데이트{{else}}Update Profile{{end}}</title></head><body class="auth-page"><header class="auth-brand"><span class="brand-symbol" aria-hidden="true"></span><span>GoAuthy</span></header><main class="auth-panel"><p class="auth-eyebrow">{{if eq .Language "ko"}}내 계정{{else}}YOUR ACCOUNT{{end}}</p><h1>{{if eq .Language "ko"}}프로필 업데이트{{else}}Update Profile{{end}}</h1>{{if .Error}}<p class="auth-error" role="alert">{{.Error}}</p>{{end}}<form method="post" action=""><input type="hidden" name="interaction" value="{{.Interaction}}"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}">{{range .Fields}}{{if .Hidden}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">{{else}}<label>{{.Label}} <input name="{{.Name}}" value="{{.Value}}"{{if .Readonly}} readonly{{end}}{{if .Required}} required{{end}}></label>{{end}}{{end}}<button type="submit">{{if eq .Language "ko"}}저장{{else}}Save{{end}}</button></form><p><a id="profile-account-link" href="{{.Account}}">{{if eq .Language "ko"}}계정으로 나가기{{else}}Exit to account{{end}}</a></p></main></body></html>`))

type profileField struct {
	Name     string
	Label    string
	Value    string
	Readonly bool
	Required bool
	Hidden   bool
}

type profilePageData struct {
	IssuerPath        string
	Interaction       string
	CSRFToken         string
	ThemeURL          string
	Error             string
	Language, Account string
	Fields            []profileField
}

// SetUserValuesPolicy validates and stores a static profile continuation policy.
// Default is disabled (RevalidateDuringLogin=false).
func (h *Handler) SetUserValuesPolicy(policy identity.UserValuesPolicy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	h.userValuesPolicy = &policy
	return nil
}

// needsProfileUpdate returns whether the authenticated user needs a profile
// update for the given request, or an error if the check could not be performed.
// The rauthy clientID is already exempt inside identity.NeedsProfileUpdate.
func (h *Handler) needsProfileUpdate(r *http.Request, subject, clientID string) (bool, error) {
	if h.userValuesPolicy == nil {
		return false, nil
	}
	return h.identity.NeedsProfileUpdate(r.Context(), *h.userValuesPolicy, subject, clientID)
}

// profileIssuerPath returns the path prefix under the issuer for /auth/profile.
func profileIssuerPath(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return "/auth/profile"
	}
	base := strings.TrimRight(u.Path, "/")
	return base + "/auth/profile"
}

// createProfileInteraction creates a new browser authorization interaction
// bound to the authenticated raw session token with the validated requestID
// and the original URL payload with 5m expiry, and redirects to the profile page.
func (h *Handler) createProfileInteraction(w http.ResponseWriter, r *http.Request, sessionToken string, requestID string, session browser.Session, originalURL string) {
	h.createProfileInteractionPayload(w, r, sessionToken, requestID, []byte(originalURL))
}

func (h *Handler) createProfileInteractionPayload(w http.ResponseWriter, r *http.Request, sessionToken, requestID string, payload []byte) {
	interaction, err := h.browser.CreateAuthorizationInteraction(r.Context(), sessionToken, requestID, payload, h.now().Add(interactionLifetime))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	redirectPath := profileIssuerPath(h.issuer) + "?interaction=" + url.QueryEscape(interaction.Token)
	http.Redirect(w, r, redirectPath, http.StatusFound)
}

// profileGET handles GET /auth/profile?interaction=<token>
func (h *Handler) profileGET(w http.ResponseWriter, r *http.Request) {
	session, sessionToken, ok := h.session(r)
	if !ok || !session.Authenticated() {
		http.Error(w, "Invalid profile request", http.StatusForbidden)
		return
	}
	interactionValues := r.URL.Query()["interaction"]
	if len(interactionValues) != 1 || interactionValues[0] == "" {
		http.Error(w, "Invalid profile request", http.StatusBadRequest)
		return
	}
	interactionToken := interactionValues[0]
	interaction, err := h.browser.LoadAuthorizationInteractionReadOnlyForSession(r.Context(), sessionToken, interactionToken)
	if err != nil {
		http.Error(w, "Invalid profile request", http.StatusForbidden)
		return
	}
	target, err := h.resolveProfileRequest(r, interaction.Payload, session)
	request := target.policy
	if err != nil {
		http.Error(w, "Invalid profile request", http.StatusForbidden)
		return
	}
	if h.userValuesPolicy == nil || !h.userValuesPolicy.RevalidateDuringLogin {
		http.Error(w, "Profile update not enabled", http.StatusServiceUnavailable)
		return
	}
	policy := *h.userValuesPolicy
	if request.ForceMFA && session.AuthenticationMethod != "mfa" {
		http.Error(w, "Invalid profile request", http.StatusForbidden)
		return
	}
	if request.MaxAgeSeconds != nil {
		maxAge := *request.MaxAgeSeconds
		if maxAge > 0 && session.CreatedAt.Add(time.Duration(maxAge)*time.Second).Before(h.now()) {
			http.Error(w, "Invalid profile request", http.StatusForbidden)
			return
		}
	}
	claims, err := h.identity.ProfileClaimsBySubject(r.Context(), session.Subject)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	csrf, err := browser.DeriveCSRFToken(sessionToken)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	fields := buildProfileFields(policy, claims)
	securityHeaders(w)
	language := i18n.UILanguageFromRequest(r)
	localizedHTMLHeaders(w, language)
	w.Header().Set("Content-Security-Policy", authorizationFormCSP(request.RedirectURI))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = profilePage.Execute(w, profilePageData{
		IssuerPath:  strings.TrimSuffix(profileIssuerPath(h.issuer), "/auth/profile"),
		Interaction: interactionToken,
		CSRFToken:   csrf,
		Language:    language,
		Account:     strings.TrimSuffix(profileIssuerPath(h.issuer), "/auth/profile") + "/account",
		Fields:      fields,
	})
}

// profilePOST handles POST /auth/profile
func (h *Handler) profilePOST(w http.ResponseWriter, r *http.Request) {
	if !sameIssuerOrigin(r, h.issuer) || crossSite(r.Header.Values("Sec-Fetch-Site")) {
		http.Error(w, "Invalid profile request", http.StatusForbidden)
		return
	}
	session, sessionToken, ok := h.session(r)
	if !ok || !session.Authenticated() {
		http.Error(w, "Invalid profile request", http.StatusForbidden)
		return
	}
	interactionValues := r.URL.Query()["interaction"]
	if len(interactionValues) != 1 || interactionValues[0] == "" {
		http.Error(w, "Invalid profile request", http.StatusBadRequest)
		return
	}
	interactionToken := interactionValues[0]
	if len(r.Header.Values("Content-Type")) != 1 {
		http.Error(w, "Invalid profile request", http.StatusBadRequest)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		http.Error(w, "Invalid profile request", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, formLimit)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid profile request", http.StatusBadRequest)
		return
	}
	csrfValues, csrfOK := r.PostForm["csrf_token"]
	if !csrfOK || len(csrfValues) != 1 || csrfValues[0] == "" {
		http.Error(w, "Invalid profile request", http.StatusBadRequest)
		return
	}
	if err := browser.ValidateCSRFToken(sessionToken, csrfValues[0]); err != nil {
		http.Error(w, "Invalid profile request", http.StatusForbidden)
		return
	}
	interactionValues, interactionOK := r.PostForm["interaction"]
	if !interactionOK || len(interactionValues) != 1 || interactionValues[0] == "" {
		http.Error(w, "Invalid profile request", http.StatusBadRequest)
		return
	}
	if interactionValues[0] != interactionToken {
		http.Error(w, "Invalid profile request", http.StatusBadRequest)
		return
	}
	if h.userValuesPolicy == nil || !h.userValuesPolicy.RevalidateDuringLogin {
		http.Error(w, "Profile update not enabled", http.StatusServiceUnavailable)
		return
	}
	policy := *h.userValuesPolicy
	interaction, err := h.browser.LoadAuthorizationInteractionReadOnlyForSession(r.Context(), sessionToken, interactionToken)
	if err != nil {
		http.Error(w, "Invalid profile request", http.StatusForbidden)
		return
	}
	target, err := h.resolveProfileRequest(r, interaction.Payload, session)
	request := target.policy
	if err != nil {
		http.Error(w, "Invalid profile request", http.StatusForbidden)
		return
	}
	if request.ForceMFA && session.AuthenticationMethod != "mfa" {
		http.Error(w, "Invalid profile request", http.StatusForbidden)
		return
	}
	if request.MaxAgeSeconds != nil {
		maxAge := *request.MaxAgeSeconds
		if maxAge > 0 && session.CreatedAt.Add(time.Duration(maxAge)*time.Second).Before(h.now()) {
			http.Error(w, "Invalid profile request", http.StatusForbidden)
			return
		}
	}
	allowed := map[string]bool{
		"csrf_token": true, "interaction": true, "given_name": true, "family_name": true,
		"preferred_username": true, "birthdate": true, "phone": true,
		"street": true, "zip": true, "city": true, "country": true, "tz": true,
	}
	for key := range r.PostForm {
		if !allowed[key] {
			http.Error(w, "Invalid profile request", http.StatusBadRequest)
			return
		}
	}
	for _, key := range []string{"csrf_token", "interaction", "given_name", "family_name", "preferred_username", "birthdate", "phone", "street", "zip", "city", "country", "tz"} {
		if len(r.PostForm[key]) > 1 {
			http.Error(w, "Invalid profile request", http.StatusBadRequest)
			return
		}
	}
	givenName := optionalFormValue(r, "given_name")
	familyName := optionalFormValue(r, "family_name")
	preferredUsername := optionalFormValue(r, "preferred_username")
	userValues := &identity.UserValuesRequest{
		Birthdate: optionalFormValue(r, "birthdate"),
		Phone:     optionalFormValue(r, "phone"),
		Street:    optionalFormValue(r, "street"),
		ZIP:       optionalFormValue(r, "zip"),
		City:      optionalFormValue(r, "city"),
		Country:   optionalFormValue(r, "country"),
		Timezone:  optionalFormValue(r, "tz"),
	}
	update := identity.SelfProfileUpdate{
		GivenName:         givenName,
		FamilyName:        familyName,
		PreferredUsername: preferredUsername,
		UserValues:        userValues,
	}
	peerIP, peerOK := h.resolvePeerIP(r)
	if !peerOK {
		http.Error(w, "Invalid profile request", http.StatusBadRequest)
		return
	}
	interactionDigest, digestErr := browser.CanonicalTokenDigest(interactionToken)
	if digestErr != nil {
		http.Error(w, "Invalid profile request", http.StatusBadRequest)
		return
	}
	guard := func() (string, []any) {
		sessionGuardSQL, sessionGuardArgs := h.browser.SessionAuthorizationGuard(session, peerIP)
		interactionGuardSQL := `EXISTS (SELECT 1 FROM browser_authorization_interactions WHERE token_digest=? AND session_digest=? AND consumed_attempt IS NULL AND expires_at_unix_ms > ?)`
		interactionGuardArgs := []any{interactionDigest, session.ID, h.now().UnixMilli()}
		return sessionGuardSQL + ` AND ` + interactionGuardSQL, append(sessionGuardArgs, interactionGuardArgs...)
	}
	_, err = h.identity.UpdateSelfProfileWithGuard(r.Context(), session.Subject, update, policy, guard)
	if err != nil {
		if errors.Is(err, identity.ErrSelfProfileInvalid) || errors.Is(err, identity.ErrUserValuesPolicy) || errors.Is(err, identity.ErrRequiredUserValue) || errors.Is(err, identity.ErrPreferredUsernameUnavailable) {
			claims, claimsErr := h.identity.ProfileClaimsBySubject(r.Context(), session.Subject)
			if claimsErr != nil {
				http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
				return
			}
			csrf, csrfErr := browser.DeriveCSRFToken(sessionToken)
			if csrfErr != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			fields := buildProfileFields(policy, claims)
			errMsg := err.Error()
			if errors.Is(err, identity.ErrPreferredUsernameUnavailable) {
				errMsg = "preferred username unavailable"
			}
			securityHeaders(w)
			language := i18n.UILanguageFromRequest(r)
			if language == "ko" && errors.Is(err, identity.ErrPreferredUsernameUnavailable) {
				errMsg = "선호 사용자 이름을 사용할 수 없습니다"
			}
			localizedHTMLHeaders(w, language)
			w.Header().Set("Content-Security-Policy", authorizationFormCSP(request.RedirectURI))
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = profilePage.Execute(w, profilePageData{
				IssuerPath:  strings.TrimSuffix(profileIssuerPath(h.issuer), "/auth/profile"),
				Interaction: interactionToken,
				CSRFToken:   csrf,
				Error:       errMsg,
				Language:    language,
				Account:     strings.TrimSuffix(profileIssuerPath(h.issuer), "/auth/profile") + "/account",
				Fields:      fields,
			})
			return
		}
		if errors.Is(err, identity.ErrSelfProfileUnauthorized) {
			http.Error(w, "Invalid profile request", http.StatusForbidden)
			return
		}
		if errors.Is(err, identity.ErrSelfProfileConflict) {
			http.Error(w, "Invalid profile request", http.StatusConflict)
			return
		}
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	consumed, err := h.browser.ConsumeAuthorizationInteraction(r.Context(), sessionToken, interactionToken)
	if err != nil {
		http.Error(w, "Invalid profile request", http.StatusForbidden)
		return
	}
	targetAfterConsume, err := h.resolveProfileRequest(r, consumed.Payload, session)
	if err != nil || (targetAfterConsume.policy.ForceMFA && session.AuthenticationMethod != "mfa") {
		http.Error(w, "Invalid profile request", http.StatusForbidden)
		return
	}
	if targetAfterConsume.approval != nil {
		h.redirectApproval(w, targetAfterConsume.approval)
		return
	}
	h.oauth.CompleteAuthorizationWithSession(w, targetAfterConsume.original, session.Subject, targetAfterConsume.policy.RequestedScopes, session.CreatedAt, session.ID, session.AuthenticationMethod)
}

// Profile handles GET/POST /auth/profile for profile continuation.
func (h *Handler) Profile(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	switch r.Method {
	case http.MethodGet:
		h.profileGET(w, r)
	case http.MethodPost:
		h.profilePOST(w, r)
	default:
		methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
	}
}

func optionalFormValue(r *http.Request, key string) *string {
	values, ok := r.PostForm[key]
	if !ok || len(values) != 1 {
		return nil
	}
	v := values[0]
	if v == "" {
		return nil
	}
	return &v
}

func buildProfileFields(policy identity.UserValuesPolicy, claims identity.ProfileClaims) []profileField {
	cfg := policy.ConfigResponse()
	var fields []profileField
	addField := func(name, label, mode string, current *string, immutable bool) {
		f := profileField{Name: name, Label: label, Required: mode == "required", Hidden: mode == "hidden"}
		if immutable && current != nil {
			f.Readonly = true
		}
		if current != nil {
			f.Value = *current
		}
		fields = append(fields, f)
	}
	addField("given_name", "Given Name", cfg.GivenName, claims.GivenName, false)
	addField("family_name", "Family Name", cfg.FamilyName, claims.FamilyName, false)
	addField("preferred_username", "Preferred Username", cfg.PreferredUsername.Mode, claims.PreferredUsername, cfg.PreferredUsername.Immutable && claims.PreferredUsername != nil)
	addField("birthdate", "Birthdate", cfg.Birthdate, claims.Birthdate, false)
	addField("phone", "Phone", cfg.Phone, claims.Phone, false)
	addField("street", "Street", cfg.Street, claims.Street, false)
	addField("zip", "ZIP", cfg.ZIP, claims.ZIP, false)
	addField("city", "City", cfg.City, claims.City, false)
	addField("country", "Country", cfg.Country, claims.Country, false)
	addField("tz", "Timezone", cfg.Timezone, claims.Timezone, false)
	return fields
}

// Profile continuations are bound to the already authenticated session and
// subject. An initial approval-login payload is not a profile continuation.
func (h *Handler) resolveProfileRequest(r *http.Request, payload []byte, session browser.Session) (authenticationRequest, error) {
	target, err := h.resolveAuthenticationRequest(r, payload)
	if err != nil {
		return authenticationRequest{}, err
	}
	if target.approval != nil && target.approval.ProfileSubject != session.Subject {
		return authenticationRequest{}, errors.New("invalid profile subject")
	}
	return target, nil
}
