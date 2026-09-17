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
	"github.com/mrchypark/goauthy/internal/identity"
)

var profilePage = template.Must(template.New("profile").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><link rel="stylesheet" href="/auth/v1/theme/global.css">{{if .ThemeURL}}<link rel="stylesheet" href="{{.ThemeURL}}">{{end}}<title>Update Profile</title></head><body><main><h1>Update Profile</h1>{{if .Error}}<p style="color:red">{{.Error}}</p>{{end}}<form method="post" action=""><input type="hidden" name="interaction" value="{{.Interaction}}"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}">{{range .Fields}}{{if .Hidden}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">{{else}}<label>{{.Label}} <input name="{{.Name}}" value="{{.Value}}"{{if .Readonly}} readonly{{end}}{{if .Required}} required{{end}}></label>{{end}}{{end}}<button type="submit">Save</button></form></main></body></html>`))

type profileField struct {
	Name     string
	Label    string
	Value    string
	Readonly bool
	Required bool
	Hidden   bool
}

type profilePageData struct {
	Interaction string
	CSRFToken   string
	ThemeURL    string
	Error       string
	Fields      []profileField
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
	interaction, err := h.browser.CreateAuthorizationInteraction(r.Context(), sessionToken, requestID, []byte(originalURL), h.now().Add(interactionLifetime))
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
	original, err := h.originalAuthorizeRequest(r, interaction.Payload)
	if err != nil {
		http.Error(w, "Invalid profile request", http.StatusForbidden)
		return
	}
	request, err := h.oauth.ValidateAuthorizationRequest(original)
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
	w.Header().Set("Content-Security-Policy", authorizationFormCSP(request.RedirectURI))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = profilePage.Execute(w, profilePageData{
		Interaction: interactionToken,
		CSRFToken:   csrf,
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
	original, err := h.originalAuthorizeRequest(r, interaction.Payload)
	if err != nil {
		http.Error(w, "Invalid profile request", http.StatusForbidden)
		return
	}
	request, err := h.oauth.ValidateAuthorizationRequest(original)
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
			w.Header().Set("Content-Security-Policy", authorizationFormCSP(request.RedirectURI))
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = profilePage.Execute(w, profilePageData{
				Interaction: interactionToken,
				CSRFToken:   csrf,
				Error:       errMsg,
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
	originalAfterConsume, err := h.originalAuthorizeRequest(r, consumed.Payload)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	requestAfterConsume, err := h.oauth.ValidateAuthorizationRequest(originalAfterConsume)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	h.oauth.CompleteAuthorizationWithSession(w, originalAfterConsume, session.Subject, requestAfterConsume.RequestedScopes, session.CreatedAt, session.ID, session.AuthenticationMethod)
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
