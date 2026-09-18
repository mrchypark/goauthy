package logout

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/i18n"
	"github.com/mrchypark/goauthy/internal/oauth"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/rhiza"
)

const (
	logoutFormLimit       = 12 << 10
	confirmationLifetime  = 5 * time.Minute
	logoutConfirmationKey = "confirmation"
	logoutRequestPrefix   = "logout-"
)

var confirmationPage = template.Must(template.New("logout-confirmation").Parse(`<!doctype html><html lang="{{.Language}}"><head><meta charset="utf-8"><title>{{.SignOut}}</title></head><body><main><h1>{{.SignOut}}</h1><p>{{.ConfirmSignOut}}</p><form method="post" action="logout"><input type="hidden" name="confirmation" value="{{.Interaction}}"><button type="submit">{{.SignOut}}</button></form></main></body></html>`))

var errLogoutUnavailable = errors.New("logout state unavailable")

// Handler is the browser and backend boundary for RP-initiated logout. It
// reloads public keys from Rhiza for every request so key rotation does not
// leave a stale verifier in process memory.
type Handler struct {
	issuer       string
	db           *rhiza.DB
	browser      *browser.Store
	oauth        *oauth.Server
	clients      []Client
	fedcmEnabled bool
}

func NewHandler(issuer string, db *rhiza.DB, browserStore *browser.Store, oauthServer *oauth.Server, clients []Client) (*Handler, error) {
	normalized, err := oidc.NormalizeIssuer(issuer)
	if err != nil {
		return nil, err
	}
	issuer = normalized
	if _, err := browser.CookieName(issuer); err != nil {
		return nil, err
	}
	if db == nil || browserStore == nil || oauthServer == nil {
		return nil, errors.New("logout handler requires database, browser store, and OAuth server")
	}
	if _, err := validateClients(clients); err != nil {
		return nil, err
	}
	return &Handler{issuer: issuer, db: db, browser: browserStore, oauth: oauthServer, clients: append([]Client(nil), clients...)}, nil
}

// EnableFedCM opts this handler into deleting the separate cross-site session
// cookie. The cookie is HTTPS-only by browser policy.
func (h *Handler) EnableFedCM(enabled bool) error {
	if enabled {
		u, err := url.Parse(h.issuer)
		if err != nil || strings.ToLower(u.Scheme) != "https" {
			return errors.New("FedCM requires an HTTPS issuer")
		}
	}
	h.fedcmEnabled = enabled
	return nil
}

// ServeHTTP accepts GET for browser navigation and form POST for confirmation
// or a backend ID-token-hint logout request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logoutSecurityHeaders(w)
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	form, err := parseLogoutForm(w, r)
	if err != nil {
		http.Error(w, "Invalid logout request", http.StatusBadRequest)
		return
	}
	current, cookieToken, hasCurrent, err := h.currentSession(r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if form.confirmation != "" {
		h.confirm(w, r, form.confirmation, current, cookieToken, hasCurrent)
		return
	}
	if form.idTokenHint == "" && !hasCurrent && (form.clientID != "" || form.redirectURI != "" || form.state != "") {
		http.Error(w, "Invalid logout request", http.StatusBadRequest)
		return
	}
	decision, err := h.plan(r.Context(), Request{IDTokenHint: form.idTokenHint, ClientID: form.clientID, PostLogoutRedirectURI: form.redirectURI, State: form.state, CurrentSubject: current.Subject, CurrentSessionID: current.ID})
	if err != nil {
		if errors.Is(err, errLogoutUnavailable) {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "Invalid logout request", http.StatusBadRequest)
		return
	}
	switch decision.Action {
	case ActionRootRedirect:
		http.Redirect(w, r, decision.RedirectURI, http.StatusSeeOther)
	case ActionConfirm:
		if !hasCurrent {
			http.Error(w, "Invalid logout request", http.StatusBadRequest)
			return
		}
		h.renderConfirmation(w, r, cookieToken, confirmationPayload{ClientID: decision.ClientID, RedirectURI: form.redirectURI, State: form.state})
	case ActionLogout:
		if err := h.revoke(r.Context(), decision.SessionID); err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		currentLogout := hasCurrent && current.ID == decision.SessionID && current.Subject == decision.Subject
		if currentLogout {
			if err := h.deleteSessionCookies(w); err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}
		if r.Method == http.MethodPost && !hasCurrent && len(r.Header.Values("Sec-Fetch-Site")) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.redirect(w, r, decision.RedirectURI)
	default:
		http.Error(w, "Invalid logout request", http.StatusBadRequest)
	}
}

type logoutForm struct {
	idTokenHint, clientID, redirectURI, state, confirmation string
}

func parseLogoutForm(w http.ResponseWriter, r *http.Request) (logoutForm, error) {
	var values url.Values
	var err error
	if r.Method == http.MethodGet {
		if len(r.URL.RawQuery) > logoutFormLimit {
			return logoutForm{}, ErrInvalidRequest
		}
		values, err = url.ParseQuery(r.URL.RawQuery)
	} else {
		if r.URL.RawQuery != "" || len(r.Header.Values("Content-Type")) != 1 {
			return logoutForm{}, ErrInvalidRequest
		}
		mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mediaErr != nil || mediaType != "application/x-www-form-urlencoded" {
			return logoutForm{}, ErrInvalidRequest
		}
		r.Body = http.MaxBytesReader(w, r.Body, logoutFormLimit)
		if err = r.ParseForm(); err == nil {
			values = r.PostForm
		}
	}
	if err != nil {
		return logoutForm{}, ErrInvalidRequest
	}
	allowed := map[string]bool{"id_token_hint": true, "client_id": true, "post_logout_redirect_uri": true, "state": true, logoutConfirmationKey: r.Method == http.MethodPost}
	for key, value := range values {
		if !allowed[key] || len(value) != 1 {
			return logoutForm{}, ErrInvalidRequest
		}
	}
	form := logoutForm{idTokenHint: values.Get("id_token_hint"), clientID: values.Get("client_id"), redirectURI: values.Get("post_logout_redirect_uri"), state: values.Get("state"), confirmation: values.Get(logoutConfirmationKey)}
	if form.confirmation != "" && (len(values) != 1 || len(form.confirmation) > 512) {
		return logoutForm{}, ErrInvalidRequest
	}
	if len(form.idTokenHint) > maxHintLength || len(form.state) > maxStateLength {
		return logoutForm{}, ErrInvalidRequest
	}
	return form, nil
}

func (h *Handler) plan(ctx context.Context, request Request) (Decision, error) {
	keys, err := oidc.LoadJWKSKeys(ctx, h.db, time.Now().UTC())
	if err != nil {
		return Decision{}, fmt.Errorf("%w: load signing keys", errLogoutUnavailable)
	}
	engine, err := New(Config{Issuer: h.issuer, Keys: jose.JSONWebKeySet{Keys: keys}, Clients: h.clients})
	if err != nil {
		return Decision{}, err
	}
	return engine.Plan(request)
}

func (h *Handler) currentSession(r *http.Request) (browser.Session, string, bool, error) {
	name, err := browser.CookieName(h.issuer)
	if err != nil {
		return browser.Session{}, "", false, err
	}
	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return browser.Session{}, "", false, nil
	}
	session, err := h.browser.LoadSessionReadOnlyForPeer(r.Context(), cookie.Value, browser.PeerIPFromContext(r.Context()))
	if err != nil {
		if errors.Is(err, browser.ErrNotFound) || errors.Is(err, browser.ErrExpired) || errors.Is(err, browser.ErrRevoked) || errors.Is(err, browser.ErrPeerIPMismatch) {
			return browser.Session{}, "", false, nil
		}
		return browser.Session{}, "", false, fmt.Errorf("%w: load browser session", errLogoutUnavailable)
	}
	if !session.Authenticated() {
		return browser.Session{}, "", false, nil
	}
	return session, cookie.Value, true, nil
}

type confirmationPayload struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"post_logout_redirect_uri"`
	State       string `json:"state"`
}

func (h *Handler) renderConfirmation(w http.ResponseWriter, r *http.Request, cookieToken string, payload confirmationPayload) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	requestID, err := newConfirmationID()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	interaction, err := h.browser.CreateAuthorizationInteraction(r.Context(), cookieToken, requestID, encoded, time.Now().Add(confirmationLifetime))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	messages := i18n.MessagesFor(strings.Join(r.Header.Values("Accept-Language"), ","))
	localizedLogoutHTMLHeaders(w, messages.Language)
	_ = confirmationPage.Execute(w, confirmationPageData{Interaction: interaction.Token, Messages: messages})
}

type confirmationPageData struct {
	Interaction string
	i18n.Messages
}

func (h *Handler) confirm(w http.ResponseWriter, r *http.Request, token string, current browser.Session, cookieToken string, hasCurrent bool) {
	if r.Method != http.MethodPost || !hasCurrent || !sameOrigin(r.Header.Values("Sec-Fetch-Site")) {
		http.Error(w, "Invalid logout request", http.StatusForbidden)
		return
	}
	interaction, err := h.browser.ConsumeAuthorizationInteraction(r.Context(), cookieToken, token)
	if err != nil {
		if !errors.Is(err, browser.ErrNotFound) && !errors.Is(err, browser.ErrExpired) && !errors.Is(err, browser.ErrRevoked) && !errors.Is(err, browser.ErrConsumed) {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "Invalid logout request", http.StatusForbidden)
		return
	}
	if !strings.HasPrefix(interaction.RequestID, logoutRequestPrefix) || interaction.Subject != current.Subject {
		http.Error(w, "Invalid logout request", http.StatusForbidden)
		return
	}
	var payload confirmationPayload
	if json.Unmarshal(interaction.Payload, &payload) != nil || payload.ClientID == "" && (payload.RedirectURI != "" || payload.State != "") {
		http.Error(w, "Invalid logout request", http.StatusBadRequest)
		return
	}
	decision, err := h.plan(r.Context(), Request{ClientID: payload.ClientID, PostLogoutRedirectURI: payload.RedirectURI, State: payload.State, CurrentSubject: current.Subject, CurrentSessionID: current.ID})
	if errors.Is(err, errLogoutUnavailable) {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if err != nil || decision.Action != ActionConfirm {
		http.Error(w, "Invalid logout request", http.StatusBadRequest)
		return
	}
	if err := h.revoke(r.Context(), current.ID); err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if err := h.deleteSessionCookies(w); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	h.redirect(w, r, decision.RedirectURI)
}

func (h *Handler) deleteSessionCookies(w http.ResponseWriter) error {
	cookie, err := browser.DeleteSessionCookie(h.issuer)
	if err != nil {
		return err
	}
	http.SetCookie(w, cookie)
	if h.fedcmEnabled {
		fedcmCookie, err := browser.DeleteFedCMSessionCookie(h.issuer)
		if err != nil {
			return err
		}
		http.SetCookie(w, fedcmCookie)
	}
	return nil
}

func (h *Handler) revoke(ctx context.Context, sessionID string) error {
	return h.oauth.RevokeOIDCSession(ctx, sessionID)
}

func (h *Handler) redirect(w http.ResponseWriter, r *http.Request, location string) {
	if location == "" {
		location = strings.TrimRight(h.issuer, "/") + "/"
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}

func newConfirmationID() (string, error) {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return logoutRequestPrefix + base64.RawURLEncoding.EncodeToString(bytes), nil
}

func sameOrigin(values []string) bool {
	return len(values) == 1 && strings.EqualFold(strings.TrimSpace(values[0]), "same-origin")
}

func logoutSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
}

func localizedLogoutHTMLHeaders(w http.ResponseWriter, language string) {
	w.Header().Set("Content-Language", language)
	w.Header().Add("Vary", "Accept-Language")
}
