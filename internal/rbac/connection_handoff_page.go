package rbac

import (
	_ "embed"
	"encoding/base64"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/saas"
)

//go:embed connection_handoff_page.html
var connectionHandoffHTML string

var connectionHandoffPage = template.Must(template.New("connection-handoff").Parse(connectionHandoffHTML))

type connectionHandoffPageData struct {
	Review                                                           saas.UseHandoffReview
	Action, CSS, CSRF, GrantExpiry, TicketExpiry, ReturnURI, Message string
	Complete, Approved                                               bool
}

// ConnectionHandoffPage is a navigation endpoint, not a Bearer API. Visiting it
// or signing in can only display a proposal; only an explicit CSRF POST consumes it.
func (h *Handler) ConnectionHandoffPage(w http.ResponseWriter, r *http.Request) {
	h.securityHeaders(w)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	render := func(status int, data connectionHandoffPageData) {
		data.CSS = h.issuer + "/account/account.css"
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_ = connectionHandoffPage.Execute(w, data)
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		h.methodNotAllowed(w)
		return
	}
	id := r.PathValue("handoff_id")
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(raw) != 18 || base64.RawURLEncoding.EncodeToString(raw) != id || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" {
		render(http.StatusBadRequest, connectionHandoffPageData{Message: "This request is invalid. Return to the requesting app and start again."})
		return
	}
	if len(r.Header.Values("Authorization")) != 0 || len(r.Header.Values("If-Match")) != 0 || len(r.Header.Values("X-CSRF-Token")) != 0 {
		h.genericUnauthorized(w)
		return
	}
	if h.saasCredentials == nil {
		h.unavailable(w)
		return
	}
	name, _ := browser.CookieName(h.issuer)
	cookies := r.CookiesNamed(name)
	if len(cookies) > 1 {
		h.genericUnauthorized(w)
		return
	}
	if r.Method == http.MethodGet {
		if !emptyBody(r) {
			h.badRequest(w)
			return
		}
		// Top-level navigation from a consumer is expected. No state is changed
		// by this page GET; unauthenticated visits do not reveal ticket existence.
		authenticated := false
		if len(cookies) == 1 {
			session, err := h.browser.LoadSessionReadOnlyForPeer(r.Context(), cookies[0].Value, browser.PeerIPFromContext(r.Context()))
			authenticated = err == nil && session.Authenticated()
		}
		if !authenticated {
			http.Redirect(w, r, h.issuer+"/account/connection-login?handoff_id="+url.QueryEscape(id), http.StatusSeeOther)
			return
		}
	}
	var approve bool
	var digest string
	if r.Method == http.MethodPost {
		issuer, _ := url.Parse(h.issuer)
		origins := r.Header.Values("Origin")
		// Native no-referrer forms send Origin:null. Fetch Metadata still proves
		// same-origin; the stdlib rejects cross-origin/null without that evidence.
		var protection http.CrossOriginProtection
		nullOriginWithoutSameOrigin := len(origins) == 1 && origins[0] == "null" && (len(r.Header.Values("Sec-Fetch-Site")) != 1 || r.Header.Get("Sec-Fetch-Site") != "same-origin")
		if protection.Check(r) != nil || nullOriginWithoutSameOrigin || len(r.Header.Values("Sec-Fetch-Site")) > 1 || len(origins) > 1 || (len(origins) == 1 && origins[0] != "null" && origins[0] != issuer.Scheme+"://"+issuer.Host) {
			h.genericUnauthorized(w)
			return
		}
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		r.Body = http.MaxBytesReader(w, r.Body, adminRequestLimit)
		if len(r.Header.Values("Content-Type")) != 1 || err != nil || media != "application/x-www-form-urlencoded" || r.ParseForm() != nil {
			h.badRequest(w)
			return
		}
		for key, values := range r.PostForm {
			if len(values) != 1 || (key != "decision" && key != "csrf_token" && key != "connector_digest" && key != "review_digest" && key != "reviewed") {
				h.badRequest(w)
				return
			}
		}
		approve = r.PostForm.Get("decision") == "approve"
		reviewDigest, legacyDigest := r.PostForm.Get("review_digest"), r.PostForm.Get("connector_digest")
		if (approve && (len(r.PostForm) != 4 || r.PostForm.Get("reviewed") != "yes" || (reviewDigest == "") == (legacyDigest == ""))) || (!approve && (r.PostForm.Get("decision") != "deny" || len(r.PostForm) != 2)) || r.PostForm.Get("csrf_token") == "" {
			h.badRequest(w)
			return
		}
		digest = reviewDigest
		if digest == "" {
			digest = legacyDigest
		}
		// Adapt the strictly parsed native form to the shared session/CSRF guard.
		r = r.Clone(r.Context())
		r.Header.Set("X-CSRF-Token", r.PostForm.Get("csrf_token"))
	}
	owner, authority, ok := h.authConnectionSubject(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		returnURI, err := h.saasCredentials.CompleteUseHandoff(r.Context(), owner, id, approve, digest, authority)
		if err != nil {
			render(http.StatusConflict, connectionHandoffPageData{Message: "This request could not be completed. It may have expired, changed or already been used. Return to the requesting app and check its status before starting again."})
			return
		}
		// Explicit navigation avoids browser-dependent CSP form-action handling
		// of cross-origin POST redirects. The server already validated this URI.
		render(http.StatusOK, connectionHandoffPageData{Complete: true, Approved: approve, ReturnURI: returnURI})
		return
	}
	review, err := h.saasCredentials.ReviewUseHandoff(r.Context(), owner, id, authority)
	if err != nil {
		render(http.StatusNotFound, connectionHandoffPageData{Message: "This request is unavailable for this account. It may have expired, changed or already been used. Return to the requesting app and start again."})
		return
	}
	csrf, err := browser.DeriveCSRFToken(cookies[0].Value)
	if err != nil {
		h.unavailable(w)
		return
	}
	render(http.StatusOK, connectionHandoffPageData{Review: review, Action: h.issuer + "/account/connection-handoffs/" + id, CSRF: csrf, GrantExpiry: time.UnixMilli(review.Grant.ExpiresAt).UTC().Format(time.RFC3339), TicketExpiry: time.UnixMilli(review.ExpiresAt).UTC().Format(time.RFC3339)})
}
