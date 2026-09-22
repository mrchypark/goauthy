package login

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/device"
	"io"
	"net/http"

	"github.com/mrchypark/goauthy/internal/oauth"
)

const approvalLoginPayload = "goauthy-approval-login/v1"

// Only the server writes this payload into a session-bound, expiring interaction.
// Destinations are identifiers, never browser-supplied return URLs.
type approvalLoginInteraction struct {
	Purpose             string
	DeviceCode          *string `json:",omitempty"`
	HandoffID           string  `json:",omitempty"`
	ForceMFA            bool
	ExpectedSubject     string `json:",omitempty"`
	ParentSessionDigest string `json:",omitempty"`
}

type authenticationRequest struct {
	policy   oauth.AuthorizationRequest
	original *http.Request
	approval *approvalLoginInteraction
}

// SetApprovalForceMFA configures the deployment policy before serving requests.
// The saved interaction can tighten this policy, but cannot weaken it.
func (h *Handler) SetApprovalForceMFA(enabled bool) { h.approvalForceMFA = enabled }

func (h *Handler) resolveAuthenticationRequest(r *http.Request, payload []byte) (authenticationRequest, error) {
	if len(payload) > 0 && payload[0] == '{' {
		var saved approvalLoginInteraction
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&saved) != nil || decoder.Decode(new(any)) != io.EOF || saved.Purpose != approvalLoginPayload {
			return authenticationRequest{}, errors.New("invalid login continuation")
		}
		if saved.DeviceCode != nil {
			if saved.HandoffID != "" || (*saved.DeviceCode != "" && !deviceLoginCode.MatchString(*saved.DeviceCode)) {
				return authenticationRequest{}, errors.New("invalid device continuation")
			}
		} else if _, ok := canonicalHandoffID(saved.HandoffID); !ok {
			return authenticationRequest{}, errors.New("invalid handoff continuation")
		}
		if saved.ExpectedSubject != "" || saved.ParentSessionDigest != "" {
			peer, ok := h.resolvePeerIP(r)
			if !ok || !saved.ForceMFA {
				return authenticationRequest{}, errors.New("invalid reauthentication")
			}
			if _, err := h.browser.LoadReauthenticationParent(r.Context(), saved.ParentSessionDigest, saved.ExpectedSubject, peer); err != nil {
				return authenticationRequest{}, err
			}
		}
		// These fields supply presentation and authentication policy only. Approval
		// continuations never enter OAuth validation or code issuance.
		return authenticationRequest{approval: &saved, policy: oauth.AuthorizationRequest{ForceMFA: saved.ForceMFA || h.approvalForceMFA, RedirectURI: h.issuer}}, nil
	}
	original, err := h.originalAuthorizeRequest(r, payload)
	if err != nil {
		return authenticationRequest{}, err
	}
	policy, err := h.oauth.ValidateAuthorizationRequest(original)
	if err != nil {
		return authenticationRequest{}, err
	}
	return authenticationRequest{original: original, policy: policy}, nil
}

func (target authenticationRequest) acceptsSubject(subject string) bool {
	return target.approval == nil || target.approval.ExpectedSubject == "" || target.approval.ExpectedSubject == subject
}

func (h *Handler) consumeAuthenticationRequest(r *http.Request, target authenticationRequest, sessionToken, interactionDigest, subject, peerIP string, consume func(context.Context) (browser.AuthorizationInteraction, error)) (browser.AuthorizationInteraction, error) {
	if !target.acceptsSubject(subject) {
		return browser.AuthorizationInteraction{}, errors.New("reauthentication subject mismatch")
	}
	if target.approval != nil && target.approval.ParentSessionDigest != "" {
		return h.browser.ConsumeReauthenticationInteractionByDigest(r.Context(), sessionToken, interactionDigest, target.approval.ParentSessionDigest, subject, peerIP)
	}
	return consume(r.Context())
}

// DeviceReviewReauthentication is called only after authenticated, rate-limited
// Device review resolves a current MFA requirement. It cannot approve a grant.
func (h *Handler) DeviceReviewReauthentication(w http.ResponseWriter, r *http.Request, code string) {
	code = device.NormalizeUserCode(code)
	if !deviceLoginCode.MatchString(code) {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	h.startApprovalReauthentication(w, r, approvalLoginInteraction{Purpose: approvalLoginPayload, DeviceCode: &code, ForceMFA: true}, "/oidc/device/login")
}

func (h *Handler) startApprovalReauthentication(w http.ResponseWriter, r *http.Request, saved approvalLoginInteraction, path string) {
	securityHeaders(w)
	current, _, ok := h.session(r)
	peer, peerOK := h.resolvePeerIP(r)
	if !ok || !current.Authenticated() || !peerOK || peer == "" {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	saved.ExpectedSubject, saved.ParentSessionDigest = current.Subject, current.ID
	saved.ForceMFA = true
	payload, err := json.Marshal(saved)
	if err != nil {
		http.Error(w, "Invalid login request", http.StatusBadRequest)
		return
	}
	interaction, csrf, cookie, err := h.createLoginInteraction(r, peer, payload)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	theme, err := h.resolveThemeURL(r.Context(), "rauthy")
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, cookie)
	h.renderApprovalLoginPage(w, r, payload, path, "Authenticate again with the same account to review this request. Signing in does not approve it.", interaction.Token, csrf, theme)
}
