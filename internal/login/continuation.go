package login

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/mrchypark/goauthy/internal/oauth"
)

const approvalLoginPayload = "goauthy-approval-login/v1"

// Only the server writes this payload into a session-bound, expiring interaction.
// Destinations are identifiers, never browser-supplied return URLs.
type approvalLoginInteraction struct {
	Purpose    string
	DeviceCode *string `json:",omitempty"`
	HandoffID  string  `json:",omitempty"`
	ForceMFA   bool
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
