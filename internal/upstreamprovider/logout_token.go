package upstreamprovider

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

const logoutEvent = "http://schemas.openid.net/event/backchannel-logout"

var ErrLogoutTokenVerification = errors.New("upstream provider: logout token verification failed")

// LogoutTokenClaims identifies upstream sessions, not local browser sessions.
// Callers must durably bind these identifiers and consume JTI with revocation.
type LogoutTokenClaims struct {
	Issuer      string
	Subject     string
	SessionID   string
	JTI         string
	ExpiresAt   time.Time
	ReplayUntil time.Time
}

// VerifyLogoutToken validates an OIDC Back-Channel Logout 1.0 errata-1 token.
// maxAge is the caller's positive acceptance window; it is not clock leeway.
// This verifies authenticity only, not replay consumption or session revocation.
func (v *JWKSVerifier) VerifyLogoutToken(ctx context.Context, raw, issuer, audience string, now time.Time, maxAge time.Duration) (*LogoutTokenClaims, error) {
	if audience == "" || maxAge <= 0 || len(raw) > 16<<10 {
		return nil, ErrLogoutTokenVerification
	}
	payload, err := v.verifyPayload(ctx, raw, issuer)
	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrLogoutTokenVerification
	}
	// Presence matters for nonce: even an empty or null nonce is prohibited.
	var claims struct {
		Issuer    string                     `json:"iss"`
		Subject   string                     `json:"sub"`
		SessionID string                     `json:"sid"`
		Audience  json.RawMessage            `json:"aud"`
		IssuedAt  int64                      `json:"iat"`
		ExpiresAt int64                      `json:"exp"`
		NotBefore int64                      `json:"nbf"`
		JTI       string                     `json:"jti"`
		Nonce     json.RawMessage            `json:"nonce"`
		Events    map[string]json.RawMessage `json:"events"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return nil, ErrLogoutTokenVerification
	}
	var audiences []string
	if json.Unmarshal(claims.Audience, &audiences) != nil {
		var one string
		if json.Unmarshal(claims.Audience, &one) != nil {
			return nil, ErrLogoutTokenVerification
		}
		audiences = []string{one}
	}
	var event map[string]json.RawMessage
	value, ok := claims.Events[logoutEvent]
	if !ok || json.Unmarshal(value, &event) != nil || event == nil || len(event) != 0 {
		return nil, ErrLogoutTokenVerification
	}
	issued, expires := time.Unix(claims.IssuedAt, 0), time.Unix(claims.ExpiresAt, 0)
	if claims.Issuer != issuer || !audienceContains(audiences, audience) ||
		(claims.Subject == "" && claims.SessionID == "") || claims.JTI == "" || len(claims.Nonce) != 0 ||
		claims.IssuedAt <= 0 || claims.ExpiresAt <= 0 || now.Before(issued) || !now.Before(expires) ||
		!expires.After(issued) || now.Sub(issued) > maxAge ||
		(claims.NotBefore != 0 && now.Before(time.Unix(claims.NotBefore, 0))) {
		return nil, ErrLogoutTokenVerification
	}
	// Retain receipts only while this token is acceptable. The extra millisecond
	// preserves the inclusive maxAge boundary in Rhiza's millisecond timestamps.
	replayUntil := issued.Add(maxAge).Add(time.Millisecond)
	if expires.Before(replayUntil) {
		replayUntil = expires
	}
	return &LogoutTokenClaims{Issuer: claims.Issuer, Subject: claims.Subject, SessionID: claims.SessionID, JTI: claims.JTI, ExpiresAt: expires, ReplayUntil: replayUntil}, nil
}
