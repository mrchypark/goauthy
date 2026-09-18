package logout

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
)

const testIssuer = "https://issuer.example.test"

func TestPlanValidHintLogsOutAndUsesExactRegisteredRedirect(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	engine, key := testEngine(t, now)
	sessionID := testSessionID(1)
	hint := testHint(t, key, now, "client-1", "user-1", sessionID)

	decision, err := engine.Plan(Request{
		IDTokenHint: hint, ClientID: "client-1", PostLogoutRedirectURI: "https://rp.example.test/logout?from=goauthy", State: "opaque state", CurrentSubject: "user-1", CurrentSessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != ActionLogout || decision.ClientID != "client-1" || decision.Subject != "user-1" || decision.SessionID != sessionID || decision.RedirectURI != "https://rp.example.test/logout?from=goauthy&state=opaque+state" {
		t.Fatalf("unexpected logout decision: %+v", decision)
	}
}

func TestPlanRejectsHintAndRedirectMismatches(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	engine, key := testEngine(t, now)
	hint := testHint(t, key, now, "client-1", "user-1", testSessionID(1))
	for _, request := range []Request{
		{IDTokenHint: hint, ClientID: "client-2"},
		{IDTokenHint: hint, PostLogoutRedirectURI: "https://rp.example.test/logout/"},
		{IDTokenHint: hint, State: "state"},
		{IDTokenHint: "not-a-jwt"},
		{IDTokenHint: hint, ClientID: "unknown"},
	} {
		if _, err := engine.Plan(request); err == nil {
			t.Fatalf("request %+v was accepted", request)
		}
	}
}

func TestPlanRequiresConfirmationForUnboundHintAndNoHintSession(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	engine, _ := testEngine(t, now)

	confirmed, err := engine.Plan(Request{CurrentSubject: "user-1", CurrentSessionID: testSessionID(1), ClientID: "client-1", PostLogoutRedirectURI: "https://rp.example.test/logout?from=goauthy", State: "state"})
	if err != nil || confirmed.Action != ActionConfirm || confirmed.RedirectURI != "https://rp.example.test/logout?from=goauthy&state=state" {
		t.Fatalf("confirmation decision=%+v err=%v", confirmed, err)
	}
	root, err := engine.Plan(Request{ClientID: "client-1", PostLogoutRedirectURI: "https://rp.example.test/logout?from=goauthy", State: "state"})
	if err != nil || root.Action != ActionRootRedirect || root.RedirectURI != testIssuer+"/" {
		t.Fatalf("root decision=%+v err=%v", root, err)
	}
	if _, err := engine.Plan(Request{CurrentSubject: "user-1", CurrentSessionID: testSessionID(1), State: "state"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("state without registered redirect error=%v", err)
	}
}

func TestPlanHintRequiresCurrentSessionBinding(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	engine, key := testEngine(t, now)
	sessionID := testSessionID(1)
	hint := testHint(t, key, now, "client-1", "user-1", sessionID)

	confirmed, err := engine.Plan(Request{IDTokenHint: hint, CurrentSubject: "user-1", CurrentSessionID: testSessionID(2)})
	if err != nil || confirmed.Action != ActionConfirm || confirmed.Subject != "" || confirmed.SessionID != "" {
		t.Fatalf("unbound hint decision=%+v err=%v", confirmed, err)
	}
	logout, err := engine.Plan(Request{IDTokenHint: hint})
	if err != nil || logout.Action != ActionLogout || logout.Subject != "user-1" || logout.SessionID != sessionID {
		t.Fatalf("no-session hint decision=%+v err=%v", logout, err)
	}
	if _, err := engine.Plan(Request{CurrentSubject: "user-1"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("partial session context error=%v", err)
	}
	if _, err := engine.Plan(Request{IDTokenHint: string(make([]byte, maxHintLength+1))}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversize hint error=%v", err)
	}
}

func TestPlanUsesLogoutHintLeewayAndRequiresGoAuthySessionClaims(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	engine, key := testEngine(t, now)
	for _, check := range []struct {
		name     string
		expires  time.Time
		azp, sid string
		ok       bool
	}{
		{name: "within leeway", expires: now.Add(-10 * time.Minute), azp: "client-1", sid: testSessionID(1), ok: true},
		{name: "beyond leeway", expires: now.Add(-10*time.Minute - time.Second), azp: "client-1", sid: testSessionID(1)},
		{name: "missing azp", expires: now.Add(time.Minute), sid: testSessionID(1)},
		{name: "missing sid", expires: now.Add(time.Minute), azp: "client-1"},
	} {
		t.Run(check.name, func(t *testing.T) {
			hint, err := oidc.SignIDToken(key, oidc.IDTokenClaims{Issuer: testIssuer, Subject: "user-1", Audience: []string{"client-1"}, AuthorizedParty: check.azp, SessionID: check.sid, IssuedAt: check.expires.Add(-time.Minute), ExpiresAt: check.expires})
			if err != nil {
				t.Fatal(err)
			}
			_, err = engine.Plan(Request{IDTokenHint: hint})
			if (err == nil) != check.ok {
				t.Fatalf("Plan() error=%v, want accepted=%v", err, check.ok)
			}
		})
	}
}

func TestPlanRejectsMalformedSessionIDHint(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	engine, key := testEngine(t, now)
	hint := testHint(t, key, now, "client-1", "user-1", "not-a-session-id")
	if _, err := engine.Plan(Request{IDTokenHint: hint}); !errors.Is(err, ErrInvalidHint) {
		t.Fatalf("malformed sid error=%v", err)
	}
}

func testSessionID(value byte) string {
	decoded := make([]byte, 32)
	decoded[0] = value
	return base64.RawURLEncoding.EncodeToString(decoded)
}

func TestNewRejectsUnsafeRedirectRegistration(t *testing.T) {
	_, key := testEngine(t, time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC))
	for _, raw := range []string{"/relative", "http://rp.example.test/logout", "https://rp.example.test/logout#fragment", "https://user@rp.example.test/logout", "https://rp.example.test/logout\r\nX-Test: bad"} {
		_, err := New(Config{Issuer: testIssuer, Keys: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, Clients: []Client{{ID: "client-1", PostLogoutRedirectURIs: []string{raw}}}})
		if err == nil {
			t.Fatalf("unsafe redirect %q accepted", raw)
		}
	}
}

func testEngine(t *testing.T, now time.Time) (*Engine, oidc.SigningKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := oidc.SigningKey{Private: private, PublicJWK: jose.JSONWebKey{Key: public, KeyID: "logout-test-key", Algorithm: "EdDSA", Use: "sig"}}
	engine, err := New(Config{
		Issuer: testIssuer, Keys: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, Now: func() time.Time { return now },
		Clients: []Client{
			{ID: "client-1", PostLogoutRedirectURIs: []string{"https://rp.example.test/logout?from=goauthy"}},
			{ID: "client-2", PostLogoutRedirectURIs: []string{"https://second-rp.example.test/logout"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine, key
}

func testHint(t *testing.T, key oidc.SigningKey, now time.Time, clientID, subject, sessionID string) string {
	t.Helper()
	hint, err := oidc.SignIDToken(key, oidc.IDTokenClaims{
		Issuer: testIssuer, Subject: subject, Audience: []string{clientID}, IssuedAt: now.Add(-time.Minute), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
		AuthorizedParty: clientID, SessionID: sessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return hint
}
