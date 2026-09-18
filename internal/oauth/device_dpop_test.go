package oauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/rhiza"
)

func TestDPoPDeviceGrantBindsAccessAndRefresh(t *testing.T) {
	db := oauthTestDB(t)
	server := userInfoTestServer(t, db, nil)
	seedDeviceUser(t, db, "device-dpop-user", nil)
	store := device.NewStore(db)
	now := time.Now().UTC()
	grant, err := store.Create(context.Background(), testClientID, []string{"goauthy.read", "offline_access"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(context.Background(), grant.UserCode, "device-dpop-user", now); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}}
	malformed := postDPoPToken(t, server, form, "invalid-proof")
	if malformed.Code != http.StatusBadRequest || tokenError(t, malformed) != "invalid_dpop_proof" {
		t.Fatal("malformed device proof did not fail with the standard error")
	}
	assertDeviceDPoPState(t, db, grant.DeviceCode, "approved", false)

	challenge := postDPoPToken(t, server, form, dpopTestProof(t, private, http.MethodPost, "/oidc/token", "device-one-abcdefgh", "", ""))
	if challenge.Code != http.StatusBadRequest || tokenError(t, challenge) != "use_dpop_nonce" || challenge.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("device challenge status=%d", challenge.Code)
	}
	assertDeviceDPoPState(t, db, grant.DeviceCode, "approved", false)

	issueProof := dpopTestProof(t, private, http.MethodPost, "/oidc/token", "device-two-abcdefgh", challenge.Header().Get("DPoP-Nonce"), "")
	issuedResponse := postDPoPToken(t, server, form, issueProof)
	issued := decodeToken(t, issuedResponse)
	if issued.TokenType != "DPoP" || issued.AccessToken == "" || issued.RefreshToken == "" {
		t.Fatal("device DPoP response lacks bound access/refresh tokens")
	}
	var responseCNF struct {
		CNF map[string]string `json:"cnf"`
	}
	if err := json.Unmarshal(issuedResponse.Body.Bytes(), &responseCNF); err != nil || responseCNF.CNF[dpopJKTClaim] == "" {
		t.Fatal("device DPoP response lacks valid cnf")
	}
	accessRequest, err := server.store.GetAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), issued.AccessToken), nil)
	if err != nil {
		t.Fatal("cannot load device access token session")
	}
	if sessionDPoPJKT(accessRequest.GetSession()) != responseCNF.CNF[dpopJKTClaim] {
		t.Fatal("stored device DPoP key binding differs")
	}
	accessClaims := jwtPayload(t, issued.AccessToken)
	if accessClaims["typ"] != "DPoP" || accessClaims["cnf"].(map[string]any)[dpopJKTClaim] != responseCNF.CNF[dpopJKTClaim] {
		t.Fatalf("device DPoP access claims=%#v", accessClaims)
	}
	encoded, err := encodeRequest(accessRequest)
	if err != nil || strings.Contains(encoded, challenge.Header().Get("DPoP-Nonce")) || strings.Contains(encoded, issueProof) {
		t.Fatal("device request encoding failed or persisted proof material")
	}
	// The device transaction keeps the claim digest as its durable consumed
	// marker; only the challenge must leave the approved grant unclaimed.
	assertDeviceDPoPState(t, db, grant.DeviceCode, "consumed", true)

	missing := postToken(server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}})
	if missing.Code == http.StatusOK {
		t.Fatal("DPoP-bound device refresh accepted without proof")
	}
	wrong := postDPoPToken(t, server, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}, dpopTestProof(t, otherPrivate, http.MethodPost, "/oidc/token", "device-refresh-wrong", "", ""))
	if wrong.Code != http.StatusBadRequest || tokenError(t, wrong) != "invalid_dpop_proof" {
		t.Fatal("DPoP-bound device refresh did not reject a different key")
	}
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}
	refreshChallenge := postDPoPToken(t, server, refreshForm, dpopTestProof(t, private, http.MethodPost, "/oidc/token", "device-refresh-one", "", ""))
	if refreshChallenge.Code != http.StatusBadRequest || tokenError(t, refreshChallenge) != "use_dpop_nonce" || refreshChallenge.Header().Get("DPoP-Nonce") == "" {
		t.Fatalf("device refresh challenge status=%d", refreshChallenge.Code)
	}
	refreshed := decodeToken(t, postDPoPToken(t, server, refreshForm, dpopTestProof(t, private, http.MethodPost, "/oidc/token", "device-refresh-two", refreshChallenge.Header().Get("DPoP-Nonce"), "")))
	if refreshed.TokenType != "DPoP" {
		t.Fatalf("device refresh token type=%q", refreshed.TokenType)
	}
}

func assertDeviceDPoPState(t *testing.T, db *rhiza.DB, deviceCode, wantState string, wantClaim bool) {
	t.Helper()
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT state, claim_token_digest IS NOT NULL FROM oauth_device_grants WHERE device_code_digest=?`, Args: []any{deviceDigestForTest(deviceCode)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 2 {
		t.Fatalf("device DPoP state rows=%#v err=%v", rows.Rows, err)
	}
	state, ok := rows.Rows[0][0].(string)
	if !ok || state != wantState {
		t.Fatalf("device DPoP state=%#v want=%q", rows.Rows[0], wantState)
	}
	claimed := rows.Rows[0][1] == int64(1)
	if claimed != wantClaim {
		t.Fatalf("device DPoP claim present=%v want=%v row=%#v", claimed, wantClaim, rows.Rows[0])
	}
}
