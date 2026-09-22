package oauth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

func TestPrincipalGuardUsesCapturedExclusiveIdentityExpiry(t *testing.T) {
	t.Parallel()
	const now int64 = 1_700_000_000_000
	db := oauthTestDB(t)
	for i, tc := range []struct {
		name     string
		expires  any
		disabled int
		revision int64
		allowed  bool
	}{
		{name: "unlimited", expires: nil, allowed: true, revision: 1},
		{name: "before", expires: now - 1, allowed: false, revision: 1},
		{name: "equal", expires: now, allowed: false, revision: 1},
		{name: "after", expires: now + 1, allowed: true, revision: 1},
		{name: "disabled", expires: now + 1, disabled: 1, allowed: false, revision: 1},
		{name: "wrong revision", expires: now + 1, allowed: false, revision: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subject := "expiry-guard-" + string(rune('a'+i))
			_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "expiry-guard-" + subject, Statements: []rhiza.SQLStatement{
				{SQL: `INSERT INTO identity_users (subject,username,password_phc,disabled,user_expires_at_unix_ms) VALUES (?, ?, ?, ?, ?)`, Args: []any{subject, subject, "phc", tc.disabled, tc.expires}},
				{SQL: `INSERT INTO rbac_principal_versions (subject,revision,updated_at_unix_ms) VALUES (?, 1, 0)`, Args: []any{subject}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			guardTx := &transaction{principalSubject: subject, principalRevision: tc.revision, issueNow: now}
			guard, args := guardTx.principalGuard()
			if !strings.Contains(guard, "user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms > ?") {
				t.Fatalf("guard=%q lacks exclusive expiry predicate", guard)
			}
			if len(args) < 2 || args[1] != now {
				t.Fatalf("guard args=%#v, captured now=%d", args, now)
			}
			result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT EXISTS (SELECT 1 FROM identity_users WHERE subject=?` + guard + `)`, Args: append([]any{subject}, args...), Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
				t.Fatalf("guard query rows=%#v err=%v", result.Rows, err)
			}
			got, ok := result.Rows[0][0].(int64)
			if !ok || (got == 1) != tc.allowed {
				t.Fatalf("guard result=%#v allowed=%t, want %t", result.Rows, got == 1, tc.allowed)
			}
		})
	}
}

func TestPrincipalGuardDoesNotApplyIdentityExpiryWithoutSubject(t *testing.T) {
	t.Parallel()
	guard, args := (&transaction{}).principalGuard()
	if guard != "" || len(args) != 0 {
		t.Fatalf("machine transaction unexpectedly received identity guard=%q args=%#v", guard, args)
	}
}

func TestExpiredDevicePrincipalLeavesNoTokenArtifacts(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	deviceCode, claimToken := "expired-account-device", "expired-account-claim"
	now := int64(1_700_000_000_000)
	server.store.now = func() time.Time { return unixMillis(now) }
	future := now + int64(time.Hour/time.Millisecond)
	_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "expired-account-device", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users (subject,username,password_phc,user_expires_at_unix_ms) VALUES (?, ?, ?, ?)`, Args: []any{"expired-device-user", "expired-device-user", "phc", now - 1}},
		{SQL: `INSERT INTO oauth_device_grants (device_code_digest,user_code_digest,client_id,scopes_json,subject,state,expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,claim_token_digest,claim_until_unix_ms,created_at_unix_ms) VALUES (?, ?, ?, ?, ?, 'approved', ?, ?, ?, ?, ?, ?)`, Args: []any{deviceCodeDigest(deviceCode), deviceCodeDigest("expired-account-code"), testClientID, `["goauthy.read","offline_access"]`, "expired-device-user", future, int64(5), now, deviceCodeDigest(claimToken), future, now}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	request := fosite.NewRequest()
	request.ID, request.Client, request.RequestedAt, request.Session = "expired-account-device-request", server.store.client, unixMillis(now), &fosite.DefaultSession{Subject: "expired-device-user"}
	request.SetRequestedScopes(fosite.Arguments{"goauthy.read", "offline_access"})
	request.GrantScope("goauthy.read")
	request.GrantScope("offline_access")
	txCtx, err := server.store.BeginDeviceTX(context.Background(), deviceCode, claimToken)
	if err != nil {
		t.Fatal(err)
	}
	txFrom(txCtx).issueNow = now // The device claim is still live; only its account is expired.
	request.Session.SetExpiresAt(fosite.AccessToken, unixMillis(future))
	request.Session.SetExpiresAt(fosite.RefreshToken, unixMillis(future))
	_, accessSignature, err := server.accessTokens.GenerateAccessToken(txCtx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.store.CreateAccessTokenSession(txCtx, accessSignature, request); err != nil {
		t.Fatal(err)
	}
	refresh, ok := server.accessTokens.(oauth2.RefreshTokenStrategy)
	if !ok {
		t.Fatal("OAuth strategy does not support refresh tokens")
	}
	_, refreshSignature, err := refresh.GenerateRefreshToken(txCtx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.store.CreateRefreshTokenSession(txCtx, refreshSignature, accessSignature, request); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(txCtx); err == nil {
		t.Fatal("expired account's device grant committed successfully")
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens), (SELECT COUNT(*) FROM oauth_token_requests), (SELECT COUNT(*) FROM oauth_refresh_tokens)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) || rows.Rows[0][1] != int64(0) || rows.Rows[0][2] != int64(0) {
		t.Fatalf("expired device principal artifacts=%#v err=%v", rows.Rows, err)
	}
	grant, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT state FROM oauth_device_grants WHERE device_code_digest=?`, Args: []any{deviceCodeDigest(deviceCode)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(grant.Rows) != 1 || grant.Rows[0][0] != "approved" {
		t.Fatalf("rejected issuance consumed the claim: rows=%v err=%v", grant.Rows, err)
	}
}
