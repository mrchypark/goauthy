package oauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

func TestDeviceCommitUsesFinalSubmissionClock(t *testing.T) {
	for _, tc := range []struct {
		name    string
		advance bool
	}{
		{name: "claim still live"},
		{name: "claim expires while queued", advance: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := oauthTestDB(t)
			server := oauthTestServer(t, db, randomSecret(t))
			base := time.Unix(1_700_000_000, 0).UTC()
			claimDeadline := base.Add(time.Minute)
			server.store.now = func() time.Time { return base }
			seedDeviceUser(t, db, "device-clock-user", nil)
			deviceCode, claimToken := "device-clock-code", "device-clock-claim"
			_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
				RequestID: "seed-device-clock-grant",
				SQL: `INSERT INTO oauth_device_grants
				(device_code_digest,user_code_digest,client_id,scopes_json,subject,state,
				expires_at_unix_ms,interval_seconds,next_poll_at_unix_ms,claim_token_digest,
				claim_until_unix_ms,created_at_unix_ms)
				VALUES (?, ?, ?, ?, ?, 'approved', ?, ?, ?, ?, ?, ?)`,
				Args: []any{deviceCodeDigest(deviceCode), deviceCodeDigest("device-clock-user-code"), testClientID,
					`["goauthy.read","offline_access"]`, "device-clock-user", base.Add(time.Hour).UnixMilli(), int64(5),
					base.UnixMilli(), deviceCodeDigest(claimToken), claimDeadline.UnixMilli(), base.UnixMilli()},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := fosite.NewRequest()
			request.ID, request.Client, request.RequestedAt = "device-clock-request", server.store.client, base
			request.Session = &fosite.DefaultSession{Subject: "device-clock-user"}
			request.SetRequestedScopes(fosite.Arguments{"goauthy.read", "offline_access"})
			request.GrantScope("goauthy.read")
			request.GrantScope("offline_access")
			request.Session.SetExpiresAt(fosite.AccessToken, base.Add(time.Hour))
			request.Session.SetExpiresAt(fosite.RefreshToken, base.Add(time.Hour))
			txCtx, err := server.store.BeginDeviceTX(context.Background(), deviceCode, claimToken)
			if err != nil {
				t.Fatal(err)
			}
			_, accessSignature, err := server.accessTokens.GenerateAccessToken(txCtx, request)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.store.CreateAccessTokenSession(txCtx, accessSignature, request); err != nil {
				t.Fatal(err)
			}
			refreshStrategy, ok := server.accessTokens.(oauth2.RefreshTokenStrategy)
			if !ok {
				t.Fatal("OAuth strategy does not support refresh tokens")
			}
			_, refreshSignature, err := refreshStrategy.GenerateRefreshToken(txCtx, request)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.store.CreateRefreshTokenSession(txCtx, refreshSignature, accessSignature, request); err != nil {
				t.Fatal(err)
			}
			if tc.advance {
				server.store.now = func() time.Time { return claimDeadline }
			}
			err = server.store.Commit(txCtx)
			if tc.advance {
				if !errors.Is(err, fosite.ErrSerializationFailure) {
					t.Fatalf("Commit error=%v", err)
				}
			} else if err != nil {
				t.Fatalf("live claim rejected: %v", err)
			}
			rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT
			(SELECT COUNT(*) FROM oauth_access_tokens),
			(SELECT COUNT(*) FROM oauth_token_requests),
			(SELECT COUNT(*) FROM oauth_refresh_tokens),
			(SELECT state FROM oauth_device_grants WHERE device_code_digest=?)`,
				Args: []any{deviceCodeDigest(deviceCode)}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 4 {
				t.Fatalf("result rows=%#v err=%v", rows.Rows, err)
			}
			if tc.advance {
				if rows.Rows[0][0] != int64(0) || rows.Rows[0][1] != int64(0) || rows.Rows[0][2] != int64(0) || rows.Rows[0][3] != "approved" {
					t.Fatalf("expired claim left artifacts or was consumed: %#v", rows.Rows)
				}
			} else if rows.Rows[0][0] != int64(1) || rows.Rows[0][1] != int64(1) || rows.Rows[0][2] != int64(1) || rows.Rows[0][3] != "consumed" {
				t.Fatalf("live claim result=%#v", rows.Rows)
			}
		})
	}
}
