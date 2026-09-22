package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestAccountDeadlineClampDeterministic(t *testing.T) {
	t.Parallel()
	now := time.Unix(100, 0).UTC()
	for _, tc := range []struct {
		name     string
		deadline *int64
		want     time.Time
		reject   bool
	}{
		{name: "unlimited", want: now.Add(time.Hour)},
		{name: "zero is expired", deadline: new(int64(0)), reject: true},
		{name: "before", deadline: new(int64(99_999)), reject: true},
		{name: "equal", deadline: new(int64(100_000)), reject: true},
		{name: "no whole JWT second remains", deadline: new(int64(100_999)), reject: true},
		{name: "one second", deadline: new(int64(101_000)), want: now.Add(time.Second)},
		{name: "fraction rounds down", deadline: new(int64(102_999)), want: now.Add(2 * time.Second)},
		{name: "shorter configured lifespan", deadline: new(int64(4_000_000)), want: now.Add(time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), accountExpiryContextKey{}, []accountExpiry{{subject: "user", deadline: tc.deadline}})
			session := &fosite.DefaultSession{Subject: "user"}
			session.SetExpiresAt(fosite.AccessToken, now.Add(time.Hour))
			err := capAccountSession(ctx, session, now)
			if (err != nil) != tc.reject {
				t.Fatalf("reject=%t err=%v", tc.reject, err)
			}
			if tc.reject {
				return
			}
			if got := session.GetExpiresAt(fosite.AccessToken); !got.Equal(tc.want) {
				t.Fatalf("access expiry=%s want=%s", got, tc.want)
			}
			if tc.deadline == nil {
				if !session.GetExpiresAt(fosite.RefreshToken).IsZero() {
					t.Fatal("NULL changed unlimited refresh")
				}
			} else if !session.GetExpiresAt(fosite.RefreshToken).Equal(time.UnixMilli(*tc.deadline).Truncate(time.Second)) {
				t.Fatal("unlimited refresh was not capped")
			}
		})
	}
}

func TestAccountExpiryCommitClockAndSnapshot(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"unchanged", "shorter future", "NULL to finite", "clock reaches deadline", "disabled", "deleted"} {
		t.Run(name, func(t *testing.T) {
			db := oauthTestDB(t)
			server := oauthTestServer(t, db, randomSecret(t))
			now := time.Unix(1_700_000_000, 0).UTC()
			server.store.now = func() time.Time { return now }
			deadline := now.Add(10 * time.Minute).UnixMilli()
			var initial any = deadline
			if name == "NULL to finite" {
				initial = nil
			}
			_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "account-commit-seed", Statements: []rhiza.SQLStatement{
				{SQL: `INSERT INTO identity_users(subject,username,password_phc,user_expires_at_unix_ms) VALUES('user-1','user-1','phc',?)`, Args: []any{initial}},
				{SQL: `INSERT INTO oauth_authorize_codes(signature,request_json,expires_at_unix_ms) VALUES('code','{}',?)`, Args: []any{now.Add(time.Hour).UnixMilli()}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			request := fosite.NewAccessRequest(&fosite.DefaultSession{Subject: "user-1"})
			request.ID, request.Client, request.RequestedAt = "account-commit", server.store.client, now
			request.GrantTypes = fosite.Arguments{"authorization_code"}
			request.Session.SetExpiresAt(fosite.AccessToken, now.Add(time.Hour))
			request.Session.SetExpiresAt(fosite.RefreshToken, now.Add(time.Hour))
			ctx, err := server.store.issuanceAccounts(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			ctx, err = server.store.BeginTX(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = server.store.InvalidateAuthorizeCodeSession(ctx, "code"); err != nil {
				t.Fatal(err)
			}
			if err = server.store.CreateAccessTokenSession(ctx, "access", request); err != nil {
				t.Fatal(err)
			}
			if err = server.store.CreateRefreshTokenSession(ctx, "refresh", "access", request); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "shorter future", "NULL to finite":
				_, err = storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "account-commit-change", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject='user-1'`, Args: []any{now.Add(5 * time.Minute).UnixMilli()}})
			case "clock reaches deadline":
				now = time.UnixMilli(deadline)
			case "disabled":
				_, err = storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "account-commit-change", SQL: `UPDATE identity_users SET disabled=1 WHERE subject='user-1'`})
			case "deleted":
				_, err = storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "account-commit-change", SQL: `DELETE FROM identity_users WHERE subject='user-1'`})
			}
			if err != nil {
				t.Fatal(err)
			}
			err = server.store.Commit(ctx)
			allowed := name == "unchanged"
			if (err == nil) != allowed {
				t.Fatalf("commit=%v allowed=%t", err, allowed)
			}
			rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT (SELECT invalidated FROM oauth_authorize_codes WHERE signature='code'),(SELECT COUNT(*) FROM oauth_access_tokens),(SELECT COUNT(*) FROM oauth_token_requests),(SELECT COUNT(*) FROM oauth_refresh_tokens)`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 4 {
				t.Fatalf("rows=%v err=%v", rows.Rows, err)
			}
			want := int64(0)
			if allowed {
				want = 1
			}
			for _, value := range rows.Rows[0] {
				if value != want {
					t.Fatalf("atomic result=%v want each %d", rows.Rows, want)
				}
			}
		})
	}
}

func TestAccountExpiryResponseRecheck(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	now := time.Unix(1_700_000_000, 0).UTC()
	server.store.now = func() time.Time { return now }
	deadline := now.Add(10 * time.Minute).UnixMilli()
	_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "account-response-seed", SQL: `INSERT INTO identity_users(subject,username,password_phc,user_expires_at_unix_ms) VALUES('user-1','user-1','phc',?)`, Args: []any{deadline}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), accountExpiryContextKey{}, []accountExpiry{{subject: "user-1", deadline: &deadline}})
	if err := server.store.validateIssuanceAccounts(ctx); err != nil {
		t.Fatalf("live response: %v", err)
	}
	now = time.UnixMilli(deadline)
	if err := server.store.validateIssuanceAccounts(ctx); err == nil {
		t.Fatal("response accepted at deadline")
	}
	now = now.Add(-10 * time.Minute)
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "account-response-shorten", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject='user-1'`, Args: []any{now.Add(5 * time.Minute).UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if err := server.store.validateIssuanceAccounts(ctx); err == nil {
		t.Fatal("response accepted after still-future deadline changed")
	}
}
