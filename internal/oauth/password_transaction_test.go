package oauth

import (
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

func TestPasswordTransactionBindsAuthenticatedSubject(t *testing.T) {
	s := oauthTestServer(t, oauthTestDB(t), randomSecret(t)).store
	ctx, err := s.beginPasswordTX(t.Context(), "authenticated-user", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	r := fosite.NewRequest()
	r.Client = s.client
	for _, session := range []fosite.Session{nil, &fosite.DefaultSession{Subject: "different-user"}, &fosite.DefaultSession{}} {
		r.Session = session
		if err := s.CreateAccessTokenSession(ctx, "access", r); !errors.Is(err, fosite.ErrInvalidGrant) {
			t.Fatalf("access accepted mismatched subject: %v", err)
		}
		if err := s.CreateRefreshTokenSession(ctx, "refresh", "access", r); !errors.Is(err, fosite.ErrInvalidGrant) {
			t.Fatalf("refresh accepted mismatched subject: %v", err)
		}
	}
	if len(txFrom(ctx).statements) != 0 {
		t.Fatal("mismatched subject queued mutations")
	}
}

func TestPasswordTransactionRejectsChangedAuthentication(t *testing.T) {
	for _, change := range []string{"reject refresh write", "expire while queued", "", "UPDATE identity_users SET password_generation=2", "UPDATE identity_authentication_modes SET generation=2", "UPDATE identity_authentication_modes SET mode='passkey'", "UPDATE identity_users SET disabled=1"} {
		t.Run(change, func(t *testing.T) {
			db := oauthTestDB(t)
			s := oauthTestServer(t, db, randomSecret(t)).store
			_, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "seed-password", Statements: []rhiza.SQLStatement{
				{SQL: `INSERT INTO identity_users(subject,username,password_phc,password_generation) VALUES('password-user','password-user','phc',1)`},
				{SQL: `INSERT INTO identity_authentication_modes(subject,mode,generation,updated_at_unix_ms) VALUES('password-user','password',1,0)`},
			}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, err := s.beginPasswordTX(t.Context(), "password-user", 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
			s.now = func() time.Time { return now }
			txFrom(ctx).issueNow = now.UnixMilli()
			if change == "expire while queued" {
				_, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "set-expiry", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=?`, Args: []any{now.Add(time.Millisecond).UnixMilli()}})
				if err != nil {
					t.Fatal(err)
				}
			}
			r := fosite.NewRequest()
			r.ID, r.Client, r.Session = "password-request", s.client, &fosite.DefaultSession{Subject: "password-user"}
			r.RequestedAt = now
			r.Session.SetExpiresAt(fosite.AccessToken, r.RequestedAt.Add(time.Hour))
			r.Session.SetExpiresAt(fosite.RefreshToken, r.RequestedAt.Add(2*time.Hour))
			if err := s.CreateAccessTokenSession(ctx, "password-access", r); err != nil {
				t.Fatal(err)
			}
			if err := s.CreateRefreshTokenSession(ctx, "password-refresh", "password-access", r); err != nil {
				t.Fatal(err)
			}
			if change == "expire while queued" {
				now = now.Add(time.Millisecond)
			} else if change == "reject refresh write" {
				_, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "reject-refresh", SQL: `CREATE TRIGGER reject_password_refresh BEFORE INSERT ON oauth_refresh_tokens BEGIN SELECT RAISE(ABORT, 'refresh write rejected'); END`})
				if err != nil {
					t.Fatal(err)
				}
			} else if change != "" {
				if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "change-password", SQL: change}); err != nil {
					t.Fatal(err)
				}
			}
			err = s.Commit(ctx)
			if change == "" && err != nil || change == "reject refresh write" && err == nil || change != "" && change != "reject refresh write" && !errors.Is(err, fosite.ErrSerializationFailure) {
				t.Fatalf("commit: %v", err)
			}
			rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens),(SELECT COUNT(*) FROM oauth_token_requests),(SELECT COUNT(*) FROM oauth_refresh_tokens)`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 {
				t.Fatalf("rows: %v %v", rows.Rows, err)
			}
			want := int64(0)
			if change == "" {
				want = 1
			}
			for _, count := range rows.Rows[0] {
				if count != want {
					t.Fatalf("artifacts: %v want each %d", rows.Rows, want)
				}
			}
		})
	}
}
