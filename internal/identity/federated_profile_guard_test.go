package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

func TestFederatedProfileGuardStaleProvider(t *testing.T) {
	store := testFederatedProfileStore(t)
	seedExistingUser(t, store, "staleprov@example.test")
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	called := false
	store.random = func(out []byte) (int, error) {
		if !called {
			called = true
			if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
				RequestID: "test-version-rotate-guard",
				Statements: []rhiza.SQLStatement{
					{SQL: "UPDATE auth_provider_runtime_versions SET version = 'v99' WHERE provider_id = '" + testFederatedProviderID + "'"},
				},
			}); err != nil {
				t.Fatalf("guard interposition: %v", err)
			}
		}
		for i := range out {
			out[i] = 1
		}
		return len(out), nil
	}
	_, err := store.UpdateFederatedProfile(context.Background(), FederatedProfileUpdateInput{
		Subject: testFederatedSubject(testFederatedNamespace),
		Config:  testFederatedProvider,
		Email:   "staleprov@example.test",
	})
	if err != ErrFederatedProfileConflict {
		t.Fatalf("expected ErrFederatedProfileConflict, got err=%v", err)
	}
}

func TestFederatedProfileGuardUnlink(t *testing.T) {
	store := testFederatedProfileStore(t)
	seedExistingUser(t, store, "unlink@example.test")
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	called := false
	store.random = func(out []byte) (int, error) {
		if !called {
			called = true
			if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
				RequestID: "test-unlink-guard",
				SQL:       "DELETE FROM identity_external_links WHERE provider_id = '" + testFederatedProviderID + "'",
			}); err != nil {
				t.Fatalf("guard interposition: %v", err)
			}
		}
		for i := range out {
			out[i] = 1
		}
		return len(out), nil
	}
	_, err := store.UpdateFederatedProfile(context.Background(), FederatedProfileUpdateInput{
		Subject: testFederatedSubject(testFederatedNamespace),
		Config:  testFederatedProvider,
		Email:   "unlink@example.test",
	})
	if err != ErrFederatedProfileConflict {
		t.Fatalf("expected ErrFederatedProfileConflict, got err=%v", err)
	}
}

func TestFederatedProfileGuardProfileUpdate(t *testing.T) {
	store := testFederatedProfileStore(t)
	subject := seedExistingUser(t, store, "profileupdate@example.test")
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	called := false
	store.random = func(out []byte) (int, error) {
		if !called {
			called = true
			if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
				RequestID: "test-profile-mutate-guard",
				Statements: []rhiza.SQLStatement{
					{SQL: "INSERT INTO identity_user_profiles(subject,email,email_verified,given_name,family_name) VALUES(?,?,?,?,?) ON CONFLICT(subject) DO UPDATE SET email_verified=excluded.email_verified,given_name=excluded.given_name",
						Args: []any{subject, "profileupdate@example.test", int64(0), "Mutated", "Profile"}},
				},
			}); err != nil {
				t.Fatalf("guard interposition: %v", err)
			}
		}
		for i := range out {
			out[i] = 1
		}
		return len(out), nil
	}
	_, err := store.UpdateFederatedProfile(context.Background(), FederatedProfileUpdateInput{
		Subject: testFederatedSubject(testFederatedNamespace),
		Config:  testFederatedProvider,
		Email:   "profileupdate@example.test",
	})
	if err != ErrFederatedProfileConflict {
		t.Fatalf("expected ErrFederatedProfileConflict, got err=%v", err)
	}
}

func TestFederatedProfileGuardLastOtherAdminRemoved(t *testing.T) {
	store := testFederatedProfileStore(t)
	subject := seedExistingUser(t, store, "lastother@example.test")
	seedAdminRole(t, store, subject)
	peer, err := store.CreateFederatedIdentity(context.Background(), FederatedCreationInput{
		Subject: upstreamprovider.SubjectResult{ProviderID: testFederatedProviderID, Subject: "admin-peer2", IdentityNamespace: testFederatedNamespace},
		Config:  testFederatedProvider,
		Email:   "admin-peer2@example.test",
	})
	if err != nil {
		t.Fatalf("CreateFederatedIdentity: %v", err)
	}
	peerAdminTrue := true
	if _, err := store.UpdateFederatedProfile(context.Background(), FederatedProfileUpdateInput{
		Subject:       upstreamprovider.SubjectResult{ProviderID: testFederatedProviderID, Subject: "admin-peer2", IdentityNamespace: testFederatedNamespace},
		Config:        testFederatedProvider,
		Email:         "admin-peer2@example.test",
		EmailVerified: true,
		AdminMapping:  &peerAdminTrue,
	}); err != nil {
		t.Fatalf("admin grant peer: %v", err)
	}
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	called := false
	store.random = func(out []byte) (int, error) {
		if !called {
			called = true
			if _, err := storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
				RequestID: "test-remove-peer-admin",
				Statements: []rhiza.SQLStatement{
					{SQL: "DELETE FROM rbac_user_roles WHERE subject=? AND role_id IN(SELECT id FROM rbac_roles WHERE name='rauthy_admin')",
						Args: []any{peer.Subject}},
				},
			}); err != nil {
				t.Fatalf("guard interposition: %v", err)
			}
		}
		for i := range out {
			out[i] = 1
		}
		return len(out), nil
	}
	adminFalse := false
	_, err = store.UpdateFederatedProfile(context.Background(), FederatedProfileUpdateInput{
		Subject:      testFederatedSubject(testFederatedNamespace),
		Config:       testFederatedProvider,
		Email:        "lastother@example.test",
		AdminMapping: &adminFalse,
	})
	if err != ErrFederatedProfileConflict {
		t.Fatalf("expected ErrFederatedProfileConflict (last-admin), got err=%v", err)
	}
	if !called {
		t.Fatal("guard interposition was not called")
	}
	assertCount(t, store, "SELECT COUNT(*) FROM rbac_user_roles WHERE subject='"+subject+"' AND role_id IN(SELECT id FROM rbac_roles WHERE name='rauthy_admin')", 1)
}

func TestFederatedProfileExpiredRejected(t *testing.T) {
	store := testFederatedProfileStore(t)
	subject := seedExistingUser(t, store, "expired@example.test")
	storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
		RequestID: "test-expire-user",
		SQL:       "UPDATE identity_users SET user_expires_at_unix_ms = 1 WHERE subject = '" + subject + "'",
	})
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	_, err := store.UpdateFederatedProfile(context.Background(), FederatedProfileUpdateInput{
		Subject: testFederatedSubject(testFederatedNamespace),
		Config:  testFederatedProvider,
		Email:   "expired@example.test",
	})
	if err != ErrFederatedProfileConflict {
		t.Fatalf("expected ErrFederatedProfileConflict for expired user, got err=%v", err)
	}
}

func TestFederatedProfileRNGFailure(t *testing.T) {
	store := testFederatedProfileStore(t)
	seedExistingUser(t, store, "rngfail@example.test")
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	store.random = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	_, err := store.UpdateFederatedProfile(context.Background(), FederatedProfileUpdateInput{
		Subject: testFederatedSubject(testFederatedNamespace),
		Config:  testFederatedProvider,
		Email:   "rngfail@example.test",
	})
	if err == nil {
		t.Fatal("expected error for RNG failure")
	}
}

func TestFederatedProfileMissingRole(t *testing.T) {
	store := testFederatedProfileStore(t)
	seedExistingUser(t, store, "norole@example.test")
	storage.Execute(context.Background(), store.db, rhiza.ExecuteRequest{
		RequestID: "test-delete-admin-role",
		SQL:       "DELETE FROM rbac_roles WHERE name = 'rauthy_admin'",
	})
	store.now = func() time.Time { return time.UnixMilli(2_000_000).UTC() }
	adminTrue := true
	_, err := store.UpdateFederatedProfile(context.Background(), FederatedProfileUpdateInput{
		Subject:       testFederatedSubject(testFederatedNamespace),
		Config:        testFederatedProvider,
		Email:         "norole@example.test",
		EmailVerified: true,
		AdminMapping:  &adminTrue,
	})
	if err != ErrFederatedProfileConflict {
		t.Fatalf("expected ErrFederatedProfileConflict for missing role, got err=%v", err)
	}
}
