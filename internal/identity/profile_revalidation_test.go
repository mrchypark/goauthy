package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func seedProfile(t *testing.T, s *Store, subject, email, preferredUsername string, givenName, familyName any, userValuesJSON string) {
	t.Helper()
	if _, err := storage.Execute(context.Background(), s.db, rhiza.ExecuteRequest{
		RequestID: "revalidation-seed-" + subject,
		SQL:       `INSERT INTO identity_user_profiles(subject,email,email_verified,preferred_username,given_name,family_name,user_values_json) VALUES(?,?,?,?,?,?,?)`,
		Args:      []any{subject, email, int64(1), preferredUsername, givenName, familyName, userValuesJSON},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNeedsProfileUpdateDisabledReturnsFalse(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	policy := UserValuesPolicy{RevalidateDuringLogin: false}
	needs, err := s.NeedsProfileUpdate(ctx, policy, "any", "any-client")
	if err != nil || needs {
		t.Fatalf("disabled: needs=%v err=%v", needs, err)
	}
}

func TestNeedsProfileUpdateRauthyClientExempt(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	policy := UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"}
	needs, err := s.NeedsProfileUpdate(ctx, policy, "any", "rauthy")
	if err != nil || needs {
		t.Fatalf("rauthy exempt: needs=%v err=%v", needs, err)
	}
}

func TestNeedsProfileUpdateValidProfileReturnsFalse(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	bootstrapPassword(t, s, "valid-sub", "valid-user", []byte("Password1"))
	seedProfile(t, s, "valid-sub", "valid@example.test", "validuser", "Given", "Family",
		`{"birthdate":"2000-01-01"}`)
	policy := UserValuesPolicy{GivenName: "required", FamilyName: "required", RevalidateDuringLogin: true}
	needs, err := s.NeedsProfileUpdate(ctx, policy, "valid-sub", "other-client")
	if err != nil {
		t.Fatal(err)
	}
	if needs {
		t.Fatal("valid profile should not need update")
	}
}

func TestNeedsProfileUpdateMissingRequiredGivenName(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	bootstrapPassword(t, s, "name-sub", "name-user", []byte("Password1"))
	seedProfile(t, s, "name-sub", "name@example.test", "nameuser", nil, "Family", `{}`)
	policy := UserValuesPolicy{GivenName: "required", FamilyName: "required", RevalidateDuringLogin: true}
	needs, err := s.NeedsProfileUpdate(ctx, policy, "name-sub", "other-client")
	if err != nil {
		t.Fatal(err)
	}
	if !needs {
		t.Fatal("missing required given_name should need update")
	}
}

func TestNeedsProfileUpdateMissingRequiredFamilyName(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	bootstrapPassword(t, s, "fam-sub", "fam-user", []byte("Password1"))
	seedProfile(t, s, "fam-sub", "fam@example.test", "famuser", "Given", nil, `{}`)
	policy := UserValuesPolicy{GivenName: "required", FamilyName: "required", RevalidateDuringLogin: true}
	needs, err := s.NeedsProfileUpdate(ctx, policy, "fam-sub", "other-client")
	if err != nil {
		t.Fatal(err)
	}
	if !needs {
		t.Fatal("missing required family_name should need update")
	}
}

func TestNeedsProfileUpdateMissingNestedBirthdate(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	bootstrapPassword(t, s, "nest-sub", "nest-user", []byte("Password1"))
	seedProfile(t, s, "nest-sub", "nest@example.test", "nestuser", "Given", "Family",
		`{"birthdate":null}`)
	policy := UserValuesPolicy{GivenName: "required", FamilyName: "required", Birthdate: "required", RevalidateDuringLogin: true}
	needs, err := s.NeedsProfileUpdate(ctx, policy, "nest-sub", "other-client")
	if err != nil {
		t.Fatal(err)
	}
	if !needs {
		t.Fatal("missing nested required birthdate should need update")
	}
}

func TestNeedsProfileUpdateInvalidPreferredUsername(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	bootstrapPassword(t, s, "pu-sub", "pu-user", []byte("Password1"))
	seedProfile(t, s, "pu-sub", "pu@example.test", "Admin", "Given", "Family", `{}`)
	policy := UserValuesPolicy{GivenName: "required", RevalidateDuringLogin: true}
	if policy.PreferredUsername == nil {
		policy.PreferredUsername, _ = NewPreferredUsernamePolicy("required", "", nil)
	}
	needs, err := s.NeedsProfileUpdate(ctx, policy, "pu-sub", "other-client")
	if err != nil {
		t.Fatal(err)
	}
	if !needs {
		t.Fatal("blacklisted preferred_username should need update")
	}
}

func TestNeedsProfileUpdateInactiveSubjectReturnsError(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	policy := UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"}
	_, err := s.NeedsProfileUpdate(ctx, policy, "nonexistent-subject", "other-client")
	if !errors.Is(err, ErrInactiveSubject) {
		t.Fatalf("expected ErrInactiveSubject, got err=%v", err)
	}
}

func TestNeedsProfileUpdateInvalidPolicyReturnsError(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	bootstrapPassword(t, s, "policy-sub", "policy-user", []byte("Password1"))
	policy := UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "BOGUS"}
	_, err := s.NeedsProfileUpdate(ctx, policy, "policy-sub", "other-client")
	if !errors.Is(err, ErrUserValuesPolicy) {
		t.Fatalf("expected ErrUserValuesPolicy, got err=%v", err)
	}
}

func TestNeedsProfileUpdateReadErrorReturnsError(t *testing.T) {
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "read-error-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	hasher, err2 := credential.NewHasher(credential.DefaultPolicy())
	if err2 != nil {
		t.Fatal(err2)
	}
	store, err3 := NewStoreWithPolicies(db, hasher, credential.DefaultRules())
	if err3 != nil {
		t.Fatal(err3)
	}
	_ = db.Close()
	ctx := context.Background()
	policy := UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"}
	_, got := store.NeedsProfileUpdate(ctx, policy, "any-subject", "other-client")
	if got == nil {
		t.Fatal("expected a non-nil error from closed DB")
	}
	if errors.Is(got, ErrInactiveSubject) {
		t.Fatalf("genuine read error must not be ErrInactiveSubject, got %v", got)
	}
}
