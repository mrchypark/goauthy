package identity

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
)

const selfProfileUpdateNow int64 = 1_800_000_000_000

func selfProfileTestAuthority() (string, []any) { return "1=1", nil }

func selfProfileFixture(t *testing.T) (*Store, UserValuesPolicy) {
	t.Helper()
	s := testResetStore(t, testRules(3))
	s.now = func() time.Time { return time.UnixMilli(selfProfileUpdateNow) }
	seedDeterministicRandom(s)
	bootstrapPassword(t, s, "target", "old@example.test", []byte("CurrentPassword1"))
	bootstrapPassword(t, s, "other", "other@example.test", []byte("CurrentPassword1"))

	userUpdateExecute(t, s, "self-profile-fixture", []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_user_profiles(subject,email,email_verified,preferred_username,given_name,family_name,user_values_json) VALUES
		 ('target','old@example.test',1,'keep-preferred','Old','Family','{"city":"Old City"}'),
		 ('other','other@example.test',1,NULL,NULL,NULL,NULL)`},
		{SQL: `INSERT INTO identity_recovery_emails(subject,email) VALUES('target','old@example.test'),('other','other@example.test')`},
		{SQL: `INSERT INTO rbac_roles(id,name,created_at_unix_ms,updated_at_unix_ms) VALUES('viewer','viewer',0,0)`},
		{SQL: `INSERT INTO rbac_user_roles(subject,role_id,granted_at_unix_ms) VALUES('target','viewer',0)`},
	})
	prefPolicy, _ := NewPreferredUsernamePolicy("optional", "", []string{"admin"})
	policy := UserValuesPolicy{
		GivenName: "optional", FamilyName: "optional",
		PreferredUsername: prefPolicy,
	}
	return s, policy
}

func TestSelfProfileValidInputAllTablesUnchangedExceptProfiles(t *testing.T) {
	s, policy := selfProfileFixture(t)
	ctx := context.Background()
	before := userUpdateSnapshot(t, s)

	city := "Seoul"
	givenNew := "New"
	familyFam := "Fam"
	keepPref := "keep-preferred"
	input := SelfProfileUpdate{
		GivenName:         &givenNew,
		FamilyName:        &familyFam,
		PreferredUsername: &keepPref,
		UserValues:        &UserValuesRequest{City: &city},
	}
	result, err := s.UpdateSelfProfileWithGuard(ctx, "target", input, policy, selfProfileTestAuthority)
	if err != nil {
		t.Fatal(err)
	}
	if result.Subject != "target" || result.User.ID != "target" {
		t.Fatalf("subject/id=%s/%s", result.Subject, result.User.ID)
	}
	if result.User.GivenName == nil || *result.User.GivenName != "New" {
		t.Fatalf("given_name=%v", result.User.GivenName)
	}
	if result.User.FamilyName == nil || *result.User.FamilyName != "Fam" {
		t.Fatalf("family_name=%v", result.User.FamilyName)
	}
	if result.User.UserValues.PreferredUsername == nil || *result.User.UserValues.PreferredUsername != "keep-preferred" {
		t.Fatalf("preferred=%v", result.User.UserValues.PreferredUsername)
	}
	if result.User.UserValues.City == nil || *result.User.UserValues.City != "Seoul" {
		t.Fatalf("city=%v", result.User.UserValues.City)
	}
	assertCount(t, s, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='target' AND given_name='New' AND family_name='Fam' AND preferred_username='keep-preferred'`, 1)
	after := userUpdateSnapshot(t, s)
	for table, rows := range before {
		if table == "identity_user_profiles" {
			continue
		}
		if len(rows) != 0 {
			assertUserUpdateSnapshotTable(t, s, table, rows, after[table])
		}
	}
}

func TestSelfProfileAuthorityFalseDeniedNoMutation(t *testing.T) {
	s, policy := selfProfileFixture(t)
	ctx := context.Background()
	givenName := "Denied"
	input := SelfProfileUpdate{GivenName: &givenName, UserValues: &UserValuesRequest{}}
	_, err := s.UpdateSelfProfileWithGuard(ctx, "target", input, policy, func() (string, []any) {
		return "0=1", nil
	})
	if !errors.Is(err, ErrSelfProfileUnauthorized) {
		t.Fatalf("err=%v", err)
	}
	assertCount(t, s, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='target' AND given_name='Old'`, 1)
}

func TestSelfProfileAuthoritySecondCallChangesGivenConflictPreservesConcurrent(t *testing.T) {
	s, policy := selfProfileFixture(t)
	ctx := context.Background()
	callCount := 0
	authority := func() (string, []any) {
		callCount++
		if callCount == 2 {
			userUpdateExecute(t, s, "concurrent", []rhiza.SQLStatement{
				{SQL: `UPDATE identity_user_profiles SET given_name='Concurrent' WHERE subject='target'`},
			})
		}
		return "1=1", nil
	}
	givenName := "New"
	keepPref := "keep-preferred"
	input := SelfProfileUpdate{GivenName: &givenName, PreferredUsername: &keepPref, UserValues: &UserValuesRequest{}}
	_, err := s.UpdateSelfProfileWithGuard(ctx, "target", input, policy, authority)
	if !errors.Is(err, ErrSelfProfileConflict) {
		t.Fatalf("err=%v", err)
	}
	assertCount(t, s, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='target' AND given_name='Concurrent'`, 1)
}

func TestSelfProfileExpiredAccountDenied(t *testing.T) {
	s, policy := selfProfileFixture(t)
	ctx := context.Background()
	userUpdateExecute(t, s, "expire", []rhiza.SQLStatement{
		{SQL: `UPDATE identity_users SET user_expires_at_unix_ms=1 WHERE subject='target'`},
	})
	givenName := "New"
	input := SelfProfileUpdate{GivenName: &givenName, UserValues: &UserValuesRequest{}}
	_, err := s.UpdateSelfProfileWithGuard(ctx, "target", input, policy, selfProfileTestAuthority)
	if !errors.Is(err, ErrSelfProfileUnauthorized) {
		t.Fatalf("err=%v", err)
	}
}

func TestSelfProfileNilNestedRequiredPreferredImmutableClearRejected(t *testing.T) {
	s, policy := selfProfileFixture(t)
	ctx := context.Background()

	immutable := policy.PreferredUsername.WithImmutable(true)
	policy.PreferredUsername = immutable
	newPref := "different"
	input := SelfProfileUpdate{PreferredUsername: &newPref, UserValues: &UserValuesRequest{}}
	_, err := s.UpdateSelfProfileWithGuard(ctx, "target", input, policy, selfProfileTestAuthority)
	if !errors.Is(err, ErrSelfProfileInvalid) {
		t.Fatalf("immutable err=%v", err)
	}

	emptyPref := ""
	input = SelfProfileUpdate{PreferredUsername: &emptyPref, UserValues: &UserValuesRequest{}}
	_, err = s.UpdateSelfProfileWithGuard(ctx, "target", input, policy, selfProfileTestAuthority)
	if !errors.Is(err, ErrSelfProfileInvalid) {
		t.Fatalf("immutable clear err=%v", err)
	}

	input = SelfProfileUpdate{PreferredUsername: nil, UserValues: &UserValuesRequest{}}
	_, err = s.UpdateSelfProfileWithGuard(ctx, "target", input, policy, selfProfileTestAuthority)
	if !errors.Is(err, ErrSelfProfileInvalid) {
		t.Fatalf("immutable nil err=%v", err)
	}
}

func TestSelfProfileDefaultNilPolicyImmutablePreferredChangeDenied(t *testing.T) {
	s, _ := selfProfileFixture(t)
	ctx := context.Background()
	nilPolicy := UserValuesPolicy{
		GivenName:         "optional",
		FamilyName:        "optional",
		PreferredUsername: nil,
	}
	diff := "different"
	input := SelfProfileUpdate{PreferredUsername: &diff, UserValues: &UserValuesRequest{}}
	_, err := s.UpdateSelfProfileWithGuard(ctx, "target", input, nilPolicy, selfProfileTestAuthority)
	if !errors.Is(err, ErrSelfProfileInvalid) {
		t.Fatalf("nil policy change err=%v", err)
	}
}

func TestSelfProfileDefaultNilPolicyImmutablePreferredClearDenied(t *testing.T) {
	s, _ := selfProfileFixture(t)
	ctx := context.Background()
	nilPolicy := UserValuesPolicy{
		GivenName:         "optional",
		FamilyName:        "optional",
		PreferredUsername: nil,
	}
	empty := ""
	input := SelfProfileUpdate{PreferredUsername: &empty, UserValues: &UserValuesRequest{}}
	_, err := s.UpdateSelfProfileWithGuard(ctx, "target", input, nilPolicy, selfProfileTestAuthority)
	if !errors.Is(err, ErrSelfProfileInvalid) {
		t.Fatalf("nil policy clear err=%v", err)
	}
}

func TestSelfProfileDefaultNilPolicyImmutablePreferredSameValueAccepted(t *testing.T) {
	s, _ := selfProfileFixture(t)
	ctx := context.Background()
	nilPolicy := UserValuesPolicy{
		GivenName:         "optional",
		FamilyName:        "optional",
		PreferredUsername: nil,
	}
	same := "keep-preferred"
	input := SelfProfileUpdate{PreferredUsername: &same, UserValues: &UserValuesRequest{}}
	result, err := s.UpdateSelfProfileWithGuard(ctx, "target", input, nilPolicy, selfProfileTestAuthority)
	if err != nil {
		t.Fatal(err)
	}
	if result.User.UserValues.PreferredUsername == nil || *result.User.UserValues.PreferredUsername != "keep-preferred" {
		t.Fatalf("preferred=%v", result.User.UserValues.PreferredUsername)
	}
}

func TestSelfProfileMutableExplicitNilPreferredClears(t *testing.T) {
	s, policy := selfProfileFixture(t)
	policy.PreferredUsername = policy.PreferredUsername.WithImmutable(false)
	ctx := context.Background()
	input := SelfProfileUpdate{PreferredUsername: nil, UserValues: &UserValuesRequest{}}
	result, err := s.UpdateSelfProfileWithGuard(ctx, "target", input, policy, selfProfileTestAuthority)
	if err != nil {
		t.Fatal(err)
	}
	if result.User.UserValues.PreferredUsername != nil {
		t.Fatalf("preferred should be nil, got %v", *result.User.UserValues.PreferredUsername)
	}
	assertCount(t, s, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='target' AND preferred_username IS NULL`, 1)
}

func TestSelfProfileDuplicatePreferredConflict(t *testing.T) {
	s, policy := selfProfileFixture(t)
	policy.PreferredUsername = policy.PreferredUsername.WithImmutable(false)
	ctx := context.Background()
	taken := "taken-name"
	userUpdateExecute(t, s, "set-other", []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_user_profiles(subject,email,email_verified,preferred_username,given_name,family_name,user_values_json) VALUES
		 ('other','other@example.test',1,?,?,?,NULL)
		 ON CONFLICT(subject) DO UPDATE SET preferred_username=excluded.preferred_username`,
			Args: []any{taken, nil, nil}},
	})
	input := SelfProfileUpdate{PreferredUsername: &taken, UserValues: &UserValuesRequest{}}
	_, err := s.UpdateSelfProfileWithGuard(ctx, "target", input, policy, selfProfileTestAuthority)
	if !errors.Is(err, ErrSelfProfileConflict) {
		t.Fatalf("err=%v", err)
	}
}

func TestSelfProfileGivenOptionalPreferredNilNamesEmptyValuesClear(t *testing.T) {
	s, policy := selfProfileFixture(t)
	ctx := context.Background()
	emptyGiven := ""
	emptyFamily := ""
	keepPref := "keep-preferred"
	input := SelfProfileUpdate{GivenName: &emptyGiven, FamilyName: &emptyFamily, PreferredUsername: &keepPref, UserValues: &UserValuesRequest{}}
	result, err := s.UpdateSelfProfileWithGuard(ctx, "target", input, policy, selfProfileTestAuthority)
	if err != nil {
		t.Fatal(err)
	}
	if result.User.GivenName != nil {
		t.Fatalf("given should be nil, got %v", *result.User.GivenName)
	}
	if result.User.FamilyName != nil {
		t.Fatalf("family should be nil, got %v", *result.User.FamilyName)
	}
	assertCount(t, s, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='target' AND given_name IS NULL AND family_name IS NULL`, 1)
}

func TestSelfProfileMissingProfileRowInsertsAfterDelete(t *testing.T) {
	s, policy := selfProfileFixture(t)
	ctx := context.Background()
	userUpdateExecute(t, s, "delete-profile", []rhiza.SQLStatement{
		{SQL: `DELETE FROM identity_user_profiles WHERE subject='target'`},
	})
	givenName := "Inserted"
	input := SelfProfileUpdate{GivenName: &givenName, UserValues: &UserValuesRequest{}}
	result, err := s.UpdateSelfProfileWithGuard(ctx, "target", input, policy, selfProfileTestAuthority)
	if err != nil {
		t.Fatal(err)
	}
	if result.User.GivenName == nil || *result.User.GivenName != "Inserted" {
		t.Fatalf("given_name=%v", result.User.GivenName)
	}
	assertCount(t, s, `SELECT COUNT(*) FROM identity_user_profiles WHERE subject='target' AND email='old@example.test' AND given_name='Inserted'`, 1)
	assertCount(t, s, `SELECT COUNT(*) FROM identity_recovery_emails WHERE subject='target' AND email='old@example.test'`, 1)
}

func assertUserUpdateSnapshotTable(t *testing.T, s *Store, table string, before, after [][]any) {
	t.Helper()
	if len(before) != len(after) {
		t.Errorf("table %s row count changed: %d -> %d", table, len(before), len(after))
		return
	}
	for i := range before {
		if len(before[i]) != len(after[i]) {
			t.Errorf("table %s row %d column count changed", table, i)
			return
		}
		for j := range before[i] {
			if !reflect.DeepEqual(before[i][j], after[i][j]) {
				t.Errorf("table %s row %d col %d changed", table, i, j)
				return
			}
		}
	}
}
