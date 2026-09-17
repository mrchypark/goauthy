package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestProfileClaimsBySubjectReadsCurrentValuesAndRejectsInactive(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	bootstrapPassword(t, s, "profile-subject", "profile@example.test", []byte("CurrentPassword1"))
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "profile-claims-seed", SQL: `INSERT INTO identity_user_profiles(subject,email,email_verified,preferred_username,given_name,family_name,user_values_json) VALUES(?,?,?,?,?,?,?)`, Args: []any{"profile-subject", "profile@example.test", int64(1), "profile-user", "Given", "Family", `{"birthdate":"2000-01-02","phone":"+82101234","street":"Main","zip":"12345","city":"Seoul","country":"KR","tz":"Asia/Seoul"}`}}); err != nil {
		t.Fatal(err)
	}
	p, err := s.ProfileClaimsBySubject(ctx, "profile-subject")
	if err != nil || p.Email == nil || *p.PreferredUsername != "profile-user" || *p.Birthdate != "2000-01-02" || *p.Timezone != "Asia/Seoul" || p.EmailVerified == nil || !*p.EmailVerified {
		t.Fatalf("profile=%#v err=%v", p, err)
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "profile-claims-disable", SQL: `UPDATE identity_users SET disabled=1 WHERE subject=?`, Args: []any{"profile-subject"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ProfileClaimsBySubject(ctx, "profile-subject"); !errors.Is(err, ErrInactiveSubject) {
		t.Fatalf("disabled err=%v", err)
	}
}
