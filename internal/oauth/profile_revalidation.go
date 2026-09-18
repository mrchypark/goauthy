package oauth

import (
	"context"
	"fmt"

	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

type profileRevalidationContextKey struct{}

// profileSnapshot captures the raw identity_user_profiles row values that
// drive ValidateFields and ValidateRegistration. The snapshot is taken before
// ResolveProfile and NeedsProfileUpdate so a concurrent profile mutation
// cannot issue a code for an invalid profile.
type profileSnapshot struct {
	subject string
	raw     string
}

// errInteractionRequired is the OIDC interaction_required authorization
// endpoint error. It signals that the end-user must interact with the
// authorization server (e.g. to complete a profile) before proceeding.
var errInteractionRequired = &fosite.RFC6749Error{
	ErrorField:       "interaction_required",
	DescriptionField: "The authorization server requires end-user interaction.",
	CodeField:        400,
}

// captureProfileSnapshot reads the raw identity_user_profiles row for subject.
// The snapshot is captured before ResolveProfile and NeedsProfileUpdate so the
// SQL fence in the code commit can detect concurrent profile mutation.
func (s *Store) captureProfileSnapshot(ctx context.Context, subject string) (profileSnapshot, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT json_array(given_name,family_name,user_values_json,preferred_username) FROM identity_user_profiles WHERE subject=?`,
		Args:        []any{subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return profileSnapshot{}, err
	}
	snap := profileSnapshot{subject: subject}
	if len(result.Rows) == 0 {
		return snap, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return profileSnapshot{}, fmt.Errorf("unexpected profile snapshot result shape")
	}
	v, ok := result.Rows[0][0].(string)
	if !ok {
		return profileSnapshot{}, fmt.Errorf("unexpected profile snapshot column type")
	}
	snap.raw = v
	return snap, nil
}

// profileGuard returns a SQL fragment and args that fence code issuance by
// the exact identity_user_profiles row captured at authorization time. A
// concurrent profile mutation between validation and commit causes the
// mutation to fail, preventing code issuance on a stale profile.
func profileGuard(snap profileSnapshot) (string, []any) {
	if snap.subject == "" {
		return "", nil
	}
	return ` AND COALESCE((SELECT json_array(given_name,family_name,user_values_json,preferred_username) FROM identity_user_profiles WHERE subject=?),'')=?`,
		[]any{snap.subject, snap.raw}
}

// SetUserValuesPolicy configures the static profile revalidation policy for
// authorization-code issuance. The default is off. When RevalidateDuringLogin
// is true, needsUpdate must be non-nil: it is the identity store's
// NeedsProfileUpdate method. This method validates the deployment policy once;
// it does not activate any main/env/config response surface.
func (s *Server) SetUserValuesPolicy(policy identity.UserValuesPolicy, needsUpdate func(context.Context, identity.UserValuesPolicy, string, string) (bool, error)) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	if policy.RevalidateDuringLogin && needsUpdate == nil {
		return identity.ErrUserValuesPolicy
	}
	s.userValuesPolicy = policy
	s.needsProfileUpdate = needsUpdate
	return nil
}
