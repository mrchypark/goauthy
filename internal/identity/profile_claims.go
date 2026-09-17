package identity

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/mrchypark/rhiza"
)

// ProfileClaims is the credential-free standard OIDC profile projection. A
// nil field means that the value is not stored; callers decide which granted
// scope is allowed to present it.
type ProfileClaims struct {
	Email, PreferredUsername, GivenName, FamilyName *string
	EmailVerified                                   *bool
	Birthdate, Phone, Street, ZIP, City, Country    *string
	Timezone                                        *string
	Language                                        *string
}

// ProfileClaimsBySubject reads the current active profile in one linearizable
// query. It intentionally does not return passwords, recovery data, or roles.
func (s *Store) ProfileClaimsBySubject(ctx context.Context, subject string) (ProfileClaims, error) {
	if err := validateSubject(subject); err != nil {
		return ProfileClaims{}, err
	}
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT u.disabled,u.user_expires_at_unix_ms,u.language,p.email,p.email_verified,p.preferred_username,p.given_name,p.family_name,p.user_values_json FROM identity_users u LEFT JOIN identity_user_profiles p ON p.subject=u.subject WHERE u.subject=?`, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return ProfileClaims{}, err
	}
	if len(r.Rows) != 1 || len(r.Rows[0]) != 9 {
		return ProfileClaims{}, ErrInactiveSubject
	}
	row := r.Rows[0]
	disabled, ok := row[0].(int64)
	if !ok || disabled != 0 {
		return ProfileClaims{}, ErrInactiveSubject
	}
	if row[1] != nil {
		expiry, ok := row[1].(int64)
		if !ok || (expiry != 0 && expiry <= s.now().UTC().UnixMilli()) {
			return ProfileClaims{}, ErrInactiveSubject
		}
	}
	out := ProfileClaims{}
	if row[2] != nil {
		v, ok := row[2].(string)
		if !ok {
			return ProfileClaims{}, errors.New("invalid identity language")
		}
		out.Language = &v
	}
	set := func(dst **string, i int) error {
		if row[i] == nil {
			return nil
		}
		v, ok := row[i].(string)
		if !ok {
			return errors.New("invalid identity profile row")
		}
		*dst = &v
		return nil
	}
	if err := set(&out.Email, 3); err != nil {
		return ProfileClaims{}, err
	}
	if row[4] != nil {
		v, ok := row[4].(int64)
		if !ok || (v != 0 && v != 1) {
			return ProfileClaims{}, errors.New("invalid identity profile email verification")
		}
		b := v == 1
		out.EmailVerified = &b
	}
	if err := set(&out.PreferredUsername, 5); err != nil {
		return ProfileClaims{}, err
	}
	if err := set(&out.GivenName, 6); err != nil {
		return ProfileClaims{}, err
	}
	if err := set(&out.FamilyName, 7); err != nil {
		return ProfileClaims{}, err
	}
	if row[8] != nil {
		raw, ok := row[8].(string)
		if !ok {
			return ProfileClaims{}, errors.New("invalid identity user values")
		}
		var values UserValuesRequest
		if err := json.Unmarshal([]byte(raw), &values); err != nil {
			return ProfileClaims{}, errors.New("invalid identity user values")
		}
		out.Birthdate, out.Phone, out.Street, out.ZIP, out.City, out.Country, out.Timezone = values.Birthdate, values.Phone, values.Street, values.ZIP, values.City, values.Country, values.Timezone
	}
	return out, nil
}
