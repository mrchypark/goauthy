package identity

import "context"

// NeedsProfileUpdate reports whether the stored profile for subject fails
// the current deployment validation policy. A false result with a nil error
// means the profile is valid or revalidation is not enabled. Read errors
// and invalid deployment policies propagate as errors.
func (s *Store) NeedsProfileUpdate(ctx context.Context, policy UserValuesPolicy, subject, clientID string) (bool, error) {
	if !policy.RevalidateDuringLogin {
		return false, nil
	}
	if clientID == "rauthy" {
		return false, nil
	}
	if err := policy.Validate(); err != nil {
		return false, err
	}
	claims, err := s.ProfileClaimsBySubject(ctx, subject)
	if err != nil {
		return false, err
	}
	values := UserValuesRequest{
		Birthdate: claims.Birthdate, Phone: claims.Phone,
		Street: claims.Street, ZIP: claims.ZIP, City: claims.City,
		Country: claims.Country, Timezone: claims.Timezone,
	}
	if err := policy.ValidateFields(claims.GivenName, claims.FamilyName, &values); err != nil {
		return true, nil
	}
	if err := policy.PreferredUsername.ValidateRegistration(claims.PreferredUsername); err != nil {
		return true, nil
	}
	return false, nil
}
