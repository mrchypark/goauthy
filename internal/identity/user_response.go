package identity

import "encoding/json"

// UserResponse is the detail wire contract, not the nullable minified list.
type UserResponse struct {
	ID                  string             `json:"id"`
	Email               string             `json:"email"`
	GivenName           *string            `json:"given_name,omitempty"`
	FamilyName          *string            `json:"family_name,omitempty"`
	Language            string             `json:"language"`
	Roles               []string           `json:"roles"`
	Groups              []string           `json:"groups,omitempty"`
	Enabled             bool               `json:"enabled"`
	EmailVerified       bool               `json:"email_verified"`
	PasswordExpires     *int64             `json:"password_expires,omitempty"`
	CreatedAt           int64              `json:"created_at"`
	LastLogin           *int64             `json:"last_login,omitempty"`
	LastFailedLogin     *int64             `json:"last_failed_login,omitempty"`
	FailedLoginAttempts *int64             `json:"failed_login_attempts,omitempty"`
	UserExpires         *int64             `json:"user_expires,omitempty"`
	AccountType         string             `json:"account_type"`
	WebauthnUserID      *string            `json:"webauthn_user_id,omitempty"`
	UserValues          UserValuesResponse `json:"user_values"`
	AuthProviderID      *string            `json:"auth_provider_id,omitempty"`
	FederationUID       *string            `json:"federation_uid,omitempty"`
	PictureID           *string            `json:"picture_id,omitempty"`
}

type UserValuesResponse struct {
	Birthdate         *string `json:"birthdate,omitempty"`
	Phone             *string `json:"phone,omitempty"`
	Street            *string `json:"street,omitempty"`
	ZIP               *string `json:"zip,omitempty"`
	City              *string `json:"city,omitempty"`
	Country           *string `json:"country,omitempty"`
	PreferredUsername *string `json:"preferred_username,omitempty"`
	Timezone          *string `json:"tz,omitempty"`
}

// UserResponseJSONSQL projects only public profile fields plus the password
// change timestamp needed for expiry policy. It never exposes a verifier.
// The subject placeholder and authorization must be supplied by the caller;
// a mutation appends this read after its admission barrier in the same batch.
const UserResponseJSONSQL = ` SELECT json_object(
 'id',u.subject,'email',COALESCE(p.email,re.email,''),'given_name',NULLIF(p.given_name,''),'family_name',p.family_name,
 'language',COALESCE(u.language,'en'),'enabled',json(CASE WHEN u.disabled=0 THEN 'true' ELSE 'false' END),
 'email_verified',json(CASE WHEN p.email_verified=1 THEN 'true' ELSE 'false' END),
 'created_at',u.created_at_unix_ms/1000,'last_login',u.last_login_at_unix_ms/1000,
 'last_failed_login',u.last_failed_login_at_unix_ms/1000,'failed_login_attempts',u.failed_login_attempts,
 'user_expires',u.user_expires_at_unix_ms/1000,
 'roles',json((SELECT json_group_array(name) FROM (SELECT r.name FROM rbac_user_roles m JOIN rbac_roles r ON r.id=m.role_id WHERE m.subject=u.subject ORDER BY r.name))),
 'groups',json((SELECT json_group_array(name) FROM (SELECT g.name FROM rbac_user_groups m JOIN rbac_groups g ON g.id=m.group_id WHERE m.subject=u.subject ORDER BY g.name))),
 'account_type',CASE WHEN EXISTS(SELECT 1 FROM identity_external_links l WHERE l.local_subject=u.subject) THEN 'federated_' ELSE '' END ||
 CASE WHEN u.password_phc<>'' AND COALESCE(am.mode,'password')='password' THEN 'password'
 WHEN EXISTS(SELECT 1 FROM identity_webauthn_credentials c WHERE c.subject=u.subject) THEN 'passkey' ELSE 'new' END,
 'webauthn_user_id',CASE WHEN EXISTS(SELECT 1 FROM identity_webauthn_credentials c WHERE c.subject=u.subject) THEN wu.user_handle END,
 'auth_provider_id',(SELECT MIN(provider_id) FROM identity_external_links l WHERE l.local_subject=u.subject HAVING COUNT(*)=1),
 'user_values',json(COALESCE(p.user_values_json,'{}')),
 'preferred_username',p.preferred_username,
 'password_changed',CASE WHEN u.password_phc<>'' AND COALESCE(am.mode,'password')='password' THEN u.password_changed_at_unix_ms ELSE 0 END)
 FROM identity_users u LEFT JOIN identity_user_profiles p ON p.subject=u.subject
 LEFT JOIN identity_recovery_emails re ON re.subject=u.subject
 LEFT JOIN identity_authentication_modes am ON am.subject=u.subject
 LEFT JOIN identity_webauthn_users wu ON wu.subject=u.subject
 WHERE u.subject=?`

func DecodeUserResponse(raw string) (UserResponse, int64, error) {
	var wire struct {
		UserResponse
		PreferredUsername *string `json:"preferred_username"`
		PasswordChanged   int64   `json:"password_changed"`
	}
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		return UserResponse{}, 0, err
	}
	wire.UserValues.PreferredUsername = wire.PreferredUsername
	if wire.AccountType == "federated_new" {
		wire.AccountType = "federated"
	}
	return wire.UserResponse, wire.PasswordChanged, nil
}
