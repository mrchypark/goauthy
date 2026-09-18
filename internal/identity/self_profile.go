package identity

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	ErrSelfProfileUnauthorized = errors.New("self profile update authorization failed")
	ErrSelfProfileConflict     = errors.New("self profile update state or authority changed")
	ErrSelfProfileInvalid      = errors.New("invalid self profile update")
)

type SelfProfileUpdate struct {
	GivenName         *string
	FamilyName        *string
	PreferredUsername *string
	UserValues        *UserValuesRequest
}

type SelfProfileUpdateResult struct {
	Subject string
	User    UserResponse
}

const selfProfileSnapshotSQL = `SELECT json_object(
	'has_profile',p.subject IS NOT NULL,
	'email',COALESCE(p.email,re.email,''),
	'verified',COALESCE(p.email_verified,0),
	'preferred',p.preferred_username,
	'given',p.given_name,
	'family',p.family_name,
	'values',json_array(p.subject,COALESCE(p.email,re.email,''),p.email_verified,p.preferred_username,p.given_name,p.family_name,COALESCE(p.user_values_json,'{}'))
	)
	FROM identity_users u LEFT JOIN identity_user_profiles p ON p.subject=u.subject
	LEFT JOIN identity_recovery_emails re ON re.subject=u.subject
	WHERE u.subject=? AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms>?)`

func (s *Store) UpdateSelfProfileWithGuard(ctx context.Context, subject string, input SelfProfileUpdate, policy UserValuesPolicy, authority func() (string, []any)) (SelfProfileUpdateResult, error) {
	if s == nil || s.db == nil || ctx == nil || authority == nil {
		return SelfProfileUpdateResult{}, ErrSelfProfileUnauthorized
	}
	if validateSubject(subject) != nil {
		return SelfProfileUpdateResult{}, ErrSelfProfileInvalid
	}
	if input.GivenName != nil && (!utf8.ValidString(*input.GivenName) || utf8.RuneCountInString(*input.GivenName) > 32) {
		return SelfProfileUpdateResult{}, ErrSelfProfileInvalid
	}
	if input.FamilyName != nil && (!utf8.ValidString(*input.FamilyName) || utf8.RuneCountInString(*input.FamilyName) > 32) {
		return SelfProfileUpdateResult{}, ErrSelfProfileInvalid
	}

	now := s.now().UTC().UnixMilli()

	authoritySQL, authorityArgs := authority()
	if strings.TrimSpace(authoritySQL) == "" || strings.Contains(authoritySQL, ";") {
		return SelfProfileUpdateResult{}, ErrSelfProfileUnauthorized
	}

	rows, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         selfProfileSnapshotSQL + ` AND (` + authoritySQL + `)`,
		Args:        append([]any{subject, now}, authorityArgs...),
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return SelfProfileUpdateResult{}, err
	}
	if len(rows.Rows) == 0 {
		return SelfProfileUpdateResult{}, ErrSelfProfileUnauthorized
	}
	if len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 {
		return SelfProfileUpdateResult{}, ErrSelfProfileConflict
	}
	snapshot, ok := rows.Rows[0][0].(string)
	var old struct {
		Preferred *string `json:"preferred"`
	}
	if !ok || json.Unmarshal([]byte(snapshot), &old) != nil {
		return SelfProfileUpdateResult{}, ErrSelfProfileConflict
	}

	preferredPolicy := policy.PreferredUsername
	finalPreferred := input.PreferredUsername
	if finalPreferred != nil && *finalPreferred == "" {
		finalPreferred = nil
	}
	if preferredPolicy.Immutable() && old.Preferred != nil && (finalPreferred == nil || *finalPreferred != *old.Preferred) {
		return SelfProfileUpdateResult{}, ErrSelfProfileInvalid
	}

	var finalGiven, finalFamily *string
	if input.GivenName != nil {
		if *input.GivenName == "" {
			finalGiven = nil
		} else {
			v := *input.GivenName
			finalGiven = &v
		}
	}
	if input.FamilyName != nil {
		if *input.FamilyName == "" {
			finalFamily = nil
		} else {
			v := *input.FamilyName
			finalFamily = &v
		}
	}

	if input.UserValues == nil {
		return SelfProfileUpdateResult{}, ErrSelfProfileInvalid
	}

	if err := policy.ValidateFields(finalGiven, finalFamily, input.UserValues); err != nil {
		return SelfProfileUpdateResult{}, err
	}
	if err := ValidateUserValuesSyntax(*input.UserValues); err != nil {
		return SelfProfileUpdateResult{}, err
	}
	if err := preferredPolicy.ValidateRegistration(finalPreferred); err != nil {
		return SelfProfileUpdateResult{}, err
	}

	newValuesJSON := "{}"
	encoded, _ := json.Marshal(input.UserValues)
	newValuesJSON = string(encoded)

	authoritySQL, authorityArgs = authority()
	if strings.TrimSpace(authoritySQL) == "" || strings.Contains(authoritySQL, ";") {
		return SelfProfileUpdateResult{}, ErrSelfProfileUnauthorized
	}

	now = s.now().UTC().UnixMilli()

	nonce, err := s.randomID(16)
	if err != nil {
		return SelfProfileUpdateResult{}, err
	}
	operation := mutationID("self-profile-update", subject, nonce)
	one := int64(1)

	guardSQL := `u.subject=? AND (` + authoritySQL + `) AND (` + selfProfileSnapshotSQL + `)=?`
	if finalPreferred != nil {
		guardSQL += ` AND NOT EXISTS(SELECT 1 FROM identity_user_profiles WHERE preferred_username=? AND subject<>?)`
	}

	var preferredArg any
	if finalPreferred != nil {
		preferredArg = *finalPreferred
	}

	args := []any{
		subject,
		preferredArg,
		updateOptionalString(finalGiven),
		updateOptionalString(finalFamily),
		nullableString(newValuesJSON),
	}
	args = append(args, subject)
	args = append(args, authorityArgs...)
	args = append(args, subject, now, snapshot)
	if finalPreferred != nil {
		args = append(args, *finalPreferred, subject)
	}

	conditionalUpsert := rhiza.SQLStatement{
		SQL: `INSERT INTO identity_user_profiles(subject,email,email_verified,preferred_username,given_name,family_name,user_values_json)
			SELECT ?,COALESCE(p.email,re.email,''),COALESCE(p.email_verified,0),?,?,?,?
			FROM identity_users u LEFT JOIN identity_user_profiles p ON p.subject=u.subject
			LEFT JOIN identity_recovery_emails re ON re.subject=u.subject
			WHERE ` + guardSQL + `
			ON CONFLICT(subject) DO UPDATE SET
			preferred_username=excluded.preferred_username,
			given_name=excluded.given_name,
			family_name=excluded.family_name,
			user_values_json=excluded.user_values_json
			RETURNING subject`,
		Args:                 args,
		WantRows:             true,
		ExpectedReturnedRows: &one,
	}

	statements := []rhiza.SQLStatement{conditionalUpsert, {SQL: UserResponseJSONSQL, Args: []any{subject}, WantRows: true, ExpectedReturnedRows: &one}}

	result, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: operation, Statements: statements})
	if result.ErrorCode == rhiza.MutationErrorCodePreconditionFailed {
		return SelfProfileUpdateResult{}, ErrSelfProfileConflict
	}
	if err != nil {
		return SelfProfileUpdateResult{}, err
	}
	if len(result.Statements) != len(statements) {
		return SelfProfileUpdateResult{}, errors.New("missing self profile update result")
	}
	responseRows := result.Statements[len(statements)-1].Rows
	if len(responseRows) != 1 || len(responseRows[0]) != 1 {
		return SelfProfileUpdateResult{}, ErrSelfProfileConflict
	}
	raw, ok := responseRows[0][0].(string)
	if !ok {
		return SelfProfileUpdateResult{}, errors.New("invalid self profile update projection")
	}
	user, _, err := DecodeUserResponse(raw)
	if err != nil {
		return SelfProfileUpdateResult{}, err
	}
	return SelfProfileUpdateResult{Subject: subject, User: user}, nil
}
