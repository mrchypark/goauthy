package rbac

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"mime"
	"net/http"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/i18n"
	"github.com/mrchypark/goauthy/internal/identity"
)

// UserUpdateRequest is the administrator user update wire contract.
type UserUpdateRequest struct {
	Email         string             `json:"email"`
	GivenName     *string            `json:"given_name,omitempty"`
	FamilyName    *string            `json:"family_name,omitempty"`
	Language      *string            `json:"language,omitempty"`
	Password      *string            `json:"password,omitempty"`
	Roles         []string           `json:"roles"`
	Groups        *[]string          `json:"groups,omitempty"`
	Enabled       bool               `json:"enabled"`
	EmailVerified bool               `json:"email_verified"`
	UserExpires   *int64             `json:"user_expires,omitempty"`
	UserValues    *UserValuesRequest `json:"user_values,omitempty"`
}

// UserValuesRequest contains only the standard profile values accepted by the API.
type UserValuesRequest = identity.UserValuesRequest

func decodeUserUpdate(w http.ResponseWriter, r *http.Request) (UserUpdateRequest, error) {
	var input UserUpdateRequest
	if r.URL.RawQuery != "" || len(r.Header.Values("Content-Type")) != 1 {
		return input, ErrInvalid
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return input, ErrInvalid
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminRequestLimit)
	body, err := io.ReadAll(r.Body)
	if err != nil || !utf8.Valid(body) || rejectDuplicateJSONFields(body) != nil {
		return input, ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return input, ErrInvalid
	}
	for key := range fields {
		switch key {
		case "email", "given_name", "family_name", "language", "password", "roles", "groups", "enabled", "email_verified", "user_expires", "user_values":
		default:
			return input, ErrInvalid
		}
	}
	for _, key := range []string{"email", "roles", "enabled", "email_verified"} {
		if len(fields[key]) == 0 || bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) {
			return input, ErrInvalid
		}
	}
	if json.Unmarshal(body, &input) != nil {
		return input, ErrInvalid
	}
	if raw, ok := fields["user_values"]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		var values map[string]json.RawMessage
		if json.Unmarshal(raw, &values) != nil || values == nil {
			return input, ErrInvalid
		}
		for key := range values {
			switch key {
			case "birthdate", "phone", "street", "zip", "city", "country", "tz":
			default:
				return input, ErrInvalid
			}
		}
	}
	if input.Email, err = identity.CanonicalEmail(input.Email); err != nil {
		return input, ErrInvalid
	}
	if input.Roles, err = canonicalNames(input.Roles, false); err != nil {
		return input, err
	}
	if input.Groups != nil {
		groups, groupErr := canonicalNames(*input.Groups, true)
		if groupErr != nil {
			return input, groupErr
		}
		input.Groups = &groups
	}
	if input.Language != nil && !i18n.ValidUserLanguage(*input.Language) {
		return input, ErrInvalid
	}
	if input.Password != nil && utf8.RuneCountInString(*input.Password) > 256 {
		return input, ErrInvalid
	}
	if input.UserExpires != nil && (*input.UserExpires < 1719784800 || *input.UserExpires > math.MaxInt64/1000) {
		return input, ErrInvalid
	}
	for _, value := range []*string{input.GivenName, input.FamilyName} {
		if value != nil && !validCreateName(*value) {
			return input, ErrInvalid
		}
	}
	if input.UserValues != nil {
		if err := validateUserValues(*input.UserValues); err != nil {
			return input, err
		}
	}
	return input, nil
}

func validateUserValues(v UserValuesRequest) error {
	if err := identity.ValidateUserValuesSyntax(v); err != nil {
		return ErrInvalid
	}
	return nil
}
