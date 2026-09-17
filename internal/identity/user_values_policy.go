package identity

import "errors"

// UserValuesPolicy is immutable deployment configuration for the ordinary
// profile fields. Empty modes use Rauthy's defaults: given_name is required,
// every other field is optional. Hidden affects presentation, not admission.
// Preferred-username policy and login-time revalidation are separate concerns.
type UserValuesPolicy struct {
	GivenName, FamilyName, Birthdate, Street, ZIP, City, Country, Phone, Timezone string
	PreferredUsername                                                             *PreferredUsernamePolicy
}

var ErrUserValuesPolicy = errors.New("invalid user values policy")
var ErrRequiredUserValue = errors.New("required user value is missing")

// UserValuesRequest contains the standard, nullable profile values. Wire
// boundaries remain responsible for unknown fields and value syntax/lengths.
type UserValuesRequest struct {
	Birthdate *string `json:"birthdate,omitempty"`
	Phone     *string `json:"phone,omitempty"`
	Street    *string `json:"street,omitempty"`
	ZIP       *string `json:"zip,omitempty"`
	City      *string `json:"city,omitempty"`
	Country   *string `json:"country,omitempty"`
	Timezone  *string `json:"tz,omitempty"`
}

func (p UserValuesPolicy) Validate() error {
	for _, mode := range []string{p.GivenName, p.FamilyName, p.Birthdate, p.Street, p.ZIP, p.City, p.Country, p.Phone, p.Timezone} {
		switch mode {
		case "", "required", "optional", "hidden":
		default:
			return ErrUserValuesPolicy
		}
	}
	return nil
}

// ValidateFields checks required presence without changing submitted values.
// This is deliberately not applied to administrative creation, matching the
// upstream exemption. Syntax validation must still run for hidden/optional data.
func (p UserValuesPolicy) ValidateFields(givenName, familyName *string, values *UserValuesRequest) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if ((p.GivenName == "" || p.GivenName == "required") && emptyUserValue(givenName)) ||
		(p.FamilyName == "required" && emptyUserValue(familyName)) {
		return ErrRequiredUserValue
	}
	// Rauthy v0.36.2 validates nested requirements only when the enclosing
	// object is present. Preserve that explicit wire distinction, not a merge
	// with the old persisted profile (PUT can clear optional values).
	if values == nil {
		return nil
	}
	for _, field := range []struct {
		mode  string
		value *string
	}{
		{p.Birthdate, values.Birthdate}, {p.Street, values.Street},
		{p.ZIP, values.ZIP}, {p.City, values.City}, {p.Country, values.Country},
		{p.Phone, values.Phone}, {p.Timezone, values.Timezone},
	} {
		if field.mode == "required" && emptyUserValue(field.value) {
			return ErrRequiredUserValue
		}
	}
	return nil
}

func emptyUserValue(value *string) bool { return value == nil || *value == "" }
