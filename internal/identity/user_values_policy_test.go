package identity

import (
	"errors"
	"testing"
)

func TestUserValuesPolicy(t *testing.T) {
	t.Parallel()
	empty, value := "", "Value"
	for _, tc := range []struct {
		name          string
		policy        UserValuesPolicy
		given, family *string
		values        *UserValuesRequest
		want          error
	}{
		{"default missing name", UserValuesPolicy{}, nil, nil, nil, ErrRequiredUserValue},
		{"default empty name", UserValuesPolicy{}, &empty, nil, nil, ErrRequiredUserValue},
		{"default valid", UserValuesPolicy{}, &value, nil, nil, nil},
		{"optional name", UserValuesPolicy{GivenName: "optional"}, nil, nil, nil, nil},
		{"hidden name accepted", UserValuesPolicy{GivenName: "hidden"}, &value, nil, nil, nil},
		{"hidden name absent", UserValuesPolicy{GivenName: "hidden"}, nil, nil, nil, nil},
		{"required family", UserValuesPolicy{FamilyName: "required"}, &value, nil, nil, ErrRequiredUserValue},
		{"required family supplied", UserValuesPolicy{FamilyName: "required"}, &value, &value, nil, nil},
		{"nested object absent upstream exemption", UserValuesPolicy{City: "required"}, &value, nil, nil, nil},
		{"nested object empty", UserValuesPolicy{City: "required"}, &value, nil, &UserValuesRequest{}, ErrRequiredUserValue},
		{"nested value empty", UserValuesPolicy{City: "required"}, &value, nil, &UserValuesRequest{City: &empty}, ErrRequiredUserValue},
		{"nested value supplied", UserValuesPolicy{City: "required"}, &value, nil, &UserValuesRequest{City: &value}, nil},
		{"invalid configuration fails closed", UserValuesPolicy{City: "REQUIRED"}, &value, nil, nil, ErrUserValuesPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.policy.ValidateFields(tc.given, tc.family, tc.values); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestUserValuesPolicyEveryNestedField(t *testing.T) {
	t.Parallel()
	empty, value := "", "Value"
	for _, field := range []string{"birthdate", "street", "zip", "city", "country", "phone", "tz"} {
		t.Run(field, func(t *testing.T) {
			policy := UserValuesPolicy{}
			values := UserValuesRequest{}
			modes := map[string]*string{"birthdate": &policy.Birthdate, "street": &policy.Street, "zip": &policy.ZIP, "city": &policy.City, "country": &policy.Country, "phone": &policy.Phone, "tz": &policy.Timezone}
			inputs := map[string]**string{"birthdate": &values.Birthdate, "street": &values.Street, "zip": &values.ZIP, "city": &values.City, "country": &values.Country, "phone": &values.Phone, "tz": &values.Timezone}
			for _, mode := range []string{"", "required", "optional", "hidden", " required", "bogus"} {
				*modes[field] = mode
				for _, input := range []*string{nil, &empty, &value} {
					*inputs[field] = input
					want := error(nil)
					if mode == "required" && emptyUserValue(input) {
						want = ErrRequiredUserValue
					}
					if mode == " required" || mode == "bogus" {
						want = ErrUserValuesPolicy
					}
					if err := policy.ValidateFields(&value, nil, &values); !errors.Is(err, want) {
						t.Fatalf("mode=%q input=%v err=%v want=%v", mode, input, err, want)
					}
				}
			}
		})
	}
}
