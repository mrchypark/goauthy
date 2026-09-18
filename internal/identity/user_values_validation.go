package identity

import (
	"regexp"
	"time"
)

var (
	userValueDate   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	userValuePhone  = regexp.MustCompile(`^\+[0-9]{0,32}$`)
	userValueStreet = regexp.MustCompile(`^[a-zA-Z0-9À-ÿ.\-\s\x{000B}\x{0085}\p{Z}]{0,48}$`)
	userValueAlnum  = regexp.MustCompile(`^[a-zA-Z0-9]{1,24}$`)
	userValueCity   = regexp.MustCompile(`^[a-zA-Z0-9À-ÿ\-\s\x{000B}\x{0085}\p{Z}]{0,48}$`)
)

// ValidateUserValuesSyntax applies upstream regex constraints to every supplied
// field. Nil fields are skipped. This is the single source of truth for both
// admin update and self-service profile validation.
func ValidateUserValuesSyntax(v UserValuesRequest) error {
	if v.Birthdate != nil && !userValueDate.MatchString(*v.Birthdate) ||
		v.Phone != nil && !userValuePhone.MatchString(*v.Phone) ||
		v.Street != nil && !userValueStreet.MatchString(*v.Street) ||
		v.ZIP != nil && !userValueAlnum.MatchString(*v.ZIP) ||
		v.City != nil && !userValueCity.MatchString(*v.City) ||
		v.Country != nil && !userValueCity.MatchString(*v.Country) {
		return ErrUserValuesPolicy
	}
	if v.Timezone != nil {
		if *v.Timezone == "" || *v.Timezone == "Local" || len(*v.Timezone) > 48 {
			return ErrUserValuesPolicy
		}
		if _, err := time.LoadLocation(*v.Timezone); err != nil {
			return ErrUserValuesPolicy
		}
	}
	return nil
}
