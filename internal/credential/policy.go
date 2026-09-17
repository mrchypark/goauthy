// Package credential - 패스워드 정책 검증 강화
package credential

import (
	"errors"
	"unicode"
)

var (
	ErrPasswordTooShort    = errors.New("password must be at least 8 characters")
	ErrPasswordTooLong     = errors.New("password must not exceed 128 characters")
	ErrPasswordNoUppercase = errors.New("password must contain at least one uppercase letter")
	ErrPasswordNoLowercase = errors.New("password must contain at least one lowercase letter")
	ErrPasswordNoDigit     = errors.New("password must contain at least one digit")
	ErrPasswordNoSpecial   = errors.New("password must contain at least one special character")
	ErrPasswordCommon      = errors.New("password is too common")
	ErrPasswordRepeating   = errors.New("password contains too many repeating characters")
	ErrPasswordSequential  = errors.New("password contains sequential characters")
)

// PasswordPolicy defines password strength requirements
type PasswordPolicy struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSpecial   bool
	MaxRepeating     int // 최대 반복 문자 수
	BlockCommon      bool
}

// DefaultPasswordPolicy returns OWASP-recommended password policy
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:        8,
		MaxLength:        128,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
		MaxRepeating:     3,
		BlockCommon:      true,
	}
}

// ValidatePasswordStrength validates password against policy
func ValidatePasswordStrength(password string, policy PasswordPolicy) error {
	// 길이 검증
	if len(password) < policy.MinLength {
		return ErrPasswordTooShort
	}
	if len(password) > policy.PasswordMaxLength() {
		return ErrPasswordTooLong
	}

	// 문자 클래스 검증
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	if policy.RequireUppercase && !hasUpper {
		return ErrPasswordNoUppercase
	}
	if policy.RequireLowercase && !hasLower {
		return ErrPasswordNoLowercase
	}
	if policy.RequireDigit && !hasDigit {
		return ErrPasswordNoDigit
	}
	if policy.RequireSpecial && !hasSpecial {
		return ErrPasswordNoSpecial
	}

	// 반복 문자 검증
	if policy.MaxRepeating > 0 {
		if HasExcessiveRepeating(password, policy.MaxRepeating) {
			return ErrPasswordRepeating
		}
	}

	// 일반 패스워드 차단
	if policy.BlockCommon {
		if IsCommonPassword(password) {
			return ErrPasswordCommon
		}
	}

	// 연속 문자 검증 (abc, 123 등)
	if HasSequentialChars(password, 4) {
		return ErrPasswordSequential
	}

	return nil
}

// PasswordMaxLength returns the maximum password length
func (p PasswordPolicy) PasswordMaxLength() int {
	if p.MaxLength <= 0 {
		return 128
	}
	return p.MaxLength
}

// HasExcessiveRepeating checks for excessive repeating characters
func HasExcessiveRepeating(password string, maxRepeating int) bool {
	if len(password) == 0 || maxRepeating <= 0 {
		return false
	}

	count := 1
	prev := rune(0)
	for _, ch := range password {
		if ch == prev {
			count++
			if count > maxRepeating {
				return true
			}
		} else {
			count = 1
			prev = ch
		}
	}
	return false
}

// HasSequentialChars checks for sequential characters (abc, 123, etc.)
func HasSequentialChars(password string, maxSequential int) bool {
	if len(password) < maxSequential {
		return false
	}

	runes := []rune(password)
	for i := 0; i <= len(runes)-maxSequential; i++ {
		// 숫자 연속 검사
		if isDigitSequence(runes[i : i+maxSequential]) {
			return true
		}
		// 알파벳 연속 검사
		if isAlphaSequence(runes[i : i+maxSequential]) {
			return true
		}
	}
	return false
}

// isDigitSequence checks if runes are sequential digits
func isDigitSequence(runes []rune) bool {
	for i := 1; i < len(runes); i++ {
		if runes[i] != runes[i-1]+1 {
			return false
		}
	}
	return runes[0] >= '0' && runes[len(runes)-1] <= '9'
}

// isAlphaSequence checks if runes are sequential alphabets
func isAlphaSequence(runes []rune) bool {
	for i := 1; i < len(runes); i++ {
		if runes[i] != runes[i-1]+1 {
			return false
		}
	}
	return (runes[0] >= 'a' && runes[len(runes)-1] <= 'z') ||
		(runes[0] >= 'A' && runes[len(runes)-1] <= 'Z')
}
