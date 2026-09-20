package credential

import (
	"errors"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	minRuleLength  = 8
	maxRuleLength  = 128
	maxRuleClass   = 32
	maxRuleHistory = 10
	maxValidDays   = 3650
	// minEntropyBits는 NIST SP 800-63B 권장사항에 따른 최소 엔트로피 비트입니다.
	minEntropyBits = 60
)

var (
	ErrInvalidPasswordRules = errors.New("invalid password rules")
	ErrPasswordRejected     = errors.New("password does not satisfy rules")
	ErrPasswordTooCommon    = errors.New("password is too common")
	ErrPasswordTooWeak      = errors.New("password has insufficient entropy")
)

// Rules defines the local password-creation policy. History is validated here
// but enforced by identity persistence, where password changes are atomic.
type Rules struct {
	LengthMin int
	LengthMax int
	LowerCase int
	UpperCase int
	Digits    int
	Special   int
	History   int
	// ValidDays is the password lifetime in days. Zero disables expiry.
	ValidDays int
	// BlockCommonPasswords는 알려진 일반 패스워드 차단을 활성화합니다.
	// NIST SP 800-63B 권장사항에 따라 기본값은 true입니다.
	BlockCommonPasswords bool
	// MinEntropyBits는 최소 엔트로피 비트 수입니다.
	// 0이면 엔트로피 검사를 비활성화합니다.
	MinEntropyBits int
}

// DefaultRules matches Rauthy's baseline local-password requirements.
func DefaultRules() Rules {
	return Rules{
		LengthMin:            14,
		LengthMax:            128,
		LowerCase:            1,
		UpperCase:            1,
		Digits:               1,
		History:              3,
		ValidDays:            180,
		BlockCommonPasswords: true,
		MinEntropyBits:       minEntropyBits,
	}
}

// Validate confirms that the rule configuration is bounded and coherent.
func (r Rules) Validate() error {
	if r.LengthMin < minRuleLength || r.LengthMin > maxRuleLength ||
		r.LengthMax < minRuleLength || r.LengthMax > maxRuleLength ||
		r.LengthMin > r.LengthMax ||
		r.LowerCase < 0 || r.LowerCase > maxRuleClass ||
		r.UpperCase < 0 || r.UpperCase > maxRuleClass ||
		r.Digits < 0 || r.Digits > maxRuleClass ||
		r.Special < 0 || r.Special > maxRuleClass ||
		r.History < 0 || r.History > maxRuleHistory ||
		r.ValidDays < 0 || r.ValidDays > maxValidDays ||
		r.MinEntropyBits < 0 || r.MinEntropyBits > 256 {
		return ErrInvalidPasswordRules
	}
	// Lowercase, uppercase, digit and special requirements are disjoint: every
	// character satisfies at most one of them, so a policy that requires more
	// such characters than the maximum length can never be met by any password.
	if r.LowerCase+r.UpperCase+r.Digits+r.Special > r.LengthMax {
		return ErrInvalidPasswordRules
	}
	return nil
}

// ValidatePassword applies this configuration without normalizing input.
func (r Rules) ValidatePassword(password []byte) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if !utf8.Valid(password) {
		return ErrPasswordRejected
	}

	// NIST SP 800-63B: 일반 패스워드 차단
	if r.BlockCommonPasswords && IsCommonPassword(string(password)) {
		return ErrPasswordTooCommon
	}

	lower, upper, digits, special, length := 0, 0, 0, 0, 0
	for _, value := range string(password) {
		length++
		switch {
		case unicode.IsLower(value):
			lower++
		case unicode.IsUpper(value):
			upper++
		case value >= '0' && value <= '9':
			digits++
		case !unicode.IsLetter(value) && !unicode.IsNumber(value):
			special++
		}
	}
	if length < r.LengthMin || length > r.LengthMax || lower < r.LowerCase || upper < r.UpperCase || digits < r.Digits || special < r.Special {
		return ErrPasswordRejected
	}

	// 엔트로피 검사
	if r.MinEntropyBits > 0 {
		entropy := calculateEntropy(string(password))
		if entropy < float64(r.MinEntropyBits) {
			return ErrPasswordTooWeak
		}
	}

	return nil
}

// calculateEntropy는 패스워드의 엔트로피를 비트 단위로 계산합니다.
// 문자셋 크기와 패스워드 길이를 기반으로 추정합니다.
func calculateEntropy(password string) float64 {
	if len(password) == 0 {
		return 0
	}

	var hasLower, hasUpper, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case !unicode.IsLetter(ch) && !unicode.IsNumber(ch):
			hasSpecial = true
		}
	}

	charsetSize := 0
	if hasLower {
		charsetSize += 26
	}
	if hasUpper {
		charsetSize += 26
	}
	if hasDigit {
		charsetSize += 10
	}
	if hasSpecial {
		charsetSize += 33 // 일반적인 특수문자
	}

	if charsetSize == 0 {
		return 0
	}

	// 엔트로피 = log2(charsetSize^length) = length * log2(charsetSize)
	return float64(len(password)) * math.Log2(float64(charsetSize))
}

// ValidatePasswordWithDetails는 패스워드 검증 결과를 상세하게 반환합니다.
func (r Rules) ValidatePasswordWithDetails(password []byte) (bool, string) {
	if err := r.ValidatePassword(password); err != nil {
		switch err {
		case ErrPasswordTooCommon:
			return false, "이 패스워드는 알려진 일반 패스워드입니다. 다른 패스워드를 선택하세요."
		case ErrPasswordTooWeak:
			return false, "패스워드의 엔트로피가 부족합니다. 더 복잡한 패스워드를 사용하세요."
		default:
			return false, "패스워드가 정책을 만족하지 않습니다."
		}
	}
	return true, ""
}

// MaskPassword은 패스워드를 마스킹하여 로그에 안전하게 기록할 수 있도록 합니다.
func MaskPassword(password string) string {
	if len(password) <= 4 {
		return strings.Repeat("*", len(password))
	}
	return password[:2] + strings.Repeat("*", len(password)-4) + password[len(password)-2:]
}
