package credential

import (
	"testing"
)

func TestValidatePasswordStrength(t *testing.T) {
	policy := DefaultPasswordPolicy()

	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{"valid strong", "MyStr0ng!Pass", nil},
		{"valid long", "ThisIsAVeryLongPassword123!@#", nil},
		{"too short", "Ab1!", ErrPasswordTooShort},
		{"no uppercase", "mylower1!", ErrPasswordNoUppercase},
		{"no lowercase", "MYUPPER1!", ErrPasswordNoLowercase},
		{"no digit", "MyPassword!", ErrPasswordNoDigit},
		{"no special", "MyPassword1", ErrPasswordNoSpecial},
		{"common password", "Passw0rd!", ErrPasswordCommon},
		{"common welcome", "Welcome1", ErrPasswordNoSpecial},
		{"repeating chars", "AAAAbbbb1!", ErrPasswordRepeating},
		{"sequential digits", "Abc12345!", ErrPasswordSequential},
		{"sequential alpha", "Abcdefg1!", ErrPasswordSequential},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tt.password, policy)
			if err != tt.wantErr {
				t.Errorf("ValidatePasswordStrength(%q) = %v, want %v", tt.password, err, tt.wantErr)
			}
		})
	}
}

func TestPasswordPolicyCustom(t *testing.T) {
	// 관대한 정책 테스트
	policy := PasswordPolicy{
		MinLength:        6,
		MaxLength:        64,
		RequireUppercase: false,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   false,
		MaxRepeating:     5,
		BlockCommon:      false,
	}

	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{"valid minimal", "abc123", nil},
		{"too short", "ab1", ErrPasswordTooShort},
		{"no lowercase", "ABC123", ErrPasswordNoLowercase},
		{"no digit", "abcdef", ErrPasswordNoDigit},
		{"repeating ok", "aaa111", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tt.password, policy)
			if err != tt.wantErr {
				t.Errorf("ValidatePasswordStrength(%q) = %v, want %v", tt.password, err, tt.wantErr)
			}
		})
	}
}

func TestPolicyIsCommonPassword(t *testing.T) {
	tests := []struct {
		password string
		want     bool
	}{
		{"password", true},
		{"Password", true},
		{"PASSWORD", true},
		{"123456", true},
		{"MyStr0ng!Pass", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.password, func(t *testing.T) {
			if got := IsCommonPassword(tt.password); got != tt.want {
				t.Errorf("IsCommonPassword(%q) = %v, want %v", tt.password, got, tt.want)
			}
		})
	}
}

func TestPolicyAddCommonPassword(t *testing.T) {
	// 새 일반 패스워드 추가
	AddCommonPassword("mycustompassword")

	if !IsCommonPassword("mycustompassword") {
		t.Error("expected mycustompassword to be common after adding")
	}
	if !IsCommonPassword("MYCUSTOMPASSWORD") {
		t.Error("expected MYCUSTOMPASSWORD to be common (case insensitive)")
	}
}

func TestPolicyHasExcessiveRepeating(t *testing.T) {
	tests := []struct {
		password string
		max      int
		want     bool
	}{
		{"aaa", 3, false},
		{"aaaa", 3, true},
		{"abc", 3, false},
		{"aabbcc", 2, false},
		{"aaabbb", 2, true},
	}

	for _, tt := range tests {
		t.Run(tt.password, func(t *testing.T) {
			if got := HasExcessiveRepeating(tt.password, tt.max); got != tt.want {
				t.Errorf("HasExcessiveRepeating(%q, %d) = %v, want %v", tt.password, tt.max, got, tt.want)
			}
		})
	}
}

func TestHasSequentialChars(t *testing.T) {
	tests := []struct {
		password string
		max      int
		want     bool
	}{
		{"abc", 4, false},
		{"abcd", 4, true},
		{"1234", 4, true},
		{"xyz", 4, false},
		{"wxyz", 4, true},
		{"abc1234", 4, true},
	}

	for _, tt := range tests {
		t.Run(tt.password, func(t *testing.T) {
			if got := HasSequentialChars(tt.password, tt.max); got != tt.want {
				t.Errorf("HasSequentialChars(%q, %d) = %v, want %v", tt.password, tt.max, got, tt.want)
			}
		})
	}
}
