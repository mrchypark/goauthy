package credential

import (
	"testing"
)

func TestIsCommonPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{"common password", "password", true},
		{"common uppercase", "Password", true},
		{"common mixed case", "Password123", true},
		{"common with special", "Password123!", true},
		{"strong unique", "Xy9#mK2$pL5@nQ8", false},
		{"empty", "", false},
		{"numeric only", "12345678", true},
		{"qwerty variant", "Qwerty123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCommonPassword(tt.password); got != tt.want {
				t.Errorf("IsCommonPassword(%q) = %v, want %v", tt.password, got, tt.want)
			}
		})
	}
}

func TestAddCommonPassword(t *testing.T) {
	// Add a custom password
	AddCommonPassword("mycustompassword")

	if !IsCommonPassword("mycustompassword") {
		t.Error("expected mycustompassword to be common after adding")
	}
	if !IsCommonPassword("MyCustomPassword") {
		t.Error("expected MyCustomPassword to be common (case insensitive)")
	}
}

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name     string
		password string
		minBits  float64
	}{
		{"lowercase only", "abcdefgh", 37},     // 8 * log2(26) ≈ 37.6
		{"mixed case", "AbCdEfGh", 45},         // 8 * log2(52) ≈ 45.6
		{"with digits", "AbCd1234", 47},         // 8 * log2(62) ≈ 47.6
		{"full charset", "Ab1!xy9#", 52},        // 8 * log2(95) ≈ 52.4
		{"empty", "", 0},
		{"single char", "a", 4.7},               // 1 * log2(26) ≈ 4.7
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := calculateEntropy(tt.password)
			if entropy < tt.minBits {
				t.Errorf("calculateEntropy(%q) = %f, want >= %f", tt.password, entropy, tt.minBits)
			}
		})
	}
}

func TestRulesValidatePasswordWithCommonBlocking(t *testing.T) {
	rules := Rules{
		LengthMin:            8,
		LengthMax:            128,
		LowerCase:            1,
		UpperCase:            1,
		Digits:               1,
		Special:              1,
		BlockCommonPasswords: true,
		MinEntropyBits:       0,
	}

	tests := []struct {
		name    string
		pass    string
		wantErr error
	}{
		{"strong password", "Xy9#mK2$pL5@nQ8!", nil},
		{"common blocked", "Password123!", ErrPasswordTooCommon},
		{"weak but not common", "Aa1!xxxx", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rules.ValidatePassword([]byte(tt.pass))
			if err != tt.wantErr {
				t.Errorf("ValidatePassword(%q) error = %v, want %v", tt.pass, err, tt.wantErr)
			}
		})
	}
}

func TestRulesValidatePasswordWithEntropy(t *testing.T) {
	rules := Rules{
		LengthMin:      8,
		LengthMax:      128,
		LowerCase:      1,
		UpperCase:      1,
		Digits:         1,
		Special:        1,
		MinEntropyBits: 60,
	}

	tests := []struct {
		name    string
		pass    string
		wantErr error
	}{
		{"high entropy", "Xy9#mK2$pL5@nQ8!", nil},
		{"low entropy", "Aa1!aaaa", ErrPasswordTooWeak},
		{"medium entropy", "AbCd1234!@#$", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rules.ValidatePassword([]byte(tt.pass))
			if err != tt.wantErr {
				t.Errorf("ValidatePassword(%q) error = %v, want %v", tt.pass, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePasswordWithDetails(t *testing.T) {
	rules := DefaultRules()

	ok, msg := rules.ValidatePasswordWithDetails([]byte("StrongP@ssw0rd123"))
	if !ok {
		t.Errorf("expected ok=true, got false: %s", msg)
	}

	ok, msg = rules.ValidatePasswordWithDetails([]byte("password"))
	if ok {
		t.Error("expected ok=false for common password")
	}
	if msg == "" {
		t.Error("expected non-empty message for common password")
	}
}

func TestMaskPassword(t *testing.T) {
	tests := []struct {
		name string
		pass string
		want string
	}{
		{"short", "abc", "***"},
		{"medium", "abcdefgh", "ab****gh"},
		{"long", "verylongpassword", "ve************rd"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MaskPassword(tt.pass); got != tt.want {
				t.Errorf("MaskPassword(%q) = %q, want %q", tt.pass, got, tt.want)
			}
		})
	}
}
