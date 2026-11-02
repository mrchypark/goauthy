package recovery

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/credential"
)

func TestBoundedPasswordAllowsPolicyMaxNonASCIIPassword(t *testing.T) {
	password := strings.Repeat("ẞ", 126) + "a4"
	if got := utf8.RuneCountInString(password); got != credential.DefaultRules().LengthMax {
		t.Fatalf("fixture has %d runes, want policy maximum %d", got, credential.DefaultRules().LengthMax)
	}
	if len(password) <= 256 {
		t.Fatalf("fixture has only %d bytes; want more than the old transport cap", len(password))
	}
	if err := credential.DefaultRules().ValidatePassword([]byte(password)); err != nil {
		t.Fatalf("policy-valid Unicode fixture rejected: %v", err)
	}
	if !bounded(password, credential.DefaultRules().LengthMax) {
		t.Fatalf("bounded rejected policy-valid password with %d runes and %d bytes", utf8.RuneCountInString(password), len(password))
	}
	if bounded(password+"a", credential.DefaultRules().LengthMax) {
		t.Fatal("bounded accepted a password longer than the policy rune maximum")
	}
}
