package browser

import (
	"errors"
	"strings"
	"testing"
)

const csrfTestSession = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
const csrfTestValue = "30bn85d8H7q5TKHktPn8xs4MJngrSTsHI1Uj14cMrpQ"

func TestCSRFTokenIsDeterministicAndBoundToSession(t *testing.T) {
	got, err := DeriveCSRFToken(csrfTestSession)
	if err != nil {
		t.Fatal(err)
	}
	if got != csrfTestValue {
		t.Fatalf("derived token=%q", got)
	}
	if err := ValidateCSRFToken(csrfTestSession, got); err != nil {
		t.Fatal(err)
	}
	other := strings.Replace(csrfTestSession, "A", "B", 1)
	if err := ValidateCSRFToken(other, got); !errors.Is(err, ErrInvalidCSRFToken) {
		t.Fatalf("token accepted for another session: %v", err)
	}
}

func TestCSRFTokenRejectsMalformedAndNonCanonicalValues(t *testing.T) {
	valid, err := DeriveCSRFToken(csrfTestSession)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, session, csrf string
	}{
		{"empty session", "", valid},
		{"short session", "AA", valid},
		{"padded session", csrfTestSession + "=", valid},
		{"invalid session alphabet", strings.Replace(csrfTestSession, "A", "+", 1), valid},
		{"empty csrf", csrfTestSession, ""},
		{"short csrf", csrfTestSession, "AA"},
		{"padded csrf", csrfTestSession, valid + "="},
		{"invalid csrf alphabet", csrfTestSession, strings.Replace(valid, "3", "+", 1)},
		{"oversize csrf", csrfTestSession, valid + "A"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateCSRFToken(test.session, test.csrf); !errors.Is(err, ErrInvalidCSRFToken) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if _, err := DeriveCSRFToken(strings.Repeat("A", 44)); !errors.Is(err, ErrInvalidCSRFToken) {
		t.Fatalf("oversize session err=%v", err)
	}
}
