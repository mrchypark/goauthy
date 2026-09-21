package credential

import (
	"errors"
	"strings"
	"testing"
)

func TestDefaultRules(t *testing.T) {
	expected := Rules{
		LengthMin:            14,
		LengthMax:            128,
		LowerCase:            1,
		UpperCase:            1,
		Digits:               1,
		History:              3,
		ValidDays:            180,
		BlockCommonPasswords: true,
		MinEntropyBits:       60,
	}
	if got, want := DefaultRules(), expected; got != want {
		t.Fatalf("rules=%+v want=%+v", got, want)
	}
}

func TestRulesValidate(t *testing.T) {
	valid := DefaultRules()
	for _, rules := range []Rules{
		{LengthMin: 7, LengthMax: 128}, {LengthMin: 8, LengthMax: 129},
		{LengthMin: 14, LengthMax: 13}, {LengthMin: 8, LengthMax: 128, LowerCase: -1},
		{LengthMin: 8, LengthMax: 128, UpperCase: 33}, {LengthMin: 8, LengthMax: 128, Digits: 33},
		{LengthMin: 8, LengthMax: 128, Special: 33}, {LengthMin: 8, LengthMax: 128, History: 11},
		{LengthMin: 8, LengthMax: 128, ValidDays: -1}, {LengthMin: 8, LengthMax: 128, ValidDays: 3651},
	} {
		if err := rules.Validate(); !errors.Is(err, ErrInvalidPasswordRules) {
			t.Errorf("rules=%+v err=%v", rules, err)
		}
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRulesValidateRejectsImpossibleClassMinimums(t *testing.T) {
	// A class minimum is satisfied by a character that cannot satisfy any other
	// class, so required classes above the maximum length describe a policy no
	// password can meet (GA-CONFIG-002).
	for _, rules := range []Rules{
		{LengthMin: 8, LengthMax: 14, LowerCase: 8, UpperCase: 8},
		{LengthMin: 8, LengthMax: 8, LowerCase: 1, UpperCase: 1, Digits: 1, Special: 6},
		{LengthMin: 8, LengthMax: 8, Special: 9},
	} {
		if err := rules.Validate(); !errors.Is(err, ErrInvalidPasswordRules) {
			t.Errorf("impossible rules=%+v err=%v", rules, err)
		}
	}
}

func TestRulesValidateAcceptsExactFitClassMinimums(t *testing.T) {
	exactFit := Rules{LengthMin: 8, LengthMax: 8, LowerCase: 1, UpperCase: 1, Digits: 1, Special: 5}
	for _, rules := range []Rules{
		exactFit,
		{LengthMin: 8, LengthMax: 128, LowerCase: 1, UpperCase: 1, Digits: 1},
		{LengthMin: 8, LengthMax: 128},
	} {
		if err := rules.Validate(); err != nil {
			t.Errorf("satisfiable rules=%+v err=%v", rules, err)
		}
	}
	if err := exactFit.ValidatePassword([]byte("Ab1!!!!!")); err != nil {
		t.Fatalf("exact-fit password rejected: %v", err)
	}
	if err := exactFit.ValidatePassword([]byte("Ab1!!!!")); !errors.Is(err, ErrPasswordRejected) {
		t.Fatalf("short password accepted: %v", err)
	}
}

func TestRulesValidDaysBoundaries(t *testing.T) {
	for _, days := range []int{0, 1, 3650} {
		rules := Rules{LengthMin: 8, LengthMax: 128, ValidDays: days}
		if err := rules.Validate(); err != nil {
			t.Fatalf("ValidDays=%d: %v", days, err)
		}
	}
}

func TestRulesValidatePassword(t *testing.T) {
	rules := DefaultRules()
	for _, test := range []struct {
		name     string
		password []byte
		wantErr  error
	}{
		{name: "default", password: []byte("CorrectHorse42")},
		{name: "too short", password: []byte("Correct42"), wantErr: ErrPasswordRejected},
		{name: "missing lowercase", password: []byte("CORRECTHORSE42"), wantErr: ErrPasswordRejected},
		{name: "missing uppercase", password: []byte("correcthorse42"), wantErr: ErrPasswordRejected},
		{name: "ASCII digits only", password: []byte("CorrectHorse\u0664\u0662"), wantErr: ErrPasswordRejected},
		{name: "invalid UTF-8", password: []byte{'C', 0xff, '4'}, wantErr: ErrPasswordRejected},
		{name: "rune length", password: []byte("\u00c4bcdefghijkl\U0001f6424"), wantErr: nil},
		{name: "rune maximum", password: []byte("A" + strings.Repeat("a", 126) + "4"), wantErr: nil},
		{name: "too many runes", password: []byte("A" + strings.Repeat("a", 127) + "4"), wantErr: ErrPasswordRejected},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := rules.ValidatePassword(test.password)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("ValidatePassword(%q) err=%v want=%v", test.password, err, test.wantErr)
			}
		})
	}
}

func TestRulesValidatePasswordClasses(t *testing.T) {
	rules := Rules{LengthMin: 8, LengthMax: 8, LowerCase: 1, UpperCase: 1, Digits: 1, Special: 1}
	if err := rules.ValidatePassword([]byte("A\u00e9bc1!de")); err != nil {
		t.Fatalf("unicode lower and punctuation special: %v", err)
	}
	if err := rules.ValidatePassword([]byte("A\u00e9bc1\u00e9de")); !errors.Is(err, ErrPasswordRejected) {
		t.Fatalf("unicode letter counted as special: %v", err)
	}
	if err := rules.ValidatePassword([]byte("A\u00e9bc1\u00b2de")); !errors.Is(err, ErrPasswordRejected) {
		t.Fatalf("unicode number counted as special: %v", err)
	}
	if err := (Rules{}).ValidatePassword([]byte("anything")); !errors.Is(err, ErrInvalidPasswordRules) {
		t.Fatalf("invalid rules err=%v", err)
	}
}
