package security

import "testing"

func TestValidHeaderText(t *testing.T) {
	for value, want := range map[string]bool{"": false, "Browser/1.0": true, "KR\tSeoul": true, "서울": false, "a\x7f": false, "a\r\nb": false, "\xff": false} {
		if got := ValidHeaderText(value); got != want {
			t.Errorf("header %q valid=%t want=%t", value, got, want)
		}
	}
}
