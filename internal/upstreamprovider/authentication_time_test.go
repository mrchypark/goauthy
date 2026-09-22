package upstreamprovider

import (
	"strings"
	"testing"
)

func TestAuthenticationTimeNumericDate(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		want    int64
		invalid bool
	}{
		{"1800000000", 1800000000, false},
		{"1800000000.0", 1800000000, false},
		{"1800000000.5", 1800000000, false},
		{"1.8e9", 1800000000, false},
		{"1799999999.9999999999999999999999999999999", 1799999999, false},
		{"1799999999." + strings.Repeat("9", 56), 1799999999, false},
		{"1800000000." + strings.Repeat("0", 59), 1800000000, false},
		{"1e999999999", 0, true},
		{"1e-999999999", 0, true},
		{"9223372036854775808", 0, true},
		{"-0.5", -1, false},
		{"1." + strings.Repeat("0", 1024), 0, true},
		{"null", 0, false},
		{`"1800000000"`, 0, true},
		{`true`, 0, true},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := decodeIDTokenClaims([]byte(`{"aud":"client","auth_time":` + tc.raw + `}`))
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid NumericDate accepted")
				}
				return
			}
			if err != nil || got.AuthenticationTime != tc.want {
				t.Fatalf("time=%v error=%v want=%d", got, err, tc.want)
			}
		})
	}
}
