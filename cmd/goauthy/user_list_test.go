package main

import "testing"

func TestUserListThresholdFromEnv(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw  string
		want uint16
	}{
		{"", 1000}, {"1", 1}, {"65535", 65535}, {"0", 0}, {"65536", 0},
		{"-1", 0}, {"+1", 0}, {"01", 0}, {" 1", 0}, {"1 ", 0}, {"1.0", 0},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := userListThresholdFromEnv(func(name string) string {
				if name != "GOAUTHY_SSP_THRESHOLD" {
					t.Fatalf("unexpected key %s", name)
				}
				return tc.raw
			})
			if got != tc.want || (err != nil) != (tc.want == 0) {
				t.Fatalf("got=%d err=%v", got, err)
			}
		})
	}
}
