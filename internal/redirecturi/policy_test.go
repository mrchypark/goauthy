package redirecturi

import "testing"

func TestPolicyMatches(t *testing.T) {
	tests := []struct {
		name           string
		allow, dynamic bool
		registered     []string
		requested      string
		want           bool
	}{
		{"exact static", false, false, []string{"https://rp.example/cb?x=1"}, "https://rp.example/cb?x=1", true},
		{"static port change", true, false, []string{"http://127.0.0.1/cb"}, "http://127.0.0.1:43123/cb", false},
		{"disabled dynamic", false, true, []string{"http://127.0.0.1/cb"}, "http://127.0.0.1:43123/cb", false},
		{"ipv4", true, true, []string{"http://127.0.0.1/cb"}, "http://127.0.0.1:43123/cb", true},
		{"ipv6", true, true, []string{"http://[::1]:1/cb"}, "http://[::1]:65535/cb", true},
		{"same query", true, true, []string{"http://127.0.0.1/cb?fixed=value"}, "http://127.0.0.1:43123/cb?fixed=value", true},
		{"different query", true, true, []string{"http://127.0.0.1/cb?fixed=value"}, "http://127.0.0.1:43123/cb?other=value", false},
		{"cross family", true, true, []string{"http://127.0.0.1/cb"}, "http://[::1]:43123/cb", false},
		{"localhost exact", true, true, []string{"http://localhost:43123/cb"}, "http://localhost:43123/cb", true},
		{"localhost port change", true, true, []string{"http://localhost:43122/cb"}, "http://localhost:43123/cb", false},
		{"localhost case", true, true, []string{"http://localhost/cb"}, "http://LOCALHOST:43123/cb", false},
		{"localhost subdomain", true, true, []string{"http://localhost/cb"}, "http://sub.localhost:43123/cb", false},
		{"localhost trailing dot", true, true, []string{"http://localhost/cb"}, "http://localhost.:43123/cb", false},
		{"localhost confusable", true, true, []string{"http://localhost/cb"}, "http://localho\u0455t:43123/cb", false},
		{"localhost encoded host", true, true, []string{"http://localhost/cb"}, "http://localhos%74:43123/cb", false},
		{"empty fragment", true, true, []string{"http://localhost/cb"}, "http://localhost:43123/cb#", false},
		{"expanded ipv6", true, true, []string{"http://[::1]/cb"}, "http://[0:0:0:0:0:0:0:1]:43123/cb", false},
		{"dns", true, true, []string{"http://loopback.example/cb"}, "http://loopback.example:43123/cb", false},
		{"unspecified", true, true, []string{"http://0.0.0.0/cb"}, "http://0.0.0.0:43123/cb", false},
		{"other loopback", true, true, []string{"http://127.0.0.2/cb"}, "http://127.0.0.2:43123/cb", false},
		{"userinfo", true, true, []string{"http://127.0.0.1/cb"}, "http://user@127.0.0.1:43123/cb", false},
		{"fragment", true, true, []string{"http://127.0.0.1/cb"}, "http://127.0.0.1:43123/cb#x", false},
		{"missing port", true, true, []string{"http://127.0.0.1:1234/cb"}, "http://127.0.0.1/cb", false},
		{"zero port", true, true, []string{"http://127.0.0.1/cb"}, "http://127.0.0.1:0/cb", false},
		{"exact empty fragment", true, false, []string{"https://rp.example/cb#"}, "https://rp.example/cb#", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := (Policy{AllowLoopback: test.allow}).Matches(test.registered, test.requested, test.dynamic); got != test.want {
				t.Fatalf("Matches(%q, %q) = %v, want %v", test.registered, test.requested, got, test.want)
			}
		})
	}
}

func TestIsLoopbackTemplate(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://127.0.0.1/callback": true, "http://[::1]:1234/callback": true,
		"http://127.0.0.1/callback?x=1": false, "http://127.0.0.1/callback#x": false,
		"http://localhost/callback": false, "http://localhost:1234/callback": true,
		"http://LOCALHOST/callback": false, "http://localhost./callback": false,
		"http://localhost.example/callback": false, "http://localho\u0455t/callback": false,
		"http://localhost/callback#": false, "http://[0:0:0:0:0:0:0:1]/callback": false,
		"http://127.0.0.2/callback":   false,
		"http://127.0.0.1:0/callback": false, "http://127.0.0.1:65536/callback": false,
	} {
		if got := IsLoopbackTemplate(raw); got != want {
			t.Fatalf("IsLoopbackTemplate(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestIsPortlessLoopbackTemplate(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://localhost/callback": false, "http://127.0.0.1/callback": true,
		"http://[::1]/callback": true, "http://localhost:43123/callback": false,
		"http://127.0.0.1:43123/callback": false, "http://[::1]:43123/callback": false,
		"http://localhost:/callback": false, "http://localhost/callback?x=1": false,
		"http://localhost/callback#": false,
	} {
		if got := IsPortlessLoopbackTemplate(raw); got != want {
			t.Fatalf("IsPortlessLoopbackTemplate(%q) = %v, want %v", raw, got, want)
		}
	}
}
