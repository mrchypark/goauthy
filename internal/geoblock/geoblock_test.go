package geoblock

import (
	_ "embed"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// GeoIP2-Country-Test.mmdb is the official MaxMind-DB test fixture.
// Source: https://github.com/maxmind/MaxMind-DB/blob/363086b7d90650100e91f954937794c6a090c2a0/test-data/GeoIP2-Country-Test.mmdb
// SHA-256: b37601903448683d241af52893c8cbf0fed461e0cdebe0bfaca01891fdeb6db9
//
//go:embed testdata/GeoIP2-Country-Test.mmdb
var countryTestDB []byte

func TestMaxMindReaderCountry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "country.mmdb")
	if err := os.WriteFile(path, countryTestDB, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenMaxMind(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	for _, test := range []struct {
		name, ip, want string
	}{
		{name: "allowed KR", ip: "2001:220::1", want: "KR"},
		{name: "denied US", ip: "149.101.100.1", want: "US"},
		{name: "unknown", ip: "214.1.1.1", want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := reader.Country(netip.MustParseAddr(test.ip))
			if err != nil || got != test.want {
				t.Fatalf("Country(%s)=%q, %v; want %q", test.ip, got, err, test.want)
			}
		})
	}
}

func TestPolicyTable(t *testing.T) {
	p, err := NewPolicy(Whitelist, []string{"DE", "FR"}, false)
	if err != nil {
		t.Fatal(err)
	}
	for country, want := range map[string]Decision{"DE": Allow, "US": Deny, "": Deny, "de": Deny} {
		if got := p.Decide(country); got != want {
			t.Fatalf("%q: got %v want %v", country, got, want)
		}
	}
	p, err = NewPolicy(Blacklist, []string{"DE"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if p.Decide("") != Deny || p.Decide("US") != Allow || p.Decide("DE") != Deny {
		t.Fatal("blacklist decisions")
	}
}

func TestNormalizeDatabaseCountry(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  string
		want string
		ok   bool
	}{
		"uppercase":          {raw: "KR", want: "KR", ok: true},
		"lowercase":          {raw: "kr", want: "KR", ok: true},
		"mixed ASCII":        {raw: "kR", want: "KR", ok: true},
		"expanding Unicode":  {raw: "ß", ok: false},
		"confusable Unicode": {raw: "KR", ok: false},
		"fullwidth Unicode":  {raw: "ＫＲ", ok: false},
		"digit":              {raw: "K1", ok: false},
		"wrong length":       {raw: "USA", ok: false},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := normalizeDatabaseCountry(tc.raw)
			if tc.ok {
				if err != nil || got != tc.want {
					t.Fatalf("got=%q err=%v want=%q", got, err, tc.want)
				}
				return
			}
			if err != ErrInvalidCountry {
				t.Fatalf("got=%q err=%v want=%v", got, err, ErrInvalidCountry)
			}
		})
	}
}

func TestHeaderTrustAndValidation(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	for name, tc := range map[string]struct {
		remote, header string
		wantErr        error
	}{
		"valid":     {"10.0.0.2:443", "DE", nil},
		"untrusted": {"192.0.2.1:443", "DE", ErrSpoofedHeader},
		"repeated":  {"10.0.0.2:443", "DE", ErrAmbiguousHeader},
		"lower":     {"10.0.0.2:443", "de", ErrInvalidCountry},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			r.Header.Add("X-Country", tc.header)
			if name == "repeated" {
				r.Header.Add("X-Country", "FR")
			}
			_, err := HeaderCountry(r, "X-Country", trusted)
			if err != tc.wantErr {
				t.Fatalf("err=%v want=%v", err, tc.wantErr)
			}
		})
	}
}

type failingLookup struct{}

func (failingLookup) Country(netip.Addr) (string, error) { return "", errors.New("lookup failed") }

type recordingLookup struct {
	want netip.Addr
}

func (l *recordingLookup) Country(ip netip.Addr) (string, error) {
	l.want = ip
	return "KR", nil
}

type emptyLookup struct{}

func (emptyLookup) Country(netip.Addr) (string, error) { return "", nil }

func TestMiddlewareUsesTrustedProxyDerivedIP(t *testing.T) {
	policy, err := NewPolicy(Whitelist, []string{"KR"}, true)
	if err != nil {
		t.Fatal(err)
	}
	lookup := &recordingLookup{}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.0.0.2:443"
	request.Header.Set("X-Forwarded-For", "198.51.100.10")
	response := httptest.NewRecorder()
	Middleware(policy, "", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, lookup, next).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || lookup.want != netip.MustParseAddr("198.51.100.10") {
		t.Fatalf("status=%d lookup IP=%s", response.Code, lookup.want)
	}
}

func TestMiddlewareHeaderOverridesLookupOnlyWhenTrusted(t *testing.T) {
	policy, err := NewPolicy(Whitelist, []string{"DE"}, true)
	if err != nil {
		t.Fatal(err)
	}
	lookup := &recordingLookup{}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.0.0.2:443"
	request.Header.Set("X-Country", "DE")
	response := httptest.NewRecorder()
	Middleware(policy, "X-Country", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, lookup, next).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || lookup.want.IsValid() {
		t.Fatalf("status=%d lookup IP=%s", response.Code, lookup.want)
	}
}

func TestMiddlewareLookupFailureBlocksWhenConfigured(t *testing.T) {
	policy, err := NewPolicy(Blacklist, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.10:443"
	recorder := httptest.NewRecorder()
	Middleware(policy, "", nil, failingLookup{}, next).ServeHTTP(recorder, r)
	if recorder.Code != http.StatusForbidden || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v", recorder.Code, recorder.Header())
	}
}

func TestMiddlewareLookupFailureAllowsBlacklistUnknownWhenConfigured(t *testing.T) {
	policy, err := NewPolicy(Blacklist, []string{"DE"}, false)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.10:443"
	recorder := httptest.NewRecorder()
	Middleware(policy, "", nil, failingLookup{}, next).ServeHTTP(recorder, r)
	if recorder.Code != http.StatusNoContent || !called {
		t.Fatalf("status=%d called=%t", recorder.Code, called)
	}
}

func TestMiddlewareEmptyLookupHonorsUnknownPolicy(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, test := range []struct {
		name   string
		policy Policy
		want   int
	}{
		{name: "whitelist", policy: Policy{Type: Whitelist}, want: http.StatusForbidden},
		{name: "blacklist block unknown", policy: Policy{Type: Blacklist, BlockUnknown: true}, want: http.StatusForbidden},
		{name: "blacklist allow unknown", policy: Policy{Type: Blacklist}, want: http.StatusNoContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = "203.0.113.10:443"
			recorder := httptest.NewRecorder()
			Middleware(test.policy, "", nil, emptyLookup{}, next).ServeHTTP(recorder, r)
			if recorder.Code != test.want {
				t.Fatalf("status=%d want=%d", recorder.Code, test.want)
			}
		})
	}
}

func TestMiddlewareRejectsMalformedTrustedForwardingBeforeUnknownAllow(t *testing.T) {
	policy, err := NewPolicy(Blacklist, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, header := range []http.Header{
		{"Forwarded": {"for=unknown"}},
		{"X-Forwarded-For": {"203.0.113.8", "198.51.100.9"}},
		{"Forwarded": {"for=203.0.113.8"}, "X-Forwarded-For": {"198.51.100.9"}},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "192.0.2.2:443"
		r.Header = header
		recorder := httptest.NewRecorder()
		Middleware(policy, "", []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, emptyLookup{}, next).ServeHTTP(recorder, r)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("headers=%v status=%d want=%d", header, recorder.Code, http.StatusForbidden)
		}
	}
}

func TestMiddlewareRejectsCountryHeaderFromUntrustedPeer(t *testing.T) {
	policy, err := NewPolicy(Blacklist, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.9:443"
	r.Header.Set("X-Country", "DE")
	recorder := httptest.NewRecorder()
	Middleware(policy, "X-Country", []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, emptyLookup{}, next).ServeHTTP(recorder, r)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", recorder.Code, http.StatusForbidden)
	}
}
