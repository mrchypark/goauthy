package webid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestHandlerRendersDeterministicActiveProfileWithoutPrivateFields(t *testing.T) {
	db := testDB(t)
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BootstrapUser(context.Background(), "subject-1", "user@example.test", mustPasswordHash(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "webid-profile", SQL: `INSERT INTO identity_user_profiles (subject,email,email_verified,given_name,family_name) VALUES (?,?,?,?,?)`, Args: []any{"subject-1", "user@example.test", int64(0), `A"lice`, "Example\n"}}); err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler("https://id.example.test/auth/v1", store)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /auth/{subject}/profile", h)

	request := httptest.NewRequest(http.MethodGet, "/auth/subject-1/profile", nil)
	first := httptest.NewRecorder()
	mux.ServeHTTP(first, request)
	second := httptest.NewRecorder()
	mux.ServeHTTP(second, request)
	if first.Code != http.StatusOK || second.Code != http.StatusOK || first.Body.String() != second.Body.String() {
		t.Fatalf("status/body mismatch: first=%d second=%d\n%s\n%s", first.Code, second.Code, first.Body, second.Body)
	}
	if first.Header().Get("Content-Type") != "text/turtle; charset=utf-8" || first.Header().Get("Cache-Control") != "no-store" || first.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers=%v", first.Header())
	}
	body := first.Body.String()
	for _, want := range []string{
		`<https://id.example.test/auth/v1/auth/subject-1/profile>`,
		`<http://www.w3.org/ns/solid/terms#oidcIssuer> <https://id.example.test/auth/v1>`,
		`<http://xmlns.com/foaf/0.1/givenname> "A\"lice"`,
		`<http://xmlns.com/foaf/0.1/family_name> "Example\n"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
	for _, secret := range []string{"user@example.test", "email", "roles", "groups"} {
		if strings.Contains(body, secret) {
			t.Fatalf("private field leaked %q: %s", secret, body)
		}
	}
}

func TestHandlerRejectsUnsafeOrUnsupportedRequests(t *testing.T) {
	store := testIdentityStore(t)
	if _, err := store.BootstrapUser(context.Background(), "subject-1", "user@example.test", mustPasswordHash(t)); err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler("https://id.example.test", store)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /auth/{subject}/profile", h)
	for _, test := range []struct {
		name, method, path, accept string
		want                       int
	}{
		{"unsupported accept", http.MethodGet, "/auth/subject-1/profile", "application/ld+json", http.StatusNotAcceptable},
		{"query", http.MethodGet, "/auth/subject-1/profile?x=1", "text/turtle", http.StatusNotFound},
		{"unsafe subject", http.MethodGet, "/auth/subject%2F1/profile", "text/turtle", http.StatusNotFound},
		{"head is not get", http.MethodHead, "/auth/subject-1/profile", "text/turtle", http.StatusMethodNotAllowed},
		{"unknown subject", http.MethodGet, "/auth/unknown/profile", "text/turtle", http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			if test.accept != "" {
				request.Header.Set("Accept", test.accept)
			}
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d want %d body=%q", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func TestAcceptsTurtleRFC9110MediaRanges(t *testing.T) {
	for _, test := range []struct {
		name   string
		values []string
		want   bool
	}{
		{name: "exact", values: []string{"text/turtle"}, want: true},
		{name: "OWS and charset", values: []string{"  text/turtle; charset=utf-8  "}, want: true},
		{name: "quality", values: []string{"text/turtle; q=0.5"}, want: true},
		{name: "combined ranges", values: []string{"application/json, text/turtle;q=0.8"}, want: true},
		{name: "multiple fields", values: []string{"application/json", "text/turtle;level=1;q=1.000"}, want: true},
		{name: "text wildcard", values: []string{"text/*;q=0.2"}, want: true},
		{name: "global wildcard", values: []string{"*/*;q=0.2"}, want: true},
		{name: "specific zero overrides wildcard", values: []string{"*/*;q=1, text/turtle;q=0"}, want: false},
		{name: "text zero overrides global", values: []string{"*/*;q=1, text/*;q=0"}, want: false},
		{name: "specific positive overrides text zero", values: []string{"text/*;q=0, text/turtle;q=0.1"}, want: true},
		{name: "quality zero", values: []string{"text/turtle;q=0"}, want: false},
		{name: "unsupported only", values: []string{"application/json"}, want: false},
		{name: "malformed media type", values: []string{"text"}, want: false},
		{name: "malformed quality", values: []string{"text/turtle;q=1.01"}, want: false},
		{name: "q outside range", values: []string{"text/turtle;q=2"}, want: false},
		{name: "q missing leading zero", values: []string{"text/turtle;q=.5"}, want: false},
		{name: "too many fractional digits", values: []string{"text/turtle;q=0.1234"}, want: false},
		{name: "trailing delimiter", values: []string{"text/turtle;"}, want: false},
		{name: "empty range", values: []string{"text/turtle,,application/json"}, want: false},
		{name: "unterminated parameter", values: []string{`text/turtle;profile="webid`}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := acceptsTurtle(test.values); got != test.want {
				t.Fatalf("acceptsTurtle(%q)=%t want %t", test.values, got, test.want)
			}
		})
	}
}

func TestAcceptsTurtleBoundsHeaderAndRanges(t *testing.T) {
	if acceptsTurtle([]string{strings.Repeat("x", maxAcceptBytes+1)}) {
		t.Fatal("accepted oversized Accept header")
	}
	tooMany := make([]string, maxAcceptRanges+1)
	for index := range tooMany {
		tooMany[index] = "text/turtle;q=0"
	}
	if acceptsTurtle(tooMany) {
		t.Fatal("accepted too many Accept ranges")
	}
	if !acceptsTurtle([]string{"text/turtle", "application/json"}) {
		t.Fatal("rejected bounded multiple Accept fields")
	}
}

func TestRenderTurtleBoundsAndEscapes(t *testing.T) {
	profile := identity.AccountProfile{Subject: "subject-1", GivenName: strings.Repeat("x", 9000)}
	if _, err := renderTurtle("https://id.example.test", profile.Subject, profile); err == nil {
		t.Fatal("oversized WebID document accepted")
	}
	if got := turtleLiteral("line\x00\n"); got != `"line\u0000\n"` {
		t.Fatalf("literal=%q", got)
	}
	if _, ok := CanonicalProfilePath("https://id.example.test", "subject-1"); !ok {
		t.Fatal("safe subject rejected")
	}
	for _, subject := range []string{"", ".", "..", "subject/1", "subject 1", "subject?1"} {
		if _, ok := CanonicalProfilePath("https://id.example.test", subject); ok {
			t.Fatalf("unsafe subject accepted: %q", subject)
		}
	}
}

func testDB(t *testing.T) *rhiza.DB {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "webid-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func testIdentityStore(t *testing.T) *identity.Store {
	t.Helper()
	store, err := identity.NewStore(testDB(t))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func mustPasswordHash(t *testing.T) string {
	t.Helper()
	hash, err := credential.Hash([]byte("CorrectPassword1!"))
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
