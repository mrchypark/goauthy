package dcr

import (
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestHasExactRedirectURI(t *testing.T) {
	ctx, store, _ := testStore(t)
	request := validRequest("redirect-match", TokenEndpointAuthNone)
	request.RedirectURIs = []string{"https://rp.example.test/callback"}
	if _, err := store.Create(ctx, request); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		uri  string
		want bool
	}{
		{name: "exact", uri: "https://rp.example.test/callback", want: true},
		{name: "prefix", uri: "https://rp.example.test/call", want: false},
		{name: "suffix", uri: "https://rp.example.test/callback/extra", want: false},
		{name: "query", uri: "https://rp.example.test/callback?next=attacker", want: false},
		{name: "fragment", uri: "https://rp.example.test/callback#attacker", want: false},
		{name: "missing", uri: "https://other.example.test/callback", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := store.HasExactRedirectURI(ctx, test.uri)
			if err != nil || got != test.want {
				t.Fatalf("HasExactRedirectURI(%q) = %v, %v; want %v, nil", test.uri, got, err, test.want)
			}
		})
	}
}

func TestHasExactRedirectURIFailsClosedOnMalformedRow(t *testing.T) {
	ctx, store, db := testStore(t)
	if _, err := store.Create(ctx, validRequest("valid-redirect", TokenEndpointAuthNone)); err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, validRequest("malformed-redirect", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "dcr-malformed-redirect",
		SQL:       `UPDATE dynamic_oauth_clients SET redirect_uris_json = ? WHERE client_id = ?`,
		Args:      []any{"not-json", created.ClientID},
	}); err != nil {
		t.Fatal(err)
	}
	matched, err := store.HasExactRedirectURI(ctx, "https://rp.example.test/callback")
	if err == nil || matched {
		t.Fatalf("malformed row matched=%v err=%v; want false and an error", matched, err)
	}
}
