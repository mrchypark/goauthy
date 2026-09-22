// This file is overlaid into the selected Beesuh checkout for the live bridge.
// It uses the real Runtime and OAuth adapter without modifying that checkout.
package beesuh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Conalog/beesuh/goauthy"
)

func TestGoAuthyOAuthLiveBridge(t *testing.T) {
	path := os.Getenv("BEESUH_E2E_GOAUTHY_OAUTH_FIXTURE")
	if path == "" {
		t.Skip("live OAuth fixture not configured; NOT VERIFIED")
	}
	var f struct {
		Issuer    string               `json:"issuer"`
		CA        string               `json:"ca_file"`
		TokenFile string               `json:"token_file"`
		Binding   goauthy.OAuthBinding `json:"binding"`
		Denied    bool                 `json:"denied"`
	}
	if json.Unmarshal(deliveryPrivateFile(t, path), &f) != nil {
		t.Fatal("invalid fixture")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(deliveryPrivateFile(t, f.CA)) {
		t.Fatal("invalid CA")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	t.Cleanup(tr.CloseIdleConnections)
	transport := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	client, err := goauthy.NewOAuthClient(f.Issuer, f.Binding, func(_ context.Context, request goauthy.OAuthTokenRequest) (string, error) {
		if request.Resource != f.Binding.Resource || request.ConsumerClientID != f.Binding.ConsumerClientID {
			t.Fatal("consumer binding changed")
		}
		return strings.TrimSpace(string(deliveryPrivateFile(t, f.TokenFile))), nil
	}, transport, transport, time.Now)
	if err != nil {
		t.Fatal("invalid OAuth client binding")
	}
	opts := nativeOptions(t.TempDir(), "", "", nil)
	opts.Native.Provider.BaseURL = strings.TrimSuffix(f.Binding.Endpoint, "/chat/completions")
	opts.RequireIdentity = true
	opts.Authorize = func(context.Context, Principal) error { return nil }
	opts.ResolveCredential = func(context.Context, Connection) (Credential, error) {
		return Credential{HTTPClient: client, AccountID: f.Binding.AccountID}, nil
	}
	runtime := nativeOpen(t, opts)
	defer runtime.Close()
	if err := runtime.RegisterConnection(context.Background(), Connection{ID: "oauth", UserID: "owner", WorkspaceID: "workspace", Kind: "provider", TargetID: "default", CredentialRef: "oauth", State: "ready"}); err != nil {
		t.Fatal("register connection")
	}
	for _, id := range []string{"first", "redelivery"} {
		out, err := deliveryRun(runtime, "oauth", id)
		if f.Denied {
			if err == nil || out.State == "succeeded" {
				t.Fatal("denied credential dispatched")
			}
			continue
		}
		var result struct {
			Text string `json:"text"`
		}
		if err != nil || json.Unmarshal(out.Output, &result) != nil || result.Text != "fixture-model-ok" {
			t.Fatal("real OAuth consumer completion failed")
		}
	}
}
