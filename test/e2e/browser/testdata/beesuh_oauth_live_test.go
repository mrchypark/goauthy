// This file is overlaid into the selected Beesuh checkout for the live bridge.
// It uses the real Runtime and OAuth adapter without modifying that checkout.
package beesuh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
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
	authority := &oauthAuthorityRecorder{transport: tr, endpoint: strings.TrimRight(f.Issuer, "/") + "/auth/v1/connection-grants/" + url.PathEscape(f.Binding.GrantID) + "/credential"}
	issuerClient := &http.Client{Transport: authority, Timeout: 15 * time.Second}
	client, err := goauthy.NewOAuthClient(f.Issuer, f.Binding, func(_ context.Context, request goauthy.OAuthTokenRequest) (string, error) {
		if request.Resource != f.Binding.Resource || request.ConsumerClientID != f.Binding.ConsumerClientID {
			t.Fatal("consumer binding changed")
		}
		return strings.TrimSpace(string(deliveryPrivateFile(t, f.TokenFile))), nil
	}, issuerClient, transport, time.Now)
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
	ack := os.NewFile(3, "checkpoint-results")
	if ack == nil {
		t.Fatal("missing checkpoint channel")
	}
	defer ack.Close()
	commands, replies := json.NewDecoder(os.Stdin), json.NewEncoder(ack)
	for checkpoint := 0; ; checkpoint++ {
		var denied bool
		if err := commands.Decode(&denied); err == io.EOF {
			return
		} else if err != nil {
			t.Fatal("invalid checkpoint")
		}
		for _, id := range []string{"first", "redelivery"} {
			authority.take()
			out, err := deliveryRun(runtime, "oauth", fmt.Sprintf("%d-%s", checkpoint, id))
			statuses := authority.take()
			want := http.StatusOK
			if denied {
				want = http.StatusNotFound
			}
			if len(statuses) == 0 {
				t.Fatal("consumer did not revalidate grant authority")
			}
			for _, status := range statuses {
				if status != want {
					t.Fatal("consumer authority request failed unexpectedly")
				}
			}
			if denied {
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
		if replies.Encode(true) != nil {
			t.Fatal("checkpoint reply failed")
		}
	}
}

// Record only endpoint/status metadata, never credentials or response bodies.
type oauthAuthorityRecorder struct {
	transport http.RoundTripper
	endpoint  string
	mu        sync.Mutex
	statuses  []int
}

func (r *oauthAuthorityRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := r.transport.RoundTrip(req)
	status := 0
	if err == nil && response != nil && req.Method == http.MethodPost && req.URL.String() == r.endpoint {
		status = response.StatusCode
	}
	r.mu.Lock()
	r.statuses = append(r.statuses, status)
	r.mu.Unlock()
	return response, err
}
func (r *oauthAuthorityRecorder) take() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := r.statuses
	r.statuses = nil
	return result
}

func TestOAuthAuthorityRecorder(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNotFound, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer server.Close()
			recorder := &oauthAuthorityRecorder{transport: http.DefaultTransport, endpoint: server.URL + "/credential"}
			client := &http.Client{Transport: recorder}
			response, err := client.Post(recorder.endpoint, "application/json", nil)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			got := recorder.take()
			if len(got) != 1 || got[0] != status || len(recorder.take()) != 0 {
				t.Fatal("authority status not recorded/reset")
			}
			response, err = client.Post(server.URL+"/wrong", "application/json", nil)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			got = recorder.take()
			if len(got) != 1 || got[0] != 0 {
				t.Fatal("wrong endpoint accepted")
			}
			server.Close()
			_, err = client.Post(recorder.endpoint, "application/json", nil)
			got = recorder.take()
			if err == nil || len(got) != 1 || got[0] != 0 {
				t.Fatal("transport failure accepted as authority response")
			}
		})
	}
}
