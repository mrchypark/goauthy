package upstreamprovider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSafeHTTPClientBlocksLoopbackAndMetadataDial(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newSafeHTTPClient(time.Second, false)
	for _, target := range []string{srv.URL, "https://169.254.169.254/latest/meta-data/"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("expected safe HTTP client to block %s", target)
		}
		if !errors.Is(err, errUnsafeUpstreamHost) {
			t.Fatalf("target=%s expected errUnsafeUpstreamHost, got %v", target, err)
		}
	}
}
