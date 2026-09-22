package device

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
)

func TestDeviceResourceRoundTripAndRecovery(t *testing.T) {
	t.Parallel()
	ctx, store, db := testStore(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	resource := "https://resource.example.test/api"
	grant, err := store.CreateWithBinding(ctx, "client", []string{"goauthy.read"}, ClientBinding{Resource: resource}, now)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT resource FROM oauth_device_grants WHERE device_code_digest=?`, Args: []any{digest(grant.DeviceCode)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != resource {
		t.Fatalf("resource row=%#v err=%v", rows.Rows, err)
	}
	for _, target := range []string{resource, "https://other.example.test/api", ""} {
		recovered, collision, err := store.recoverCreate(ctx, digest(grant.DeviceCode), digest(NormalizeUserCode(grant.UserCode)), "client", "", target, `["goauthy.read"]`, grant)
		if err != nil || recovered != (target == resource) || collision != (target != resource) {
			t.Fatalf("recovery target=%q recovered=%v collision=%v err=%v", target, recovered, collision, err)
		}
	}
	if err := store.Approve(ctx, grant.UserCode, "subject", now); err != nil {
		t.Fatal(err)
	}
	polled, err := store.Poll(ctx, grant.DeviceCode, "client", now)
	if err != nil || polled.Status != StatusClaimed || polled.Resource != resource {
		t.Fatalf("poll=%#v err=%v", polled, err)
	}
}

func TestDeviceResourceValidation(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testStore(t)
	for _, resource := range []string{"http://resource.example.test", "https://resource.example.test?x=1", "https://resource.example.test#x", "https://resource.example.test?", "https://resource.example.test#", "https://:443", "https://user:pass@resource.example.test", " https://resource.example.test", "https://resource.example.test/\n"} {
		if _, err := store.CreateWithBinding(ctx, "client", nil, ClientBinding{Resource: resource}, time.UnixMilli(1_700_000_000_000).UTC()); !errors.Is(err, ErrInvalidTarget) {
			t.Fatalf("resource %q error=%v", resource, err)
		}
	}
}

func TestDeviceHTTPRejectsMalformedOrUnauthorizedResource(t *testing.T) {
	t.Parallel()
	_, store, _ := testStore(t)
	h, err := NewHandler(store, "https://issuer.example.test", func(r *http.Request, clientID string, scopes []string) error {
		if r.PostForm.Get("resource") == "https://resource.example.test/api" {
			SetResource(r, r.PostForm.Get("resource"))
		}
		return nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, form string }{
		{"duplicate", "client_id=client&scope=goauthy.read&resource=https%3A%2F%2Fresource.example.test%2Fapi&resource=https%3A%2F%2Fresource.example.test%2Fapi"},
		{"malformed", "client_id=client&scope=goauthy.read&resource=http%3A%2F%2Fresource.example.test"},
		{"unauthorized", "client_id=client&scope=goauthy.read&resource=https%3A%2F%2Fother.example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/oidc/device", strings.NewReader(tc.form))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.RemoteAddr = "127.0.0.1:1234"
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"error":"invalid_target"`) {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
