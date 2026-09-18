package backchannel

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestWorkerDeliversSubjectOnlyAndSeparateSubjects(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	type received struct {
		raw   map[string]any
		token string
		err   error
	}
	results := make(chan received, 2)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			results <- received{err: err}
			return
		}
		token := r.Form.Get("logout_token")
		raw, err := rawJWTClaims(token)
		results <- received{raw: raw, token: token, err: err}
		w.WriteHeader(http.StatusNoContent)
	})
	w, db := newTestWorker(t)
	// Use TLS and the worker's configured root to exercise the real signed wire token.
	tlsServer := httptest.NewTLSServer(handler)
	defer tlsServer.Close()
	roots := x509.NewCertPool()
	roots.AddCert(tlsServer.Certificate())
	w.RootCAs = roots
	insertSubjectDelivery(t, db, "subject-a", "client-1", "alice", tlsServer.URL, now)
	insertSubjectDelivery(t, db, "subject-b", "client-1", "bob", tlsServer.URL, now)
	got := make([]received, 0, 2)
	for i := 0; i < 2; i++ {
		if err := w.Step(context.Background(), now); err != nil {
			t.Fatal(err)
		}
		var r received
		select {
		case r = <-results:
		default:
			t.Fatal("worker completed without an HTTP delivery")
		}
		if r.err != nil {
			t.Fatal(r.err)
		}
		got = append(got, r)
	}
	if len(got) != 2 {
		t.Fatalf("deliveries=%d, want 2", len(got))
	}
	key, err := w.LoadSigningKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		claims, err := oidc.VerifyLogoutToken(r.token, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, w.Issuer, "client-1", now)
		if err != nil || claims.SessionID != "" || claims.Subject == "" {
			t.Fatalf("verified claims=%#v err=%v", claims, err)
		}
	}
	if _, ok := got[0].raw["sid"]; ok {
		t.Fatalf("subject-only token included sid: %#v", got[0].raw)
	}
	if _, ok := got[1].raw["sid"]; ok {
		t.Fatalf("subject-only token included sid: %#v", got[1].raw)
	}
	if got[0].raw["sub"] == got[1].raw["sub"] {
		t.Fatalf("subjects were not delivered separately: %#v", got)
	}
	if got[0].raw["sub"] != "alice" || got[1].raw["sub"] != "bob" {
		t.Fatalf("subjects=%#v, want alice and bob", got)
	}
	for _, eventID := range []string{"subject-a", "subject-b"} {
		_, done, failed, _ := deliveryState(t, db, eventID, "client-1")
		if !done || failed {
			t.Fatalf("%s state done=%v failed=%v", eventID, done, failed)
		}
	}
}

func TestWorkerSubjectFailureEventUsesSubjectOnce(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	w, db := newTestWorker(t)
	insertSubjectDelivery(t, db, "subject-fail", "client-1", "alice", server.URL, now)
	if err := w.Step(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	_, _, _, next := deliveryState(t, db, "subject-fail", "client-1")
	if err := w.Step(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	_, _, _, next = deliveryState(t, db, "subject-fail", "client-1")
	if err := w.Step(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	_, done, failed, _ := deliveryState(t, db, "subject-fail", "client-1")
	if !failed || done {
		t.Fatalf("final state done=%v failed=%v", done, failed)
	}
	if err := w.Step(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT text FROM event_log WHERE typ='BackchannelLogoutFailed'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "client-1 / alice" {
		t.Fatalf("failure events=%#v err=%v", rows.Rows, err)
	}
}

func rawJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("bad JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	err = json.Unmarshal(b, &claims)
	return claims, err
}

func insertSubjectDelivery(t *testing.T, db *rhiza.DB, eventID, clientID, subject, endpoint string, now time.Time) {
	t.Helper()
	insertDelivery(t, db, eventID, clientID, "subject-"+eventID, endpoint, true, true, now)
	_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "subject-" + eventID, SQL: `UPDATE oidc_backchannel_deliveries SET subject=?, sid=NULL WHERE event_id=? AND client_id=?`, Args: []any{subject, eventID, clientID}})
	if err != nil {
		t.Fatal(err)
	}
}
