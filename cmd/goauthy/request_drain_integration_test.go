//go:build goauthy_integration

package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/rhiza"
)

func TestRuntimeShutdownRegisteredRefresh(t *testing.T) {
	for _, forced := range []bool{false, true} {
		name := "drain-completes"
		if forced {
			name = "drain-times-out"
		}
		t.Run(name, func(t *testing.T) {
			// Exactly the runtime relationship: Open inherits the signal context;
			// only inbound requests are detached until lifecycle finishes draining.
			signalCtx, stop := context.WithCancel(t.Context())
			defer stop()
			directory := migratedDataDir(t, "shutdown-refresh")
			db, err := rhiza.Open(signalCtx, rhiza.Config{NodeID: "shutdown-refresh", DataDir: directory})
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			tokenEntered, reply := make(chan struct{}), make(chan struct{})
			var release sync.Once
			unblock := func() { release.Do(func() { close(reply) }) }
			var tokens, identities atomic.Int64
			provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/token":
					call := tokens.Add(1)
					if err := r.ParseForm(); err != nil || r.Form.Get("refresh_token") != "once" {
						t.Error("wrong refresh token")
					}
					if call == 1 {
						close(tokenEntered)
					} else {
						t.Error("provider mutation replayed")
					}
					select {
					case <-reply:
					case <-r.Context().Done():
						return
					}
					_, _ = io.WriteString(w, `{"access_token":"new","refresh_token":"next","token_type":"Bearer","scope":"openid","expires_in":3600}`)
				case "/identity":
					identities.Add(1)
					if r.Header.Get("Authorization") != "Bearer new" {
						t.Error("identity did not verify refreshed token")
					}
					_, _ = io.WriteString(w, `{"sub":"account"}`)
				default:
					t.Error("unexpected provider path")
					http.NotFound(w, r)
				}
			}))
			defer provider.Close()
			defer unblock()
			providers, credentials, keys := saas.IntegrationRegisteredRefresh(t, db, provider)
			requestContexts := make(chan context.Context, 1)
			refreshDone := make(chan error, 1)
			authority := func() (string, []any) { return "1", nil }
			app := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestContexts <- r.Context()
				_, err := credentials.RefreshOAuth2(r.Context(), providers, "owner", "collection", "connection", 1, authority)
				refreshDone <- err
				if err != nil {
					http.Error(w, "refresh failed", http.StatusBadGateway)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			drain := newRequestDrain(signalCtx, app.Config)
			defer drain.cancel()
			app.Start()
			defer app.Close()
			responseDone := make(chan struct{})
			go func() {
				defer close(responseDone)
				resp, err := app.Client().Post(app.URL, "text/plain", nil)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
			}()
			select {
			case <-tokenEntered:
			case <-time.After(5 * time.Second):
				t.Fatal("refresh did not reach provider")
			}
			requestCtx := <-requestContexts
			shutdownEntered := make(chan struct{})
			app.Config.RegisterOnShutdown(func() { close(shutdownEntered) })
			lifecycleDone := make(chan error, 1)
			go func() {
				storageMayClose, err := drain.runLifecycle(signalCtx, app.Config, nil, nil, nil, func() {
					providers.CloseConnections()
					credentials.CloseConnections()
				})
				if !storageMayClose {
					t.Error("cleanup did not drain; storage cannot close")
				}
				select {
				case <-drain.done:
				default:
					t.Error("shared lifecycle returned before handler cleanup")
				}
				lifecycleDone <- err
			}()
			stop()
			<-shutdownEntered
			if requestCtx.Err() != nil {
				t.Fatal("signal canceled active request before drain")
			}
			if !forced {
				unblock()
			}
			lifecycleErr := <-lifecycleDone
			if forced && !errors.Is(lifecycleErr, context.DeadlineExceeded) {
				t.Fatalf("forced drain=%v", lifecycleErr)
			}
			if !forced && lifecycleErr != nil {
				t.Fatalf("graceful drain=%v", lifecycleErr)
			}
			refreshErr := <-refreshDone
			if !forced && refreshErr != nil {
				t.Fatalf("in-flight refresh failed during drain: %v", refreshErr)
			}
			if forced && refreshErr == nil {
				t.Fatal("timed-out refresh reported success")
			}
			queryCtx, cancelQuery := context.WithTimeout(t.Context(), time.Second)
			defer cancelQuery()
			result, err := db.Query(queryCtx, rhiza.QueryRequest{SQL: `SELECT state,token_version,refresh_claim FROM saas_connection_credentials WHERE connection_id='connection'`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil {
				t.Fatalf("storage unavailable before close: %v", err)
			}
			wantState, wantVersion, wantIdentities := "ready", int64(2), int64(1)
			if forced {
				wantState, wantVersion, wantIdentities = "uncertain", 1, 0
			}
			if len(result.Rows) != 1 || result.Rows[0][0] != wantState || result.Rows[0][1] != wantVersion {
				t.Fatalf("durable state=%v", result.Rows)
			}
			if tokens.Load() != 1 || identities.Load() != wantIdentities {
				t.Fatalf("tokens=%d identities=%d", tokens.Load(), identities.Load())
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			// Reopen after storage close: replay rejection must survive restart, with
			// a fresh (unsealed) owner, rather than relying on the old owner's seal.
			reopened, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "shutdown-refresh", DataDir: directory})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			// The durable state query also proves the version/uncertainty survived close.
			persisted, err := reopened.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT state,token_version FROM saas_connection_credentials WHERE connection_id='connection'`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(persisted.Rows) != 1 || persisted.Rows[0][0] != wantState || persisted.Rows[0][1] != wantVersion {
				t.Fatalf("reopened state=%v err=%v", persisted.Rows, err)
			}
			freshProviders, err := saas.NewProviderStore(reopened, keys)
			if err != nil {
				t.Fatal(err)
			}
			defer freshProviders.CloseConnections()
			freshCredentials, err := saas.NewCredentialStore(reopened, keys)
			if err != nil {
				t.Fatal(err)
			}
			defer freshCredentials.CloseConnections()
			if _, err := freshCredentials.RefreshOAuth2(t.Context(), freshProviders, "owner", "collection", "connection", 1, authority); !errors.Is(err, saas.ErrCredentialNotFound) {
				t.Fatalf("durable replay fence=%v", err)
			}
			if tokens.Load() != 1 {
				t.Fatal("provider mutation replayed")
			}
			<-responseDone
		})
	}
}
