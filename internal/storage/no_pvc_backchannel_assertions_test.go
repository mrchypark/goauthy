package storage_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/backchannel"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestNoPVCBackchannelDeliveryRecovery(t *testing.T) {
	t.Parallel()
	const (
		clientID = "recovered-backchannel-client"
		subject  = "recovered-backchannel-user"
		issuer   = "https://recovery.example.test"
	)
	root := os.Getenv("GOAUTHY_BACKCHANNEL_RECOVERY_ROOT")
	if root == "" {
		root = t.TempDir()
		tokens := make(chan string, 2)
		rp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/logout" || r.ParseForm() != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			select {
			case tokens <- r.PostForm.Get("logout_token"):
			default:
				t.Error("unexpected extra logout delivery")
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer rp.Close()
		run := func(phase string) {
			t.Helper()
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNoPVCBackchannelDeliveryRecovery$")
			cmd.Env = append(os.Environ(),
				"GOAUTHY_BACKCHANNEL_RECOVERY_ROOT="+root,
				"GOAUTHY_BACKCHANNEL_RECOVERY_PHASE="+phase,
				"GOAUTHY_BACKCHANNEL_RECOVERY_URI="+rp.URL+"/logout",
				"GOAUTHY_BACKCHANNEL_RECOVERY_CA="+base64.StdEncoding.EncodeToString(rp.Certificate().Raw),
				"GOAUTHY_RECOVERY_S3_ENDPOINT=", "GOAUTHY_RECOVERY_GCS_BUCKET=",
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s failed: %v\n%s", phase, err, out)
			}
		}
		run("write")
		if len(tokens) != 0 {
			t.Fatal("delivery occurred before recovery")
		}
		run("recover")
		var public jose.JSONWebKey
		data, err := os.ReadFile(filepath.Join(root, "public-key.json"))
		if err != nil || json.Unmarshal(data, &public) != nil {
			t.Fatal("writer public key unavailable", err)
		}
		select {
		case token := <-tokens:
			claims, err := oidc.VerifyLogoutToken(token, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}}, issuer, clientID, time.Now().UTC())
			if err != nil || claims.Subject != subject || claims.SessionID != "" {
				t.Fatal("invalid recovered logout claims", err)
			}
			signed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := signed.Verify(public.Key)
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(payload, &raw); err != nil {
				t.Fatal(err)
			}
			if _, exists := raw["sid"]; exists {
				t.Fatal("subject-only logout included sid")
			}
		default:
			t.Fatal("recovered worker made no HTTP delivery")
		}
		if len(tokens) != 0 {
			t.Fatal("duplicate recovered delivery")
		}
		return
	}

	phase := os.Getenv("GOAUTHY_BACKCHANNEL_RECOVERY_PHASE")
	if phase != "write" && phase != "recover" {
		t.Fatalf("invalid recovery phase %q", phase)
	}
	ctx := t.Context()
	logoutURI := os.Getenv("GOAUTHY_BACKCHANNEL_RECOVERY_URI")
	keyDir := filepath.Join(root, "keys")
	dataDir := filepath.Join(root, phase)
	objectDir := filepath.Join(root, "objects")
	config := noPVCExportConfig(t, root, dataDir, objectDir)
	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if phase == "recover" {
		defer db.Close()
	}
	if phase == "write" {
		if err := storage.Migrate(ctx, db); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keyDir, "test-key"), []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32))), 0600); err != nil {
			t.Fatal(err)
		}
		keyring, err := oidc.LoadKeyring(keyDir, "test-key")
		if err != nil {
			t.Fatal(err)
		}
		key, err := oidc.EnsureSigningKey(ctx, db, keyring, issuer, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		public, err := json.Marshal(key.PublicJWK)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "public-key.json"), public, 0600); err != nil {
			t.Fatal(err)
		}
		users, err := identity.NewStore(db)
		if err != nil {
			t.Fatal(err)
		}
		phc, err := credential.Hash([]byte("Disposable recovery password 7!"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := users.BootstrapUser(ctx, subject, "recovery@example.test", phc); err != nil {
			t.Fatal(err)
		}
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "seed-recovered-backchannel", Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES(?,?,?,1,0,1)`, Args: []any{subject, clientID, logoutURI}},
		}}); err != nil {
			t.Fatal(err)
		}
		if err := users.DeleteUser(ctx, subject); err != nil {
			t.Fatal(err)
		}
		os.Exit(0) // Skip Close: recovery must use the object store, not a clean checkpoint.
	}

	if err := storage.Ready(ctx, db); err != nil {
		t.Fatal(err)
	}
	delivery, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT client_id,sid,subject,logout_uri,attempts,delivered_at_unix_ms,failed_at_unix_ms FROM oidc_backchannel_deliveries`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(delivery.Rows) != 1 || len(delivery.Rows[0]) != 7 {
		t.Fatalf("recovered delivery rows=%#v err=%v", delivery.Rows, err)
	}
	row := delivery.Rows[0]
	if row[0] != clientID || row[1] != nil || row[2] != subject || row[3] != logoutURI || row[4] != int64(0) || row[5] != nil || row[6] != nil {
		t.Fatalf("recovered pending delivery=%#v", row)
	}
	association, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT logout_uri FROM oidc_user_clients WHERE subject=? AND client_id=?`, Args: []any{subject, clientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(association.Rows) != 0 {
		t.Fatalf("deleted association reappeared=%#v err=%v", association.Rows, err)
	}
	keyring, err := oidc.LoadKeyring(keyDir, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := base64.StdEncoding.DecodeString(os.Getenv("GOAUTHY_BACKCHANNEL_RECOVERY_CA"))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	worker := backchannel.Worker{DB: db, Issuer: issuer, WorkerID: "recovered-worker",
		LoadSigningKey: func(ctx context.Context) (oidc.SigningKey, error) {
			return oidc.LoadActiveSigningKey(ctx, db, keyring, issuer)
		},
		TickInterval: time.Second, RetryBase: time.Second, LeaseDuration: 10 * time.Second,
		RequestTimeout: time.Second, MaxAttempts: 3, TokenLifetime: time.Minute, RootCAs: roots, AllowPrivate: true}
	now := time.Now().UTC()
	if err := worker.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	done, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT attempts,delivered_at_unix_ms,failed_at_unix_ms,lease_token,lease_until_unix_ms FROM oidc_backchannel_deliveries`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(done.Rows) != 1 || len(done.Rows[0]) != 5 {
		t.Fatal("delivery state unavailable", err)
	}
	state := done.Rows[0]
	if state[0] != int64(1) || state[1] != now.UnixMilli() || state[2] != nil || state[3] != nil || state[4] != nil {
		t.Fatalf("delivery not completed: %#v", state)
	}
	if err := worker.Step(ctx, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}
