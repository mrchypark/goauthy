package dcr

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestIdempotencyKeyIsExactlyOneBoundedHTTPToken(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		setup func(*http.Request)
		want  bool
	}{
		{"valid", func(r *http.Request) { r.Header.Set("Idempotency-Key", "order_01.v1") }, true},
		{"missing", func(*http.Request) {}, false},
		{"duplicate", func(r *http.Request) { r.Header.Add("Idempotency-Key", "one"); r.Header.Add("Idempotency-Key", "two") }, false},
		{"space", func(r *http.Request) { r.Header.Set("Idempotency-Key", "one two") }, false},
		{"unicode", func(r *http.Request) { r.Header.Set("Idempotency-Key", "é") }, false},
		{"too long", func(r *http.Request) { r.Header.Set("Idempotency-Key", strings.Repeat("x", 129)) }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", registrationPath, nil)
			test.setup(r)
			_, got := idempotencyKey(r)
			if got != test.want {
				t.Fatalf("valid=%v want=%v", got, test.want)
			}
		})
	}
}

func TestAnonymousIdempotentCreateRateLimitReplayAndBoundary(t *testing.T) {
	t.Parallel()
	ctx, store, db := testStore(t)
	store.keyring = testEnvelopeKeyring(t)
	base := time.Date(2026, 9, 4, 12, 0, 30, 0, time.UTC)
	store.now = func() time.Time { return base }
	request := validRequest("", TokenEndpointAuthNone)
	request.Contacts = []string{"support@example.test", "mailto:z@example.test"}
	request.LogoURI = "https://rp.example.test/logo.svg"
	request.TOSURI = "https://rp.example.test/terms"
	request.PolicyURI = "https://rp.example.test/privacy"
	digest, err := effectiveCreateDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	build := func(registration Registration) ([]byte, error) {
		return registrationResponseBody("https://id.example.test", registration, true)
	}
	first, err := store.CreateAnonymousIdempotent(ctx, request, "key-1", netip.MustParseAddr("192.0.2.1"), digest, time.Minute, build)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := store.CreateAnonymousIdempotent(ctx, request, "key-1", netip.MustParseAddr("::ffff:192.0.2.1"), digest, time.Minute, build)
	if err != nil || !replay.replay || !bytes.Equal(first.response, replay.response) {
		t.Fatalf("replay=%#v err=%v", replay, err)
	}
	secondRequest := request
	secondRequest.Name = "Second RP"
	secondDigest, err := effectiveCreateDigest(secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateAnonymousIdempotent(ctx, secondRequest, "key-2", netip.MustParseAddr("192.0.2.1"), secondDigest, time.Minute, build)
	var limited *RateLimitError
	if !errors.As(err, &limited) || !limited.RetryNotBefore.Equal(base.Add(time.Minute)) {
		t.Fatalf("rate limit err=%v retry=%v", err, limited)
	}
	if _, err := store.CreateAnonymousIdempotent(ctx, request, "key-3", netip.MustParseAddr("192.0.2.2"), digest, time.Minute, build); err != nil {
		t.Fatalf("separate IP: %v", err)
	}
	base = base.Add(time.Minute)
	if _, err := store.CreateAnonymousIdempotent(ctx, request, "key-4", netip.MustParseAddr("192.0.2.1"), digest, time.Minute, build); err != nil {
		t.Fatalf("next boundary: %v", err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM dynamic_oauth_clients WHERE anonymous=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(3) {
		t.Fatalf("anonymous clients=%#v err=%v", rows.Rows, err)
	}
	contacts, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM dynamic_oauth_clients WHERE anonymous=1 AND contacts_json = ? AND logo_uri = ? AND tos_uri = ? AND policy_uri = ?`, Args: []any{`["mailto:z@example.test","support@example.test"]`, request.LogoURI, request.TOSURI, request.PolicyURI}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(contacts.Rows) != 1 || contacts.Rows[0][0] != int64(3) {
		t.Fatalf("anonymous contacts=%#v err=%v", contacts.Rows, err)
	}
}

func TestConcurrentAnonymousCreateConvergesWithoutOrphans(t *testing.T) {
	t.Parallel()
	ctx, store, db := testStore(t)
	keyring := testEnvelopeKeyring(t)
	store.keyring = keyring
	request := validRequest("", TokenEndpointAuthNone)
	digest, err := effectiveCreateDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	build := func(registration Registration) ([]byte, error) {
		return registrationResponseBody("https://id.example.test", registration, true)
	}
	start := make(chan struct{})
	errs := make(chan error, 4)
	for range 4 {
		go func() {
			<-start
			_, err := NewStore(db, Config{Keyring: keyring, Now: func() time.Time { return time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC) }}).CreateAnonymousIdempotent(ctx, request, "key", netip.MustParseAddr("192.0.2.9"), digest, time.Minute, build)
			errs <- err
		}()
	}
	close(start)
	for range 4 {
		err := <-errs
		if err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM dynamic_oauth_clients WHERE anonymous=1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) {
		t.Fatalf("anonymous clients=%#v err=%v", rows.Rows, err)
	}
}

func TestAnonymousCreateRollbackDoesNotReserveOrOrphan(t *testing.T) {
	t.Parallel()
	ctx, store, db := testStore(t)
	store.keyring = testEnvelopeKeyring(t)
	store.now = func() time.Time { return time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC) }
	if _, err := store.Create(ctx, validRequest("taken", TokenEndpointAuthNone)); err != nil {
		t.Fatal(err)
	}
	digest, err := effectiveCreateDigest(validRequest("taken", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	build := func(registration Registration) ([]byte, error) {
		return registrationResponseBody("https://id.example.test", registration, true)
	}
	ip := netip.MustParseAddr("192.0.2.10")
	if _, err := store.CreateAnonymousIdempotent(ctx, validRequest("taken", TokenEndpointAuthNone), "failed", ip, digest, time.Minute, build); err == nil {
		t.Fatal("duplicate client accepted")
	}
	request := validRequest("", TokenEndpointAuthNone)
	digest, err = effectiveCreateDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateAnonymousIdempotent(ctx, request, "next", ip, digest, time.Minute, build); err != nil {
		t.Fatalf("failed transaction reserved rate limit: %v", err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM dcr_registration_idempotency WHERE principal_digest = ?`, Args: []any{digestString("anonymous/192.0.2.10")}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) {
		t.Fatalf("idempotency rows=%#v err=%v", rows.Rows, err)
	}
}

func TestEffectiveCreateDigestCanonicalizesSetLikeMetadata(t *testing.T) {
	t.Parallel()
	left := validRequest("", TokenEndpointAuthClientBasic)
	right := validRequest("", TokenEndpointAuthClientBasic)
	right.RedirectURIs = []string{"https://b.example.test/callback", "https://a.example.test/callback"}
	left.RedirectURIs = []string{"https://a.example.test/callback", "https://b.example.test/callback"}
	left.GrantTypes = []string{"refresh_token", "authorization_code"}
	right.GrantTypes = []string{"authorization_code", "refresh_token"}
	left.Audiences = []string{"https://api.b.example.test", "https://api.a.example.test"}
	right.Audiences = []string{"https://api.a.example.test", "https://api.b.example.test"}
	left.ClientURI = "https://rp.example.test"
	right.ClientURI = "https://rp.example.test"
	left.LogoURI = "https://rp.example.test/logo.svg"
	right.LogoURI = "https://rp.example.test/logo.svg"
	left.TOSURI = "https://rp.example.test/terms"
	right.TOSURI = "https://rp.example.test/terms"
	left.PolicyURI = "https://rp.example.test/privacy"
	right.PolicyURI = "https://rp.example.test/privacy"
	left.Contacts = []string{"mailto:z@example.test", "support@example.test"}
	right.Contacts = []string{"support@example.test", "mailto:z@example.test"}
	leftDigest, err := effectiveCreateDigest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := effectiveCreateDigest(right)
	if err != nil || leftDigest != rightDigest {
		t.Fatalf("set-like metadata digests differ: left=%q right=%q err=%v", leftDigest, rightDigest, err)
	}
	if left.RedirectURIs[0] != "https://a.example.test/callback" || left.GrantTypes[0] != "refresh_token" {
		t.Fatal("digest canonicalization mutated caller metadata")
	}
	if left.Contacts[0] != "mailto:z@example.test" || right.Contacts[0] != "support@example.test" {
		t.Fatal("contact digest canonicalization mutated caller metadata")
	}
	right.ClientURI = "https://other.example.test"
	differentURI, err := effectiveCreateDigest(right)
	if err != nil || differentURI == leftDigest {
		t.Fatalf("client URI was not part of the idempotency digest: uri=%q err=%v", differentURI, err)
	}
	right.LogoURI = "https://other.example.test/logo.svg"
	differentURI, err = effectiveCreateDigest(right)
	if err != nil || differentURI == leftDigest {
		t.Fatalf("logo URI was not part of the idempotency digest: uri=%q err=%v", differentURI, err)
	}
	defaulted := left
	defaulted.TokenEndpointAuthMethod = ""
	defaultDigest, err := effectiveCreateDigest(defaulted)
	if err != nil || defaultDigest != leftDigest {
		t.Fatalf("default auth method digest differs: default=%q explicit=%q err=%v", defaultDigest, leftDigest, err)
	}
}

func TestIdempotentCreateReplaysEncryptedResponseAndRejectsMismatch(t *testing.T) {
	t.Parallel()
	ctx, store, db := testStore(t)
	store.keyring = testEnvelopeKeyring(t)
	request := validRequest("", TokenEndpointAuthClientBasic)
	request.Contacts = []string{"support@example.test", "mailto:z@example.test"}
	digest, err := effectiveCreateDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	build := func(registration Registration) ([]byte, error) {
		return registrationResponseBody("https://id.example.test", registration, true)
	}
	first, err := store.CreateIdempotent(ctx, request, "key-1", testGlobalToken, digest, build)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := store.CreateIdempotent(ctx, request, "key-1", testGlobalToken, digest, build)
	if err != nil || !replay.replay || !bytes.Equal(first.response, replay.response) {
		t.Fatalf("replay=%#v err=%v", replay, err)
	}
	request.Name = "Different RP"
	differentDigest, err := effectiveCreateDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateIdempotent(ctx, request, "key-1", testGlobalToken, differentDigest, build); err != ErrIdempotencyMismatch {
		t.Fatalf("mismatch err=%v", err)
	}
	request.Name = "Example RP"
	other, err := store.CreateIdempotent(ctx, request, "key-1", "other-global-token", digest, build)
	if err != nil || other.registration.ClientID == first.registration.ClientID {
		t.Fatalf("principal separation registration=%#v err=%v", other.registration, err)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT response_envelope FROM dcr_registration_idempotency`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 2 {
		t.Fatalf("idempotency rows=%#v err=%v", result.Rows, err)
	}
	for _, row := range result.Rows {
		envelope := row[0].(string)
		if strings.Contains(envelope, first.registration.ClientSecret) || strings.Contains(envelope, first.registration.RegistrationAccessToken) || strings.Contains(envelope, "key-1") {
			t.Fatal("idempotency ciphertext contains plaintext credential or key")
		}
	}
}

func TestIdempotentCreateDoesNotRevealCredentialsBeforeAckDurability(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		anonymous bool
	}{
		{name: "authenticated"},
		{name: "anonymous", anonymous: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			objectStoreDir := t.TempDir()
			db := openTestDBWithConfig(t, "dcr-before-ack-"+tc.name, rhiza.Config{
				ObjStoreProvider:   rhiza.ObjectStoreProviderFilesystem,
				ObjStoreDir:        objectStoreDir,
				ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck,
			})

			keyring := testEnvelopeKeyring(t)
			base := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
			store := NewStore(db, Config{Keyring: keyring, Now: func() time.Time { return base }})
			request := validRequest("before-ack-"+tc.name, TokenEndpointAuthClientBasic)
			digest, err := effectiveCreateDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			build := func(registration Registration) ([]byte, error) {
				return registrationResponseBody("https://id.example.test", registration, true)
			}
			call := func() (idempotentRegistration, error) {
				if tc.anonymous {
					return store.CreateAnonymousIdempotent(ctx, request, "before-ack-key", netip.MustParseAddr("192.0.2.88"), digest, time.Minute, build)
				}
				return store.CreateIdempotent(ctx, request, "before-ack-key", testGlobalToken, digest, build)
			}

			backup := objectStoreDir + "-unavailable"
			if err := os.Rename(objectStoreDir, backup); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(objectStoreDir, []byte("object store unavailable"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = os.Remove(objectStoreDir)
				_ = os.Rename(backup, objectStoreDir)
			})

			for attempt := range 2 {
				result, err := call()
				if !errors.Is(err, rhiza.ErrCommitUnknown) {
					t.Fatalf("unavailable before-ack store attempt %d returned err=%v", attempt, err)
				}
				if result.registration.ClientID != "" || result.registration.ClientSecret != "" || result.registration.RegistrationAccessToken != "" || len(result.response) != 0 {
					t.Fatalf("unavailable before-ack store attempt %d revealed registration=%#v response=%q", attempt, result.registration, result.response)
				}
				// Model an independent retry with a different request timestamp.
				base = base.Add(time.Millisecond)
				store = NewStore(db, Config{Keyring: keyring, Now: func() time.Time { return base }})
			}

			if err := os.Remove(objectStoreDir); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(backup, objectStoreDir); err != nil {
				t.Fatal(err)
			}
			recovered, err := call()
			if err != nil || !recovered.replay || len(recovered.response) == 0 {
				t.Fatalf("recovery replay=%#v err=%v", recovered, err)
			}
			clients, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{request.ClientID}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(clients.Rows) != 1 || clients.Rows[0][0] != int64(1) {
				t.Fatalf("recovered client count=%#v err=%v", clients.Rows, err)
			}
		})
	}
}

func TestIdempotentReplaySurvivesActiveMasterKeyChange(t *testing.T) {
	t.Parallel()
	ctx, _, db := testStore(t)
	old, replacement := rewrapKeyrings(t)
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	request := validRequest("idempotency-key-change", TokenEndpointAuthClientBasic)
	digest, err := effectiveCreateDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	build := func(registration Registration) ([]byte, error) {
		return registrationResponseBody("https://id.example.test", registration, true)
	}
	oldStore := NewStore(db, Config{Keyring: old, Now: func() time.Time { return now }})
	created, err := oldStore.CreateIdempotent(ctx, request, "key-change", testGlobalToken, digest, build)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := oldStore.CreateIdempotent(ctx, request, "key-change", testGlobalToken, digest, build); err != nil || !replay.replay || !bytes.Equal(created.response, replay.response) {
		t.Fatalf("old-key replay=%#v err=%v", replay, err)
	}
	replacementStore := NewStore(db, Config{Keyring: replacement, Now: func() time.Time { return now }})
	replay, err := replacementStore.CreateIdempotent(ctx, request, "key-change", testGlobalToken, digest, build)
	if err != nil || !replay.replay || !bytes.Equal(created.response, replay.response) {
		t.Fatalf("replacement-key replay=%#v err=%v", replay, err)
	}
}

func TestRegistrationHTTPIdempotencyReplaysExact201AndRejectsMismatch(t *testing.T) {
	t.Parallel()
	h := testHandler(t, testGlobalToken)
	body := `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Example RP","contacts":["support@example.test","mailto:z@example.test"]}`
	first := httptest.NewRecorder()
	h.ServeHTTP(first, request(http.MethodPost, registrationPath, body, testGlobalToken))
	reordered := strings.Replace(body, `"contacts":["support@example.test","mailto:z@example.test"]`, `"contacts":["mailto:z@example.test","support@example.test"]`, 1)
	second := httptest.NewRecorder()
	h.ServeHTTP(second, request(http.MethodPost, registrationPath, reordered, testGlobalToken))
	if first.Code != http.StatusCreated || second.Code != http.StatusCreated || !bytes.Equal(first.Body.Bytes(), second.Body.Bytes()) {
		t.Fatalf("replay first=%d second=%d firstBody=%q secondBody=%q", first.Code, second.Code, first.Body.String(), second.Body.String())
	}
	different := strings.Replace(body, "Example RP", "Different RP", 1)
	mismatch := httptest.NewRecorder()
	h.ServeHTTP(mismatch, request(http.MethodPost, registrationPath, different, testGlobalToken))
	if mismatch.Code != http.StatusUnprocessableEntity || mismatch.Body.String() != `{"error":"invalid_request"}`+"\n" {
		t.Fatalf("mismatch status=%d body=%q", mismatch.Code, mismatch.Body.String())
	}
}

func testEnvelopeKeyring(t *testing.T) EnvelopeKeyring {
	t.Helper()
	directory := t.TempDir()
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	if err := os.WriteFile(directory+"/master-1", []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(directory, "master-1")
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func TestConcurrentIdempotentCreateConvergesToOneCredentialSet(t *testing.T) {
	t.Parallel()
	ctx, store, db := testStore(t)
	keyring := testEnvelopeKeyring(t)
	store.keyring = keyring
	request := validRequest("", TokenEndpointAuthNone)
	digest, err := effectiveCreateDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	build := func(registration Registration) ([]byte, error) {
		return registrationResponseBody("https://id.example.test", registration, true)
	}
	start := make(chan struct{})
	results := make(chan idempotentRegistration, 4)
	errors := make(chan error, 4)
	for range 4 {
		go func() {
			<-start
			result, err := NewStore(db, Config{Keyring: keyring}).CreateIdempotent(ctx, request, "barrier-key", testGlobalToken, digest, build)
			results <- result
			errors <- err
		}()
	}
	close(start)
	var first []byte
	for range 4 {
		result := <-results
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = result.response
		} else if !bytes.Equal(first, result.response) {
			t.Fatal("concurrent responses diverged")
		}
	}
	clients, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM dynamic_oauth_clients`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(clients.Rows) != 1 || clients.Rows[0][0] != int64(1) {
		t.Fatalf("dynamic clients=%#v err=%v", clients.Rows, err)
	}
}

func TestExpiredIdempotencyEntryCanBeReused(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testStore(t)
	store.keyring = testEnvelopeKeyring(t)
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }
	request := validRequest("", TokenEndpointAuthNone)
	digest, err := effectiveCreateDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	build := func(registration Registration) ([]byte, error) {
		return registrationResponseBody("https://id.example.test", registration, true)
	}
	first, err := store.CreateIdempotent(ctx, request, "expired-key", testGlobalToken, digest, build)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return base.Add(idempotencyTTL) }
	second, err := store.CreateIdempotent(ctx, request, "expired-key", testGlobalToken, digest, build)
	if err != nil || second.replay || second.registration.ClientID == first.registration.ClientID {
		t.Fatalf("expired entry replay=%v first=%q second=%q err=%v", second.replay, first.registration.ClientID, second.registration.ClientID, err)
	}
}

func TestExpiredIdempotencyReuseSurvivesCleanupBacklog(t *testing.T) {
	t.Parallel()
	ctx, store, db := testStore(t)
	store.keyring = testEnvelopeKeyring(t)
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }
	request := validRequest("", TokenEndpointAuthNone)
	digest, err := effectiveCreateDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	key := "backlog-private"
	seedExpiredIdempotencyBacklog(t, ctx, db, digestString(testGlobalToken), digestString(key), base)
	if _, err := store.CreateIdempotent(ctx, request, key, testGlobalToken, digest, func(registration Registration) ([]byte, error) {
		return registrationResponseBody("https://id.example.test", registration, true)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAnonymousExpiredIdempotencyReuseSurvivesCleanupBacklog(t *testing.T) {
	t.Parallel()
	ctx, store, db := testStore(t)
	store.keyring = testEnvelopeKeyring(t)
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }
	request := validRequest("", TokenEndpointAuthNone)
	digest, err := effectiveCreateDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	key, ip := "backlog-anonymous", netip.MustParseAddr("192.0.2.11")
	seedExpiredIdempotencyBacklog(t, ctx, db, digestString("anonymous/"+ip.String()), digestString(key), base)
	if _, err := store.CreateAnonymousIdempotent(ctx, request, key, ip, digest, time.Minute, func(registration Registration) ([]byte, error) {
		return registrationResponseBody("https://id.example.test", registration, true)
	}); err != nil {
		t.Fatal(err)
	}
}

func seedExpiredIdempotencyBacklog(t *testing.T, ctx context.Context, db *rhiza.DB, principalDigest, keyDigest string, expires time.Time) {
	t.Helper()
	statements := make([]rhiza.SQLStatement, 0, 66)
	for i := range 65 {
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO dcr_registration_idempotency (principal_digest,key_digest,request_digest,client_id,response_envelope,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: []any{digestString("backlog-principal-" + string(rune(i))), digestString("backlog-key-" + string(rune(i))), digestString("backlog-request-" + string(rune(i))), "backlog", "x", expires.Add(-time.Millisecond).UnixMilli(), expires.Add(-time.Minute).UnixMilli()}})
	}
	statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO dcr_registration_idempotency (principal_digest,key_digest,request_digest,client_id,response_envelope,expires_at_unix_ms,created_at_unix_ms) VALUES (?,?,?,?,?,?,?)`, Args: []any{principalDigest, keyDigest, digestString("target-request"), "target", "x", expires.UnixMilli(), expires.Add(-time.Minute).UnixMilli()}})
	for i := 0; i < len(statements); i += 64 {
		end := i + 64
		if end > len(statements) {
			end = len(statements)
		}
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "seed-expired-dcr-idempotency/" + keyDigest[:14] + string(rune('a'+i/64)), Statements: statements[i:end]}); err != nil {
			t.Fatal(err)
		}
	}
}
