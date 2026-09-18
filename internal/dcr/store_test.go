package dcr

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

func TestCreateConfidentialNeverPersistsPlaintextCredentials(t *testing.T) {
	ctx, store, db := testStore(t)
	registration, err := store.Create(ctx, validRequest("confidential-client", TokenEndpointAuthClientBasic))
	if err != nil {
		t.Fatal(err)
	}
	if registration.ClientSecret == "" || registration.RegistrationAccessToken == "" {
		t.Fatal("confidential registration did not return one-time credentials")
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT secret_hash, registration_token_digest FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{registration.ClientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		t.Fatalf("credentials row=%#v err=%v", result.Rows, err)
	}
	secretHash, ok := result.Rows[0][0].(string)
	if !ok || secretHash == registration.ClientSecret || !strings.HasPrefix(secretHash, "$2") {
		t.Fatalf("secret was not stored as bcrypt hash: %q", secretHash)
	}
	if strings.Contains(secretHash, registration.ClientSecret) {
		t.Fatal("plaintext client secret leaked into hash column")
	}
	digest, ok := result.Rows[0][1].(string)
	if !ok || len(digest) != 43 || strings.Contains(digest, registration.RegistrationAccessToken) {
		t.Fatalf("registration token was not stored as a SHA-256 digest: %#v", result.Rows[0][1])
	}
	loaded, err := store.GetRegistration(ctx, registration.ClientID, registration.RegistrationAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ClientSecret != "" || loaded.RegistrationAccessToken != "" {
		t.Fatal("recoverable registration returned raw credentials")
	}
	if _, err := store.GetRegistration(ctx, registration.ClientID, "wrong"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong registration token err=%v", err)
	}
}

func TestCreatePublicAndConfidentialClients(t *testing.T) {
	ctx, store, _ := testStore(t)
	public, err := store.Create(ctx, validRequest("public-client", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	if public.ClientSecret != "" {
		t.Fatal("public client received a secret")
	}
	publicClient, err := store.GetClient(ctx, public.ClientID)
	if err != nil || !publicClient.IsPublic() || len(publicClient.GetHashedSecret()) != 0 {
		t.Fatalf("public client=%#v err=%v", publicClient, err)
	}
	confidential, err := store.Create(ctx, validRequest("post-client", TokenEndpointAuthClientPost))
	if err != nil {
		t.Fatal(err)
	}
	client, err := store.GetClient(ctx, confidential.ClientID)
	if err != nil || client.IsPublic() || len(client.GetHashedSecret()) == 0 {
		t.Fatalf("confidential client=%#v err=%v", client, err)
	}
	if err := bcryptCompare(client.GetHashedSecret(), confidential.ClientSecret); err != nil {
		t.Fatalf("stored hash does not authenticate returned secret: %v", err)
	}
}

func TestAuthenticateUsesOneSnapshotAcrossTokenRotation(t *testing.T) {
	ctx, store, db := testStore(t)
	created, err := store.Create(ctx, validRequest("snapshot-auth", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	var rotated Registration
	var interposeErr error
	store.afterRegistrationSnapshot = func() {
		store.afterRegistrationSnapshot = nil
		rotated, interposeErr = NewStore(db).Update(ctx, created.ClientID, created.RegistrationAccessToken, validRequest(created.ClientID, TokenEndpointAuthNone))
	}
	defer func() { store.afterRegistrationSnapshot = nil }()

	got, err := store.GetRegistration(ctx, created.ClientID, created.RegistrationAccessToken)
	if interposeErr != nil {
		t.Fatalf("interposed rotation: %v", interposeErr)
	}
	if err != nil || got.Name != created.Name {
		t.Fatalf("snapshot authentication registration=%#v err=%v", got, err)
	}
	if _, err := store.GetRegistration(ctx, created.ClientID, created.RegistrationAccessToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old token remained valid after interposed rotation: %v", err)
	}
	if _, err := store.GetRegistration(ctx, created.ClientID, rotated.RegistrationAccessToken); err != nil {
		t.Fatalf("rotated token was not persisted: %v", err)
	}
}

func TestLoadRejectsMalformedPersistedCredentialInvariant(t *testing.T) {
	for _, test := range []struct {
		name   string
		method string
		value  any
	}{
		{name: "public with hash", method: TokenEndpointAuthNone, value: "not-public"},
		{name: "confidential without hash", method: TokenEndpointAuthClientBasic, value: nil},
		{name: "confidential malformed hash", method: TokenEndpointAuthClientPost, value: "not-bcrypt"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, store, db := malformedCredentialStore(t, test.method, test.value)
			clientID, token := "malformed-client", "registration-token"
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
				RequestID: "dcr-malformed-secret-" + strings.ReplaceAll(test.name, " ", "-"),
				SQL: `INSERT INTO dynamic_oauth_clients
					(client_id,secret_hash,registration_token_digest,redirect_uris_json,scopes_json,default_scopes_json,grant_types_json,response_types_json,audiences_json,token_endpoint_auth_method,name,force_mfa,created_at_unix_ms,last_used_at_unix_ms,client_uri,contacts_json,logo_uri,tos_uri,policy_uri,anonymous)
					VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL,0)`,
				Args: []any{clientID, test.value, digestString(token), `["https://rp.example.test/callback"]`, `["openid"]`, `[]`, `["authorization_code"]`, `["code"]`, `[]`, test.method, "Example RP", int64(0), int64(1_700_000_000_000)},
			}); err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.load(ctx, clientID); err == nil {
				t.Fatal("malformed persisted credential invariant was accepted")
			}
			if _, err := store.GetRegistration(ctx, clientID, token); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("malformed row auth err=%v", err)
			}
		})
	}
}

func malformedCredentialStore(t *testing.T, method string, secretHash any) (context.Context, *Store, *rhiza.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "dcr-malformed-" + method, DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "dcr-malformed-schema", SQL: `CREATE TABLE dynamic_oauth_clients (
		client_id TEXT PRIMARY KEY NOT NULL,
		secret_hash TEXT,
		registration_token_digest TEXT NOT NULL UNIQUE,
		redirect_uris_json TEXT NOT NULL,
		scopes_json TEXT NOT NULL,
		default_scopes_json TEXT NOT NULL,
		grant_types_json TEXT NOT NULL,
		response_types_json TEXT NOT NULL,
		audiences_json TEXT NOT NULL,
		token_endpoint_auth_method TEXT NOT NULL,
		name TEXT NOT NULL,
		force_mfa INTEGER NOT NULL,
		created_at_unix_ms INTEGER NOT NULL,
		last_used_at_unix_ms INTEGER,
		client_uri TEXT,
		contacts_json TEXT,
		logo_uri TEXT,
		tos_uri TEXT,
		policy_uri TEXT,
		anonymous INTEGER NOT NULL
	) STRICT`}); err != nil {
		t.Fatal(err)
	}
	return ctx, NewStore(db), db
}

func TestCreateDeviceOnlyClientPersistsDeviceGrantWithoutRedirects(t *testing.T) {
	ctx, store, _ := testStore(t)
	request := validRequest("device-only-client", TokenEndpointAuthNone)
	request.RedirectURIs = nil
	request.ResponseTypes = nil
	request.GrantTypes = []string{deviceGrantType}
	registration, err := store.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	client, err := store.GetClient(ctx, registration.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.GetRegistration(ctx, registration.ClientID, registration.RegistrationAccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.RedirectURIs) != 0 || len(loaded.ResponseTypes) != 0 || !client.IsPublic() || len(client.GetRedirectURIs()) != 0 || !client.GetGrantTypes().Has(deviceGrantType) {
		t.Fatalf("stored device registration=%+v client public=%t redirects=%v grants=%v", loaded, client.IsPublic(), client.GetRedirectURIs(), client.GetGrantTypes())
	}
}

func TestCreatePersistsCanonicalContactsAndLoadsThem(t *testing.T) {
	ctx, store, db := testStore(t)
	request := validRequest("contacts-client", TokenEndpointAuthNone)
	request.Contacts = []string{"support@example.test", "mailto:z@example.test"}
	request.LogoURI = "https://rp.example.test/logo.svg"
	request.TOSURI = "https://rp.example.test/terms"
	request.PolicyURI = "https://rp.example.test/privacy"
	created, err := store.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT contacts_json, logo_uri, tos_uri, policy_uri FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{created.ClientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 4 || rows.Rows[0][0] != `["mailto:z@example.test","support@example.test"]` || rows.Rows[0][1] != request.LogoURI || rows.Rows[0][2] != request.TOSURI || rows.Rows[0][3] != request.PolicyURI {
		t.Fatalf("stored metadata=%#v err=%v", rows.Rows, err)
	}
	loaded, err := store.GetRegistration(ctx, created.ClientID, created.RegistrationAccessToken)
	if err != nil || len(loaded.Contacts) != 2 || loaded.Contacts[0] != "mailto:z@example.test" || loaded.Contacts[1] != "support@example.test" {
		t.Fatalf("loaded contacts=%v err=%v", loaded.Contacts, err)
	}
}

func TestScopePolicyRejectsInvalidDefaults(t *testing.T) {
	if _, err := NewScopePolicy([]string{"openid"}, []string{"profile"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-subset default err=%v", err)
	}
	if _, err := NewScopePolicy([]string{"openid", "openid"}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate allowed err=%v", err)
	}
}

func TestRegistrationJSONPersistsEmptyDefaultsAsJSONArray(t *testing.T) {
	_, _, defaults, _, _, _, err := registrationJSON(Registration{})
	if err != nil || defaults != "[]" {
		t.Fatalf("defaults=%q err=%v", defaults, err)
	}
}

func TestCreatePersistsDefaultScopesAndUpdatePreservesPolicy(t *testing.T) {
	ctx, store, _ := testStore(t)
	request := validRequest("scope-policy", TokenEndpointAuthNone)
	request.Scopes = []string{"openid", "tenant"}
	request.DefaultScopes = []string{"openid"}
	created, err := store.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	request.Scopes = []string{"openid"}
	request.DefaultScopes = nil
	updated, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(updated.Scopes, " ") != "openid tenant" || strings.Join(updated.DefaultScopes, " ") != "openid" {
		t.Fatalf("updated policy allowed=%v default=%v", updated.Scopes, updated.DefaultScopes)
	}
	defaults, err := store.DefaultScopes(ctx, created.ClientID)
	if err != nil || strings.Join(defaults, " ") != "openid" {
		t.Fatalf("defaults=%v err=%v", defaults, err)
	}
}

func TestDynamicStoreForceMFAIsAlwaysFalse(t *testing.T) {
	ctx, store, _ := testStore(t)
	request := validRequest("force-mfa", TokenEndpointAuthClientBasic)
	request.ForceMFA = true
	created, err := store.Create(ctx, request)
	if err != nil || created.ForceMFA {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	if force, err := store.ForceMFA(ctx, created.ClientID); err != nil || force {
		t.Fatalf("force=%v err=%v", force, err)
	}
	loaded, err := store.GetRegistration(ctx, created.ClientID, created.RegistrationAccessToken)
	if err != nil || loaded.ForceMFA {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
	updated, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, request)
	if err != nil || updated.ForceMFA {
		t.Fatalf("updated=%#v err=%v", updated, err)
	}
	if force, err := store.ForceMFA(ctx, created.ClientID); err != nil || force {
		t.Fatalf("force=%v err=%v", force, err)
	}
	if _, err := store.ForceMFA(ctx, "missing"); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("missing force MFA err=%v", err)
	}
}

func TestCreateDuplicateAndCrossStoreRead(t *testing.T) {
	ctx, store, db := testStore(t)
	request := validRequest("shared-client", TokenEndpointAuthClientBasic)
	registration, err := store.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, request); !errors.Is(err, ErrClientExists) {
		t.Fatalf("duplicate Create err=%v", err)
	}
	other := NewStore(db)
	client, err := other.GetClient(ctx, registration.ClientID)
	if err != nil || client.GetID() != registration.ClientID {
		t.Fatalf("cross-store GetClient client=%#v err=%v", client, err)
	}
	if _, err := other.GetClient(ctx, "missing"); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("missing client err=%v", err)
	}
	if _, err := other.GetRegistration(ctx, registration.ClientID, registration.RegistrationAccessToken); err != nil {
		t.Fatal(err)
	}
}

func TestCreateRejectsReservedClientIDBeforePersistence(t *testing.T) {
	ctx, _, db := testStore(t)
	store := NewStore(db, Config{ReservedClientIDs: []string{"bootstrap-client"}})
	if _, err := store.Create(ctx, validRequest("bootstrap-client", TokenEndpointAuthClientBasic)); !errors.Is(err, ErrReservedClientID) {
		t.Fatalf("reserved Create err=%v", err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT client_id FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{"bootstrap-client"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 0 {
		t.Fatalf("reserved row=%#v err=%v", rows.Rows, err)
	}
	created, err := store.Create(ctx, validRequest("neighbor-client", TokenEndpointAuthNone))
	if err != nil || created.ClientID != "neighbor-client" {
		t.Fatalf("neighbor registration=%#v err=%v", created, err)
	}
}

func TestConcurrentCreateRejectsReservedClientIDWithoutArtifacts(t *testing.T) {
	ctx, _, db := testStore(t)
	store := NewStore(db, Config{ReservedClientIDs: []string{"bootstrap-client"}})
	errs := make(chan error, 2)
	var start sync.WaitGroup
	start.Add(1)
	for range 2 {
		go func() {
			start.Wait()
			_, err := store.Create(ctx, validRequest("bootstrap-client", TokenEndpointAuthClientBasic))
			errs <- err
		}()
	}
	start.Done()
	for range 2 {
		if err := <-errs; !errors.Is(err, ErrReservedClientID) {
			t.Fatalf("reserved concurrent Create err=%v", err)
		}
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT client_id FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{"bootstrap-client"}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 0 {
		t.Fatalf("reserved concurrent row=%#v err=%v", rows.Rows, err)
	}
}

func TestCreateFailsClosedOnInvalidInvariant(t *testing.T) {
	ctx, store, _ := testStore(t)
	request := validRequest("invalid", TokenEndpointAuthClientBasic)
	request.RedirectURIs = []string{"http://rp.example.test/callback"}
	if _, err := store.Create(ctx, request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("HTTP redirect err=%v", err)
	}
	request = validRequest("invalid", TokenEndpointAuthClientBasic)
	request.ResponseTypes = nil
	if _, err := store.Create(ctx, request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing code response type err=%v", err)
	}
}

func TestDeleteRegistrationRemovesOnlyAuthenticatedClient(t *testing.T) {
	ctx, store, _ := testStore(t)
	created, err := store.Create(ctx, validRequest("delete-client", TokenEndpointAuthClientBasic))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteRegistration(ctx, created.ClientID, created.RegistrationAccessToken); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteRegistration(ctx, created.ClientID, created.RegistrationAccessToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replayed delete err=%v", err)
	}
	if _, err := store.GetRegistration(ctx, created.ClientID, created.RegistrationAccessToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("deleted registration err=%v", err)
	}
	if _, err := store.GetClient(ctx, created.ClientID); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("deleted client err=%v", err)
	}
}

func TestDeleteRegistrationRejectsWrongOrUnknownTokenWithoutMutation(t *testing.T) {
	ctx, store, _ := testStore(t)
	created, err := store.Create(ctx, validRequest("delete-deny", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []struct{ clientID, token string }{
		{created.ClientID, "wrong"},
		{"missing-client", created.RegistrationAccessToken},
		{"bad/client", created.RegistrationAccessToken},
		{created.ClientID, ""},
	} {
		if err := store.DeleteRegistration(ctx, attempt.clientID, attempt.token); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("DeleteRegistration(%q, token) err=%v", attempt.clientID, err)
		}
		if _, err := store.GetRegistration(ctx, created.ClientID, created.RegistrationAccessToken); err != nil {
			t.Fatalf("rejected delete changed registration: %v", err)
		}
	}
}

func TestDeleteRegistrationRejectsStaleTokenAfterRotation(t *testing.T) {
	ctx, store, _ := testStore(t)
	created, err := store.Create(ctx, validRequest("delete-stale", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, validRequest(created.ClientID, TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteRegistration(ctx, created.ClientID, created.RegistrationAccessToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("stale delete err=%v", err)
	}
	if _, err := store.GetRegistration(ctx, created.ClientID, updated.RegistrationAccessToken); err != nil {
		t.Fatalf("stale delete changed rotated registration: %v", err)
	}
}

func TestDeleteRegistrationAndUpdateHaveExactlyOneWinner(t *testing.T) {
	ctx, store, _ := testStore(t)
	created, err := store.Create(ctx, validRequest("delete-update-race", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	update := validRequest(created.ClientID, TokenEndpointAuthNone)
	update.Name = "Updated before delete"
	start := make(chan struct{})
	type updateOutcome struct {
		registration Registration
		err          error
	}
	updates := make(chan updateOutcome, 1)
	deletes := make(chan error, 1)
	go func() {
		<-start
		registration, err := NewStore(store.db).Update(ctx, created.ClientID, created.RegistrationAccessToken, update)
		updates <- updateOutcome{registration, err}
	}()
	go func() {
		<-start
		deletes <- NewStore(store.db).DeleteRegistration(ctx, created.ClientID, created.RegistrationAccessToken)
	}()
	close(start)
	updated := <-updates
	deleted := <-deletes
	updateWon, deleteWon := updated.err == nil, deleted == nil
	if updateWon == deleteWon {
		t.Fatalf("update err=%v delete err=%v", updated.err, deleted)
	}
	if deleteWon {
		if _, err := store.GetClient(ctx, created.ClientID); !errors.Is(err, fosite.ErrNotFound) {
			t.Fatalf("delete winner resurrected client: %v", err)
		}
		return
	}
	if !errors.Is(deleted, ErrUnauthorized) {
		t.Fatalf("losing delete err=%v", deleted)
	}
	if _, err := store.GetRegistration(ctx, created.ClientID, updated.registration.RegistrationAccessToken); err != nil {
		t.Fatalf("update winner was deleted: %v", err)
	}
}

func TestUpdateRotatesConfidentialCredentialsAcrossStores(t *testing.T) {
	ctx, store, db := testStore(t)
	created, err := store.Create(ctx, validRequest("update-client", TokenEndpointAuthClientBasic))
	if err != nil {
		t.Fatal(err)
	}
	before, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT secret_hash, registration_token_digest, created_at_unix_ms FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{created.ClientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(before.Rows) != 1 {
		t.Fatalf("before=%#v err=%v", before.Rows, err)
	}
	request := validRequest(created.ClientID, TokenEndpointAuthClientBasic)
	request.RedirectURIs = []string{"https://new-rp.example.test/callback"}
	request.Scopes = []string{"openid"}
	request.GrantTypes = []string{"authorization_code"}
	request.ResponseTypes = []string{"code"}
	request.Audiences = nil
	request.Name = "Updated RP"
	updated, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, request)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ClientSecret == "" || updated.ClientSecret == created.ClientSecret || updated.RegistrationAccessToken == "" || updated.RegistrationAccessToken == created.RegistrationAccessToken || updated.Name != request.Name || updated.CreatedAt != created.CreatedAt {
		t.Fatalf("updated registration=%#v", updated)
	}
	after, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT secret_hash, registration_token_digest, created_at_unix_ms FROM dynamic_oauth_clients WHERE client_id = ?`, Args: []any{created.ClientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(after.Rows) != 1 || len(after.Rows[0]) != 3 {
		t.Fatalf("after=%#v err=%v", after.Rows, err)
	}
	if before.Rows[0][0] == after.Rows[0][0] || before.Rows[0][1] == after.Rows[0][1] || before.Rows[0][2] != after.Rows[0][2] {
		t.Fatalf("credentials were not rotated or creation changed: before=%#v after=%#v", before.Rows, after.Rows)
	}
	other := NewStore(db)
	if _, err := other.GetRegistration(ctx, created.ClientID, created.RegistrationAccessToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old registration token err=%v", err)
	}
	if _, err := other.GetRegistration(ctx, created.ClientID, updated.RegistrationAccessToken); err != nil {
		t.Fatalf("new registration token err=%v", err)
	}
	client, err := other.GetClient(ctx, created.ClientID)
	if err != nil || client.GetRedirectURIs()[0] != request.RedirectURIs[0] || client.GetScopes()[0] != "openid" {
		t.Fatalf("updated client=%#v err=%v", client, err)
	}
	if err := bcryptCompare(client.GetHashedSecret(), created.ClientSecret); err == nil {
		t.Fatal("old client secret remained valid")
	}
	if err := bcryptCompare(client.GetHashedSecret(), updated.ClientSecret); err != nil {
		t.Fatalf("new client secret is invalid: %v", err)
	}
}

func TestUpdateRotatesOnlyRegistrationTokenForPublicClient(t *testing.T) {
	ctx, store, db := testStore(t)
	created, err := store.Create(ctx, validRequest("public-update", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	updated, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, validRequest(created.ClientID, TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	if updated.ClientSecret != "" || updated.RegistrationAccessToken == "" || updated.RegistrationAccessToken == created.RegistrationAccessToken {
		t.Fatalf("public update=%#v", updated)
	}
	other := NewStore(db)
	if _, err := other.GetRegistration(ctx, created.ClientID, created.RegistrationAccessToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old public token err=%v", err)
	}
	client, err := other.GetClient(ctx, created.ClientID)
	if err != nil || !client.IsPublic() || len(client.GetHashedSecret()) != 0 {
		t.Fatalf("public client=%#v err=%v", client, err)
	}
}

func TestUpdateRejectsWrongTokenAndAuthenticationMethodChange(t *testing.T) {
	ctx, store, _ := testStore(t)
	created, err := store.Create(ctx, validRequest("update-deny", TokenEndpointAuthClientBasic))
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest(created.ClientID, TokenEndpointAuthClientBasic)
	request.Name = "Not Applied"
	if _, err := store.Update(ctx, created.ClientID, "wrong", request); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong registration token err=%v", err)
	}
	request.TokenEndpointAuthMethod = TokenEndpointAuthNone
	if _, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("authentication method change err=%v", err)
	}
	request = validRequest("other-client", TokenEndpointAuthClientBasic)
	if _, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("client ID change err=%v", err)
	}
	loaded, err := store.GetRegistration(ctx, created.ClientID, created.RegistrationAccessToken)
	if err != nil || loaded.Name != "Example RP" {
		t.Fatalf("rejected update changed registration=%#v err=%v", loaded, err)
	}
}

func TestUpdateMarksLastUsedAtFromStoreClock(t *testing.T) {
	ctx, store, _ := testStore(t)
	fixed := time.Date(2026, time.January, 2, 3, 4, 5, 987000000, time.FixedZone("KST", 9*60*60))
	store.now = func() time.Time { return fixed }
	created, err := store.Create(ctx, validRequest("last-used-mark", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	if created.CreatedAt.UnixMilli() != fixed.UnixMilli() || created.LastUsedAt != nil {
		t.Fatalf("created registration=%#v", created)
	}
	updated, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, validRequest(created.ClientID, TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	if updated.LastUsedAt == nil || updated.LastUsedAt.UnixMilli() != fixed.UnixMilli() {
		t.Fatalf("updated last_used_at=%v", updated.LastUsedAt)
	}
	loaded, err := store.GetRegistration(ctx, created.ClientID, updated.RegistrationAccessToken)
	if err != nil || loaded.LastUsedAt == nil || loaded.LastUsedAt.UnixMilli() != fixed.UnixMilli() {
		t.Fatalf("persisted registration=%#v err=%v", loaded, err)
	}
}

func TestFailedAndStaleUpdateDoNotTouchLastUsedAt(t *testing.T) {
	ctx, store, _ := testStore(t)
	fixed := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return fixed }
	created, err := store.Create(ctx, validRequest("last-used-deny", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(ctx, created.ClientID, "wrong", validRequest(created.ClientID, TokenEndpointAuthNone)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong token err=%v", err)
	}
	loaded, exists, err := store.load(ctx, created.ClientID)
	if err != nil || !exists || loaded.LastUsedAt != nil {
		t.Fatalf("rejected update changed registration=%#v err=%v", loaded, err)
	}

	updated, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, validRequest(created.ClientID, TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	firstUsed := updated.LastUsedAt.UnixMilli()
	store.now = func() time.Time { return fixed.Add(time.Hour) }
	if _, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, validRequest(created.ClientID, TokenEndpointAuthNone)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("stale token err=%v", err)
	}
	loaded, exists, err = store.load(ctx, created.ClientID)
	if err != nil || !exists || loaded.LastUsedAt == nil || loaded.LastUsedAt.UnixMilli() != firstUsed {
		t.Fatalf("stale update changed last_used_at registration=%#v err=%v", loaded, err)
	}
}

func TestUpdateLastUsedAtIsMonotonic(t *testing.T) {
	ctx, store, _ := testStore(t)
	late := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	early := late.Add(-time.Hour)
	store.now = func() time.Time { return late }
	created, err := store.Create(ctx, validRequest("last-used-monotonic", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, validRequest(created.ClientID, TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return early }
	second, err := store.Update(ctx, created.ClientID, first.RegistrationAccessToken, validRequest(created.ClientID, TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	if second.LastUsedAt == nil || second.LastUsedAt.UnixMilli() != late.UnixMilli() {
		t.Fatalf("returned last_used_at reg=%#v", second)
	}
	loaded, err := store.GetRegistration(ctx, created.ClientID, second.RegistrationAccessToken)
	if err != nil || loaded.LastUsedAt == nil || loaded.LastUsedAt.UnixMilli() != late.UnixMilli() {
		t.Fatalf("persisted last_used_at registration=%#v err=%v", loaded, err)
	}
}

func TestUpdateWithGeneratedClientAndEmptyAudience(t *testing.T) {
	ctx, store, _ := testStore(t)
	request := CreateRequest{RedirectURIs: []string{"https://rp.example.test/callback"}, Scopes: []string{"openid", "goauthy.read"}, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: TokenEndpointAuthClientBasic, Name: "Before Update"}
	created, err := store.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	request.RedirectURIs = []string{"https://rp.example.test/updated"}
	request.Name = "After Update"
	if _, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, request); err != nil {
		t.Fatalf("Update err=%v", err)
	}
}

func TestUpdateConcurrentChangesYieldOneWinnerAndOneConflict(t *testing.T) {
	ctx, store, _ := testStore(t)
	created, err := store.Create(ctx, validRequest("update-race", TokenEndpointAuthClientBasic))
	if err != nil {
		t.Fatal(err)
	}
	first := validRequest(created.ClientID, TokenEndpointAuthClientBasic)
	first.Name = "First winner"
	second := validRequest(created.ClientID, TokenEndpointAuthClientBasic)
	second.Name = "Second winner"
	start := make(chan struct{})
	type outcome struct {
		registration Registration
		err          error
	}
	results := make(chan outcome, 2)
	go func() {
		<-start
		registration, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, first)
		results <- outcome{registration, err}
	}()
	go func() {
		<-start
		registration, err := NewStore(store.db).Update(ctx, created.ClientID, created.RegistrationAccessToken, second)
		results <- outcome{registration, err}
	}()
	close(start)
	var winner, conflicts int
	var won Registration
	for range 2 {
		result := <-results
		if result.err == nil {
			winner++
			won = result.registration
		} else if errors.Is(result.err, ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("Update err=%v", result.err)
		}
	}
	if winner != 1 || conflicts != 1 {
		t.Fatalf("winners=%d conflicts=%d", winner, conflicts)
	}
	if _, err := store.GetRegistration(ctx, created.ClientID, created.RegistrationAccessToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old token err=%v", err)
	}
	stored, err := store.GetRegistration(ctx, created.ClientID, won.RegistrationAccessToken)
	if err != nil || (stored.Name != first.Name && stored.Name != second.Name) {
		t.Fatalf("persisted winner=%#v err=%v", stored, err)
	}
	winnerRequest := first
	if stored.Name == second.Name {
		winnerRequest = second
	}
	if replay, err := store.Update(ctx, created.ClientID, won.RegistrationAccessToken, winnerRequest); err != nil || replay.RegistrationAccessToken == won.RegistrationAccessToken {
		t.Fatalf("same desired request with rotated token replay=%#v err=%v", replay, err)
	}
}

func TestUpdateConcurrentDynamicClientsYieldExactlyOneWinner(t *testing.T) {
	ctx, store, _ := testStore(t)
	created, err := store.Create(ctx, validRequest("force-mfa-race", TokenEndpointAuthNone))
	if err != nil {
		t.Fatal(err)
	}
	first := validRequest(created.ClientID, TokenEndpointAuthNone)
	first.Name, first.ForceMFA = "First", true
	second := validRequest(created.ClientID, TokenEndpointAuthNone)
	second.Name, second.ForceMFA = "Second", true
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, request := range []CreateRequest{first, second} {
		go func(request CreateRequest) {
			<-start
			_, err := NewStore(store.db).Update(ctx, created.ClientID, created.RegistrationAccessToken, request)
			results <- err
		}(request)
	}
	close(start)
	var winners, rejected int
	for range 2 {
		switch err := <-results; {
		case err == nil:
			winners++
		case errors.Is(err, ErrConflict), errors.Is(err, ErrUnauthorized):
			rejected++
		default:
			t.Fatalf("Update err=%v", err)
		}
	}
	if winners != 1 || rejected != 1 {
		t.Fatalf("winners=%d rejected=%d", winners, rejected)
	}
	// The surviving value must agree with the winning complete replacement,
	// rather than a stale metadata mix.
	row, exists, err := store.load(ctx, created.ClientID)
	if err != nil || !exists {
		t.Fatalf("load exists=%v err=%v", exists, err)
	}
	if (row.Name != first.Name && row.Name != second.Name) || row.ForceMFA {
		t.Fatalf("stored a mixed update: %#v", row)
	}
}

func TestCreateReturnsInsertFailureWhenReconciliationFindsNoRow(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "dcr-insert-failure", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// This table deliberately models a storage-side constraint that the Store
	// cannot know in advance. The failed INSERT leaves no row to reconcile.
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "dcr-insert-failure-schema", SQL: `CREATE TABLE dynamic_oauth_clients (
		client_id TEXT PRIMARY KEY NOT NULL,
		secret_hash TEXT,
		registration_token_digest TEXT NOT NULL UNIQUE,
		redirect_uris_json TEXT NOT NULL,
		scopes_json TEXT NOT NULL,
		grant_types_json TEXT NOT NULL,
		response_types_json TEXT NOT NULL,
		audiences_json TEXT NOT NULL,
		token_endpoint_auth_method TEXT NOT NULL,
		name TEXT NOT NULL CHECK (name = 'blocked'),
		created_at_unix_ms INTEGER NOT NULL,
		last_used_at_unix_ms INTEGER
	) STRICT`}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(db).Create(ctx, validRequest("storage-reject", TokenEndpointAuthNone)); err == nil {
		t.Fatal("Create reported success after a rejected INSERT")
	}
}

func testStore(t *testing.T) (context.Context, *Store, *rhiza.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "dcr-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return ctx, NewStore(db), db
}

func validRequest(clientID, method string) CreateRequest {
	return CreateRequest{ClientID: clientID, RedirectURIs: []string{"https://rp.example.test/callback"}, Scopes: []string{"openid", "goauthy.read"}, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, Audiences: []string{"https://api.example.test"}, TokenEndpointAuthMethod: method, Name: "Example RP"}
}

func bcryptCompare(hash []byte, secret string) error {
	return bcrypt.CompareHashAndPassword(hash, []byte(secret))
}

func TestCreatePasswordClientWithoutRedirects(t *testing.T) {
	for _, method := range []string{TokenEndpointAuthNone, TokenEndpointAuthClientBasic, TokenEndpointAuthClientPost} {
		t.Run(method, func(t *testing.T) {
			ctx, store, _ := testStore(t)
			request := validRequest("password-client", method)
			request.RedirectURIs, request.ResponseTypes = nil, nil
			request.GrantTypes = []string{"password", "refresh_token"}
			created, err := store.Create(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			client, err := store.GetClient(ctx, created.ClientID)
			if err != nil {
				t.Fatal(err)
			}
			got, err := store.GetRegistration(ctx, created.ClientID, created.RegistrationAccessToken)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.RedirectURIs) != 0 || len(got.ResponseTypes) != 0 || !client.GetGrantTypes().Has("password") || !client.GetGrantTypes().Has("refresh_token") || client.IsPublic() != (method == TokenEndpointAuthNone) {
				t.Fatal("password registration did not round trip")
			}
		})
	}
}

func TestBackchannelLogoutURIRoundTripAndRotation(t *testing.T) {
	ctx, store, db := testStore(t)
	request := validRequest("backchannel-uri", TokenEndpointAuthClientBasic)
	request.BackchannelLogoutURI = "https://rp.example.test/logout"
	created, err := store.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "backchannel-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('user',?,?,0,0,1)`, Args: []any{created.ClientID, request.BackchannelLogoutURI}},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('sid',?,?,0,0,1)`, Args: []any{created.ClientID, request.BackchannelLogoutURI}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	reader := NewStore(db)
	check := func(reg Registration, want string) {
		t.Helper()
		got, err := reader.GetRegistration(ctx, reg.ClientID, reg.RegistrationAccessToken)
		if err != nil {
			t.Fatal(err)
		}
		client, err := reader.GetClient(ctx, reg.ClientID)
		if err != nil {
			t.Fatal(err)
		}
		provider, ok := client.(interface{ GetBackchannelLogoutURI() string })
		if !ok || got.BackchannelLogoutURI != want || provider.GetBackchannelLogoutURI() != want {
			t.Fatal("backchannel metadata and OAuth client disagree")
		}
		for _, table := range []string{"oidc_user_clients", "oidc_session_clients"} {
			q, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT logout_uri FROM " + table + " WHERE client_id=?", Args: []any{reg.ClientID}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != want {
				t.Fatalf("association %s did not synchronize: %v", table, err)
			}
		}
	}
	check(created, request.BackchannelLogoutURI)
	_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "backchannel-fail", SQL: `CREATE TRIGGER reject_uri_sync BEFORE UPDATE ON oidc_session_clients BEGIN SELECT RAISE(ABORT,'sync failed'); END`})
	if err != nil {
		t.Fatal(err)
	}
	request.BackchannelLogoutURI = "https://rp.example.test/rejected"
	if _, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, request); err == nil {
		t.Fatal("failed sync committed")
	}
	check(created, created.BackchannelLogoutURI)
	_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "backchannel-restore", SQL: `DROP TRIGGER reject_uri_sync`})
	if err != nil {
		t.Fatal(err)
	}

	for _, uri := range []string{"https://rp.example.test/new-logout", ""} {
		request.BackchannelLogoutURI = uri
		updated, err := store.Update(ctx, created.ClientID, created.RegistrationAccessToken, request)
		if err != nil {
			t.Fatal(err)
		}
		check(updated, uri)
		if _, err := reader.GetRegistration(ctx, created.ClientID, created.RegistrationAccessToken); err == nil {
			t.Fatal("old registration token remained valid")
		}
		created = updated
	}
}
