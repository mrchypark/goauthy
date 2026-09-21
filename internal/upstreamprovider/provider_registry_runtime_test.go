package upstreamprovider

import (
	"errors"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func runtimeFixture(t *testing.T) *mutationFixture {
	t.Helper()
	f := newMutationFixture(t)
	// Principal with Create+Update+Delete so runtime tests that
	// delete and recreate providers are authorized.
	_, delToken, err := f.keys.Create(f.ctx, nil, apikey.Request{
		Name:   "runtime-full",
		Access: []apikey.Access{{Group: authProvidersGroup, AccessRights: []apikey.Right{apikey.Create, apikey.Update, apikey.Delete}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	delP, err := f.keys.Authenticate(f.ctx, "API-Key "+delToken)
	if err != nil {
		t.Fatal(err)
	}
	f.principal = &delP
	return f
}

func readRuntimeVersion(t *testing.T, db *rhiza.DB, id string) string {
	t.Helper()
	result, err := db.Query(t.Context(), rhiza.QueryRequest{
		SQL:         "SELECT version FROM auth_provider_runtime_versions WHERE provider_id=?",
		Args:        []any{id},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("read version %s: rows=%d err=%v", id, len(result.Rows), err)
	}
	ver, ok := result.Rows[0][0].(string)
	if !ok || ver == "" {
		t.Fatalf("version %s: %v", id, result.Rows[0][0])
	}
	return ver
}

func seedProviderWithVersion(t *testing.T, f *mutationFixture, id string) {
	t.Helper()
	req := validProviderMutationRequest()
	req.ClientSecret = nil
	if _, err := f.store.CreateAuthorized(f.ctx, id, f.newRequestID("seed-"+id), req, f.keys, f.principal); err != nil {
		t.Fatal(err)
	}
}

func hasRuntimeVersion(t *testing.T, db *rhiza.DB, id string) bool {
	t.Helper()
	result, err := db.Query(t.Context(), rhiza.QueryRequest{
		SQL:         "SELECT 1 FROM auth_provider_runtime_versions WHERE provider_id=?",
		Args:        []any{id},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		t.Fatal(err)
	}
	return len(result.Rows) > 0
}

func TestRuntimeVersionOnCreate(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	req := validProviderMutationRequest()
	req.ClientSecret = nil

	doc, err := f.store.CreateAuthorized(f.ctx, "rt-create", f.newRequestID("create"), req, f.keys, f.principal)
	if err != nil {
		t.Fatal(err)
	}
	if doc.ID != "rt-create" {
		t.Fatalf("ID = %q", doc.ID)
	}
	ver := readRuntimeVersion(t, f.db, "rt-create")
	if ver == "" {
		t.Fatal("version is empty")
	}
	gotDoc, gotVer, err := f.store.GetRuntime(f.ctx, "rt-create")
	if err != nil {
		t.Fatalf("GetRuntime: %v", err)
	}
	if gotDoc.ID != doc.ID || gotVer != ver {
		t.Fatalf("GetRuntime: id=%q ver=%q want id=%q ver=%q", gotDoc.ID, gotVer, doc.ID, ver)
	}
}

func TestRuntimeVersionAlwaysNewOnUpdate(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	seedProviderWithVersion(t, f, "rt-upd")
	v1 := readRuntimeVersion(t, f.db, "rt-upd")

	req := validProviderMutationRequest()
	req.ClientSecret = nil
	if _, err := f.store.UpdateAuthorized(f.ctx, "rt-upd", f.newRequestID("update"), req, f.keys, f.principal); err != nil {
		t.Fatal(err)
	}
	v2 := readRuntimeVersion(t, f.db, "rt-upd")
	if v2 == v1 {
		t.Fatalf("version did not change: %q", v2)
	}
}

func TestRuntimeVersionAlwaysNewOnNoopUpdate(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	seedProviderWithVersion(t, f, "rt-noop")
	v1 := readRuntimeVersion(t, f.db, "rt-noop")

	req := validProviderMutationRequest()
	req.Name = "seed-rt-noop"
	req.ClientSecret = nil
	if _, err := f.store.UpdateAuthorized(f.ctx, "rt-noop", f.newRequestID("noop"), req, f.keys, f.principal); err != nil {
		t.Fatal(err)
	}
	v2 := readRuntimeVersion(t, f.db, "rt-noop")
	if v2 == v1 {
		t.Fatalf("noop version did not change: %q", v2)
	}
}

func TestRuntimeVersionAlwaysNewOnDisableEnable(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	seedProviderWithVersion(t, f, "rt-de")
	v1 := readRuntimeVersion(t, f.db, "rt-de")

	disableReq := validProviderMutationRequest()
	disableReq.Enabled = false
	disableReq.ClientSecret = nil
	if _, err := f.store.UpdateAuthorized(f.ctx, "rt-de", f.newRequestID("disable"), disableReq, f.keys, f.principal); err != nil {
		t.Fatal(err)
	}
	v2 := readRuntimeVersion(t, f.db, "rt-de")
	if v2 == v1 {
		t.Fatalf("disable version did not change: %q", v2)
	}

	enableReq := validProviderMutationRequest()
	enableReq.ClientSecret = nil
	if _, err := f.store.UpdateAuthorized(f.ctx, "rt-de", f.newRequestID("enable"), enableReq, f.keys, f.principal); err != nil {
		t.Fatal(err)
	}
	v3 := readRuntimeVersion(t, f.db, "rt-de")
	if v3 == v2 {
		t.Fatalf("enable version did not change: %q", v3)
	}
	if v3 == v1 {
		t.Fatalf("enable resurrected old version: %q", v3)
	}
}

func TestRuntimeVersionNewOnDeleteRecreate(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	seedProviderWithVersion(t, f, "rt-dr")
	v1 := readRuntimeVersion(t, f.db, "rt-dr")

	if err := f.store.DeleteAuthorized(f.ctx, "rt-dr", f.newRequestID("delete"), f.keys, f.principal); err != nil {
		t.Fatal(err)
	}
	if hasRuntimeVersion(t, f.db, "rt-dr") {
		t.Fatal("version still exists after delete")
	}

	req := validProviderMutationRequest()
	req.ClientSecret = nil
	if _, err := f.store.CreateAuthorized(f.ctx, "rt-dr", f.newRequestID("recreate"), req, f.keys, f.principal); err != nil {
		t.Fatal(err)
	}
	v2 := readRuntimeVersion(t, f.db, "rt-dr")
	if v2 == v1 {
		t.Fatalf("recreate resurrected old version: %q", v2)
	}
}

func TestRuntimeVersionNotChangedOnFailedCreate(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	seedProviderWithVersion(t, f, "rt-fc")
	v1 := readRuntimeVersion(t, f.db, "rt-fc")

	req := validProviderMutationRequest()
	req.ClientSecret = nil
	_, err := f.store.CreateAuthorized(f.ctx, "rt-fc", f.newRequestID("dup-create"), req, f.keys, f.principal)
	if !errors.Is(err, ErrProviderExists) {
		t.Fatalf("dup create: err=%v", err)
	}
	v2 := readRuntimeVersion(t, f.db, "rt-fc")
	if v2 != v1 {
		t.Fatalf("failed create changed version: %q -> %q", v1, v2)
	}
}

func TestRuntimeVersionNotChangedOnFailedUpdate(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	req := validProviderMutationRequest()
	req.ClientSecret = nil
	_, err := f.store.UpdateAuthorized(f.ctx, "rt-missing", f.newRequestID("miss-upd"), req, f.keys, f.principal)
	if !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("miss update: err=%v", err)
	}
	if hasRuntimeVersion(t, f.db, "rt-missing") {
		t.Fatal("version row created for missing provider")
	}
}

func TestRuntimeVersionNotChangedOnRevokedKey(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	seedProviderWithVersion(t, f, "rt-rk")
	v1 := readRuntimeVersion(t, f.db, "rt-rk")

	req := validProviderMutationRequest()
	req.ClientSecret = nil
	requestID := f.newRequestID("create-revoked")

	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "revoke-key-rt",
		SQL:       "UPDATE api_keys SET secret_digest=? WHERE name=?",
		Args:      []any{strings.Repeat("Z", 43), f.principal.Name},
	}); err != nil {
		t.Fatal(err)
	}
	_, err := f.store.UpdateAuthorized(f.ctx, "rt-rk", requestID, req, f.keys, f.principal)
	if !errors.Is(err, apikey.ErrForbidden) {
		t.Fatalf("revoked create: err=%v", err)
	}
	v2 := readRuntimeVersion(t, f.db, "rt-rk")
	if v2 != v1 {
		t.Fatalf("revoked key changed version: %q -> %q", v1, v2)
	}
}

func TestGetRuntimeDisabledProviderFailsClosed(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	seedProviderWithVersion(t, f, "rt-dis")

	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "disable-rt-dis",
		SQL:       "UPDATE auth_providers SET enabled=0 WHERE id=?",
		Args:      []any{"rt-dis"},
	}); err != nil {
		t.Fatal(err)
	}
	_, _, err := f.store.GetRuntime(f.ctx, "rt-dis")
	if !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("disabled GetRuntime: err=%v, want ErrProviderNotFound", err)
	}
}

func TestGetRuntimeMissingProviderFailsClosed(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	_, _, err := f.store.GetRuntime(f.ctx, "rt-noexist")
	if !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("missing GetRuntime: err=%v, want ErrProviderNotFound", err)
	}
}

func TestGetRuntimeMissingVersionFailsClosed(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	req := validProviderMutationRequest()
	req.ClientSecret = nil
	if _, err := f.store.CreateAuthorized(f.ctx, "rt-nover", f.newRequestID("create-nover"), req, f.keys, f.principal); err != nil {
		t.Fatal(err)
	}
	// Delete just the version row to simulate missing runtime metadata.
	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "del-ver-rt-nover",
		SQL:       "DELETE FROM auth_provider_runtime_versions WHERE provider_id=?",
		Args:      []any{"rt-nover"},
	}); err != nil {
		t.Fatal(err)
	}
	_, _, err := f.store.GetRuntime(f.ctx, "rt-nover")
	if !errors.Is(err, ErrVersionMissing) {
		t.Fatalf("missing version GetRuntime: err=%v, want ErrVersionMissing", err)
	}
}

func TestRuntimeVersionNotModifiedByRewrap(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	secret := "rewrap-secret"
	req := validProviderMutationRequest()
	req.ClientSecret = &secret
	if _, err := f.store.CreateAuthorized(f.ctx, "rt-rw", f.newRequestID("create-rw"), req, f.keys, f.principal); err != nil {
		t.Fatal(err)
	}
	v1 := readRuntimeVersion(t, f.db, "rt-rw")

	_, err := RewrapAuthProviderSecretBatch(f.ctx, f.db, f.keyring, "")
	if err != nil {
		t.Fatal(err)
	}
	v2 := readRuntimeVersion(t, f.db, "rt-rw")
	if v2 != v1 {
		t.Fatalf("rewrap changed version: %q -> %q", v1, v2)
	}
}

func TestRuntimeVersionAtomicUnauthorized(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	seedProviderWithVersion(t, f, "rt-unauth")
	v1 := readRuntimeVersion(t, f.db, "rt-unauth")

	_, unauthToken, err := f.keys.Create(f.ctx, nil, apikey.Request{
		Name:   "unauth-rt",
		Access: []apikey.Access{{Group: "Users", AccessRights: []apikey.Right{apikey.Read}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	unauthP, err := f.keys.Authenticate(f.ctx, "API-Key "+unauthToken)
	if err != nil {
		t.Fatal(err)
	}
	req := validProviderMutationRequest()
	req.ClientSecret = nil
	_, err = f.store.UpdateAuthorized(f.ctx, "rt-unauth", f.newRequestID("unauth-upd"), req, f.keys, &unauthP)
	if !errors.Is(err, apikey.ErrForbidden) {
		t.Fatalf("unauth update: err=%v", err)
	}
	v2 := readRuntimeVersion(t, f.db, "rt-unauth")
	if v2 != v1 {
		t.Fatalf("unauth changed version: %q -> %q", v1, v2)
	}
}

func TestUpdateAuthorizedMissingTargetNoVersionRow(t *testing.T) {
	t.Parallel()
	f := runtimeFixture(t)
	req := validProviderMutationRequest()
	req.ClientSecret = nil
	_, err := f.store.UpdateAuthorized(f.ctx, "rt-noexist-update", f.newRequestID("miss-upd"), req, f.keys, f.principal)
	if !errors.Is(err, ErrProviderNotFound) {
		f.t.Fatalf("missing update: err=%v", err)
	}
	if hasRuntimeVersion(t, f.db, "rt-noexist-update") {
		f.t.Fatal("version row created for non-existent provider update")
	}
}
