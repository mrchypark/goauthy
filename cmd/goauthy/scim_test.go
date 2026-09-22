package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/scim"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestLoadSCIMProvidersStrictAndSafe(t *testing.T) {
	t.Parallel()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("bearer-secret\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "providers.json")
	document := map[string]any{"providers": []any{map[string]any{
		"id": "primary", "base_url": "https://scim.example.test/v2", "token_file": tokenPath,
	}}}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	providers, err := loadSCIMProviders(configPath)
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := providers["primary"]
	if !ok || provider.baseURL != "https://scim.example.test/v2" || provider.token != "bearer-secret" || provider.rootCAs != nil || provider.syncDeleteUsers {
		t.Fatalf("provider=%#v", provider)
	}

	for name, raw := range map[string]string{
		"unknown field":     `{"providers":[{"id":"p","base_url":"https://scim.example.test","token_file":"x","unexpected":true}]}`,
		"duplicate field":   `{"providers":[{"id":"p","base_url":"https://scim.example.test","base_url":"https://other.example.test","token_file":"x"}]}`,
		"second document":   `{"providers":[]}{"providers":[]}`,
		"http":              `{"providers":[{"id":"p","base_url":"http://scim.example.test","token_file":"x"}]}`,
		"escaped base path": `{"providers":[{"id":"p","base_url":"https://scim.example.test/%2Fv2","token_file":"x"}]}`,
		"delete policy":     `{"providers":[{"id":"p","base_url":"https://scim.example.test","token_file":"x","delete_policy":"unlink"}]}`,
		"invalid id":        `{"providers":[{"id":"P","base_url":"https://scim.example.test","token_file":"x"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "providers.json")
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadSCIMProviders(path); err == nil {
				t.Fatal("accepted invalid SCIM configuration")
			}
		})
	}
}

const testSCIMCAPEM = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----
`

func TestLoadSCIMRootCAsStrictAndSafe(t *testing.T) {
	t.Parallel()
	if pool, err := loadSCIMRootCAs(""); err != nil || pool != nil {
		t.Fatalf("omitted CA file: pool=%v err=%v", pool, err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte(testSCIMCAPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := loadSCIMRootCAs(path)
	if err != nil || len(pool.Subjects()) != 1 {
		t.Fatalf("valid CA: pool=%v err=%v", pool, err)
	}
	for name, contents := range map[string][]byte{
		"empty":         nil,
		"malformed":     []byte("-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n"),
		"non-PEM":       []byte("not a PEM certificate"),
		"trailing data": []byte(testSCIMCAPEM + "not PEM"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadSCIMRootCAs(path); err == nil {
				t.Fatal("accepted invalid CA file")
			}
		})
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{'a'}, maxSCIMCAFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSCIMRootCAs(path); err == nil {
		t.Fatal("accepted oversized CA file")
	}
	if err := os.WriteFile(path, []byte(testSCIMCAPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSCIMRootCAs(path); err == nil {
		t.Fatal("accepted CA file readable by other users")
	}
	if _, err := loadSCIMRootCAs(filepath.Dir(path)); err == nil {
		t.Fatal("accepted CA directory")
	}
}

func TestLoadSCIMProvidersLoadsOptionalCAFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	caPath := filepath.Join(dir, "ca.pem")
	configPath := filepath.Join(dir, "providers.json")
	for path, data := range map[string][]byte{tokenPath: []byte("token"), caPath: []byte(testSCIMCAPEM)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	data, err := json.Marshal(map[string]any{"providers": []any{map[string]any{
		"id": "primary", "base_url": "https://scim.example.test", "token_file": tokenPath, "ca_file": caPath,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	providers, err := loadSCIMProviders(configPath)
	if err != nil || providers["primary"].rootCAs == nil || len(providers["primary"].rootCAs.Subjects()) != 1 {
		t.Fatalf("providers=%#v err=%v", providers, err)
	}
}

func TestDecodeSCIMProviderSyncDeleteUsersIsStrict(t *testing.T) {
	t.Parallel()
	base := `"id":"primary","base_url":"https://scim.example.test/v2","token_file":"token"`
	for name, raw := range map[string]string{
		"default": `{` + base + `}`,
		"true":    `{` + base + `,"sync_delete_users":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			provider, err := decodeSCIMProvider([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			if provider.SyncDeleteUsers != (name == "true") {
				t.Fatalf("SyncDeleteUsers=%v", provider.SyncDeleteUsers)
			}
		})
	}
	if _, err := decodeSCIMProvider([]byte(`{` + base + `,"sync_delete_users":"true"}`)); err == nil {
		t.Fatal("accepted non-boolean sync_delete_users")
	}
}

func TestSCIMRuntimeFromEnvUnsetIsDisabled(t *testing.T) {
	t.Parallel()
	runtime, err := scimRuntimeFromEnv(func(string) string { return "" }, nil, nil, nil)
	if err != nil || runtime != nil {
		t.Fatalf("runtime=%v err=%v", runtime, err)
	}
}

func TestLoadSCIMTokenTrimsExactlyOneLineEndingAndRejectsUnsafeValues(t *testing.T) {
	t.Parallel()
	for name, input := range map[string][]byte{
		"lf":        []byte("token\n"),
		"crlf":      []byte("token\r\n"),
		"double lf": []byte("token\n\n"),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(path, input, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := loadSCIMToken(path)
			if name == "double lf" {
				if err == nil {
					t.Fatal("accepted token with two trailing line endings")
				}
				return
			}
			if err != nil || got != "token" {
				t.Fatalf("token=%q err=%v", got, err)
			}
		})
	}
	for name, input := range map[string][]byte{
		"empty":   nil,
		"space":   []byte("token "),
		"control": []byte("token\x01"),
		"nul":     []byte("token\x00"),
		"invalid": []byte{0xff},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(path, input, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadSCIMToken(path); err == nil {
				t.Fatal("accepted unsafe SCIM token")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'a'}, maxSCIMTokenFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSCIMToken(path); err == nil {
		t.Fatal("accepted oversized SCIM token")
	}
	if err := os.WriteFile(path, []byte("token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSCIMToken(path); err == nil {
		t.Fatal("accepted token file readable by other users")
	}
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	if got, err := loadSCIMToken(path); err != nil || got != "token" {
		t.Fatalf("rejected operator/group-readable token: token=%q err=%v", got, err)
	}
	if _, err := loadSCIMToken(filepath.Dir(path)); err == nil {
		t.Fatal("accepted token directory")
	}
}

func TestSCIMRuntimeStepScansEveryProviderAndDrainsBoundedJobs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "cmd-scim-test", DataDir: migratedDataDir(t, "cmd-scim-test")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		subject, username string
	}{
		{"subject-a", "alice"},
		{"subject-b", "bob"},
	} {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
			RequestID: "cmd-scim-seed-" + row.subject,
			Statements: []rhiza.SQLStatement{
				{SQL: `INSERT INTO identity_users (subject,username,password_phc,disabled,password_changed_at_unix_ms,password_generation) VALUES (?,?,?,0,0,1)`, Args: []any{row.subject, row.username, "phc"}},
				{SQL: `INSERT INTO identity_authentication_modes (subject,mode,generation,updated_at_unix_ms) VALUES (?,'password',1,0)`, Args: []any{row.subject}},
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
	var reconciled []string
	outbox := scim.NewOutbox(db, func(_ context.Context, id string) (scim.Reconciler, error) {
		return reconcilerFunc(func(_ context.Context, request scim.Request) (scim.Result, error) {
			reconciled = append(reconciled, id+":"+request.User.ExternalID)
			return scim.Result{Action: scim.ActionCreated}, nil
		}), nil
	}, scim.OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{7}, 256))})
	runtime := &scimRuntime{identities: store, outbox: outbox, providers: map[string]configuredSCIMProvider{"a": {}, "b": {}}, providerIDs: []string{"a", "b"}, drainLimit: 3}
	now := time.UnixMilli(50_000)
	if err := runtime.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(reconciled) != 3 {
		t.Fatalf("reconciled=%v", reconciled)
	}
	if err := runtime.Step(ctx, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(reconciled) != 4 {
		t.Fatalf("repeated scan starved pending jobs: reconciled=%v", reconciled)
	}
	for _, providerID := range runtime.providerIDs {
		for _, subject := range []string{"subject-a", "subject-b"} {
			if _, found, err := outbox.Lookup(ctx, providerID, subject); err != nil || !found {
				t.Fatalf("lookup %s/%s found=%v err=%v", providerID, subject, found, err)
			}
		}
	}
}

func TestSCIMRuntimeStepEnqueuesMappedGroupAfterUsers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "cmd-scim-group-test", DataDir: migratedDataDir(t, "cmd-scim-group-test")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "cmd-scim-group-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users (subject,username,password_phc,disabled,password_changed_at_unix_ms,password_generation) VALUES ('subject-a','alice','phc',0,0,1),('subject-b','bob','phc',0,0,1)`},
		{SQL: `INSERT INTO identity_authentication_modes (subject,mode,generation,updated_at_unix_ms) VALUES ('subject-a','password',1,0),('subject-b','password',1,0)`},
		{SQL: `INSERT INTO rbac_groups (id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) VALUES ('group-1','Engineering',NULL,1,0,0)`},
		{SQL: `INSERT INTO rbac_user_groups (subject,group_id,granted_at_unix_ms) VALUES ('subject-a','group-1',0),('subject-b','group-1',0)`},
	}}); err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(55_000)
	mappings := scim.NewUserMappingStore(db)
	if err := mappings.Put(ctx, "provider", "subject-a", "remote-b", now); err != nil {
		t.Fatal(err)
	}
	if err := mappings.Put(ctx, "provider", "subject-b", "remote-a", now); err != nil {
		t.Fatal(err)
	}
	var requests []scim.Request
	outbox := scim.NewOutbox(db, func(_ context.Context, _ string) (scim.Reconciler, error) {
		return reconcilerFunc(func(_ context.Context, request scim.Request) (scim.Result, error) {
			requests = append(requests, request)
			if request.Group.ExternalID == "" {
				remoteID := map[string]string{"subject-a": "remote-b", "subject-b": "remote-a"}[request.User.ExternalID]
				return scim.Result{Action: scim.ActionCreated, RemoteID: remoteID}, nil
			}
			return scim.Result{Action: scim.ActionCreated}, nil
		}), nil
	}, scim.OutboxConfig{Mapping: mappings, Random: bytes.NewReader(bytes.Repeat([]byte{22}, 128))})
	runtime := &scimRuntime{identities: store, outbox: outbox, mappings: mappings, providers: map[string]configuredSCIMProvider{"provider": {}}, providerIDs: []string{"provider"}, drainLimit: 3}
	if err := runtime.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 3 || requests[0].Group.ExternalID != "" || requests[1].Group.ExternalID != "" || requests[2].Group.ExternalID != "group:group-1" {
		t.Fatalf("delivery order=%#v", requests)
	}
	got := requests[2].Group.Members
	want := []scim.GroupMember{{Value: "remote-a", Display: "bob"}, {Value: "remote-b", Display: "alice"}}
	if len(got) != len(want) {
		t.Fatalf("group members=%#v want=%#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("group members[%d]=%#v want=%#v", i, got[i], want[i])
		}
	}
	job, found, err := outbox.LookupGroup(ctx, "provider", "group:group-1")
	if err != nil || !found || job.Status != "succeeded" {
		t.Fatalf("group job=%+v found=%v err=%v", job, found, err)
	}
	if job, found, err := outbox.Lookup(ctx, "provider", "group:group-1"); err != nil || !found || job.Status != "succeeded" {
		t.Fatalf("namespaced group lookup=%+v found=%v err=%v", job, found, err)
	}
}

func TestSCIMRuntimeStepUsesTombstoneIntentForDeletePolicy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "cmd-scim-tombstone-test", DataDir: migratedDataDir(t, "cmd-scim-tombstone-test")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "cmd-scim-tombstone-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users (subject,username,password_phc,disabled,password_changed_at_unix_ms,password_generation) VALUES ('subject-current','current','phc',0,0,1),('subject-deleted','deleted','phc',0,0,1),('subject-unlinked','unlinked','phc',0,0,1)`},
		{SQL: `INSERT INTO identity_authentication_modes (subject,mode,generation,updated_at_unix_ms) VALUES ('subject-current','password',1,0),('subject-deleted','password',1,0),('subject-unlinked','password',1,0)`},
	}}); err != nil {
		t.Fatal(err)
	}
	seedRuntimeTombstone(t, db, "subject-deleted", "deleted", true, 1, []identity.SCIMTombstoneProvider{{ID: "delete", DeletePolicy: scim.DeleteRemote}, {ID: "unlink", DeletePolicy: scim.DeleteRemote}})
	seedRuntimeTombstone(t, db, "subject-unlinked", "unlinked", false, 2, []identity.SCIMTombstoneProvider{{ID: "delete", DeletePolicy: scim.DeleteRemote}, {ID: "unlink", DeletePolicy: scim.UnlinkRemote}})
	var requests []struct {
		provider string
		request  scim.Request
	}
	outbox := scim.NewOutbox(db, func(_ context.Context, id string) (scim.Reconciler, error) {
		return reconcilerFunc(func(_ context.Context, request scim.Request) (scim.Result, error) {
			requests = append(requests, struct {
				provider string
				request  scim.Request
			}{id, request})
			return scim.Result{Action: scim.ActionNoop}, nil
		}), nil
	}, scim.OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{9}, 256))})
	runtime := &scimRuntime{identities: store, outbox: outbox, providers: map[string]configuredSCIMProvider{
		"delete": {deletePolicy: scim.DeleteRemote}, "unlink": {deletePolicy: scim.UnlinkRemote},
	}, providerIDs: []string{"delete", "unlink"}, drainLimit: 8}
	now := time.UnixMilli(60_000)
	if err := runtime.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 6 {
		t.Fatalf("drain ran %d requests, want 6", len(requests))
	}
	for _, want := range []struct {
		provider, subject string
		policy            scim.DeletePolicy
	}{
		{"delete", "subject-deleted", scim.DeleteRemote},
		{"unlink", "subject-deleted", scim.DeleteRemote},
		{"delete", "subject-unlinked", scim.DeleteRemote},
		{"unlink", "subject-unlinked", scim.UnlinkRemote},
	} {
		job, found, err := outbox.Lookup(ctx, want.provider, want.subject)
		if err != nil || !found || !job.Request.Delete || job.Request.DeletePolicy != want.policy {
			t.Fatalf("tombstone job %s/%s: %#v found=%v err=%v", want.provider, want.subject, job.Request, found, err)
		}
	}
	for _, got := range requests {
		if (got.request.User.ExternalID == "subject-deleted" || got.request.User.ExternalID == "subject-unlinked") && !got.request.Delete {
			t.Fatalf("tombstoned subject was recreated: %#v", got)
		}
	}
}

func TestSCIMRuntimeStepCleansTombstoneOnlyAfterEveryProviderDeleteSucceeds(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		drainLimit int
		err        error
		wantGone   bool
	}{
		{name: "all succeeded", drainLimit: 2, wantGone: true},
		{name: "retry", drainLimit: 2, err: errors.New("temporary failure")},
		{name: "dead", drainLimit: 2, err: scim.ErrProtocol},
		{name: "missing provider completion", drainLimit: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "cmd-scim-cleanup-" + strings.ReplaceAll(test.name, " ", "-"), DataDir: migratedDataDir(t, "cmd-scim-cleanup-"+strings.ReplaceAll(test.name, " ", "-"))})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			if err := storage.Migrate(ctx, db); err != nil {
				t.Fatal(err)
			}
			store, err := identity.NewStore(db)
			if err != nil {
				t.Fatal(err)
			}
			seedRuntimeTombstone(t, db, "deleted-subject", "deleted", true, 1, []identity.SCIMTombstoneProvider{{ID: "one", DeletePolicy: scim.DeleteRemote}, {ID: "two", DeletePolicy: scim.DeleteRemote}})
			outbox := scim.NewOutbox(db, func(_ context.Context, _ string) (scim.Reconciler, error) {
				return reconcilerFunc(func(_ context.Context, _ scim.Request) (scim.Result, error) {
					if test.err != nil {
						return scim.Result{}, test.err
					}
					return scim.Result{Action: scim.ActionNoop}, nil
				}), nil
			}, scim.OutboxConfig{Retention: time.Hour, RetryBase: time.Hour, Random: bytes.NewReader(bytes.Repeat([]byte{11}, 256))})
			runtime := &scimRuntime{identities: store, outbox: outbox, providers: map[string]configuredSCIMProvider{
				"one": {}, "two": {},
			}, providerIDs: []string{"one", "two"}, drainLimit: test.drainLimit}
			now := time.UnixMilli(70_000)
			if err := runtime.Step(ctx, now); err != nil {
				t.Fatal(err)
			}
			deleted, err := store.ListSCIMDeletedUsers(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if gotGone := len(deleted) == 0; gotGone != test.wantGone {
				t.Fatalf("tombstone removed=%v, remaining=%#v, want removed=%v", gotGone, deleted, test.wantGone)
			}
			if !test.wantGone {
				return
			}
			for _, providerID := range runtime.providerIDs {
				job, found, err := outbox.Lookup(ctx, providerID, "deleted-subject")
				if err != nil || !found || job.Status != "succeeded" {
					t.Fatalf("completed delete %s: job=%#v found=%v err=%v", providerID, job, found, err)
				}
			}
			if err := runtime.Step(ctx, now.Add(outbox.Retention)); err != nil {
				t.Fatal(err)
			}
			for _, providerID := range runtime.providerIDs {
				if _, found, err := outbox.Lookup(ctx, providerID, "deleted-subject"); err != nil || found {
					t.Fatalf("retained delete %s: found=%v err=%v", providerID, found, err)
				}
			}
		})
	}
}

func TestSCIMRuntimeStepPreservesTerminalDeletesForLiveTombstoneAndCleansOtherWork(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "cmd-scim-outbox-cleanup", DataDir: migratedDataDir(t, "cmd-scim-outbox-cleanup")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "cmd-scim-outbox-cleanup-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users (subject,username,password_phc,disabled,password_changed_at_unix_ms,password_generation) VALUES ('live-subject','live','phc',0,0,1)`},
		{SQL: `INSERT INTO identity_authentication_modes (subject,mode,generation,updated_at_unix_ms) VALUES ('live-subject','password',1,0)`},
	}}); err != nil {
		t.Fatal(err)
	}
	seedRuntimeTombstone(t, db, "deleted-subject", "deleted", true, 1, []identity.SCIMTombstoneProvider{{ID: "provider", DeletePolicy: scim.DeleteRemote}})
	outbox := scim.NewOutbox(db, func(_ context.Context, _ string) (scim.Reconciler, error) {
		return reconcilerFunc(func(_ context.Context, request scim.Request) (scim.Result, error) {
			if request.Delete {
				return scim.Result{}, scim.ErrProtocol
			}
			return scim.Result{Action: scim.ActionNoop}, nil
		}), nil
	}, scim.OutboxConfig{Retention: time.Hour, Random: bytes.NewReader(bytes.Repeat([]byte{12}, 256))})
	runtime := &scimRuntime{identities: store, outbox: outbox, providers: map[string]configuredSCIMProvider{"provider": {}}, providerIDs: []string{"provider"}, drainLimit: 2}
	now := time.UnixMilli(80_000)
	if err := runtime.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, found, err := outbox.Lookup(ctx, "provider", "deleted-subject"); err != nil || !found {
		t.Fatalf("terminal delete found=%v err=%v", found, err)
	}
	if _, found, err := outbox.Lookup(ctx, "provider", "live-subject"); err != nil || !found {
		t.Fatalf("terminal non-delete found=%v err=%v", found, err)
	}
	if err := runtime.Step(ctx, now.Add(outbox.Retention)); err != nil {
		t.Fatal(err)
	}
	if deleted, err := store.ListSCIMDeletedUsers(ctx); err != nil || len(deleted) != 1 {
		t.Fatalf("tombstones=%#v err=%v", deleted, err)
	}
	if _, found, err := outbox.Lookup(ctx, "provider", "deleted-subject"); err != nil || !found {
		t.Fatalf("protected delete found=%v err=%v", found, err)
	}
	if _, found, err := outbox.Lookup(ctx, "provider", "live-subject"); err != nil || found {
		t.Fatalf("non-delete cleanup found=%v err=%v", found, err)
	}
}

func TestSCIMRuntimeStepUsesCapturedTombstoneProviders(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "cmd-scim-snapshot", DataDir: migratedDataDir(t, "cmd-scim-snapshot")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedRuntimeTombstone(t, db, "deleted", "deleted", false, 1, []identity.SCIMTombstoneProvider{
		{ID: "old", DeletePolicy: scim.UnlinkRemote},
		{ID: "removed", DeletePolicy: scim.DeleteRemote},
	})
	outbox := scim.NewOutbox(db, func(_ context.Context, _ string) (scim.Reconciler, error) {
		return reconcilerFunc(func(_ context.Context, _ scim.Request) (scim.Result, error) {
			return scim.Result{Action: scim.ActionNoop}, nil
		}), nil
	}, scim.OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{13}, 256))})
	runtime := &scimRuntime{identities: store, outbox: outbox, providers: map[string]configuredSCIMProvider{
		"old": {deletePolicy: scim.DeleteRemote}, "new": {deletePolicy: scim.DeleteRemote},
	}, providerIDs: []string{"new", "old"}, drainLimit: 4}
	now := time.UnixMilli(90_000)
	if err := runtime.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	old, found, err := outbox.Lookup(ctx, "old", "deleted")
	if err != nil || !found || old.Request.DeletePolicy != scim.UnlinkRemote {
		t.Fatalf("captured old delete=%#v found=%v err=%v", old.Request, found, err)
	}
	if _, found, err := outbox.Lookup(ctx, "new", "deleted"); err != nil || found {
		t.Fatalf("new provider received historical delete: found=%v err=%v", found, err)
	}
	if deleted, err := store.ListSCIMDeletedUsers(ctx); err != nil || len(deleted) != 1 {
		t.Fatalf("removed provider obligation was lost: %#v err=%v", deleted, err)
	}
	runtime.providers["removed"] = configuredSCIMProvider{deletePolicy: scim.UnlinkRemote}
	runtime.providerIDs = []string{"old", "removed"}
	if err := runtime.Step(ctx, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	removed, found, err := outbox.Lookup(ctx, "removed", "deleted")
	if err != nil || !found || removed.Request.DeletePolicy != scim.DeleteRemote {
		t.Fatalf("re-added provider did not resume captured obligation: %#v found=%v err=%v", removed.Request, found, err)
	}
	if deleted, err := store.ListSCIMDeletedUsers(ctx); err != nil || len(deleted) != 0 {
		t.Fatalf("completed captured obligations did not clean tombstone: %#v err=%v", deleted, err)
	}
}

func TestSCIMRuntimeStepRejectsMalformedHardDeleteSnapshot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "cmd-scim-invalid-hard-delete", DataDir: migratedDataDir(t, "cmd-scim-invalid-hard-delete")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedRuntimeTombstone(t, db, "deleted", "deleted", true, 1, []identity.SCIMTombstoneProvider{{ID: "provider", DeletePolicy: scim.UnlinkRemote}})
	outbox := scim.NewOutbox(db, func(_ context.Context, _ string) (scim.Reconciler, error) {
		return nil, errors.New("reconciler must not be requested")
	}, scim.OutboxConfig{})
	runtime := &scimRuntime{identities: store, outbox: outbox, providers: map[string]configuredSCIMProvider{"provider": {}}, providerIDs: []string{"provider"}, drainLimit: 1}
	if err := runtime.Step(ctx, time.UnixMilli(91_000)); err == nil {
		t.Fatal("accepted malformed hard-delete snapshot")
	}
	if _, found, err := outbox.Lookup(ctx, "provider", "deleted"); err != nil || found {
		t.Fatalf("malformed hard-delete snapshot enqueued work: found=%v err=%v", found, err)
	}
	if deleted, err := store.ListSCIMDeletedUsers(ctx); err != nil || len(deleted) != 1 {
		t.Fatalf("malformed hard-delete snapshot was cleaned: %#v err=%v", deleted, err)
	}
}

func TestSCIMRuntimeStepRejectsHardDeleteWithoutProviderSnapshot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "cmd-scim-empty-hard-delete", DataDir: migratedDataDir(t, "cmd-scim-empty-hard-delete")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedRuntimeTombstone(t, db, "deleted", "deleted", true, 1, nil)
	outbox := scim.NewOutbox(db, func(_ context.Context, _ string) (scim.Reconciler, error) {
		return nil, errors.New("reconciler must not be requested")
	}, scim.OutboxConfig{})
	runtime := &scimRuntime{identities: store, outbox: outbox, providers: map[string]configuredSCIMProvider{"provider": {}}, providerIDs: []string{"provider"}, drainLimit: 1}
	if err := runtime.Step(ctx, time.UnixMilli(91_100)); err == nil {
		t.Fatal("accepted hard-delete snapshot without providers")
	}
	if _, found, err := outbox.Lookup(ctx, "provider", "deleted"); err != nil || found {
		t.Fatalf("empty hard-delete snapshot enqueued work: found=%v err=%v", found, err)
	}
	if deleted, err := store.ListSCIMDeletedUsers(ctx); err != nil || len(deleted) != 1 {
		t.Fatalf("empty hard-delete snapshot was cleaned: %#v err=%v", deleted, err)
	}
}

func TestSCIMRuntimeStepRejectsStaleTombstoneGeneration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "cmd-scim-stale-tombstone", DataDir: migratedDataDir(t, "cmd-scim-stale-tombstone")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	provider := []identity.SCIMTombstoneProvider{{ID: "provider", DeletePolicy: scim.DeleteRemote}}
	seedRuntimeTombstoneWithGeneration(t, db, "deleted", "deleted", false, 1, "AAAAAAAAAAAAAAAAAAAAAA", provider)
	outbox := scim.NewOutbox(db, func(_ context.Context, _ string) (scim.Reconciler, error) {
		return nil, errors.New("stale delete must not be reconciled")
	}, scim.OutboxConfig{})
	runtime := &scimRuntime{identities: store, outbox: outbox, providers: map[string]configuredSCIMProvider{"provider": {}}, providerIDs: []string{"provider"}, drainLimit: 1}
	runtime.beforeTombstoneEnqueue = func() {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "cmd-scim-remove-stale", Statements: []rhiza.SQLStatement{
			{SQL: `DELETE FROM scim_user_tombstone_providers WHERE local_external_id='deleted'`},
			{SQL: `DELETE FROM scim_user_tombstones WHERE local_external_id='deleted'`},
		}}); err != nil {
			t.Fatal(err)
		}
		seedRuntimeTombstoneWithGeneration(t, db, "deleted", "replacement", false, 2, "BBBBBBBBBBBBBBBBBBBBBB", provider)
	}
	if err := runtime.Step(ctx, time.UnixMilli(92_000)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := outbox.Lookup(ctx, "provider", "deleted"); err != nil || found {
		t.Fatalf("stale tombstone delete admitted: found=%v err=%v", found, err)
	}
}

func TestSCIMRuntimeStepSkipsEmptyGenerationTombstoneAndProcessesLiveWork(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "cmd-scim-empty-generation", DataDir: migratedDataDir(t, "cmd-scim-empty-generation")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	seedRuntimeTombstoneWithGeneration(t, db, "legacy", "legacy", false, 1, "", []identity.SCIMTombstoneProvider{{ID: "provider", DeletePolicy: scim.DeleteRemote}})
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "cmd-scim-empty-generation-live", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users (subject,username,password_phc,disabled,password_changed_at_unix_ms,password_generation) VALUES ('live','live','phc',0,0,1)`},
		{SQL: `INSERT INTO identity_authentication_modes (subject,mode,generation,updated_at_unix_ms) VALUES ('live','password',1,0)`},
	}}); err != nil {
		t.Fatal(err)
	}
	outbox := scim.NewOutbox(db, func(_ context.Context, _ string) (scim.Reconciler, error) {
		return reconcilerFunc(func(_ context.Context, request scim.Request) (scim.Result, error) {
			if request.User.ExternalID != "live" || request.Delete {
				t.Fatalf("unexpected request: %#v", request)
			}
			return scim.Result{Action: scim.ActionNoop}, nil
		}), nil
	}, scim.OutboxConfig{})
	runtime := &scimRuntime{identities: store, outbox: outbox, providers: map[string]configuredSCIMProvider{"provider": {}}, providerIDs: []string{"provider"}, drainLimit: 2}
	if err := runtime.Step(ctx, time.UnixMilli(93_000)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := outbox.Lookup(ctx, "provider", "live"); err != nil || !found {
		t.Fatalf("live work was not processed: found=%v err=%v", found, err)
	}
	if _, found, err := outbox.Lookup(ctx, "provider", "legacy"); err != nil || found {
		t.Fatalf("empty-generation tombstone was enqueued: found=%v err=%v", found, err)
	}
	if deleted, err := store.ListSCIMDeletedUsers(ctx); err != nil || len(deleted) != 1 || deleted[0].Generation != "" {
		t.Fatalf("empty-generation tombstone was not retained: %#v err=%v", deleted, err)
	}
}

func seedRuntimeTombstone(t *testing.T, db *rhiza.DB, externalID, userName string, hardDelete bool, deletedAt int64, providers []identity.SCIMTombstoneProvider) {
	seedRuntimeTombstoneWithGeneration(t, db, externalID, userName, hardDelete, deletedAt, "AAAAAAAAAAAAAAAAAAAAAA", providers)
}

func seedRuntimeTombstoneWithGeneration(t *testing.T, db *rhiza.DB, externalID, userName string, hardDelete bool, deletedAt int64, generation string, providers []identity.SCIMTombstoneProvider) {
	t.Helper()
	hard := int64(0)
	if hardDelete {
		hard = 1
	}
	statements := []rhiza.SQLStatement{{SQL: `INSERT INTO scim_user_tombstones (local_external_id,user_name,active,hard_delete,provider_snapshot_complete,generation,deleted_at_unix_ms) VALUES (?,?,1,?,1,?,?)`, Args: []any{externalID, userName, hard, generation, deletedAt}}}
	for _, provider := range providers {
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO scim_user_tombstone_providers (local_external_id,client_id,delete_policy) VALUES (?,?,?)`, Args: []any{externalID, provider.ID, int64(provider.DeletePolicy)}})
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "cmd-scim-tombstone-" + externalID + "-" + generation, Statements: statements}); err != nil {
		t.Fatal(err)
	}
}

// TestSCIMRuntimeStepClaimsEachJobWithItsOwnLeaseTime covers a long pass that
// reused one captured timestamp across up to drainLimit deliveries: later
// claims then received a lease that had already expired, so another replica
// could take over work this process was still delivering.
func TestSCIMRuntimeStepClaimsEachJobWithItsOwnLeaseTime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "cmd-scim-fresh-claim", DataDir: migratedDataDir(t, "cmd-scim-fresh-claim")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "cmd-scim-fresh-claim-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users (subject,username,password_phc,disabled,password_changed_at_unix_ms,password_generation) VALUES ('subject-a','alice','phc',0,0,1),('subject-b','bob','phc',0,0,1)`},
		{SQL: `INSERT INTO identity_authentication_modes (subject,mode,generation,updated_at_unix_ms) VALUES ('subject-a','password',1,0),('subject-b','password',1,0)`},
	}}); err != nil {
		t.Fatal(err)
	}
	var leases []int64
	outbox := scim.NewOutbox(db, func(_ context.Context, id string) (scim.Reconciler, error) {
		return reconcilerFunc(func(deliveryCtx context.Context, _ scim.Request) (scim.Result, error) {
			result, err := db.Query(deliveryCtx, rhiza.QueryRequest{SQL: `SELECT lease_until_unix_ms FROM scim_user_outbox WHERE client_id=? AND status='processing'`, Args: []any{id}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
				t.Fatalf("lease lookup rows=%#v err=%v", result.Rows, err)
			}
			lease, ok := result.Rows[0][0].(int64)
			if !ok {
				t.Fatalf("lease value=%#v", result.Rows[0][0])
			}
			leases = append(leases, lease)
			return scim.Result{Action: scim.ActionNoop}, nil
		}), nil
	}, scim.OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{31}, 512))})
	runtime := &scimRuntime{identities: store, outbox: outbox, providers: map[string]configuredSCIMProvider{"provider": {}}, providerIDs: []string{"provider"}, drainLimit: 2}
	started := time.UnixMilli(1_700_000_000_000)
	readings := 0
	// Every claim runs after the earlier external requests consumed time.
	runtime.now = func() time.Time {
		readings++
		return started.Add(time.Duration(readings) * 90 * time.Second)
	}
	if err := runtime.Step(ctx, started); err != nil {
		t.Fatal(err)
	}
	if readings != 2 || len(leases) != 2 {
		t.Fatalf("claim readings=%d leases=%v", readings, leases)
	}
	for i := range leases {
		if want := started.Add(time.Duration(i+1) * 90 * time.Second).Add(time.Minute).UnixMilli(); leases[i] != want {
			t.Fatalf("lease[%d]=%d want=%d: the claim reused a stale timestamp", i, leases[i], want)
		}
	}
}

// TestSCIMRuntimeStepOversizedGroupDoesNotStallUnrelatedWork covers one mapped
// group above the supported projection size stalling delivery of every other
// provider's queued deletion: the failure must be recorded durably and the
// drain must still run, before and after a restart.
func TestSCIMRuntimeStepOversizedGroupDoesNotStallUnrelatedWork(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "cmd-scim-oversized-group", DataDir: migratedDataDir(t, "cmd-scim-oversized-group")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	// The projection limit is 4096 members, and every member of a projected
	// group must resolve to a remote user id first.
	const oversizedMembers = 4097
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "cmd-scim-oversized-group-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO rbac_groups (id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) VALUES ('group-big','Big',NULL,1,0,0)`},
		{SQL: `WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<?) INSERT INTO rbac_user_groups (subject,group_id,granted_at_unix_ms) SELECT 'member-'||n,'group-big',0 FROM seq`, Args: []any{int64(oversizedMembers + 1)}},
		{SQL: `WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<?) INSERT INTO scim_user_mappings (client_id,local_external_id,remote_user_id,updated_at_unix_ms) SELECT 'grouped','member-'||n,'remote-'||n,0 FROM seq`, Args: []any{int64(oversizedMembers + 1)}},
	}}); err != nil {
		t.Fatal(err)
	}
	seedRuntimeTombstone(t, db, "subject-gone", "gone", false, 1, []identity.SCIMTombstoneProvider{{ID: "cleanup", DeletePolicy: scim.DeleteRemote}})
	deliveries := 0
	outbox := scim.NewOutbox(db, func(_ context.Context, id string) (scim.Reconciler, error) {
		return reconcilerFunc(func(_ context.Context, request scim.Request) (scim.Result, error) {
			if request.Group.ExternalID != "" {
				t.Fatalf("provider %s received the oversized group: %+v", id, request)
			}
			deliveries++
			return scim.Result{Action: scim.ActionNoop}, nil
		}), nil
	}, scim.OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{41}, 1024))})
	providers := map[string]configuredSCIMProvider{"grouped": {}, "cleanup": {}}
	mappings := scim.NewUserMappingStore(db)
	runtime := &scimRuntime{identities: store, outbox: outbox, mappings: mappings, providers: providers, providerIDs: []string{"grouped", "cleanup"}, drainLimit: 4}
	if err := runtime.Step(ctx, time.UnixMilli(100_000)); err != nil {
		t.Fatalf("oversized group stopped the pass: %v", err)
	}
	job, found, err := outbox.Lookup(ctx, "cleanup", "subject-gone")
	if err != nil || !found || job.Status != "succeeded" || !job.Request.Delete || deliveries != 1 {
		t.Fatalf("unrelated delete job=%+v found=%v deliveries=%d err=%v", job, found, deliveries, err)
	}
	if _, found, err := outbox.LookupGroup(ctx, "grouped", "group:group-big"); err != nil || found {
		t.Fatalf("oversized group queued work found=%v err=%v", found, err)
	}
	assertSCIMProjectionFailureEvent(t, db, `grouped / GroupCreateUpdate("group:group-big")`)
	// Neither a restart nor newly queued work may be stalled by the group that
	// fails on every pass, and its durable record must not be duplicated.
	seedRuntimeTombstone(t, db, "subject-later", "later", false, 2, []identity.SCIMTombstoneProvider{{ID: "cleanup", DeletePolicy: scim.DeleteRemote}})
	restarted := &scimRuntime{identities: store, outbox: outbox, mappings: mappings, providers: providers, providerIDs: []string{"grouped", "cleanup"}, drainLimit: 4}
	if err := restarted.Step(ctx, time.UnixMilli(200_000)); err != nil {
		t.Fatalf("oversized group stopped the restarted pass: %v", err)
	}
	if job, found, err := outbox.Lookup(ctx, "cleanup", "subject-later"); err != nil || !found || job.Status != "succeeded" || deliveries != 2 {
		t.Fatalf("post-restart delete job=%+v found=%v deliveries=%d err=%v", job, found, deliveries, err)
	}
	assertSCIMProjectionFailureEvent(t, db, `grouped / GroupCreateUpdate("group:group-big")`)
}

func assertSCIMProjectionFailureEvent(t *testing.T, db *rhiza.DB, wantPrefix string) {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT text FROM event_log WHERE typ=?`, Args: []any{string(eventlog.ScimTaskFailed)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("failure events=%#v err=%v", result.Rows, err)
	}
	text, ok := result.Rows[0][0].(string)
	if !ok || !strings.HasPrefix(text, wantPrefix) || !strings.Contains(text, "exceeds the supported projection size") {
		t.Fatalf("failure event text=%#v", result.Rows[0][0])
	}
}

type reconcilerFunc func(context.Context, scim.Request) (scim.Result, error)

func (f reconcilerFunc) Reconcile(ctx context.Context, request scim.Request) (scim.Result, error) {
	return f(ctx, request)
}

func TestSCIMRuntimeRunStopsDeterministicallyOnCancellation(t *testing.T) {
	t.Parallel()
	runtime := &scimRuntime{}
	if err := runtime.Run(context.Background(), time.Second, time.Now, nil); err == nil {
		t.Fatal("accepted unconfigured SCIM runtime")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	validRuntime := &scimRuntime{identities: &identity.Store{}, outbox: &scim.Outbox{}, providerIDs: []string{"provider"}, drainLimit: 1}
	errorsSeen := 0
	if err := validRuntime.Run(ctx, time.Hour, func() time.Time { return time.UnixMilli(1) }, func(err error) {
		if err == nil {
			t.Fatal("scheduler callback received nil error")
		}
		errorsSeen++
		cancel()
	}); err != nil {
		t.Fatal(err)
	}
	if errorsSeen != 1 {
		t.Fatalf("errorsSeen=%d", errorsSeen)
	}
}
