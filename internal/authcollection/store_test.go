package authcollection

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func collectionFixture(t *testing.T) (*Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "auth-collection-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"owner-1", "owner-2"} {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "auth-owner-" + subject, SQL: `INSERT INTO identity_users(subject,username,password_phc) VALUES(?,?,?)`, Args: []any{subject, subject, "phc"}}); err != nil {
			t.Fatal(err)
		}
	}
	return NewStore(db), ctx
}
func allow() func() (string, []any) { return func() (string, []any) { return "1", nil } }
func definition() DefinitionInput {
	return DefinitionInput{ID: "collection-1", Name: "Accounts", AuthMethod: "oauth2", Enabled: true, Fields: []Field{{Name: "label", Type: "string", Required: true, MaxLength: 32}, {Name: "kind", Type: "enum", Required: true, Options: []string{"work", "personal"}}}}
}

func TestDefinitionAndConnectionCRUDAndGuards(t *testing.T) {
	s, ctx := collectionFixture(t)
	d, err := s.CreateDefinition(ctx, definition(), allow())
	if err != nil || d.Revision != 1 {
		t.Fatalf("create definition=%+v err=%v", d, err)
	}
	meta := json.RawMessage(`{"label":"main","kind":"work"}`)
	c, err := s.CreateConnection(ctx, "owner-1", d.ID, d.Revision, meta, allow())
	if err != nil {
		t.Fatal(err)
	}
	if c.State != "draft" || c.OwnerSubject != "owner-1" {
		t.Fatalf("connection=%+v", c)
	}
	if _, err := s.GetConnection(ctx, "owner-2", d.ID, c.ID, allow()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-owner read=%v", err)
	}
	if err := s.DeleteDefinition(ctx, d.ID, d.Revision, allow()); !errors.Is(err, ErrConflict) {
		t.Fatalf("used definition delete=%v", err)
	}
	if _, err := s.UpdateConnection(ctx, "owner-1", d.ID, c.ID, c.Revision, d.Revision, json.RawMessage(`{"label":"backup","kind":"personal"}`), allow()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateConnection(ctx, "owner-1", d.ID, c.ID, c.Revision, d.Revision, meta, allow()); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale connection update=%v", err)
	}
}

func TestUpdateConnectionAcceptsGeneratedLeadingIDs(t *testing.T) {
	s, ctx := collectionFixture(t)
	d, err := s.CreateDefinition(ctx, definition(), allow())
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"_generated-id", "-generated-id"} {
		if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "leading-connection-id-" + string(rune('0'+i)), SQL: `INSERT INTO auth_collection_connections(id,collection_id,owner_subject,state,revision,definition_revision,metadata_json,generation) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{id, d.ID, "owner-1", "draft", int64(1), d.Revision, `{"label":"main","kind":"work"}`, "generation"}}); err != nil {
			t.Fatal(err)
		}
		updated, err := s.UpdateConnection(ctx, "owner-1", d.ID, id, 1, d.Revision, json.RawMessage(`{"label":"backup","kind":"personal"}`), allow())
		if err != nil {
			t.Fatal(err)
		}
		if updated.ID != id || updated.Revision != 2 {
			t.Fatalf("updated connection=%+v", updated)
		}
	}
}

func TestDefinitionValidationAndDisabledRevisionAuthority(t *testing.T) {
	s, ctx := collectionFixture(t)
	for _, f := range []Field{{Name: "password", Type: "string"}, {Name: "x", Type: "float"}, {Name: "x", Type: "string", MaxLength: 5000}} {
		in := definition()
		in.Fields = []Field{f}
		if _, err := s.CreateDefinition(ctx, in, allow()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid field %+v err=%v", f, err)
		}
	}
	d, err := s.CreateDefinition(ctx, definition(), allow())
	if err != nil {
		t.Fatal(err)
	}
	d.Enabled = false
	d, err = s.UpdateDefinition(ctx, d.ID, d.Revision, DefinitionInput{ID: d.ID, Name: d.Name, AuthMethod: d.AuthMethod, Enabled: false, Fields: d.Fields}, allow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateConnection(ctx, "owner-1", d.ID, d.Revision, json.RawMessage(`{"label":"x","kind":"work"}`), allow()); !errors.Is(err, ErrConflict) {
		t.Fatalf("disabled create=%v", err)
	}
	if _, err = s.CreateDefinition(ctx, definition(), func() (string, []any) { return "", nil }); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("nil authority=%v", err)
	}
	in := definition()
	in.ID = "collection-2"
	if _, err := s.CreateDefinition(ctx, in, allow()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateDefinition(ctx, in.ID, 1, in, func() (string, []any) { return `EXISTS(SELECT 1 WHERE 0)`, nil }); err == nil {
		t.Fatalf("commit authority loss=%v", err)
	}
	tomb, err := s.CreateDefinition(ctx, DefinitionInput{ID: "tombstone", Name: "T", AuthMethod: "api_key", Enabled: true}, allow())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDefinition(ctx, tomb.ID, tomb.Revision, allow()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateDefinition(ctx, DefinitionInput{ID: tomb.ID, Name: "T2", AuthMethod: "api_key", Enabled: true}, allow()); !errors.Is(err, ErrConflict) {
		t.Fatalf("tombstone reuse=%v", err)
	}
	badMeta := json.RawMessage(`{"label":"x","kind":"work","kind":"personal"}`)
	if _, err := s.CreateConnection(ctx, "owner-1", in.ID, 1, badMeta, allow()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate metadata=%v", err)
	}
}

func TestConnectionOwnerExpiryUsesInjectedClock(t *testing.T) {
	s, ctx := collectionFixture(t)
	base := time.UnixMilli(2_000_000_000_000).UTC()
	s.now = func() time.Time { return base }
	d, err := s.CreateDefinition(ctx, definition(), allow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "auth-expire-owner", SQL: `UPDATE identity_users SET user_expires_at_unix_ms=? WHERE subject=?`, Args: []any{base.Add(time.Second).UnixMilli(), "owner-1"}}); err != nil {
		t.Fatal(err)
	}
	c, err := s.CreateConnection(ctx, "owner-1", d.ID, d.Revision, json.RawMessage(`{"label":"x","kind":"work"}`), allow())
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return base.Add(time.Second) }
	if _, err := s.GetConnection(ctx, "owner-1", d.ID, "missing", allow()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired owner read=%v", err)
	}
	if _, err := s.GetConnection(ctx, "owner-1", d.ID, c.ID, allow()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired owner existing read=%v", err)
	}
	if _, err := s.CreateConnection(ctx, "owner-1", d.ID, d.Revision, json.RawMessage(`{"label":"y","kind":"work"}`), allow()); err == nil {
		t.Fatal("expired owner create succeeded")
	}
	if _, err := s.UpdateConnection(ctx, "owner-1", d.ID, c.ID, c.Revision, d.Revision, c.Metadata, allow()); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired owner update=%v", err)
	}
	if err := s.DeleteConnection(ctx, "owner-1", d.ID, c.ID, c.Revision, allow()); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired owner delete=%v", err)
	}
	if list, err := s.ListConnections(ctx, "owner-1", d.ID, allow()); err != nil || len(list) != 0 {
		t.Fatalf("expired owner list=%v err=%v", list, err)
	}
}

func TestDefinitionSchemaGuardSeesInterposedConnection(t *testing.T) {
	s, ctx := collectionFixture(t)
	in := definition()
	d, err := s.CreateDefinition(ctx, in, allow())
	if err != nil {
		t.Fatal(err)
	}
	in.AuthMethod = "api_key"
	var created Connection
	interpose := func() (string, []any) {
		var err error
		created, err = s.CreateConnection(ctx, "owner-1", d.ID, d.Revision, json.RawMessage(`{"label":"x","kind":"work"}`), allow())
		if err != nil {
			t.Fatal(err)
		}
		return "1", nil
	}
	if _, err := s.UpdateDefinition(ctx, d.ID, d.Revision, in, interpose); !errors.Is(err, ErrConflict) {
		t.Fatalf("schema changed after interposed connection: %v", err)
	}
	got, err := s.GetDefinition(ctx, d.ID, allow())
	if err != nil || got.AuthMethod != d.AuthMethod || got.Revision != d.Revision {
		t.Fatalf("definition=%+v err=%v", got, err)
	}
	if _, err := s.GetConnection(ctx, "owner-1", d.ID, created.ID, allow()); err != nil {
		t.Fatal(err)
	}
}

func TestMetadataIntegerAndEmptySchemaValidation(t *testing.T) {
	s, ctx := collectionFixture(t)
	empty := DefinitionInput{ID: "empty-schema", Name: "Empty", AuthMethod: "api_key", Enabled: true, Fields: nil}
	d, err := s.CreateDefinition(ctx, empty, allow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateConnection(ctx, "owner-1", d.ID, d.Revision, json.RawMessage(`{"undeclared":"x"}`), allow()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("undeclared metadata=%v", err)
	}
	for i, raw := range []string{`{"label":9223372036854775808}`, `{"label":1.5}`} {
		in := definition()
		in.ID = "integer-" + string(rune('0'+i))
		in.Fields = []Field{{Name: "label", Type: "integer"}}
		d, err := s.CreateDefinition(ctx, in, allow())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateConnection(ctx, "owner-1", d.ID, d.Revision, json.RawMessage(raw), allow()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("integer metadata %s err=%v", raw, err)
		}
	}
}

func TestAuthMethodUpdateReadbackAndRevokedAuthority(t *testing.T) {
	s, ctx := collectionFixture(t)
	d, err := s.CreateDefinition(ctx, definition(), allow())
	if err != nil {
		t.Fatal(err)
	}
	d, err = s.UpdateDefinition(ctx, d.ID, d.Revision, DefinitionInput{ID: d.ID, Name: d.Name, AuthMethod: "device_flow", Enabled: d.Enabled, Fields: d.Fields}, allow())
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDefinition(ctx, d.ID, allow())
	if err != nil || got.AuthMethod != "device_flow" {
		t.Fatalf("auth method readback=%+v err=%v", got, err)
	}
	if _, err := s.CreateDefinition(ctx, DefinitionInput{ID: "revoked", Name: "Revoked", AuthMethod: "oauth2", Enabled: true}, func() (string, []any) { return `EXISTS(SELECT 1 WHERE 0)`, nil }); err == nil {
		t.Fatal("revoked authority succeeded")
	}
}

func TestDefinitionProviderIDsCRUDAndRevision(t *testing.T) {
	s, ctx := collectionFixture(t)
	in := DefinitionInput{ID: "providers", Name: "Providers", AuthMethod: "oauth2", Enabled: true, ProviderIDs: []string{"github", "acme_1"}}
	d, err := s.CreateDefinition(ctx, in, allow())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(d.ProviderIDs, ","); got != "github,acme_1" {
		t.Fatalf("created providers=%q", got)
	}
	got, err := s.GetDefinition(ctx, d.ID, allow())
	if err != nil || strings.Join(got.ProviderIDs, ",") != "github,acme_1" {
		t.Fatalf("get=%+v err=%v", got, err)
	}
	list, err := s.ListDefinitions(ctx, allow())
	if err != nil || len(list) != 1 || len(list[0].ProviderIDs) != 2 {
		t.Fatalf("list=%+v err=%v", list, err)
	}
	if _, err := s.CreateConnection(ctx, "owner-1", d.ID, d.Revision, json.RawMessage(`{}`), allow()); err != nil {
		t.Fatalf("connection=%v", err)
	}
	in.ProviderIDs = []string{"github"}
	updated, err := s.UpdateDefinition(ctx, d.ID, d.Revision, in, allow())
	if err != nil || updated.Revision != 2 || strings.Join(updated.ProviderIDs, ",") != "github" {
		t.Fatalf("update=%+v err=%v", updated, err)
	}
	if _, err := s.UpdateDefinition(ctx, d.ID, d.Revision, in, allow()); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale provider update=%v", err)
	}
}

func TestDefinitionProviderIDsValidation(t *testing.T) {
	s, ctx := collectionFixture(t)
	for name, in := range map[string]DefinitionInput{
		"duplicate":        {ID: "dup-provider", Name: "P", AuthMethod: "oauth2", Enabled: true, ProviderIDs: []string{"github", "github"}},
		"uppercase":        {ID: "upper-provider", Name: "P", AuthMethod: "oauth2", Enabled: true, ProviderIDs: []string{"GitHub"}},
		"empty":            {ID: "empty-provider", Name: "P", AuthMethod: "oauth2", Enabled: true, ProviderIDs: []string{""}},
		"api key multiple": {ID: "api-provider", Name: "P", AuthMethod: "api_key", Enabled: true, ProviderIDs: []string{"github", "other"}},
	} {
		if _, err := s.CreateDefinition(ctx, in, allow()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s err=%v", name, err)
		}
	}
	for _, method := range []string{"oauth2", "api_key", "device_flow"} {
		in := DefinitionInput{ID: "empty-" + method, Name: "P", AuthMethod: method, Enabled: true}
		got, err := s.CreateDefinition(ctx, in, allow())
		if err != nil || got.ProviderIDs == nil {
			t.Fatalf("%s empty providers=%+v err=%v", method, got, err)
		}
	}
	if got, err := s.CreateDefinition(ctx, DefinitionInput{ID: "api-provider-one", Name: "P", AuthMethod: "api_key", Enabled: true, ProviderIDs: []string{"github"}}, allow()); err != nil || len(got.ProviderIDs) != 1 {
		t.Fatalf("api key provider=%+v err=%v", got, err)
	}
}

func TestDecodeDefinitionRejectsMalformedRows(t *testing.T) {
	valid := []any{"collection-1", "Accounts", "oauth2", int64(1), int64(1), "[]", "[]"}
	for name, row := range map[string][]any{
		"short":              valid[:6],
		"nil id":             {nil, "Accounts", "oauth2", int64(1), int64(1), "[]", "[]"},
		"wrong enabled":      {"collection-1", "Accounts", "oauth2", "true", int64(1), "[]", "[]"},
		"wrong fields":       {"collection-1", "Accounts", "oauth2", int64(1), int64(1), int64(1), "[]"},
		"wrong providers":    {"collection-1", "Accounts", "oauth2", int64(1), int64(1), "[]", int64(1)},
		"provider object":    {"collection-1", "Accounts", "oauth2", int64(1), int64(1), "[]", `{}`},
		"provider invalid":   {"collection-1", "Accounts", "oauth2", int64(1), int64(1), "[]", `["GitHub"]`},
		"provider duplicate": {"collection-1", "Accounts", "oauth2", int64(1), int64(1), "[]", `["github","github"]`},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := decodeDefinition(row); !errors.Is(err, ErrInvalid) || got.ID != "" || got.ProviderIDs != nil {
				t.Fatalf("definition=%+v err=%v", got, err)
			}
		})
	}
	got, err := decodeDefinition(valid)
	if err != nil || got.ProviderIDs == nil || got.Fields == nil {
		t.Fatalf("valid definition=%+v err=%v", got, err)
	}
}

// seedDefinitions fills the definition table to an exact row count without a
// create loop, the state an accumulated deployment reaches. deleted marks the
// seeded rows as tombstones so a capacity test does not also count them live.
func seedDefinitions(t *testing.T, ctx context.Context, s *Store, n int, deleted bool) {
	t.Helper()
	values := make([]string, n)
	args := make([]any, 0, n*9)
	d := int64(0)
	if deleted {
		d = 1
	}
	for i := 0; i < n; i++ {
		values[i] = "(?,?,?,?,?,?,?,?,?)"
		id := "seed-" + strconv.Itoa(i)
		args = append(args, id, id, "oauth2", int64(1), int64(1), "generation", "[]", "[]", d)
	}
	// The engine caps one statement at 999 bound arguments, so seed in batches.
	const perStatement = 999 / 9
	for start, batch := 0, 0; start < n; start, batch = start+perStatement, batch+1 {
		end := start + perStatement
		if end > n {
			end = n
		}
		request := rhiza.ExecuteRequest{RequestID: "auth-collection-seed-" + strconv.Itoa(n) + "-" + strconv.Itoa(batch), SQL: "INSERT INTO auth_collection_definitions(id,name,auth_method,enabled,revision,generation,fields_json,providers_json,deleted) VALUES " + strings.Join(values[start:end], ","), Args: args[start*9 : end*9]}
		if _, err := storage.Execute(ctx, s.db, request); err != nil {
			t.Fatal(err)
		}
	}
}

// Every accepted state keeps a supported enumeration path: creation stops
// exactly where the bounded list read would start failing.
func TestDefinitionCapacityKeepsListEnumerable(t *testing.T) {
	s, ctx := collectionFixture(t)
	// A full table may already exist from earlier releases, so records that
	// predate the bound must stay listable even though no new create fits.
	seedDefinitions(t, ctx, s, maxList, true)
	if _, err := s.CreateDefinition(ctx, DefinitionInput{ID: "over-capacity", Name: "N", AuthMethod: "api_key", Enabled: true}, allow()); !errors.Is(err, ErrConflict) {
		t.Fatalf("create past definition capacity=%v", err)
	}
	// The list still answers; the seeded rows are tombstones, so it is empty.
	if list, err := s.ListDefinitions(ctx, allow()); err != nil || len(list) != 0 {
		t.Fatalf("definition list at capacity=%d err=%v", len(list), err)
	}
}

// The bound is exclusive, so the accepted ceiling lists in full.
func TestDefinitionCapacityBoundIsExclusive(t *testing.T) {
	s, ctx := collectionFixture(t)
	seedDefinitions(t, ctx, s, maxList-1, false)
	if _, err := s.CreateDefinition(ctx, DefinitionInput{ID: "capacity-one", Name: "N", AuthMethod: "api_key", Enabled: true}, allow()); err != nil {
		t.Fatalf("create below definition capacity=%v", err)
	}
	if list, err := s.ListDefinitions(ctx, allow()); err != nil || len(list) != maxList {
		t.Fatalf("definition list at accepted ceiling=%d err=%v", len(list), err)
	}
	if _, err := s.CreateDefinition(ctx, DefinitionInput{ID: "capacity-two", Name: "N", AuthMethod: "api_key", Enabled: true}, allow()); !errors.Is(err, ErrConflict) {
		t.Fatalf("create at definition capacity=%v", err)
	}
}

func TestConnectionCapacityKeepsListEnumerable(t *testing.T) {
	s, ctx := collectionFixture(t)
	d, err := s.CreateDefinition(ctx, definition(), allow())
	if err != nil {
		t.Fatal(err)
	}
	meta := json.RawMessage(`{"label":"x","kind":"work"}`)
	first, err := s.CreateConnection(ctx, "owner-1", d.ID, d.Revision, meta, allow())
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < maxList; i++ {
		if _, err := s.CreateConnection(ctx, "owner-1", d.ID, d.Revision, meta, allow()); err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
	}
	if _, err := s.CreateConnection(ctx, "owner-1", d.ID, d.Revision, meta, allow()); !errors.Is(err, ErrConflict) {
		t.Fatalf("create past connection capacity=%v", err)
	}
	if list, err := s.ListConnections(ctx, "owner-1", d.ID, allow()); err != nil || len(list) != maxList {
		t.Fatalf("connection list at capacity=%d err=%v", len(list), err)
	}
	if _, err := s.CreateConnection(ctx, "owner-2", d.ID, d.Revision, meta, allow()); err != nil {
		t.Fatalf("another owner at capacity=%v", err)
	}
	if err := s.DeleteConnection(ctx, "owner-1", d.ID, first.ID, first.Revision, allow()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateConnection(ctx, "owner-1", d.ID, d.Revision, meta, allow()); err != nil {
		t.Fatalf("create after freeing capacity=%v", err)
	}
}
