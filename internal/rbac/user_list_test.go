package rbac

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func userListStore(t *testing.T) *Store {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "user-list-" + t.Name(), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	s := NewStore(db)
	rows := []struct {
		id                   string
		ms                   int64
		email, given, family string
	}{
		{"a", 1000, "a@example.test", "A", "Alpha"},
		{"b", 1000, "", "", ""},
		{"c", 1000, "c@example.test", "", "Gamma"},
	}
	for i, u := range rows {
		statements := []rhiza.SQLStatement{{SQL: `INSERT INTO identity_users(subject,username,password_phc,created_at_unix_ms) VALUES (?,?,?,?)`, Args: []any{u.id, u.id, "phc", u.ms}}}
		if u.email != "" {
			statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO identity_user_profiles(subject,email,given_name,family_name) VALUES (?,?,?,?)`, Args: []any{u.id, u.email, nullableTest(u.given), nullableTest(u.family)}})
		}
		if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "user-list-seed-" + string(rune('a'+i)), Statements: statements}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func nullableTest(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func TestListUsersEmptyAndDenied(t *testing.T) {
	s := userListStore(t)
	ctx := context.Background()
	got, err := s.listUsers(ctx, "1=1", nil, UserListOptions{}, 2)
	if err != nil || got.Count != 3 {
		t.Fatalf("authorized=%+v err=%v", got, err)
	}
	got, err = s.listUsers(ctx, "0", nil, UserListOptions{}, 2)
	if !errors.Is(err, ErrUnauthorized) || len(got.Users) != 0 {
		t.Fatalf("denied=%+v err=%v", got, err)
	}
}

func TestListUsersTiesForwardBackwardAndCursor(t *testing.T) {
	s := userListStore(t)
	ctx := context.Background()
	opt := UserListOptions{PageSize: 1}
	first, err := s.listUsers(ctx, "1=1", nil, opt, 2)
	if err != nil || len(first.Users) != 2 || first.Users[0].ID != "a" || first.Users[1].ID != "b" || first.ContinuationToken == "" {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	second, err := s.listUsers(ctx, "1=1", nil, UserListOptions{PageSize: 1, Cursor: first.ContinuationToken}, 2)
	if err != nil || len(second.Users) != 1 || second.Users[0].ID != "c" {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	back, err := s.listUsers(ctx, "1=1", nil, UserListOptions{PageSize: 1, Backwards: true}, 2)
	if err != nil || len(back.Users) != 2 || back.Users[0].ID != "b" || back.Users[1].ID != "c" {
		t.Fatalf("back=%+v err=%v", back, err)
	}
	back2, err := s.listUsers(ctx, "1=1", nil, UserListOptions{PageSize: 1, Backwards: true, Cursor: back.ContinuationToken}, 2)
	if err != nil || len(back2.Users) != 1 || back2.Users[0].ID != "a" {
		t.Fatalf("back2=%+v err=%v", back2, err)
	}
	if _, err := s.listUsers(ctx, "1=1", nil, UserListOptions{Cursor: "u1.bad"}, 2); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed cursor err=%v", err)
	}
}

func TestListUsersNullableAndOffset(t *testing.T) {
	s := userListStore(t)
	got, err := s.listUsers(context.Background(), "1=1", nil, UserListOptions{PageSize: 2, Offset: 1}, 10)
	if err != nil || got.Count != 3 || len(got.Users) != 3 || got.Users[1].GivenName != nil || got.Users[1].Email != "" {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	if got.Users[0].CreatedAt != 1 || got.Users[0].LastLogin != nil {
		t.Fatalf("timestamps=%+v", got.Users[0])
	}
}

func TestListUsersEmptyPagesKeepAuthorizedCount(t *testing.T) {
	s := userListStore(t)
	ctx := context.Background()
	page, err := s.listUsers(ctx, "1=1", nil, UserListOptions{PageSize: 1, Offset: 1}, 1)
	if err != nil || page.Count != 3 || len(page.Users) != 1 || page.Users[0].ID != "b" {
		t.Fatalf("offset=%+v err=%v", page, err)
	}
	page, err = s.listUsers(ctx, "1=1", nil, UserListOptions{PageSize: 1, Offset: 65535}, 3)
	if err != nil || page.Count != 3 || !page.Paginated || len(page.Users) != 0 || page.Users == nil || page.ContinuationToken != "" {
		t.Fatalf("empty page=%+v err=%v", page, err)
	}
	for _, backwards := range []bool{false, true} {
		cursor := ""
		ids := []string{}
		for range 4 {
			part, err := s.listUsers(ctx, "1=1", nil, UserListOptions{PageSize: 1, Backwards: backwards, Cursor: cursor}, 1)
			if err != nil || part.Count != 3 || !part.Paginated {
				t.Fatalf("part=%+v err=%v", part, err)
			}
			for _, u := range part.Users {
				ids = append(ids, u.ID)
			}
			cursor = part.ContinuationToken
		}
		want := "abc"
		if backwards {
			want = "cba"
		}
		if strings.Join(ids, "") != want || cursor != "" {
			t.Fatalf("traversal=%v cursor empty=%v", ids, cursor == "")
		}
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "user-list-empty-fixture", SQL: `DELETE FROM identity_users`}); err != nil {
		t.Fatal(err)
	}
	empty, err := s.listUsers(ctx, "1=1", nil, UserListOptions{}, 1)
	if err != nil || empty.Count != 0 || empty.Paginated || empty.Users == nil || len(empty.Users) != 0 {
		t.Fatalf("empty authorized=%+v err=%v", empty, err)
	}
	if _, err := s.listUsers(ctx, "0", nil, UserListOptions{}, 1); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("empty unauthorized=%v", err)
	}
}

func TestUserListCursorRoundTripAndBounds(t *testing.T) {
	for _, c := range []userListCursor{{0, "legacy-admin"}, {1700000000123, "사용자/a"}, {1, "a\tb"}, {1, strings.Repeat("x", 512)}} {
		token, err := encodeUserListCursor(c)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeUserListCursor(token)
		if err != nil || *decoded != c || len(token) > 700 {
			t.Fatalf("cursor round trip err=%v", err)
		}
		for _, bad := range []string{token + "=", token + "\n", "v2." + strings.TrimPrefix(token, "u1.")} {
			if _, err := decodeUserListCursor(bad); err == nil {
				t.Fatal("noncanonical cursor accepted")
			}
		}
	}
	for _, bad := range []string{"", "u1.", "u1.AA", strings.Repeat("a", 701), "u1.________________"} {
		if _, err := decodeUserListCursor(bad); err == nil {
			t.Fatal("invalid cursor accepted")
		}
	}
}
