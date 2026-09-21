package apikey

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestKeysRejectsNestedDuplicateJSONField(t *testing.T) {
	t.Parallel()
	h := NewHandler(nil, func(http.ResponseWriter, *http.Request, bool) bool { return true })
	r := httptest.NewRequest(http.MethodPost, "/auth/v1/api_keys", strings.NewReader(`{"name":"nested","access":{"groups":["Roles"],"groups":["Users"]}}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Keys(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestAuthorizationHeaderNeverFallsBackToBrowserAdmin(t *testing.T) {
	t.Parallel()
	db := openTestDB(t, "apikey-http")
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := store.Create(context.Background(), nil, Request{Name: "reader", Access: []Access{{Group: GroupAPIKeys, AccessRights: []Right{Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	h := NewHandler(store, func(w http.ResponseWriter, _ *http.Request, mutation bool) bool {
		called = true
		w.WriteHeader(http.StatusForbidden)
		return false
	})
	for _, values := range [][]string{{"Bearer junk"}, {"API-Key " + token, "Bearer junk"}} {
		r := httptest.NewRequest(http.MethodGet, "/auth/v1/api_keys", nil)
		for _, value := range values {
			r.Header.Add("Authorization", value)
		}
		w := httptest.NewRecorder()
		h.Keys(w, r)
		if called || w.Code != http.StatusUnauthorized {
			t.Fatalf("headers=%q browser=%v status=%d", values, called, w.Code)
		}
	}
}

func TestAPIKeyCannotManageAPIKeys(t *testing.T) {
	t.Parallel()
	db := openTestDB(t, "apikey-http-deny")
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := store.Create(context.Background(), nil, Request{Name: "manager", Access: []Access{{Group: GroupAPIKeys, AccessRights: []Right{Read, Create, Update, Delete}}}})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	h := NewHandler(store, func(http.ResponseWriter, *http.Request, bool) bool {
		called = true
		return true
	})
	header := "API-Key " + token
	cases := []struct {
		method, path, body string
	}{
		{http.MethodGet, "/auth/v1/api_keys", ""},
		{http.MethodPost, "/auth/v1/api_keys", `{"name":"new-key","access":[{"group":"Roles","access_rights":["read"]}]}`},
		{http.MethodPut, "/auth/v1/api_keys/manager", `{"name":"manager","access":[{"group":"ApiKeys","access_rights":["read"]}]}`},
		{http.MethodDelete, "/auth/v1/api_keys/manager", ""},
		{http.MethodPut, "/auth/v1/api_keys/manager/secret", ""},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Authorization", header)
		if tc.body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		switch {
		case tc.path == "/auth/v1/api_keys":
			h.Keys(w, r)
		case tc.path == "/auth/v1/api_keys/manager":
			r.SetPathValue("name", "manager")
			h.Key(w, r)
		default:
			r.SetPathValue("name", "manager")
			h.Secret(w, r)
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s status=%d, want %d", tc.method, tc.path, w.Code, http.StatusForbidden)
		}
	}
	if called {
		t.Fatal("API-key authorization fell back to browser admin")
	}
}

func TestEventsRequiresEventsReadAndStrictCursorQuery(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t, "apikey-events-http")
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, readerToken, err := store.Create(ctx, nil, Request{Name: "events-reader", Access: []Access{{Group: "Events", AccessRights: []Right{Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	_, noEventsToken, err := store.Create(ctx, nil, Request{Name: "not-reader", Access: []Access{{Group: "Groups", AccessRights: []Right{Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	browserCalls := 0
	h := NewHandler(store, func(http.ResponseWriter, *http.Request, bool) bool { browserCalls++; return true })
	request := httptest.NewRequest(http.MethodGet, "/auth/v1/events?limit=1", nil)
	request.Header.Set("Authorization", "API-Key "+readerToken)
	response := httptest.NewRecorder()
	h.Events(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" || browserCalls != 0 || strings.Contains(response.Body.String(), readerToken) || strings.Contains(response.Body.String(), "events-reader") {
		t.Fatalf("status=%d headers=%v browser=%d body=%q", response.Code, response.Header(), browserCalls, response.Body.String())
	}
	var page auditEventsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Events) != 1 || page.NextCursor == nil || page.Events[0].TargetHash == "" {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	next := httptest.NewRequest(http.MethodGet, "/auth/v1/events?limit=1&sequence="+strconv.FormatInt(page.NextCursor.Sequence, 10), nil)
	next.Header.Set("Authorization", "API-Key "+readerToken)
	nextResponse := httptest.NewRecorder()
	h.Events(nextResponse, next)
	if nextResponse.Code != http.StatusOK {
		t.Fatalf("next status=%d", nextResponse.Code)
	}

	for _, raw := range []string{"?limit=0", "?limit=33", "?limit=01", "?sequence=0", "?sequence=01", "?sequence=-1", "?sequence=1.0", "?limit=1&limit=2", "?unknown=1", "?limit=%", "?limit=1;bad=2"} {
		r := httptest.NewRequest(http.MethodGet, "/auth/v1/events"+raw, nil)
		r.Header.Set("Authorization", "API-Key "+readerToken)
		w := httptest.NewRecorder()
		h.Events(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("query %q status=%d", raw, w.Code)
		}
	}
	for _, authorization := range []string{"", "Bearer ignored", "API-Key " + noEventsToken} {
		r := httptest.NewRequest(http.MethodGet, "/auth/v1/events", nil)
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}
		w := httptest.NewRecorder()
		h.Events(w, r)
		want := http.StatusUnauthorized
		if authorization == "API-Key "+noEventsToken {
			want = http.StatusForbidden
		}
		if w.Code != want || browserCalls != 0 {
			t.Fatalf("authorization=%q status=%d browser=%d", authorization, w.Code, browserCalls)
		}
	}
}

func TestScopedAPIKeyCanTestOnlyItself(t *testing.T) {
	t.Parallel()
	db := bootstrapTestDB(t, "apikey-self-test")
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_100_000_000, 0)
	store.now = func() time.Time { return now }
	expires := now.Add(time.Hour).Unix()
	_, token, err := store.Create(t.Context(), nil, Request{Name: "scoped-reader", Exp: &expires, Access: []Access{{Group: "Clients", AccessRights: []Right{Read}}}})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := store.Authenticate(t.Context(), "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(store, func(http.ResponseWriter, *http.Request, bool) bool {
		t.Error("self-test used browser authentication")
		return false
	})
	for _, name := range []string{"scoped-reader", "another-key"} {
		req := httptest.NewRequest(http.MethodGet, "/auth/v1/api_keys/"+name+"/test", nil)
		req.SetPathValue("name", name)
		req.Header.Set("Authorization", "API-Key "+token)
		response := httptest.NewRecorder()
		handler.Test(response, req)
		if name != principal.Name {
			if response.Code == http.StatusOK {
				t.Fatal("self-test disclosed another key")
			}
			continue
		}
		if response.Code != http.StatusOK {
			t.Fatalf("scoped self-test status=%d", response.Code)
		}
		var key Key
		if err := json.Unmarshal(response.Body.Bytes(), &key); err != nil {
			t.Fatal(err)
		}
		if key.Name != name || len(key.Access) != 1 || key.Access[0].Group != "Clients" || strings.Contains(response.Body.String(), token) {
			t.Fatal("invalid self-test metadata or secret disclosure")
		}
	}
	now = time.Unix(expires, 0)
	if _, err := store.Get(t.Context(), principal); err != nil {
		t.Fatal("self metadata denied at inclusive expiry boundary")
	}
	now = now.Add(time.Millisecond)
	if _, err := store.Get(t.Context(), principal); err == nil {
		t.Fatal("expired principal read self metadata")
	}
	now = time.Unix(expires-1, 0)
	if _, err := store.Get(t.Context(), Principal{Name: principal.Name}); err == nil {
		t.Fatal("name-only forged principal read self metadata")
	}
	if _, err := store.Rotate(t.Context(), nil, principal.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(t.Context(), principal); err == nil {
		t.Fatal("rotated principal read self metadata")
	}
}
