package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/mrchypark/goauthy/internal/scim"
)

func fixtureClient(t *testing.T, s *state) (*scim.Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(s.publicHandler())
	client, err := scim.New(scim.Config{BaseURL: server.URL + "/scim/v2", Token: "fixture-token", HTTPClient: server.Client()})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client, server
}

func TestBearerAuthAndCRUDUnlinkDelete(t *testing.T) {
	s := newState("fixture-token")
	client, server := fixtureClient(t, s)
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/scim/v2/Users")
	if err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized response=%v err=%v", response, err)
	}
	_ = response.Body.Close()
	ctx := context.Background()
	u := scim.User{ExternalID: "external-1", UserName: "alice", Active: true}
	result, err := client.SyncUser(ctx, u)
	if err != nil || result.Action != scim.ActionCreated || result.RemoteID != "u-1" {
		t.Fatalf("create result=%+v err=%v", result, err)
	}
	get, err := http.NewRequest(http.MethodGet, server.URL+"/scim/v2/Users/u-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	get.Header.Set("Authorization", "Bearer fixture-token")
	response, err = server.Client().Do(get)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("get response=%v err=%v", response, err)
	}
	decoder := json.NewDecoder(response.Body)
	var remote user
	firstErr := decoder.Decode(&remote)
	secondErr := decoder.Decode(&struct{}{})
	_ = response.Body.Close()
	if firstErr != nil || secondErr != io.EOF || remote.ID != "u-1" {
		t.Fatalf("GET body user=%+v first=%v second=%v", remote, firstErr, secondErr)
	}
	u.Active = false
	result, err = client.SyncUser(ctx, u)
	if err != nil || result.Action != scim.ActionUpdated || result.RemoteID != "u-1" {
		t.Fatalf("update result=%+v err=%v", result, err)
	}
	result, err = client.DeleteUser(ctx, u, scim.UnlinkRemote)
	if err != nil || result.Action != scim.ActionUnlinked {
		t.Fatalf("unlink result=%+v err=%v", result, err)
	}
	_, _, users, _ := s.snapshot()
	if len(users) != 1 || users[0].ExternalID != "" || users[0].ID != "u-1" {
		t.Fatalf("unlinked users=%+v", users)
	}
	// A fresh external ID makes the retained remote user independently deletable.
	u = scim.User{ExternalID: "external-2", UserName: "bob", Active: true}
	if result, err = client.SyncUser(ctx, u); err != nil || result.Action != scim.ActionCreated || result.RemoteID != "u-2" {
		t.Fatalf("second create result=%+v err=%v", result, err)
	}
	if result, err = client.DeleteUser(ctx, u, scim.DeleteRemote); err != nil || result.Action != scim.ActionDeleted || result.RemoteID != "u-2" {
		t.Fatalf("delete result=%+v err=%v", result, err)
	}
	_, _, users, _ = s.snapshot()
	if len(users) != 1 || users[0].ID != "u-1" {
		t.Fatalf("deleted users=%+v", users)
	}
}

func TestGroupCRUDAndCanonicalMembers(t *testing.T) {
	s := newState("fixture-token")
	client, server := fixtureClient(t, s)
	defer server.Close()
	ctx := context.Background()
	want := scim.Group{ExternalID: "group:engineering", DisplayName: "Engineering", Members: []scim.GroupMember{{Value: "remote-b", Display: "Bob"}, {Value: "remote-a", Display: "Alice"}}}
	result, err := client.SyncGroup(ctx, want)
	if err != nil || result.Action != scim.ActionCreated || result.RemoteID != "g-1" {
		t.Fatalf("group create result=%+v err=%v", result, err)
	}
	want.DisplayName = "Platform"
	result, err = client.SyncGroup(ctx, want)
	if err != nil || result.Action != scim.ActionUpdated || result.RemoteID != "g-1" {
		t.Fatalf("group update result=%+v err=%v", result, err)
	}
	groups := s.snapshotGroups()
	if len(groups) != 1 || groups[0].ExternalID != want.ExternalID || groups[0].DisplayName != want.DisplayName || len(groups[0].Members) != 2 || groups[0].Members[0].Value != "remote-a" || groups[0].Members[1].Value != "remote-b" {
		t.Fatalf("fixture groups=%+v", groups)
	}
}

func TestResponseModesAndAdminEndpoints(t *testing.T) {
	s := newState("fixture-token")
	for _, tc := range []struct {
		mode string
		want int
	}{{"success", http.StatusOK}, {"temporary", http.StatusServiceUnavailable}, {"permanent", http.StatusBadRequest}, {"drop", http.StatusServiceUnavailable}} {
		t.Run(tc.mode, func(t *testing.T) {
			s.mu.Lock()
			s.mode = tc.mode
			s.mu.Unlock()
			r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users?filter=externalId+eq+%22none%22&startIndex=1&count=100", nil)
			r.Header.Set("Authorization", "Bearer fixture-token")
			w := httptest.NewRecorder()
			s.serveSCIM(w, r)
			if w.Code != tc.want {
				t.Fatalf("mode %s status=%d want=%d", tc.mode, w.Code, tc.want)
			}
		})
	}
	admin := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/mode", bytes.NewBufferString(`{"mode":"temporary"}`))
	req.Header.Set("Content-Type", "application/json")
	s.adminHandler().ServeHTTP(admin, req)
	if admin.Code != http.StatusNoContent {
		t.Fatalf("admin mode status=%d", admin.Code)
	}
	stateResponse := httptest.NewRecorder()
	s.adminHandler().ServeHTTP(stateResponse, httptest.NewRequest(http.MethodGet, "/admin/state", nil))
	var state struct {
		Requests uint64 `json:"requests"`
		Mode     string `json:"mode"`
		Calls    []call `json:"calls"`
	}
	if err := json.Unmarshal(stateResponse.Body.Bytes(), &state); err != nil || state.Requests != 4 || state.Mode != "temporary" || len(state.Calls) != 4 {
		t.Fatalf("state=%s parsed=%+v err=%v", stateResponse.Body.String(), state, err)
	}
	reset := httptest.NewRecorder()
	s.adminHandler().ServeHTTP(reset, httptest.NewRequest(http.MethodPost, "/admin/reset", nil))
	if reset.Code != http.StatusNoContent {
		t.Fatalf("reset=%d", reset.Code)
	}
	requests, mode, users, calls := s.snapshot()
	if requests != 0 || mode != "success" || len(users) != 0 || len(calls) != 0 {
		t.Fatalf("reset snapshot=%d %s %v %v", requests, mode, users, calls)
	}
}

func TestCountersAndConcurrentRequests(t *testing.T) {
	s := newState("fixture-token")
	const workers = 64
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users?filter=userName+eq+%22nobody%22&startIndex=1&count=100", nil)
			r.Header.Set("Authorization", "Bearer fixture-token")
			s.serveSCIM(httptest.NewRecorder(), r)
		}()
	}
	wg.Wait()
	requests, _, _, calls := s.snapshot()
	if requests != workers || len(calls) != workers {
		t.Fatalf("requests=%d calls=%d want=%d", requests, len(calls), workers)
	}
	for i, c := range calls {
		if c.Number != uint64(i+1) {
			t.Fatalf("call order=%+v", calls)
		}
	}
}

func TestTargetBoundsBeforeCallLogging(t *testing.T) {
	for _, target := range []string{
		"/" + strings.Repeat("a", maxPathBytes+1),
		"/scim/v2/Users?" + strings.Repeat("a", maxQueryBytes+1),
		"/scim/v2/Users?" + url.Values{"filter": {`externalId eq "` + strings.Repeat("a", maxFilterBytes) + `"`}, "startIndex": {"1"}, "count": {"100"}}.Encode(),
	} {
		s := newState("fixture-token")
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.Header.Set("Authorization", "Bearer fixture-token")
		w := httptest.NewRecorder()
		s.serveSCIM(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("target length %d status=%d", len(target), w.Code)
		}
		requests, _, _, calls := s.snapshot()
		if requests != 0 || len(calls) != 0 {
			t.Fatalf("rejected target logged requests=%d calls=%+v", requests, calls)
		}
	}
	s := newState("fixture-token")
	filter := `externalId eq "` + strings.Repeat(`\"`, 512) + `"`
	r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users?"+url.Values{"filter": {filter}, "startIndex": {"1"}, "count": {"100"}}.Encode(), nil)
	r.Header.Set("Authorization", "Bearer fixture-token")
	w := httptest.NewRecorder()
	s.serveSCIM(w, r)
	requests, _, _, calls := s.snapshot()
	if w.Code != http.StatusOK || requests != 1 || len(calls) != 1 || calls[0].Filter != filter {
		t.Fatalf("boundary status=%d requests=%d calls=%+v", w.Code, requests, calls)
	}
}

func TestDropResetsHTTP1TLSConnection(t *testing.T) {
	s := newState("fixture-token")
	s.mu.Lock()
	s.mode = "drop"
	s.mu.Unlock()
	server := httptest.NewUnstartedServer(s.publicHandler())
	server.EnableHTTP2 = false
	server.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()
	request, err := http.NewRequest(http.MethodGet, server.URL+"/scim/v2/Users?filter=externalId+eq+%22none%22&startIndex=1&count=100", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer fixture-token")
	response, err := server.Client().Do(request)
	if response != nil || err == nil {
		if response != nil {
			_ = response.Body.Close()
		}
		t.Fatalf("drop response=%v err=%v", response, err)
	}
}

func TestStrictInputAndConfig(t *testing.T) {
	s := newState("fixture-token")
	request := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(`{"unknown":true}`))
	request.Header.Set("Authorization", "Bearer fixture-token")
	request.Header.Set("Content-Type", "application/scim+json")
	w := httptest.NewRecorder()
	s.serveSCIM(w, request)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown json status=%d", w.Code)
	}
	env := map[string]string{"SCIM_FIXTURE_TLS_CERT_FILE": "/cert", "SCIM_FIXTURE_TLS_KEY_FILE": "/key", "SCIM_FIXTURE_BEARER_TOKEN": "token"}
	if got, err := configFromEnv(func(key string) string { return env[key] }); err != nil || got.addr != tlsAddr || got.adminAddr != adminAddr {
		t.Fatalf("config=%+v err=%v", got, err)
	}
	env["SCIM_FIXTURE_ADMIN_ADDR"] = "0.0.0.0:8083"
	if _, err := configFromEnv(func(key string) string { return env[key] }); err == nil {
		t.Fatal("public admin address accepted")
	}
	env["SCIM_FIXTURE_ADMIN_ADDR"] = "localhost:8083"
	if _, err := configFromEnv(func(key string) string { return env[key] }); err == nil {
		t.Fatal("hostname admin address accepted")
	}
}
