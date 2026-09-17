package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
)

type scimResourceFailureState struct {
	UserSubject string         `json:"userSubject"`
	UserRemote  string         `json:"userRemote"`
	GroupID     string         `json:"groupID"`
	Baseline    int            `json:"baseline"`
	UserEvent   eventlog.Event `json:"userEvent"`
	GroupEvent  eventlog.Event `json:"groupEvent"`
}

func TestSCIMResourceFailureEvents(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_SCIM_RESOURCE_FAILURE_EVENTS") != "1" {
		t.Skip("set GOAUTHY_E2E_SCIM_RESOURCE_FAILURE_EVENTS=1 to run SCIM resource failure-event E2E")
	}
	primary, secondary, tertiary, fixtureAdmin, username, password, statePath := scimFailureConfig(t)
	fixture := &http.Client{Timeout: 5 * time.Second}
	assertSCIMBootstrapProjection(t, fixture, fixtureAdmin)
	admin := newBrowserClient(t)
	_, cookie := loginForAuthorizationURL(t, admin, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "scim-resource-failure", "scim-resource-failure-nonce"), primary, secondary, username, password, "scim-resource-failure")
	csrf, err := browsersession.DeriveCSRFToken(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	subject := createSCIMFailureUser(t, admin, primary, csrf)
	remoteID := waitForSCIMResourceProjection(t, fixture, fixtureAdmin, subject)
	setSCIMFixtureMode(t, fixture, fixtureAdmin, "temporary")
	baseline := scimFixtureBaseline(t, fixture, fixtureAdmin)
	group := rbacCreate(t, admin, primary, "groups", "scim-resource-failure-group", nil, csrf)
	deleteSCIMUser(t, admin, primary, subject, csrf, http.StatusNoContent)

	client := admin
	nodes := []string{primary, secondary, tertiary}
	groupEvent, userEvent := waitForSCIMResourceFailureEvents(t, client, nodes[0], fixtureAdmin, subject, remoteID, group.ID, baseline)
	assertSCIMResourceFailureEvent(t, groupEvent, "GroupCreateUpdate", "group:"+group.ID)
	assertSCIMResourceFailureEvent(t, userEvent, "UserDelete", subject)
	assertSCIMResourceAttempts(t, fixture, fixtureAdmin, subject, remoteID, group.ID, baseline, 5)
	for _, node := range nodes[1:] {
		gotGroup, gotUser := waitForSCIMResourceFailureEvents(t, client, node, "", subject, remoteID, group.ID, baseline)
		assertSameSCIMResourceEvent(t, groupEvent, gotGroup, node+" group")
		assertSameSCIMResourceEvent(t, userEvent, gotUser, node+" user")
	}
	for _, node := range nodes {
		stream := collectStreamEvents(t, client, node, "latest=1000&level=critical", func(events []eventlog.Event) bool {
			return hasSCIMResourceFailureEvents(events, subject, group.ID)
		})
		groups, users := matchingSCIMResourceEvents(stream, subject, group.ID)
		if len(groups) != 1 || len(users) != 1 {
			t.Fatalf("SCIM resource failure SSE node=%s group=%d user=%d, want one each", node, len(groups), len(users))
		}
		assertSameSCIMResourceEvent(t, groupEvent, groups[0], node+" group SSE")
		assertSameSCIMResourceEvent(t, userEvent, users[0], node+" user SSE")
	}
	writeSCIMResourceFailureState(t, statePath, scimResourceFailureState{UserSubject: subject, UserRemote: remoteID, GroupID: group.ID, Baseline: baseline, UserEvent: userEvent, GroupEvent: groupEvent})
}

func TestSCIMResourceFailureEventsPersisted(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_SCIM_RESOURCE_FAILURE_EVENTS_PERSISTENCE") != "1" {
		t.Skip("set GOAUTHY_E2E_SCIM_RESOURCE_FAILURE_EVENTS_PERSISTENCE=1 to run SCIM resource failure persistence E2E")
	}
	primary, secondary, tertiary, fixtureAdmin, username, password, statePath := scimFailureConfig(t)
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read SCIM resource failure state: %v", err)
	}
	var state scimResourceFailureState
	if err := json.Unmarshal(raw, &state); err != nil || state.UserSubject == "" || state.UserRemote == "" || state.GroupID == "" {
		t.Fatalf("invalid SCIM resource failure state: decode=%v", err)
	}
	assertSCIMResourceFailureEvent(t, state.GroupEvent, "GroupCreateUpdate", "group:"+state.GroupID)
	assertSCIMResourceFailureEvent(t, state.UserEvent, "UserDelete", state.UserSubject)
	fixture := &http.Client{Timeout: 5 * time.Second}
	groupCalls, userCalls := scimFixtureTargetCallCount(t, fixture, fixtureAdmin, state.UserSubject, state.UserRemote, state.GroupID, state.Baseline)
	if groupCalls != 5 || userCalls != 5 {
		t.Fatalf("SCIM persisted target calls group=%d user=%d, want 5 each", groupCalls, userCalls)
	}
	client := newBrowserClient(t)
	_, _ = loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), "scim-resource-failure-persisted", "scim-resource-failure-persisted-nonce"), primary, secondary, username, password, "scim-resource-failure-persisted")
	for _, node := range []string{primary, secondary, tertiary} {
		groups, users := matchingSCIMResourceEvents(queryLifecycleEvents(t, client, node), state.UserSubject, state.GroupID)
		if len(groups) != 1 || len(users) != 1 {
			t.Fatalf("persisted SCIM resource POST node=%s group=%d user=%d, want one each", node, len(groups), len(users))
		}
		assertSameSCIMResourceEvent(t, state.GroupEvent, groups[0], node+" group")
		assertSameSCIMResourceEvent(t, state.UserEvent, users[0], node+" user")
		stream := collectStreamEvents(t, client, node, "latest=1000&level=critical", func(events []eventlog.Event) bool {
			return hasSCIMResourceFailureEvents(events, state.UserSubject, state.GroupID)
		})
		groups, users = matchingSCIMResourceEvents(stream, state.UserSubject, state.GroupID)
		if len(groups) != 1 || len(users) != 1 {
			t.Fatalf("persisted SCIM resource SSE node=%s group=%d user=%d, want one each", node, len(groups), len(users))
		}
		assertSameSCIMResourceEvent(t, state.GroupEvent, groups[0], node+" group SSE")
		assertSameSCIMResourceEvent(t, state.UserEvent, users[0], node+" user SSE")
	}
	gotGroup, gotUser := scimFixtureTargetCallCount(t, fixture, fixtureAdmin, state.UserSubject, state.UserRemote, state.GroupID, state.Baseline)
	if gotGroup != groupCalls || gotUser != userCalls {
		t.Fatalf("SCIM target calls changed after restart: before=%d/%d after=%d/%d", groupCalls, userCalls, gotGroup, gotUser)
	}
}

func createSCIMFailureUser(t *testing.T, client *http.Client, base, csrf string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"email": "scim-resource-failure@goauthy.e2e", "language": "en", "roles": []string{}, "preferred_username": "scim-resource-failure", "tz": "UTC", "user_expires": 4102444800})
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, client, http.MethodPost, base+"/auth/v1/users", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf})
	defer response.Body.Close()
	var created struct {
		ID string `json:"id"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&created) != nil || created.ID == "" {
		t.Fatalf("SCIM resource fixture user creation status=%d", response.StatusCode)
	}
	return created.ID
}

func waitForSCIMResourceProjection(t *testing.T, client *http.Client, fixture, subject string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		response, err := client.Get(fixture + "/admin/state")
		if err == nil {
			var state struct {
				Users []struct {
					ID         string `json:"id"`
					ExternalID string `json:"externalId"`
				} `json:"users"`
			}
			if response.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&state) == nil {
				response.Body.Close()
				for _, user := range state.Users {
					if user.ExternalID == subject && user.ID != "" {
						return user.ID
					}
				}
			} else {
				response.Body.Close()
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("timed out waiting for SCIM resource projection")
		case <-ticker.C:
		}
	}
}

func waitForSCIMResourceFailureEvents(t *testing.T, client *http.Client, base, fixture, subject, remoteID, groupID string, baseline int) (eventlog.Event, eventlog.Event) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 26*time.Minute)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	lastGroup, lastUser := -1, -1
	for {
		if fixture != "" {
			groupCalls, userCalls := scimFixtureTargetCallCount(t, client, fixture, subject, remoteID, groupID, baseline)
			if groupCalls != lastGroup || userCalls != lastUser {
				t.Logf("SCIM resource targets group=%d user=%d", groupCalls, userCalls)
				lastGroup, lastUser = groupCalls, userCalls
			}
		}
		groups, users := matchingSCIMResourceEvents(queryLifecycleEvents(t, client, base), subject, groupID)
		if len(groups) > 1 || len(users) > 1 {
			t.Fatalf("SCIM resource failure events node=%s group=%d user=%d", base, len(groups), len(users))
		}
		if len(groups) == 1 && len(users) == 1 {
			return groups[0], users[0]
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for SCIM resource failure events node=%s", base)
		case <-ticker.C:
		}
	}
}

func matchingSCIMResourceEvents(events []eventlog.Event, subject, groupID string) (groups, users []eventlog.Event) {
	for _, event := range events {
		if event.Type != eventlog.ScimTaskFailed || event.Text == nil {
			continue
		}
		if *event.Text == `fixture / GroupCreateUpdate("group:`+groupID+`")` {
			groups = append(groups, event)
		}
		if *event.Text == `fixture / UserDelete("`+subject+`")` {
			users = append(users, event)
		}
	}
	return
}

func hasSCIMResourceFailureEvents(events []eventlog.Event, subject, groupID string) bool {
	groups, users := matchingSCIMResourceEvents(events, subject, groupID)
	return len(groups) > 0 && len(users) > 0
}

func assertSCIMResourceFailureEvent(t *testing.T, event eventlog.Event, action, externalID string) {
	t.Helper()
	want := `fixture / ` + action + `("` + externalID + `")`
	if event.ID == "" || event.Timestamp <= 0 || event.Level != eventlog.Critical || event.Type != eventlog.ScimTaskFailed || event.IP != nil || event.Data == nil || *event.Data != 5 || event.Text == nil || *event.Text != want {
		t.Fatalf("invalid SCIM resource failure event: %+v", event)
	}
}

func assertSameSCIMResourceEvent(t *testing.T, want, got eventlog.Event, where string) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("SCIM resource event differs at %s want=%+v got=%+v", where, want, got)
	}
}

func writeSCIMResourceFailureState(t *testing.T, path string, state scimResourceFailureState) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertSCIMResourceAttempts(t *testing.T, client *http.Client, fixture, subject, remoteID, groupID string, baseline, want int) {
	t.Helper()
	groupCalls, userCalls := scimFixtureTargetCallCount(t, client, fixture, subject, remoteID, groupID, baseline)
	if groupCalls != want || userCalls != want {
		t.Fatalf("SCIM resource target calls group=%d user=%d, want %d each", groupCalls, userCalls, want)
	}
}

type scimFixtureCall struct {
	Number int    `json:"number"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Filter string `json:"filter"`
}

func scimFixtureTargetCallCount(t *testing.T, client *http.Client, fixture, subject, remoteID, groupID string, baseline int) (int, int) {
	t.Helper()
	response, err := client.Get(fixture + "/admin/state")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var state struct {
		Users []struct {
			ID         string `json:"id"`
			ExternalID string `json:"externalId"`
		} `json:"users"`
		Groups []struct {
			ExternalID string `json:"externalId"`
		} `json:"groups"`
		Mode  string            `json:"mode"`
		Calls []scimFixtureCall `json:"calls"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&state) != nil {
		t.Fatalf("read SCIM fixture state status=%d", response.StatusCode)
	}
	if state.Mode != "temporary" {
		t.Fatalf("SCIM fixture mode=%q, want temporary", state.Mode)
	}
	foundUser := false
	for _, user := range state.Users {
		if user.ExternalID == subject {
			foundUser = true
			if remoteID != "" && user.ID != remoteID {
				t.Fatalf("SCIM delete target %s remote id=%q, want %q", subject, user.ID, remoteID)
			}
		}
	}
	if !foundUser {
		t.Fatalf("failed SCIM delete target %s disappeared remotely", subject)
	}
	for _, group := range state.Groups {
		if group.ExternalID == "group:"+groupID {
			t.Fatalf("failed SCIM group %s unexpectedly exists remotely", groupID)
		}
	}
	groupFilter := `externalId eq "group:` + groupID + `"`
	groupCalls, userCalls, err := classifySCIMResourceCalls(state.Calls, baseline, subject, remoteID, groupFilter)
	if err != nil {
		t.Fatal(err)
	}
	return groupCalls, userCalls
}

func TestClassifySCIMResourceCalls(t *testing.T) {
	calls := []scimFixtureCall{{Number: 1, Method: http.MethodGet, Path: "/scim/v2/Groups", Filter: `externalId eq "group:g"`}, {Number: 2, Method: http.MethodGet, Path: "/scim/v2/Users", Filter: `externalId eq "u"`}}
	for n := 3; n <= 7; n++ {
		calls = append(calls, scimFixtureCall{Number: n, Method: http.MethodGet, Path: "/scim/v2/Groups", Filter: `externalId eq "group:g"`}, scimFixtureCall{Number: n + 5, Method: http.MethodGet, Path: "/scim/v2/Users/r"})
	}
	groupCalls, userCalls, err := classifySCIMResourceCalls(calls, 2, "u", "r", `externalId eq "group:g"`)
	if err != nil || groupCalls != 5 || userCalls != 5 {
		t.Fatalf("counts=%d/%d err=%v", groupCalls, userCalls, err)
	}
	calls = append(calls, scimFixtureCall{Number: 20, Method: http.MethodPost, Path: "/scim/v2/Groups"})
	if _, _, err := classifySCIMResourceCalls(calls, 2, "u", "r", `externalId eq "group:g"`); err == nil {
		t.Fatal("mutation was accepted")
	}
}

func scimFixtureBaseline(t *testing.T, client *http.Client, fixture string) int {
	t.Helper()
	response, err := client.Get(fixture + "/admin/state")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var state struct {
		Mode  string            `json:"mode"`
		Calls []scimFixtureCall `json:"calls"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&state) != nil {
		t.Fatalf("read SCIM fixture baseline status=%d", response.StatusCode)
	}
	if state.Mode != "temporary" {
		t.Fatalf("SCIM fixture mode=%q, want temporary", state.Mode)
	}
	max := 0
	for _, call := range state.Calls {
		if call.Number > max {
			max = call.Number
		}
	}
	return max
}

func classifySCIMResourceCalls(calls []scimFixtureCall, baseline int, subject, remoteID, groupFilter string) (int, int, error) {
	groupCalls, userCalls := 0, 0
	userFilter := `externalId eq "` + subject + `"`
	for _, call := range calls {
		if call.Number <= baseline {
			continue
		}
		group := call.Path == "/scim/v2/Groups" && call.Filter == groupFilter
		user := call.Path == "/scim/v2/Users/"+url.PathEscape(remoteID) || call.Path == "/scim/v2/Users" && call.Filter == userFilter
		if call.Method != http.MethodGet {
			return 0, 0, errors.New("unexpected SCIM resource mutation after baseline: " + call.Method + " " + call.Path)
		}
		if !group && !user {
			continue
		}
		if group {
			groupCalls++
		}
		if user {
			userCalls++
		}
	}
	return groupCalls, userCalls, nil
}
