package scim

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func testGroup() Group {
	return Group{
		ExternalID:  "group-1",
		DisplayName: "Engineering",
		Members: []GroupMember{
			{Value: "user-b", Display: "b@example.test"},
			{Value: "user-a", Display: "a@example.test"},
		},
	}
}

func writeGroupList(w http.ResponseWriter, groups []Group) {
	w.Header().Set("Content-Type", "application/scim+json")
	for i := range groups {
		groups[i].Schemas = []string{groupSchema}
	}
	_ = json.NewEncoder(w).Encode(struct {
		Schemas      []string `json:"schemas"`
		TotalResults int      `json:"totalResults"`
		StartIndex   int      `json:"startIndex"`
		ItemsPerPage int      `json:"itemsPerPage"`
		Resources    []Group  `json:"Resources"`
	}{[]string{listResponseSchema}, len(groups), 1, len(groups), groups})
}

func writeGroup(w http.ResponseWriter, group Group) {
	group.Schemas = []string{groupSchema}
	w.Header().Set("Content-Type", "application/scim+json")
	_ = json.NewEncoder(w).Encode(group)
}

func TestSyncGroupCreateUpdateAndCanonicalMembers(t *testing.T) {
	t.Parallel()
	var remote Group
	var postPayload, putPayload Group
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if strings.Contains(r.URL.Query().Get("filter"), "externalId") {
				if remote.ID == "" {
					writeGroupList(w, nil)
				} else {
					writeGroupList(w, []Group{remote})
				}
				return
			}
			writeGroupList(w, nil)
			return
		}
		var got groupPayload
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&got); err != nil {
			t.Fatalf("decode %s: %v", r.Method, err)
		}
		if len(got.Members) != 2 || got.Members[0].Value != "user-a" || got.Members[1].Value != "user-b" {
			t.Fatalf("members were not canonical: %#v", got.Members)
		}
		if r.Method == http.MethodPost {
			postPayload = Group{ExternalID: *got.ExternalID, DisplayName: got.DisplayName, Members: got.Members}
			remote = Group{ID: "remote-1", ExternalID: postPayload.ExternalID, DisplayName: postPayload.DisplayName, Members: postPayload.Members}
			w.Header().Set("Content-Type", "application/scim+json")
			w.WriteHeader(http.StatusCreated)
			writeGroup(w, remote)
			return
		}
		if r.Method != http.MethodPut || r.URL.Path != "/scim/v2/Groups/remote-1" {
			t.Fatalf("unexpected mutation %s %s", r.Method, r.URL.Path)
		}
		putPayload = Group{ExternalID: *got.ExternalID, DisplayName: got.DisplayName, Members: got.Members}
		remote.DisplayName = got.DisplayName
		remote.Members = got.Members
		writeGroup(w, remote)
	}))
	defer server.Close()

	want := testGroup()
	result, err := client.SyncGroup(context.Background(), want)
	if err != nil || result.Action != ActionCreated || result.RemoteID != "remote-1" {
		t.Fatalf("create result=%#v err=%v", result, err)
	}
	if postPayload.ExternalID != want.ExternalID {
		t.Fatalf("post payload=%#v", postPayload)
	}

	want.DisplayName = "Platform"
	result, err = client.SyncGroup(context.Background(), want)
	if err != nil || result.Action != ActionUpdated || result.RemoteID != "remote-1" {
		t.Fatalf("update result=%#v err=%v", result, err)
	}
	if putPayload.DisplayName != "Platform" {
		t.Fatalf("put payload=%#v", putPayload)
	}
	result, err = client.SyncGroup(context.Background(), want)
	if err != nil || result.Action != ActionUnchanged {
		t.Fatalf("unchanged result=%#v err=%v", result, err)
	}
}

func TestEmptyGroupMembersSerializeAsArray(t *testing.T) {
	t.Parallel()
	client, server := testClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	payload, err := client.marshalGroupPayload(Group{ExternalID: "group-1", DisplayName: "Engineering"}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"externalId":"group-1","displayName":"Engineering","members":[]}`
	if string(payload) != want {
		t.Fatalf("payload=%s want=%s", payload, want)
	}
}

func TestSyncGroupUsesSafeDisplayNameFallback(t *testing.T) {
	t.Parallel()
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if strings.Contains(r.URL.Query().Get("filter"), "externalId") {
				writeGroupList(w, nil)
				return
			}
			writeGroupList(w, []Group{{ID: "remote", DisplayName: "Engineering"}})
			return
		}
		if r.Method != http.MethodPut {
			t.Fatalf("unexpected method %s", r.Method)
		}
		var got groupPayload
		if json.NewDecoder(r.Body).Decode(&got) != nil || got.ExternalID == nil || *got.ExternalID != "group-1" {
			t.Fatal("fallback did not claim the unmanaged group")
		}
		w.Header().Set("Content-Type", "application/scim+json")
		w.WriteHeader(http.StatusOK)
		writeGroup(w, Group{ID: "remote", ExternalID: "group-1", DisplayName: "Engineering", Members: testGroup().Members})
	}))
	defer server.Close()
	result, err := client.SyncGroup(context.Background(), testGroup())
	if err != nil || result.Action != ActionUpdated {
		t.Fatalf("fallback result=%#v err=%v", result, err)
	}
}

func TestSyncGroupRejectsAmbiguousOrConflictingIdentity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		resources []Group
		want      error
	}{
		{name: "duplicate external", resources: []Group{{ID: "a", ExternalID: "group-1", DisplayName: "Engineering"}, {ID: "b", ExternalID: "group-1", DisplayName: "Engineering"}}, want: ErrAmbiguous},
		{name: "duplicate display", resources: []Group{{ID: "a", DisplayName: "Engineering"}, {ID: "b", DisplayName: "Engineering"}}, want: ErrAmbiguous},
		{name: "managed conflict", resources: []Group{{ID: "a", ExternalID: "other", DisplayName: "Engineering"}}, want: ErrIdentifierChanged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					if tc.name == "managed conflict" && strings.Contains(r.URL.Query().Get("filter"), "externalId") {
						writeGroupList(w, nil)
					} else {
						writeGroupList(w, tc.resources)
					}
					return
				}
				t.Fatal("mutation after unsafe lookup")
			}))
			defer server.Close()
			_, err := client.SyncGroup(context.Background(), testGroup())
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want=%v", err, tc.want)
			}
		})
	}
}

func TestGroupValidationRejectsDuplicatesMalformedAndOversize(t *testing.T) {
	t.Parallel()
	client, server := testClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("invalid group reached transport") }))
	// t.Cleanup runs after the parallel subtests below finish; a defer here
	// would close the server before they resume.
	t.Cleanup(server.Close)
	for name, group := range map[string]Group{
		"duplicate member": {ExternalID: "group-1", DisplayName: "Engineering", Members: []GroupMember{{Value: "user-1"}, {Value: "user-1"}}},
		"slash member id":  {ExternalID: "group-1", DisplayName: "Engineering", Members: []GroupMember{{Value: "user/1"}}},
		"invalid utf8":     {ExternalID: string([]byte{0xff}), DisplayName: "Engineering"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := client.SyncGroup(context.Background(), group); !errors.Is(err, ErrInvalidGroup) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	oversize, err := New(Config{BaseURL: server.URL + "/scim/v2", Token: "secret", HTTPClient: server.Client(), MaxResponseBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oversize.SyncGroup(context.Background(), testGroup()); !errors.Is(err, ErrInvalidGroup) {
		t.Fatalf("oversize err=%v", err)
	}
}

func TestGroupRejectsMalformedRemoteAndOversizeResponses(t *testing.T) {
	t.Parallel()
	for name, write := range map[string]func(http.ResponseWriter){
		"wrong schema": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/scim+json")
			_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"r","displayName":"Engineering"}`))
		},
		"duplicate member": func(w http.ResponseWriter) {
			writeGroup(w, Group{ID: "r", ExternalID: "group-1", DisplayName: "Engineering", Members: []GroupMember{{Value: "u"}, {Value: "u"}}})
		},
		"oversize": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/scim+json")
			_, _ = w.Write([]byte(strings.Repeat("x", defaultResponseLimit+1)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					write(w)
					return
				}
				t.Fatal("mutation after malformed response")
			}))
			defer server.Close()
			_, err := client.SyncGroup(context.Background(), testGroup())
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestGroupResponseFailureClassification(t *testing.T) {
	t.Parallel()
	for name, status := range map[string]int{
		"rate limited":        http.StatusTooManyRequests,
		"service unavailable": http.StatusServiceUnavailable,
		"bad request":         http.StatusBadRequest,
		"malformed response":  http.StatusOK,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Fatalf("unexpected mutation %s", r.Method)
				}
				w.WriteHeader(status)
				if status == http.StatusOK {
					_, _ = w.Write([]byte("not json"))
				}
			}))
			defer server.Close()

			_, err := client.SyncGroup(context.Background(), testGroup())
			if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
				if !errors.Is(err, ErrRetryable) {
					t.Fatalf("err=%v, want retryable", err)
				}
				return
			}
			if !errors.Is(err, ErrProtocol) || errors.Is(err, ErrRetryable) {
				t.Fatalf("err=%v, want permanent protocol failure", err)
			}
		})
	}
}

func TestGroupPartialResponseBodyIsRetryable(t *testing.T) {
	t.Parallel()
	client, err := New(Config{BaseURL: "https://scim.example.test", Token: "token", HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/scim+json"}}, Body: &partialReadCloser{data: []byte(`{`), err: io.ErrUnexpectedEOF}, Request: r}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SyncGroup(context.Background(), testGroup()); !errors.Is(err, ErrRetryable) {
		t.Fatalf("err=%v", err)
	}
}

func TestDeleteGroupOnlyDeletesManagedAndUnlinkClearsExternalID(t *testing.T) {
	t.Parallel()
	var deleted, unlinked bool
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if strings.Contains(r.URL.Query().Get("filter"), "externalId") {
				writeGroupList(w, []Group{{ID: "remote", ExternalID: "group-1", DisplayName: "Engineering", Members: []GroupMember{{Value: "remote-user"}}}})
				return
			}
			t.Fatal("delete must not use displayName fallback")
		}
		if r.Method == http.MethodPut {
			var got groupPayload
			if json.NewDecoder(r.Body).Decode(&got) != nil || got.ExternalID != nil || !sameMembers(got.Members, []GroupMember{{Value: "remote-user"}}) {
				t.Fatal("unlink did not send externalId null")
			}
			unlinked = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodDelete {
			deleted = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatalf("unexpected method %s", r.Method)
	}))
	defer server.Close()
	group := testGroup()
	result, err := client.DeleteGroup(context.Background(), group, UnlinkRemote)
	if err != nil || result.Action != ActionUnlinked || !unlinked || deleted {
		t.Fatalf("unlink result=%#v err=%v unlinked=%v deleted=%v", result, err, unlinked, deleted)
	}
	result, err = client.DeleteGroup(context.Background(), group, DeleteRemote)
	if err != nil || result.Action != ActionDeleted || !deleted {
		t.Fatalf("delete result=%#v err=%v deleted=%v", result, err, deleted)
	}
}

func TestBodylessGroupCreateLocationMustBeExact(t *testing.T) {
	t.Parallel()
	for name, location := range map[string]string{
		"missing": "",
		"query":   "/scim/v2/Groups/new?x=1",
		"wrong":   "/other/new",
		"dot":     "/scim/v2/Groups/../new",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					writeGroupList(w, nil)
					return
				}
				if location != "" {
					if strings.HasPrefix(location, "/") {
						location = "https://" + r.Host + location
					}
					w.Header().Set("Location", location)
				}
				w.WriteHeader(http.StatusCreated)
			}))
			defer server.Close()
			_, err := client.SyncGroup(context.Background(), testGroup())
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
