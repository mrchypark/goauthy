package scim

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type partialReadCloser struct {
	data []byte
	err  error
}

func (r *partialReadCloser) Read(p []byte) (int, error) {
	if len(r.data) != 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, r.err
}

func (*partialReadCloser) Close() error { return nil }

func testClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	client, err := New(Config{BaseURL: server.URL + "/scim/v2", Token: "secret", HTTPClient: server.Client()})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client, server
}

func TestNewEnforcesTransportPolicyWithoutMutatingCaller(t *testing.T) {
	callerRedirect := func(*http.Request, []*http.Request) error { return errors.New("caller") }
	caller := &http.Client{CheckRedirect: callerRedirect}
	c, err := New(Config{BaseURL: "https://scim.example.test", Token: "token", HTTPClient: caller})
	if err != nil {
		t.Fatal(err)
	}
	if c.httpClient == caller || c.httpClient.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("client policy was not cloned")
	}
	if caller.CheckRedirect(nil, nil).Error() != "caller" {
		t.Fatal("caller client mutated")
	}
	for _, raw := range []string{"http://scim.example.test", "https://user@scim.example.test", "https://scim.example.test?x=1", "https://scim.example.test/%2fUsers", "https:opaque"} {
		if _, err := New(Config{BaseURL: raw, Token: "token"}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("New(%q) error=%v", raw, err)
		}
	}
}

func TestRetryableTransportAndServerStatus(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()
			if _, err := client.SyncUser(context.Background(), User{ExternalID: "ext", UserName: "alice"}); !errors.Is(err, ErrRetryable) {
				t.Fatalf("err=%v", err)
			}
		})
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	client, err := NewClient(server.URL, "token", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SyncUser(context.Background(), User{ExternalID: "ext", UserName: "alice"}); !errors.Is(err, ErrRetryable) {
		t.Fatalf("TLS certificate err=%v", err)
	}
}

func TestRetryablePartialResponseBody(t *testing.T) {
	client, err := New(Config{BaseURL: "https://scim.example.test", Token: "token", HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/scim+json"}}, Body: &partialReadCloser{data: []byte(`{`), err: io.ErrUnexpectedEOF}, Request: r}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SyncUser(context.Background(), User{ExternalID: "ext", UserName: "alice"}); !errors.Is(err, ErrRetryable) {
		t.Fatalf("err=%v", err)
	}
	if _, err := boundedBody(strings.NewReader("xx"), 1); !errors.Is(err, ErrProtocol) {
		t.Fatalf("oversize err=%v", err)
	}
}

func TestNewCustomRootCAs(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	trustedRoots := x509.NewCertPool()
	trustedRoots.AddCert(server.Certificate())
	wrongRoots := unrelatedRootPool(t)

	for name, roots := range map[string]*x509.CertPool{
		"correct root": trustedRoots,
		"absent root":  nil,
		"wrong root":   wrongRoots,
	} {
		t.Run(name, func(t *testing.T) {
			client, err := New(Config{BaseURL: server.URL, Token: "token", RootCAs: roots})
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.httpClient.Get(server.URL)
			if name == "correct root" {
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				return
			}
			if err == nil {
				response.Body.Close()
				t.Fatal("request unexpectedly trusted server certificate")
			}
		})
	}
}

func unrelatedRootPool(t *testing.T) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated test root"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return roots
}

func TestNewCustomRootCAsClonesSecureTransport(t *testing.T) {
	roots := x509.NewCertPool()
	callerTLS := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "wrong.example.test", InsecureSkipVerify: true}
	callerTransport := &http.Transport{TLSClientConfig: callerTLS}
	caller := &http.Client{Transport: callerTransport}

	client, err := New(Config{BaseURL: "https://scim.example.test", Token: "token", HTTPClient: caller, RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok || transport == callerTransport || transport.TLSClientConfig == callerTLS {
		t.Fatal("secure transport was not cloned")
	}
	if transport.Proxy != nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.TLSClientConfig.ServerName != "" || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("secure transport policy was not retained")
	}
	if transport.TLSClientConfig.RootCAs == roots {
		t.Fatal("root pool was not cloned")
	}
	if callerTransport.TLSClientConfig.MinVersion != tls.VersionTLS13 || callerTransport.TLSClientConfig.RootCAs != roots || callerTransport.TLSClientConfig.ServerName != "wrong.example.test" || !callerTransport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("caller transport mutated")
	}
}

func TestNewRejectsCustomTLSDialHooks(t *testing.T) {
	for name, transport := range map[string]*http.Transport{
		"DialTLS":        {DialTLS: func(string, string) (net.Conn, error) { return nil, errors.New("unexpected") }},
		"DialTLSContext": {DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unexpected") }},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(Config{BaseURL: "https://scim.example.test", Token: "token", HTTPClient: &http.Client{Transport: transport}}); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestSyncUserCreateThenUpdateAndUnchanged(t *testing.T) {
	var mu sync.Mutex
	var remote = User{ID: "r-1", ExternalID: "ext-1", UserName: "alice", Active: false}
	var methods []string
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method+" "+r.URL.Path)
		current := remote
		mu.Unlock()
		if r.Method == http.MethodGet {
			if !strings.Contains(r.URL.Query().Get("filter"), `externalId eq "ext-1"`) {
				writeList(w, nil)
				return
			}
			writeList(w, []User{current})
			return
		}
		if r.Method != http.MethodPut || r.URL.Path != "/scim/v2/Users/r-1" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		var got User
		if json.NewDecoder(r.Body).Decode(&got) != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		mu.Lock()
		remote.UserName, remote.Active = got.UserName, got.Active
		current = remote
		current.Schemas = []string{userSchema}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/scim+json")
		_ = json.NewEncoder(w).Encode(current)
	}))
	defer server.Close()

	got, err := client.SyncUser(context.Background(), User{ExternalID: "ext-1", UserName: "alice", Active: true})
	if err != nil || got.Action != ActionUpdated || got.RemoteID != "r-1" {
		t.Fatalf("update result=%#v err=%v", got, err)
	}
	got, err = client.SyncUser(context.Background(), User{ExternalID: "ext-1", UserName: "alice", Active: true})
	if err != nil || got.Action != ActionUnchanged {
		t.Fatalf("unchanged result=%#v err=%v", got, err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, method := range methods {
		if strings.HasPrefix(method, "POST") {
			t.Fatal("unexpected create")
		}
	}
}

func TestSyncUserCreatesAfterEmptyExternalIDAndExactUsernameSearch(t *testing.T) {
	var paths []string
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.RequestURI())
		if r.Method == http.MethodGet {
			if strings.Contains(r.URL.Query().Get("filter"), "externalId") {
				writeList(w, nil)
				return
			}
			writeList(w, nil)
			return
		}
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/scim+json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"created","externalId":"ext-2","userName":"alice","active":true}`))
		}
	}))
	defer server.Close()
	result, err := client.SyncUser(context.Background(), User{ExternalID: "ext-2", UserName: "alice", Active: true})
	if err != nil || result.Action != ActionCreated || result.RemoteID != "created" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if len(paths) != 3 || !strings.Contains(paths[1], "userName") {
		t.Fatalf("paths=%v", paths)
	}
}

func TestSyncUserRejectsAmbiguousAndIdentifierChange(t *testing.T) {
	for name, resources := range map[string][]User{
		"duplicate": {{ID: "a", ExternalID: "ext", UserName: "alice"}, {ID: "b", ExternalID: "ext", UserName: "alice"}},
		"changed":   {{ID: "a", ExternalID: "other", UserName: "alice"}},
	} {
		t.Run(name, func(t *testing.T) {
			client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					writeList(w, resources)
					return
				}
				t.Fatal("mutation after unsafe lookup")
			}))
			defer server.Close()
			_, err := client.SyncUser(context.Background(), User{ExternalID: "ext", UserName: "alice", Active: true})
			want := ErrAmbiguous
			if name == "changed" {
				want = ErrIdentifierChanged
			}
			if !errors.Is(err, want) {
				t.Fatalf("err=%v want=%v", err, want)
			}
		})
	}
}

func TestDeleteAndUnlinkAreExplicit(t *testing.T) {
	var deleted, unlinked bool
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeList(w, []User{{ID: "remote", ExternalID: "ext", UserName: "alice", Active: true}})
			return
		}
		if r.Method == http.MethodDelete {
			deleted = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodPatch {
			var patch struct {
				Schemas    []string `json:"schemas"`
				Operations []struct {
					Op   string `json:"op"`
					Path string `json:"path"`
				} `json:"Operations"`
			}
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil || len(patch.Schemas) != 1 || patch.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:PatchOp" || len(patch.Operations) != 1 || patch.Operations[0].Op != "remove" || patch.Operations[0].Path != "externalId" {
				t.Fatalf("unlink patch=%+v err=%v", patch, err)
			}
			unlinked = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatal("unexpected mutation")
	}))
	defer server.Close()
	user := User{ExternalID: "ext", UserName: "alice"}
	result, err := client.DeleteUser(context.Background(), user, UnlinkRemote)
	if err != nil || result.Action != ActionUnlinked || deleted || !unlinked {
		t.Fatalf("unlink result=%#v err=%v deleted=%v unlinked=%v", result, err, deleted, unlinked)
	}
	result, err = client.DeleteUser(context.Background(), user, DeleteRemote)
	if err != nil || result.Action != ActionDeleted || !deleted {
		t.Fatalf("delete result=%#v err=%v deleted=%v", result, err, deleted)
	}
}

func TestMappedDeleteTargetsRemoteIDWithoutUserNameFallback(t *testing.T) {
	var calls []string
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.URL.Query().Get("filter") != "" {
			t.Fatalf("mapped delete searched instead of targeting mapping: %s", r.URL.RawQuery)
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/scim+json")
			_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"remote","externalId":"ext","userName":"other","active":true}`))
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("method=%s", r.Method)
		}
	}))
	defer server.Close()
	result, err := client.Reconcile(context.Background(), Request{User: User{ExternalID: "ext", UserName: "alice"}, Delete: true, DeletePolicy: DeleteRemote, remoteID: "remote"})
	if err != nil || result.Action != ActionDeleted || strings.Join(calls, ",") != "GET /scim/v2/Users/remote,DELETE /scim/v2/Users/remote" {
		t.Fatalf("result=%+v err=%v calls=%v", result, err, calls)
	}
}

func TestMappedDeleteRejectsMismatchedExternalID(t *testing.T) {
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("mutation after mismatched mapping: %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/scim+json")
		_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"remote","externalId":"other","userName":"alice","active":true}`))
	}))
	defer server.Close()
	_, err := client.Reconcile(context.Background(), Request{User: User{ExternalID: "ext", UserName: "alice"}, Delete: true, DeletePolicy: DeleteRemote, remoteID: "remote"})
	if !errors.Is(err, ErrIdentifierChanged) {
		t.Fatalf("err=%v", err)
	}
}

func TestMappedDeleteMissingRemoteIsNoop(t *testing.T) {
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/scim/v2/Users/remote" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	result, err := client.Reconcile(context.Background(), Request{User: User{ExternalID: "ext", UserName: "alice"}, Delete: true, DeletePolicy: DeleteRemote, remoteID: "remote"})
	if err != nil || result.Action != ActionNoop {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestListRejectsUnboundedAndNonJSONResponses(t *testing.T) {
	for name, response := range map[string]func(http.ResponseWriter){
		"non-json": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("{}"))
		},
		"partial": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/scim+json")
			_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":2,"Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"a","externalId":"ext","userName":"a"}]}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response(w)
			}))
			defer server.Close()
			_, err := client.SyncUser(context.Background(), User{ExternalID: "ext", UserName: "alice"})
			want := ErrProtocol
			if name == "partial" {
				want = ErrAmbiguous
			}
			if !errors.Is(err, want) {
				t.Fatalf("err=%v want=%v", err, want)
			}
		})
	}
}

func TestRequestsCarryBearerAndDoNotFollowRedirect(t *testing.T) {
	followed := make(chan struct{}, 1)
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/scim/v2/Users" {
			if r.Header.Get("Authorization") != "Bearer secret" {
				t.Errorf("authorization=%q", r.Header.Get("Authorization"))
			}
			w.Header().Set("Location", "/followed")
			w.WriteHeader(http.StatusFound)
			return
		}
		followed <- struct{}{}
	}))
	defer server.Close()
	_, err := client.SyncUser(context.Background(), User{ExternalID: "ext", UserName: "alice"})
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v", err)
	}
	select {
	case <-followed:
		t.Fatal("redirect was followed")
	default:
	}
}

func TestCreateAllowsBodyless201AndRejectsWrongRepresentation(t *testing.T) {
	for name, body := range map[string]string{
		"bodyless": "",
		"wrong-id": `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"new","externalId":"other","userName":"alice"}`,
	} {
		t.Run(name, func(t *testing.T) {
			client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					writeList(w, nil)
					return
				}
				if body != "" {
					w.Header().Set("Content-Type", "application/scim+json")
				} else {
					w.Header().Set("Location", "https://"+r.Host+"/scim/v2/Users/created")
				}
				w.WriteHeader(http.StatusCreated)
				if body != "" {
					_, _ = w.Write([]byte(body))
				}
			}))
			defer server.Close()
			result, err := client.SyncUser(context.Background(), User{ExternalID: "ext", UserName: "alice"})
			if name == "bodyless" {
				if err != nil || result.Action != ActionCreated || result.RemoteID != "created" {
					t.Fatalf("result=%#v err=%v", result, err)
				}
			} else if !errors.Is(err, ErrIdentifierChanged) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestUpdateRejectsChangedRepresentationIdentity(t *testing.T) {
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeList(w, []User{{ID: "remote", ExternalID: "ext", UserName: "alice"}})
			return
		}
		w.Header().Set("Content-Type", "application/scim+json")
		_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"remote","externalId":"ext","userName":"other"}`))
	}))
	defer server.Close()
	_, err := client.SyncUser(context.Background(), User{ExternalID: "ext", UserName: "alice", Active: true})
	if !errors.Is(err, ErrIdentifierChanged) {
		t.Fatalf("err=%v", err)
	}
}

func TestRejectsInvalidUTF8AndWrongDeleteStatus(t *testing.T) {
	called := false
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		writeList(w, []User{{ID: "remote", ExternalID: "ext", UserName: "alice"}})
	}))
	defer server.Close()
	if _, err := client.SyncUser(context.Background(), User{ExternalID: string([]byte{0xff}), UserName: "alice"}); !errors.Is(err, ErrInvalidUser) || called {
		t.Fatalf("invalid utf8 err=%v called=%v", err, called)
	}

	client, server = testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeList(w, []User{{ID: "remote", ExternalID: "ext", UserName: "alice"}})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if _, err := client.DeleteUser(context.Background(), User{ExternalID: "ext", UserName: "alice"}, DeleteRemote); !errors.Is(err, ErrProtocol) {
		t.Fatalf("wrong delete status err=%v", err)
	}
}

func TestRejectsDotRemoteIDs(t *testing.T) {
	for _, id := range []string{".", ".."} {
		client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				writeList(w, []User{{ID: id, ExternalID: "ext", UserName: "alice"}})
				return
			}
			t.Fatal("mutation after invalid remote ID")
		}))
		_, err := client.SyncUser(context.Background(), User{ExternalID: "ext", UserName: "alice"})
		server.Close()
		if !errors.Is(err, ErrProtocol) {
			t.Errorf("id=%q err=%v", id, err)
		}
	}
}

func TestBodylessCreateLocationMustBeExactBaseUserURL(t *testing.T) {
	for name, location := range map[string]string{
		"missing":      "",
		"cross-origin": "https://other.example/Users/new",
		"query":        "/scim/v2/Users/new?x=1",
		"fragment":     "/scim/v2/Users/new#x",
		"dot":          "/scim/v2/Users/../new",
	} {
		t.Run(name, func(t *testing.T) {
			client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					writeList(w, nil)
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
			_, err := client.SyncUser(context.Background(), User{ExternalID: "ext", UserName: "alice"})
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestCreateAndUpdateRejectActiveMismatch(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					if method == http.MethodPut {
						writeList(w, []User{{ID: "remote", ExternalID: "ext", UserName: "alice", Active: false}})
					} else {
						writeList(w, nil)
					}
					return
				}
				w.Header().Set("Content-Type", "application/scim+json")
				_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"remote","externalId":"ext","userName":"alice","active":false}`))
			}))
			defer server.Close()
			_, err := client.SyncUser(context.Background(), User{ExternalID: "ext", UserName: "alice", Active: true})
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func writeList(w http.ResponseWriter, users []User) {
	w.Header().Set("Content-Type", "application/scim+json")
	for i := range users {
		users[i].Schemas = []string{userSchema}
	}
	_ = json.NewEncoder(w).Encode(struct {
		Schemas      []string `json:"schemas"`
		TotalResults int      `json:"totalResults"`
		Resources    []User   `json:"Resources"`
	}{[]string{listResponseSchema}, len(users), users})
}
