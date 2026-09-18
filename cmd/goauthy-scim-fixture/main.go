// Command goauthy-scim-fixture is a deterministic, test-only SCIM 2.0 user provider.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxBody        = 8 << 10
	maxHeaderBytes = 16 << 10
	maxPathBytes   = 1024
	maxQueryBytes  = 8 << 10
	maxFilterBytes = 2*512 + 32
	maxUsers       = 1024
	maxGroups      = 1024
	maxCalls       = 1024
	tlsAddr        = ":8444"
	adminAddr      = "127.0.0.1:8083"
	userSchema     = "urn:ietf:params:scim:schemas:core:2.0:User"
	groupSchema    = "urn:ietf:params:scim:schemas:core:2.0:Group"
	listSchema     = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	patchSchema    = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

type config struct{ addr, adminAddr, certFile, keyFile, token string }

func configFromEnv(getenv func(string) string) (config, error) {
	c := config{addr: getenv("SCIM_FIXTURE_ADDR"), adminAddr: getenv("SCIM_FIXTURE_ADMIN_ADDR"), certFile: getenv("SCIM_FIXTURE_TLS_CERT_FILE"), keyFile: getenv("SCIM_FIXTURE_TLS_KEY_FILE"), token: getenv("SCIM_FIXTURE_BEARER_TOKEN")}
	if c.addr == "" {
		c.addr = tlsAddr
	}
	if c.adminAddr == "" {
		c.adminAddr = adminAddr
	}
	if c.certFile == "" || c.keyFile == "" || !validText(c.token, 1024) {
		return config{}, errors.New("SCIM_FIXTURE_TLS_CERT_FILE, SCIM_FIXTURE_TLS_KEY_FILE, and SCIM_FIXTURE_BEARER_TOKEN are required")
	}
	if err := loopbackAddr(c.adminAddr); err != nil {
		return config{}, fmt.Errorf("SCIM_FIXTURE_ADMIN_ADDR: %w", err)
	}
	return c, nil
}

func validText(v string, limit int) bool {
	return v != "" && len(v) <= limit && strings.TrimSpace(v) == v
}
func loopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return errors.New("must use a loopback address")
	}
	return nil
}

type user struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id"`
	ExternalID string   `json:"externalId,omitempty"`
	UserName   string   `json:"userName"`
	Active     bool     `json:"active"`
}
type groupMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}
type group struct {
	Schemas     []string      `json:"schemas"`
	ID          string        `json:"id"`
	ExternalID  string        `json:"externalId,omitempty"`
	DisplayName string        `json:"displayName"`
	Members     []groupMember `json:"members"`
}
type call struct {
	Number uint64 `json:"number"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Filter string `json:"filter,omitempty"`
}
type state struct {
	token                         string
	mu                            sync.Mutex
	users                         map[string]user
	groups                        map[string]group
	nextID, nextGroupID, requests uint64
	mode                          string
	calls                         []call
}

func newState(token string) *state { s := &state{token: token}; s.resetLocked(); return s }
func (s *state) resetLocked() {
	s.users = make(map[string]user)
	s.groups = make(map[string]group)
	s.nextID = 1
	s.nextGroupID = 1
	s.requests = 0
	s.mode = "success"
	s.calls = nil
}
func (s *state) reset() { s.mu.Lock(); s.resetLocked(); s.mu.Unlock() }

func (s *state) publicHandler() http.Handler { return http.HandlerFunc(s.serveSCIM) }
func (s *state) serveSCIM(w http.ResponseWriter, r *http.Request) {
	q, ok := validTarget(r)
	if !ok {
		s.scimError(w, http.StatusBadRequest, "invalid request target")
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		s.scimError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !validRequest(r, q) {
		s.scimError(w, http.StatusBadRequest, "invalid request target")
		return
	}
	s.mu.Lock()
	s.requests++
	c := call{Number: s.requests, Method: r.Method, Path: r.URL.Path, Filter: q.Get("filter")}
	if len(s.calls) == maxCalls {
		copy(s.calls, s.calls[1:])
		s.calls = s.calls[:maxCalls-1]
	}
	s.calls = append(s.calls, c)
	mode := s.mode
	s.mu.Unlock()
	if mode != "success" {
		s.modeResponse(w, r, mode)
		return
	}
	switch {
	case r.URL.Path == "/scim/v2/Users":
		switch r.Method {
		case http.MethodGet:
			s.listUsers(w, q)
		case http.MethodPost:
			s.createUser(w, r)
		default:
			s.method(w, r, "GET, POST")
		}
	case strings.HasPrefix(r.URL.Path, "/scim/v2/Users/") && strings.Count(strings.TrimPrefix(r.URL.Path, "/scim/v2/Users/"), "/") == 0:
		id := strings.TrimPrefix(r.URL.Path, "/scim/v2/Users/")
		if !validText(id, 128) {
			s.scimError(w, http.StatusBadRequest, "invalid id")
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.getUser(w, id)
		case http.MethodPut:
			s.putUser(w, r, id)
		case http.MethodPatch:
			s.unlinkUser(w, r, id)
		case http.MethodDelete:
			s.deleteUser(w, id)
		default:
			s.method(w, r, "GET, PUT, PATCH, DELETE")
		}
	case r.URL.Path == "/scim/v2/Groups":
		switch r.Method {
		case http.MethodGet:
			s.listGroups(w, q)
		case http.MethodPost:
			s.createGroup(w, r)
		default:
			s.method(w, r, "GET, POST")
		}
	case strings.HasPrefix(r.URL.Path, "/scim/v2/Groups/") && strings.Count(strings.TrimPrefix(r.URL.Path, "/scim/v2/Groups/"), "/") == 0:
		id := strings.TrimPrefix(r.URL.Path, "/scim/v2/Groups/")
		if !validText(id, 128) {
			s.scimError(w, http.StatusBadRequest, "invalid id")
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.getGroup(w, id)
		case http.MethodPut:
			s.putGroup(w, r, id)
		case http.MethodDelete:
			s.deleteGroup(w, id)
		default:
			s.method(w, r, "GET, PUT, DELETE")
		}
	default:
		s.scimError(w, http.StatusNotFound, "not found")
	}
}

// validTarget bounds every string retained in the call log before recording it.
func validTarget(r *http.Request) (url.Values, bool) {
	if len(r.URL.Path) > maxPathBytes || len(r.URL.RawQuery) > maxQueryBytes {
		return nil, false
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, false
	}
	return q, true
}

func validRequest(r *http.Request, q url.Values) bool {
	switch {
	case r.URL.Path == "/scim/v2/Users" && r.Method == http.MethodGet:
		if q.Get("startIndex") != "1" || q.Get("count") != "100" || len(q) != 3 || len(q.Get("filter")) > maxFilterBytes {
			return false
		}
		_, _, ok := parseFilter(q.Get("filter"))
		return ok
	case r.URL.Path == "/scim/v2/Groups" && r.Method == http.MethodGet:
		if q.Get("startIndex") != "1" || q.Get("count") != "100" || len(q) != 3 || len(q.Get("filter")) > maxFilterBytes {
			return false
		}
		_, _, ok := parseFilter(q.Get("filter"))
		return ok
	case r.URL.Path == "/scim/v2/Users":
		return r.URL.RawQuery == ""
	case strings.HasPrefix(r.URL.Path, "/scim/v2/Users/") && strings.Count(strings.TrimPrefix(r.URL.Path, "/scim/v2/Users/"), "/") == 0:
		return r.URL.RawQuery == "" && validText(strings.TrimPrefix(r.URL.Path, "/scim/v2/Users/"), 128)
	case r.URL.Path == "/scim/v2/Groups":
		return r.URL.RawQuery == ""
	case strings.HasPrefix(r.URL.Path, "/scim/v2/Groups/") && strings.Count(strings.TrimPrefix(r.URL.Path, "/scim/v2/Groups/"), "/") == 0:
		return r.URL.RawQuery == "" && validText(strings.TrimPrefix(r.URL.Path, "/scim/v2/Groups/"), 128)
	default:
		return r.URL.RawQuery == ""
	}
}

func (s *state) modeResponse(w http.ResponseWriter, _ *http.Request, mode string) {
	switch mode {
	case "temporary":
		s.scimError(w, http.StatusServiceUnavailable, "temporary fixture failure")
	case "permanent":
		s.scimError(w, http.StatusBadRequest, "permanent fixture failure")
	case "drop":
		if h, ok := w.(http.Hijacker); ok {
			conn, _, err := h.Hijack()
			if err == nil {
				_ = conn.Close()
				return
			}
		}
		s.scimError(w, http.StatusServiceUnavailable, "dropped fixture response")
	}
}
func (s *state) listUsers(w http.ResponseWriter, q url.Values) {
	field, value, ok := parseFilter(q.Get("filter"))
	if !ok {
		s.scimError(w, http.StatusBadRequest, "invalid filter")
		return
	}
	s.mu.Lock()
	resources := make([]user, 0, 1)
	for _, u := range s.users {
		if (field == "externalId" && u.ExternalID == value) || (field == "userName" && u.UserName == value) {
			resources = append(resources, u)
		}
	}
	s.mu.Unlock()
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	s.json(w, http.StatusOK, struct {
		Schemas   []string `json:"schemas"`
		Resources []user   `json:"Resources"`
		Total     int      `json:"totalResults"`
		Start     int      `json:"startIndex"`
		Items     int      `json:"itemsPerPage"`
	}{[]string{listSchema}, resources, len(resources), 1, len(resources)})
}

func (s *state) listGroups(w http.ResponseWriter, q url.Values) {
	field, value, ok := parseFilter(q.Get("filter"))
	if !ok || field == "userName" {
		s.scimError(w, http.StatusBadRequest, "invalid filter")
		return
	}
	s.mu.Lock()
	resources := make([]group, 0, 1)
	for _, g := range s.groups {
		if (field == "externalId" && g.ExternalID == value) || (field == "displayName" && g.DisplayName == value) {
			resources = append(resources, g)
		}
	}
	s.mu.Unlock()
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	s.json(w, http.StatusOK, struct {
		Schemas   []string `json:"schemas"`
		Resources []group  `json:"Resources"`
		Total     int      `json:"totalResults"`
		Start     int      `json:"startIndex"`
		Items     int      `json:"itemsPerPage"`
	}{[]string{listSchema}, resources, len(resources), 1, len(resources)})
}

func (s *state) createGroup(w http.ResponseWriter, r *http.Request) {
	in, ok := readGroup(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	for _, g := range s.groups {
		if in.ExternalID != "" && g.ExternalID == in.ExternalID || g.DisplayName == in.DisplayName {
			s.mu.Unlock()
			s.scimError(w, http.StatusConflict, "duplicate group")
			return
		}
	}
	if len(s.groups) >= maxGroups {
		s.mu.Unlock()
		s.scimError(w, http.StatusServiceUnavailable, "group limit reached")
		return
	}
	in.ID = "g-" + strconv.FormatUint(s.nextGroupID, 10)
	s.nextGroupID++
	in.Schemas = []string{groupSchema}
	in.Members = canonicalGroupMembers(in.Members)
	s.groups[in.ID] = in
	created := in
	s.mu.Unlock()
	s.json(w, http.StatusCreated, created)
}

func (s *state) getGroup(w http.ResponseWriter, id string) {
	s.mu.Lock()
	g, ok := s.groups[id]
	s.mu.Unlock()
	if !ok {
		s.scimError(w, http.StatusNotFound, "not found")
		return
	}
	s.json(w, http.StatusOK, g)
}

func (s *state) putGroup(w http.ResponseWriter, r *http.Request, id string) {
	in, ok := readGroup(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	if _, ok := s.groups[id]; !ok {
		s.mu.Unlock()
		s.scimError(w, http.StatusNotFound, "not found")
		return
	}
	for otherID, g := range s.groups {
		if otherID != id && ((in.ExternalID != "" && g.ExternalID == in.ExternalID) || g.DisplayName == in.DisplayName) {
			s.mu.Unlock()
			s.scimError(w, http.StatusConflict, "duplicate group")
			return
		}
	}
	in.ID = id
	in.Schemas = []string{groupSchema}
	in.Members = canonicalGroupMembers(in.Members)
	s.groups[id] = in
	updated := in
	s.mu.Unlock()
	s.json(w, http.StatusOK, updated)
}

func (s *state) deleteGroup(w http.ResponseWriter, id string) {
	s.mu.Lock()
	_, ok := s.groups[id]
	delete(s.groups, id)
	s.mu.Unlock()
	if !ok {
		s.scimError(w, http.StatusNotFound, "not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func canonicalGroupMembers(members []groupMember) []groupMember {
	result := append([]groupMember(nil), members...)
	sort.Slice(result, func(i, j int) bool { return result[i].Value < result[j].Value })
	return result
}

func readGroup(w http.ResponseWriter, r *http.Request) (group, bool) {
	var g group
	if !readJSON(w, r, &g) || len(g.Schemas) != 1 || g.Schemas[0] != groupSchema || !validText(g.DisplayName, 512) || len(g.Members) > maxUsers {
		http.Error(w, "invalid group", http.StatusBadRequest)
		return group{}, false
	}
	for _, member := range g.Members {
		if !validText(member.Value, 512) || member.Display != "" && !validText(member.Display, 512) {
			http.Error(w, "invalid group", http.StatusBadRequest)
			return group{}, false
		}
	}
	return g, true
}

func parseFilter(v string) (string, string, bool) {
	for _, field := range []string{"externalId", "userName", "displayName"} {
		prefix := field + ` eq "`
		if strings.HasPrefix(v, prefix) && strings.HasSuffix(v, `"`) {
			raw := strings.TrimSuffix(strings.TrimPrefix(v, prefix), `"`)
			var out strings.Builder
			for i := 0; i < len(raw); i++ {
				if raw[i] == '\\' {
					i++
					if i >= len(raw) || (raw[i] != '\\' && raw[i] != '"') {
						return "", "", false
					}
				}
				out.WriteByte(raw[i])
			}
			if validText(out.String(), 512) {
				return field, out.String(), true
			}
		}
	}
	return "", "", false
}
func (s *state) createUser(w http.ResponseWriter, r *http.Request) {
	in, ok := readUser(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	for _, u := range s.users {
		if u.ExternalID == in.ExternalID || u.UserName == in.UserName {
			s.mu.Unlock()
			s.scimError(w, http.StatusConflict, "duplicate user")
			return
		}
	}
	if len(s.users) >= maxUsers {
		s.mu.Unlock()
		s.scimError(w, http.StatusServiceUnavailable, "user limit reached")
		return
	}
	in.ID = "u-" + strconv.FormatUint(s.nextID, 10)
	s.nextID++
	in.Schemas = []string{userSchema}
	s.users[in.ID] = in
	created := in
	s.mu.Unlock()
	s.json(w, http.StatusCreated, created)
}
func (s *state) getUser(w http.ResponseWriter, id string) {
	s.mu.Lock()
	u, ok := s.users[id]
	s.mu.Unlock()
	if !ok {
		s.scimError(w, http.StatusNotFound, "not found")
		return
	}
	s.json(w, http.StatusOK, u)
}
func (s *state) putUser(w http.ResponseWriter, r *http.Request, id string) {
	in, ok := readUser(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	if _, ok := s.users[id]; !ok {
		s.mu.Unlock()
		s.scimError(w, http.StatusNotFound, "not found")
		return
	}
	for otherID, u := range s.users {
		if otherID != id && (u.ExternalID == in.ExternalID || u.UserName == in.UserName) {
			s.mu.Unlock()
			s.scimError(w, http.StatusConflict, "duplicate user")
			return
		}
	}
	in.ID = id
	in.Schemas = []string{userSchema}
	s.users[id] = in
	updated := in
	s.mu.Unlock()
	s.json(w, http.StatusOK, updated)
}
func (s *state) unlinkUser(w http.ResponseWriter, r *http.Request, id string) {
	var in struct {
		Schemas    []string `json:"schemas"`
		Operations []struct {
			Op   string `json:"op"`
			Path string `json:"path"`
		} `json:"Operations"`
	}
	if !readJSON(w, r, &in) || len(in.Schemas) != 1 || in.Schemas[0] != patchSchema || len(in.Operations) != 1 || in.Operations[0].Op != "remove" || in.Operations[0].Path != "externalId" {
		s.scimError(w, http.StatusBadRequest, "invalid patch")
		return
	}
	s.mu.Lock()
	u, ok := s.users[id]
	if ok {
		u.ExternalID = ""
		s.users[id] = u
	}
	s.mu.Unlock()
	if !ok {
		s.scimError(w, http.StatusNotFound, "not found")
		return
	}
	s.json(w, http.StatusOK, u)
}
func (s *state) deleteUser(w http.ResponseWriter, id string) {
	s.mu.Lock()
	_, ok := s.users[id]
	delete(s.users, id)
	s.mu.Unlock()
	if !ok {
		s.scimError(w, http.StatusNotFound, "not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func readUser(w http.ResponseWriter, r *http.Request) (user, bool) {
	var u user
	if !readJSON(w, r, &u) || len(u.Schemas) != 1 || u.Schemas[0] != userSchema || !validText(u.ExternalID, 512) || !validText(u.UserName, 512) {
		http.Error(w, "invalid user", http.StatusBadRequest)
		return user{}, false
	}
	return u, true
}
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.URL.RawQuery != "" || !strings.EqualFold(strings.Split(r.Header.Get("Content-Type"), ";")[0], "application/scim+json") {
		http.Error(w, "content type must be application/scim+json", http.StatusUnsupportedMediaType)
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil || d.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return false
	}
	return true
}
func (s *state) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (s *state) scimError(w http.ResponseWriter, status int, detail string) {
	s.json(w, status, struct {
		Schemas []string `json:"schemas"`
		Detail  string   `json:"detail"`
		Status  string   `json:"status"`
	}{[]string{"urn:ietf:params:scim:api:messages:2.0:Error"}, detail, strconv.Itoa(status)})
}
func (s *state) method(w http.ResponseWriter, _ *http.Request, allow string) {
	w.Header().Set("Allow", allow)
	s.scimError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (s *state) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/reset", s.adminReset)
	mux.HandleFunc("/admin/mode", s.adminMode)
	mux.HandleFunc("/admin/state", s.adminState)
	mux.HandleFunc("/admin/calls", s.adminCalls)
	mux.HandleFunc("/admin/count", s.adminCount)
	return mux
}
func adminMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.URL.RawQuery != "" {
		http.Error(w, "query not accepted", http.StatusBadRequest)
		return false
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}
func emptyBody(w http.ResponseWriter, r *http.Request) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 0))
	if err != nil || len(b) != 0 {
		http.Error(w, "body not accepted", http.StatusBadRequest)
		return false
	}
	return true
}
func (s *state) adminReset(w http.ResponseWriter, r *http.Request) {
	if !adminMethod(w, r, http.MethodPost) || !emptyBody(w, r) {
		return
	}
	s.reset()
	w.WriteHeader(http.StatusNoContent)
}
func (s *state) adminMode(w http.ResponseWriter, r *http.Request) {
	if !adminMethod(w, r, http.MethodPost) {
		return
	}
	var in struct {
		Mode string `json:"mode"`
	}
	if !readAdminJSON(w, r, &in) || (in.Mode != "success" && in.Mode != "temporary" && in.Mode != "permanent" && in.Mode != "drop") {
		http.Error(w, "invalid mode", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.mode = in.Mode
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
func readAdminJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.EqualFold(strings.Split(r.Header.Get("Content-Type"), ";")[0], "application/json") {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	d.DisallowUnknownFields()
	return d.Decode(v) == nil && d.Decode(&struct{}{}) == io.EOF
}
func (s *state) snapshot() (uint64, string, []user, []call) {
	s.mu.Lock()
	defer s.mu.Unlock()
	users := make([]user, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].ID < users[j].ID })
	calls := append([]call(nil), s.calls...)
	return s.requests, s.mode, users, calls
}
func (s *state) snapshotGroups() []group {
	s.mu.Lock()
	defer s.mu.Unlock()
	groups := make([]group, 0, len(s.groups))
	for _, g := range s.groups {
		g.Members = canonicalGroupMembers(g.Members)
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	return groups
}
func (s *state) adminState(w http.ResponseWriter, r *http.Request) {
	if !adminMethod(w, r, http.MethodGet) {
		return
	}
	n, m, u, c := s.snapshot()
	g := s.snapshotGroups()
	writeAdmin(w, struct {
		Requests uint64  `json:"requests"`
		Mode     string  `json:"mode"`
		Users    []user  `json:"users"`
		Groups   []group `json:"groups"`
		Calls    []call  `json:"calls"`
	}{n, m, u, g, c})
}
func (s *state) adminCalls(w http.ResponseWriter, r *http.Request) {
	if !adminMethod(w, r, http.MethodGet) {
		return
	}
	_, _, _, c := s.snapshot()
	writeAdmin(w, struct {
		Calls []call `json:"calls"`
	}{c})
}
func (s *state) adminCount(w http.ResponseWriter, r *http.Request) {
	if !adminMethod(w, r, http.MethodGet) {
		return
	}
	n, _, _, _ := s.snapshot()
	writeAdmin(w, struct {
		Requests uint64 `json:"requests"`
	}{n})
}
func writeAdmin(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func server(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, MaxHeaderBytes: maxHeaderBytes, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
}
func run() error {
	c, err := configFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	s := newState(c.token)
	public := server(c.addr, s.publicHandler())
	public.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{cert}}
	public.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	admin := server(c.adminAddr, s.adminHandler())
	l, err := net.Listen("tcp", c.addr)
	if err != nil {
		return err
	}
	errCh := make(chan error, 2)
	go func() { errCh <- public.ServeTLS(l, "", "") }()
	go func() { errCh <- admin.ListenAndServe() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = public.Shutdown(shutdown)
	return admin.Shutdown(shutdown)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
