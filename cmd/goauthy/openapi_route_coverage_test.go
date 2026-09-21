package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/apidocs"
)

// TestOpenAPIRouteCoverage keeps the checked-in contract honest when a
// production Handle/HandleFunc route is added. It checks operations, not body
// schemas; those are intentionally catalogued separately.
func TestOpenAPIRouteCoverage(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	want := sourceRoutes(t, filepath.Join(root, "cmd", "goauthy", "main.go"), filepath.Join(root, "cmd", "goauthy", "upstream.go"), filepath.Join(root, "internal", "kv", "http.go"))
	for path, methods := range kvRoutes {
		if want[path] == nil {
			want[path] = map[string]bool{}
		}
		for method := range methods {
			want[path][method] = true
		}
	}
	for path, methods := range extraRoutes {
		if want[path] == nil {
			want[path] = map[string]bool{}
		}
		for method := range methods {
			want[path][method] = true
		}
	}
	docBytes, err := apidocs.Document("http://localhost:8080", apidocs.Features{DCR: true, Passkeys: true, Recovery: true, OpenRegistration: true, Blacklist: true, WebID: true, FedCM: true, FedCMLanding: "/auth/v1/account", Upstream: true})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		t.Fatal(err)
	}
	var missing []string
	for path, methods := range want {
		for method := range methods {
			if _, ok := doc.Paths[path][strings.ToLower(method)]; !ok {
				missing = append(missing, method+" "+path)
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("implemented routes missing from OpenAPI catalog: %s", strings.Join(missing, ", "))
	}
}

var extraRoutes = map[string]map[string]bool{
	"/.well-known/web-identity": {"GET": true},
	"/auth/v1/fed_cm/config":    {"GET": true}, "/auth/v1/fed_cm/accounts": {"GET": true},
	"/auth/v1/fed_cm/client_meta": {"GET": true}, "/auth/v1/fed_cm/token": {"POST": true},
	"/auth/v1/fed_cm/status": {"GET": true}, "/auth/v1/account": {"GET": true, "POST": true},
	"/upstream/{providerID}/start": {"GET": true}, "/upstream/{providerID}/callback": {"GET": true},
	"/auth/v1/blacklist": {"GET": true, "POST": true}, "/auth/v1/blacklist/{ip}": {"GET": true, "PUT": true, "DELETE": true},
	"/auth/v1/users/attr/{name}": {"PUT": true, "DELETE": true},
}

var kvRoutes = map[string]map[string]bool{
	"/auth/v1/kv/ns": {"GET": true, "POST": true}, "/auth/v1/kv/ns/{ns}": {"PUT": true, "DELETE": true},
	"/auth/v1/kv/ns/{ns}/access": {"GET": true, "POST": true}, "/auth/v1/kv/ns/{ns}/access/{id}": {"PUT": true, "DELETE": true},
	"/auth/v1/kv/ns/{ns}/access/{id}/secret": {"POST": true}, "/auth/v1/kv/ns/{ns}/values": {"GET": true, "POST": true, "PUT": true},
	"/auth/v1/kv/ns/{ns}/values/{key}": {"DELETE": true}, "/auth/v1/kv/pub/{ns}/{key}": {"GET": true},
	"/auth/v1/kv/keys": {"GET": true, "PUT": true}, "/auth/v1/kv/keys/{key}": {"GET": true, "DELETE": true},
	"/auth/v1/kv/values": {"GET": true}, "/auth/v1/kv/test": {"GET": true},
}

func sourceRoutes(t *testing.T, files ...string) map[string]map[string]bool {
	t.Helper()
	routes := map[string]map[string]bool{}
	for _, file := range files {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (selector.Sel.Name != "Handle" && selector.Sel.Name != "HandleFunc") {
				return true
			}
			literal, ok := call.Args[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			route, err := strconv.Unquote(literal.Value)
			if err != nil {
				return true
			}
			parts := strings.SplitN(route, " ", 2)
			if len(parts) != 2 || !validMethod(parts[0]) {
				return true
			}
			path := parts[1]
			if path == "/{$}" {
				path = "/"
			}
			if path == "/auth/v1/users/{first}/{second}" {
				path = "/auth/v1/users/{subject}/attr"
			}
			if excludedRoute(path) {
				return true
			}
			if routes[path] == nil {
				routes[path] = map[string]bool{}
			}
			routes[path][parts[0]] = true
			return true
		})
	}
	return routes
}

func validMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		return true
	}
	return false
}
func excludedRoute(path string) bool {
	// Health endpoints are root-only bypasses, outside the issuer API server URL.
	return path == "/livez" || path == "/readyz" || path == "/metrics" || strings.HasPrefix(path, "/auth/v1/docs") || strings.HasSuffix(path, "/{$}")
}
func repoRoot(t *testing.T) string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}
