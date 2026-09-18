package apidocs

import (
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestUserCreateContractIsRecoveryGated(t *testing.T) {
	for _, tc := range []struct {
		name     string
		features Features
		present  bool
	}{{"disabled", Features{}, false}, {"enabled", Features{Recovery: true}, true}} {
		t.Run(tc.name, func(t *testing.T) {
			doc := &openapi3.T{Paths: openapi3.NewPaths(), Components: &openapi3.Components{Schemas: openapi3.Schemas{}}}
			if err := addAdminOperations(doc, tc.features); err != nil {
				t.Fatal(err)
			}
			path := doc.Paths.Find("/auth/v1/users")
			if !tc.present {
				if path != nil && path.Post != nil {
					t.Fatal("unexpected create route")
				}
				return
			}
			if path == nil || path.Post == nil {
				t.Fatal("missing create route")
			}
			schema := path.Post.RequestBody.Value.Content.Get("application/json").Schema.Value
			preferred := schema.Properties["preferred_username"].Value
			if preferred.Pattern != "" || !preferred.Nullable || !strings.Contains(preferred.Description, "Runtime") || !strings.Contains(preferred.Description, "exempts required and blacklist") {
				t.Fatal("preferred username schema must describe runtime policy and admin exemption")
			}
			for _, field := range []string{"email", "language", "roles"} {
				if schema.Properties[field] == nil {
					t.Fatalf("missing %s", field)
				}
			}
			for _, field := range []string{"email", "language", "roles"} {
				found := false
				for _, required := range schema.Required {
					if required == field {
						found = true
					}
				}
				if !found {
					t.Fatalf("%s not required", field)
				}
			}
			if schema.Properties["user_expires"].Value.Min == nil || *schema.Properties["user_expires"].Value.Min != 1719784800 {
				t.Fatal("expiry lower bound missing")
			}
			if path.Post.Responses.Status(200) == nil || path.Post.Responses.Status(406) == nil || path.Post.Responses.Status(403) == nil {
				t.Fatal("create statuses incomplete")
			}
			for _, tc := range []struct {
				name, field string
				value       any
				valid       bool
			}{
				{"empty roles", "roles", []any{}, true},
				{"missing email", "email", nil, false},
				{"null roles", "roles", nil, false},
				{"nullable groups", "groups", nil, true},
				{"nullable name", "given_name", nil, true},
				{"nullable expiry", "user_expires", nil, true},
				{"early expiry", "user_expires", float64(1), false},
				{"role dot", "roles", []any{"role.name"}, true},
				{"group dot", "groups", []any{"group.name"}, false},
				{"duplicate roles", "roles", []any{"viewer", "viewer"}, false},
				{"email independent of timezone limit", "email", strings.Repeat("a", 60) + "@example.test", true},
				{"long timezone", "tz", strings.Repeat("a", 49), false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					value := map[string]any{"email": "a@example.test", "language": "en", "roles": []any{}}
					value[tc.field] = tc.value
					if tc.name == "missing email" {
						delete(value, "email")
					}
					err := schema.VisitJSON(value)
					if tc.valid != (err == nil) {
						t.Fatalf("schema validation err=%v", err)
					}
				})
			}
		})
	}
}
