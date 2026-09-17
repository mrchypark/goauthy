package apidocs

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mrchypark/goauthy/internal/rbac"
)

func TestUserDetailContract(t *testing.T) {
	b, err := Document("https://issuer.example", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(b)
	if err != nil {
		t.Fatal(err)
	}
	op := doc.Paths.Value("/auth/v1/users/{subject}").Get
	if op == nil || op.Responses.Status(200) == nil || op.Responses.Status(428) == nil {
		t.Fatal("missing detail responses")
	}
	if op.Parameters.GetByInAndName("path", "subject") == nil {
		t.Fatal("missing subject parameter")
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	schema := op.Responses.Status(200).Value.Content["application/json"].Schema.Value
	str := "value"
	ts := int64(1)
	for _, user := range []rbac.UserResponse{
		{ID: "user", Language: "en", Roles: []string{}, Enabled: true, AccountType: "new"},
		{ID: "user", Email: "user@example.test", Language: "en", Roles: []string{"viewer"}, Groups: []string{"team/a"}, Enabled: true, EmailVerified: true, AccountType: "federated_password", GivenName: &str, CreatedAt: 1, LastLogin: &ts, PasswordExpires: &ts, AuthProviderID: &str, UserValues: rbac.UserValuesResponse{Birthdate: &str}},
	} {
		b, err := json.Marshal(user)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]any
		if err = json.Unmarshal(b, &wire); err != nil {
			t.Fatal(err)
		}
		if err = schema.VisitJSON(wire); err != nil {
			t.Fatalf("actual DTO rejected %s: %v", b, err)
		}
		for _, language := range []string{"de", "en", "fr", "ko", "nb", "nl", "ru", "uk", "zhhans"} {
			wire["language"] = language
			if err := schema.VisitJSON(wire); err != nil {
				t.Fatalf("language %s: %v", language, err)
			}
		}
		for _, language := range []any{"", "zh_hans", "en-US", "xx", nil} {
			wire["language"] = language
			if schema.VisitJSON(wire) == nil {
				t.Fatalf("invalid language accepted: %v", language)
			}
		}
		wire["language"] = "en"
		for _, name := range []string{"given_name", "last_login", "groups", "user_values"} {
			old, exists := wire[name]
			wire[name] = nil
			if schema.VisitJSON(wire) == nil {
				t.Fatalf("accepted null %s", name)
			}
			if exists {
				wire[name] = old
			} else {
				delete(wire, name)
			}
		}
		wire["password_phc"] = "not-public"
		if schema.VisitJSON(wire) == nil {
			t.Fatal("accepted extra field")
		}
	}
}
