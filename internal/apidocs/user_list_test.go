package apidocs

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mrchypark/goauthy/internal/rbac"
)

func TestUserListContract(t *testing.T) {
	b, err := Document("https://issuer.example", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(b)
	if err != nil {
		t.Fatal(err)
	}
	op := doc.Paths.Value("/auth/v1/users").Get
	if op == nil || op.Responses.Status(200) == nil || op.Responses.Status(206) == nil {
		t.Fatal("user list must expose 200 and 206")
	}
	for _, name := range []string{"page_size", "offset", "backwards", "continuation_token", "session_state"} {
		if op.Parameters.GetByInAndName("query", name) == nil {
			t.Errorf("missing query parameter %s", name)
		}
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestUserListWireSamples(t *testing.T) {
	b, err := Document("https://issuer.example", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(b)
	if err != nil {
		t.Fatal(err)
	}
	item := doc.Paths.Value("/auth/v1/users").Get.Responses.Status(200).Value.Content.Get("application/json").Schema.Value.Items.Value
	name, picture, last := "Given", "picture", int64(1700000010)
	for _, actual := range []rbac.UserResponseSimple{{ID: "legacy", Email: ""}, {ID: "user", Email: "user@example.test", GivenName: &name, FamilyName: &name, CreatedAt: 1700000000, LastLogin: &last, PictureID: &picture}} {
		wire, err := json.Marshal(actual)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(wire, &value); err != nil {
			t.Fatal(err)
		}
		if err := item.VisitJSON(value); err != nil {
			t.Fatalf("actual DTO rejected: %v", err)
		}
	}
	emptyWire, err := json.Marshal([]rbac.UserResponseSimple{})
	if err != nil {
		t.Fatal(err)
	}
	if string(emptyWire) != "[]" {
		t.Fatal("empty DTO list is not array")
	}
	samples := []map[string]any{
		{"id": "u1", "email": "u@example.test", "given_name": nil, "family_name": nil, "created_at": float64(0), "last_login": nil, "picture_id": nil},
		{"id": "u2", "email": "u2@example.test", "given_name": "Given", "family_name": "Family", "created_at": float64(1700000000), "last_login": float64(1700000010), "picture_id": "pic"},
	}
	for _, sample := range samples {
		if err := item.VisitJSON(sample); err != nil {
			t.Fatalf("wire sample rejected: %v", err)
		}
	}
	for _, name := range []string{"id", "email", "given_name", "family_name", "created_at", "last_login", "picture_id"} {
		found := false
		for _, required := range item.Required {
			if required == name {
				found = true
			}
		}
		if !found {
			t.Errorf("generated DTO omitted required field %s", name)
		}
	}
}
