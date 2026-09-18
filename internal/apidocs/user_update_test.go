package apidocs

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mrchypark/goauthy/internal/rbac"
)

func TestUserUpdateContract(t *testing.T) {
	b, err := Document("https://issuer.example", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(b)
	if err != nil {
		t.Fatal(err)
	}
	if err = doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	op := doc.Paths.Value("/auth/v1/users/{subject}").Put
	if op == nil || op.Security == nil || len(*op.Security) != 2 || op.Parameters.GetByInAndName("path", "subject") == nil {
		t.Fatal("missing update authorization/path")
	}
	if !strings.Contains(op.Description, "given_name is required by default") || !strings.Contains(op.Description, "creation is exempt") {
		t.Fatal("missing runtime profile policy contract")
	}
	for _, status := range []int{200, 400, 401, 403, 404, 409, 428, 503} {
		if op.Responses.Status(status) == nil {
			t.Fatalf("missing %d", status)
		}
	}
	schema := op.RequestBody.Value.Content["application/json"].Schema.Value
	for _, tc := range []struct {
		body  string
		valid bool
	}{
		{`{"email":"a@example.test","roles":[],"enabled":false,"email_verified":false}`, true},
		{`{"email":"a@example.test","roles":[],"enabled":true,"email_verified":true,"language":null,"password":null,"user_values":null,"groups":null,"user_expires":null}`, true},
		{`{"email":"a@example.test","roles":[],"email_verified":false}`, false},
		{`{"email":"a@example.test","roles":null,"enabled":true,"email_verified":true}`, false},
		{`{"email":"a@example.test","roles":[],"enabled":null,"email_verified":true}`, false},
		{`{"email":"a@example.test","roles":[],"enabled":true,"email_verified":true,"user_values":{"preferred_username":"different"}}`, false},
		{`{"email":"a@example.test","roles":[],"enabled":true,"email_verified":true,"user_values":{"zip":""}}`, false},
		{`{"email":"a@example.test","roles":[],"enabled":true,"email_verified":true,"user_expires":1}`, false},
	} {
		var value any
		if json.Unmarshal([]byte(tc.body), &value) != nil {
			t.Fatal("bad fixture")
		}
		if err := schema.VisitJSON(value); tc.valid != (err == nil) {
			t.Fatalf("body=%s error=%v", tc.body, err)
		}
	}
	user := rbac.UserResponse{ID: "user", Email: "a@example.test", Language: "en", Roles: []string{}, Enabled: true, AccountType: "password"}
	wire, _ := json.Marshal(user)
	var value any
	if err := json.Unmarshal(wire, &value); err != nil {
		t.Fatal(err)
	}
	if err := op.Responses.Status(200).Value.Content["application/json"].Schema.Value.VisitJSON(value); err != nil {
		t.Fatal(err)
	}
}
