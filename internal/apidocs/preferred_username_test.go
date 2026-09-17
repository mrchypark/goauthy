package apidocs

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestPreferredUsernameUpdateContract(t *testing.T) {
	b, err := Document("https://issuer.example", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	op := doc.Paths.Value("/auth/v1/users/{subject}/self/preferred_username").Put
	if op == nil || op.Security == nil || len(*op.Security) != 2 || op.Parameters.GetByInAndName("path", "subject") == nil {
		t.Fatal("missing preferred username authorization/path")
	}
	for _, status := range []int{200, 400, 401, 403, 404, 406, 409, 428, 503} {
		if op.Responses.Status(status) == nil {
			t.Fatalf("missing response %d", status)
		}
	}
	if len(op.Responses.Status(200).Value.Content) != 0 {
		t.Fatal("success must have empty body")
	}
	schema := op.RequestBody.Value.Content["application/json"].Schema.Value
	if schema.Properties["preferred_username"].Value.Pattern != "" {
		t.Fatal("runtime regex must not be hardcoded in OpenAPI")
	}
	for _, tc := range []struct {
		body  string
		valid bool
	}{
		{`{}`, true}, {`{"preferred_username":null,"force_overwrite":null}`, true},
		{`{"preferred_username":"next","force_overwrite":true}`, true},
		{`null`, false}, {`[]`, false}, {`{"preferred_username":5}`, false},
		{`{"force_overwrite":"true"}`, false}, {`{"unknown":true}`, false},
	} {
		var body any
		if err := json.Unmarshal([]byte(tc.body), &body); err != nil {
			t.Fatal(err)
		}
		if err := schema.VisitJSON(body); (err == nil) != tc.valid {
			t.Fatalf("body=%s err=%v", tc.body, err)
		}
	}
}
