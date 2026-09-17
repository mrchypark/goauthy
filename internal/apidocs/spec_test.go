package apidocs

import (
	"bytes"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestDocumentValidDeterministicAndDeploymentSpecific(t *testing.T) {
	all := Features{DCR: true, Passkeys: true, Recovery: true, OpenRegistration: true, Blacklist: true, WebID: true, FedCM: true, Upstream: true, FedCMLanding: "/auth/fedcm-login"}
	for _, features := range []Features{{}, all} {
		first, err := Document("https://id.example.test/tenant", features)
		if err != nil {
			t.Fatal(err)
		}
		for range 4 {
			next, err := Document("https://id.example.test/tenant", features)
			if err != nil || !bytes.Equal(first, next) {
				t.Fatalf("contract nondeterministic: %v", err)
			}
		}
		doc, err := openapi3.NewLoader().LoadFromData(first)
		if err != nil {
			t.Fatal(err)
		}
		if err := doc.Validate(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(doc.Servers) != 1 || doc.Servers[0].URL != "https://id.example.test/tenant" {
			t.Fatal("issuer server does not match deployment")
		}
		if got := doc.Components.SecuritySchemes["browserSession"].Value.Name; got != "__Host-goauthy_session" {
			t.Fatalf("secure browser cookie name=%q", got)
		}
		if (doc.Paths.Value("/oidc/register") != nil) != features.DCR {
			t.Fatal("DCR feature gate differs")
		}
		for path, item := range doc.Paths.Map() {
			for method, op := range item.Operations() {
				if op.OperationID == "" || op.Responses.Len() == 0 {
					t.Fatalf("empty contract for %s %s", method, path)
				}
			}
		}
	}
}
