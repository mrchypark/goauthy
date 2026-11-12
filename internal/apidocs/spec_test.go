package apidocs

import (
	"bytes"
	"runtime/debug"
	"strconv"
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

func TestOpenAPIVersionUsesBuildIdentity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		injected string
		info     *debug.BuildInfo
		ok       bool
		want     string
	}{
		{name: "injected release", injected: "v1.4.0", ok: true, want: "1.4.0"},
		{name: "module version", info: &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, ok: true, want: "1.2.3"},
		{name: "vcs revision", info: &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "0123456789abcdef"}}}, ok: true, want: "devel+0123456789ab"},
		{name: "dirty revision", info: &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "short"}, {Key: "vcs.modified", Value: "true"}}}, ok: true, want: "devel+short-dirty"},
		{name: "unknown", ok: false, want: "development"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := versionFromBuildInfoWithInjected(tc.injected, tc.info, tc.ok); got != tc.want {
				t.Fatalf("version=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestEveryErrorResponseHasSchema(t *testing.T) {
	data, err := Document("https://id.example.test", Features{DCR: true, Passkeys: true, Recovery: true, OpenRegistration: true, Blacklist: true, WebID: true, FedCM: true, Upstream: true})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	for path, item := range doc.Paths.Map() {
		for method, operation := range item.Operations() {
			for code, response := range operation.Responses.Map() {
				status, err := strconv.Atoi(code)
				if err != nil || status < 400 {
					continue
				}
				if response == nil || response.Value == nil || len(response.Value.Content) == 0 {
					t.Fatalf("%s %s %s has no response schema", method, path, code)
				}
				for media, content := range response.Value.Content {
					if content == nil || content.Schema == nil {
						t.Fatalf("%s %s %s %s has no schema", method, path, code, media)
					}
				}
			}
		}
	}
}

func TestAccountLoginDocumentsRetryableHTMLErrors(t *testing.T) {
	data, err := Document("https://id.example.test", Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	login := doc.Paths.Value("/account/login").Post
	for _, status := range []int{401, 429} {
		response := login.Responses.Status(status)
		if response == nil || response.Value.Content["text/html"] == nil {
			t.Fatalf("account login %d must document its retryable HTML response", status)
		}
	}
}
