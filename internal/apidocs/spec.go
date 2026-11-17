package apidocs

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/oidc"
)

// Features mirrors runtime route switches, not hypothetical upstream capabilities.
type Features struct {
	DCR, Passkeys, Recovery, OpenRegistration, Blacklist, WebID, FedCM, Upstream bool
	DCRAnonymous                                                                 bool
	FedCMLanding                                                                 string
}

// Document describes this deployment. It never discovers URLs or fetches remote
// schemas: all operations and schemas come from the checked-in Go contract.
func Document(issuer string, features Features) ([]byte, error) {
	issuer, err := oidc.NormalizeIssuer(issuer)
	if err != nil {
		return nil, err
	}
	cookieName, err := browser.CookieName(issuer)
	if err != nil {
		return nil, err
	}
	components := openapi3.NewComponents()
	components.Schemas = openapi3.Schemas{}
	components.Schemas["Error"] = &openapi3.SchemaRef{Value: openapi3.NewObjectSchema().WithProperties(map[string]*openapi3.Schema{
		"error":             openapi3.NewStringSchema(),
		"error_code":        openapi3.NewStringSchema(),
		"error_description": openapi3.NewStringSchema(),
		"error_uri":         openapi3.NewStringSchema(),
	})}
	components.SecuritySchemes = openapi3.SecuritySchemes{
		"browserSession": {Value: &openapi3.SecurityScheme{Type: "apiKey", In: "cookie", Name: cookieName, Description: "Authenticated, active browser session. Administrative operations also require the goauthy_admin role; Init sessions are not sufficient."}},
		"csrfToken":      {Value: &openapi3.SecurityScheme{Type: "apiKey", In: "header", Name: "X-CSRF-Token", Description: "Session-bound CSRF token; required together with the browser session for the documented mutations."}},
		"bearerToken":    {Value: &openapi3.SecurityScheme{Type: "http", Scheme: "bearer", Description: "OAuth access token with the required audience, scopes and proof binding."}},
		"apiKey":         {Value: &openapi3.SecurityScheme{Type: "apiKey", In: "header", Name: "Authorization", Description: "Use API-Key <name>$<secret>. Only the operation's explicitly permitted access rights are accepted."}},
		"kvBearer":       {Value: &openapi3.SecurityScheme{Type: "http", Scheme: "bearer", Description: "Namespace-scoped KV access credential in the form <id>$<secret>; not an OAuth access token."}},
	}
	doc := &openapi3.T{
		OpenAPI: "3.0.3", Info: &openapi3.Info{Title: "GoAuthy API", Version: runtimeVersion(),
			Description: "GoAuthy deployment API. Optional routes appear only when configured. Swagger UI is read-only; browser CSRF and role requirements still apply."},
		Servers: openapi3.Servers{{URL: issuer}}, Paths: openapi3.NewPaths(), Components: &components,
	}
	for _, add := range []func(*openapi3.T, Features) error{addProtocolOperations, addAccountOperations, addAdminOperations, addKVOperations, addFedCMOperations, addRetirementOperations} {
		if err := add(doc, features); err != nil {
			return nil, fmt.Errorf("build API contract: %w", err)
		}
	}
	if err := addAuthCollectionOperations(doc); err != nil {
		return nil, fmt.Errorf("build API contract: %w", err)
	}
	describeErrorResponses(doc)
	describeLoginHTMLResponses(doc)
	encoded, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	// The library resolves local component references before validating them.
	// External refs are disabled by default and are never enabled here.
	resolved, err := openapi3.NewLoader().LoadFromData(encoded)
	if err != nil {
		return nil, fmt.Errorf("resolve API contract: %w", err)
	}
	if err := resolved.Validate(context.Background()); err != nil {
		return nil, fmt.Errorf("validate API contract: %w", err)
	}
	return encoded, nil
}

func runtimeVersion() string {
	info, ok := debug.ReadBuildInfo()
	return versionFromBuildInfoWithInjected(buildVersion, info, ok)
}

func versionFromBuildInfo(info *debug.BuildInfo, ok bool) string {
	return versionFromBuildInfoWithInjected("", info, ok)
}

// buildVersion is set by release and container builds through -ldflags.
var buildVersion string

func versionFromBuildInfoWithInjected(injected string, info *debug.BuildInfo, ok bool) string {
	if version := strings.TrimPrefix(strings.TrimSpace(injected), "v"); version != "" {
		return version
	}
	if !ok || info == nil {
		return "development"
	}
	if version := strings.TrimPrefix(strings.TrimSpace(info.Main.Version), "v"); version != "" && version != "(devel)" {
		return version
	}
	revision, modified := "", false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if revision != "" {
		if len(revision) > 12 {
			revision = revision[:12]
		}
		if modified {
			revision += "-dirty"
		}
		return "devel+" + revision
	}
	return "development"
}

func describeErrorResponses(doc *openapi3.T) {
	text := &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}
	structured := &openapi3.SchemaRef{Ref: "#/components/schemas/Error"}
	for _, item := range doc.Paths.Map() {
		for _, operation := range item.Operations() {
			for code, response := range operation.Responses.Map() {
				status, err := strconv.Atoi(code)
				if err != nil || status < 400 || response == nil || response.Value == nil || len(response.Value.Content) != 0 {
					continue
				}
				response.Value.Content = openapi3.Content{
					"text/plain":       {Schema: text},
					"application/json": {Schema: structured},
				}
			}
		}
	}
}

func describeLoginHTMLResponses(doc *openapi3.T) {
	text := &openapi3.SchemaRef{Value: openapi3.NewStringSchema()}
	for _, path := range []string{"/account/login", "/auth/login"} {
		item := doc.Paths.Value(path)
		if item == nil || item.Post == nil {
			continue
		}
		for _, status := range []int{http.StatusUnauthorized, http.StatusTooManyRequests} {
			response := item.Post.Responses.Status(status)
			if response == nil || response.Value == nil {
				continue
			}
			if response.Value.Content == nil {
				response.Value.Content = openapi3.Content{}
			}
			response.Value.Content["text/html"] = &openapi3.MediaType{Schema: text}
		}
	}
}
