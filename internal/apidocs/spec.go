package apidocs

import (
	"context"
	"encoding/json"
	"fmt"

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
	components.SecuritySchemes = openapi3.SecuritySchemes{
		"browserSession": {Value: &openapi3.SecurityScheme{Type: "apiKey", In: "cookie", Name: cookieName, Description: "Authenticated, active browser session. Administrative operations also require the rauthy_admin role; Init sessions are not sufficient."}},
		"csrfToken":      {Value: &openapi3.SecurityScheme{Type: "apiKey", In: "header", Name: "X-CSRF-Token", Description: "Session-bound CSRF token; required together with the browser session for the documented mutations."}},
		"bearerToken":    {Value: &openapi3.SecurityScheme{Type: "http", Scheme: "bearer", Description: "OAuth access token with the required audience, scopes and proof binding."}},
		"apiKey":         {Value: &openapi3.SecurityScheme{Type: "apiKey", In: "header", Name: "Authorization", Description: "Use API-Key <name>$<secret>. Only the operation's explicitly permitted access rights are accepted."}},
		"kvBearer":       {Value: &openapi3.SecurityScheme{Type: "http", Scheme: "bearer", Description: "Namespace-scoped KV access credential in the form <id>$<secret>; not an OAuth access token."}},
	}
	doc := &openapi3.T{
		OpenAPI: "3.0.3", Info: &openapi3.Info{Title: "GoAuthy API", Version: "rauthy-v0.36.2",
			Description: "GoAuthy deployment API. Rauthy v0.36.2 is the compatibility target, not a claim of complete parity. Optional routes appear only when configured. Swagger UI is read-only; browser CSRF and role requirements still apply."},
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
