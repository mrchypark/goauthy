package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

type discoveryMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	DPoPSigningAlgValuesSupported     []string `json:"dpop_signing_alg_values_supported"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ClientIDMetadataDocumentSupported bool     `json:"client_id_metadata_document_supported,omitempty"`
}

// DiscoveryOptions contains only capabilities backed by a configured runtime
// implementation. A configured feature must not be advertised until it is
// safe to serve its complete protocol flow.
type DiscoveryOptions struct {
	PasswordGrantEnabled              bool
	RegistrationEnabled               bool
	ClientIDMetadataDocumentSupported bool
}

type openIDDiscoveryMetadata struct {
	discoveryMetadata
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	BackChannelLogoutSupported        bool     `json:"backchannel_logout_supported"`
	BackChannelLogoutSessionSupported bool     `json:"backchannel_logout_session_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

// DiscoveryHandler serves OAuth 2.0 authorization-server metadata.
func DiscoveryHandler(issuer string, registrationEnabled ...bool) http.Handler {
	return DiscoveryHandlerWithOptions(issuer, DiscoveryOptions{RegistrationEnabled: len(registrationEnabled) != 0 && registrationEnabled[0]})
}

// DiscoveryHandlerWithOptions serves OAuth 2.0 authorization-server metadata
// for the configured capability set.
func DiscoveryHandlerWithOptions(issuer string, options DiscoveryOptions) http.Handler {
	body, err := discoveryDocument(issuer, options)
	return cachedDiscoveryHandler(body, err)
}

// OpenIDDiscoveryHandler serves only the OIDC capabilities implemented by the
// authorization-code and refresh-token paths.
func OpenIDDiscoveryHandler(issuer string, registrationEnabled ...bool) http.Handler {
	return OpenIDDiscoveryHandlerWithOptions(issuer, DiscoveryOptions{RegistrationEnabled: len(registrationEnabled) != 0 && registrationEnabled[0]})
}

// OpenIDDiscoveryHandlerWithOptions serves OIDC discovery metadata for the
// configured capability set.
func OpenIDDiscoveryHandlerWithOptions(issuer string, options DiscoveryOptions) http.Handler {
	body, err := openIDDiscoveryDocument(issuer, options)
	return cachedDiscoveryHandler(body, err)
}

func cachedDiscoveryHandler(body []byte, err error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		digest := sha256.Sum256(body)
		etag := `"` + base64.RawURLEncoding.EncodeToString(digest[:]) + `"`
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
		w.Header().Set("ETag", etag)
		if matchesETag(r.Header.Get("If-None-Match"), etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(body)
	})
}

func discoveryDocument(rawIssuer string, options DiscoveryOptions) ([]byte, error) {
	issuer, err := NormalizeIssuer(rawIssuer)
	if err != nil {
		return nil, err
	}
	return json.Marshal(metadata(issuer, options))
}

func openIDDiscoveryDocument(rawIssuer string, options DiscoveryOptions) ([]byte, error) {
	issuer, err := NormalizeIssuer(rawIssuer)
	if err != nil {
		return nil, err
	}
	return json.Marshal(openIDDiscoveryMetadata{
		discoveryMetadata:                 metadata(issuer, options),
		UserInfoEndpoint:                  issuer + "/oidc/userinfo",
		EndSessionEndpoint:                issuer + "/oidc/logout",
		BackChannelLogoutSupported:        true,
		BackChannelLogoutSessionSupported: true,
		ScopesSupported:                   []string{"openid", "profile", "email", "address", "phone", "goauthy.read", "offline_access", "groups"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"EdDSA"},
		ClaimsSupported:                   []string{"iss", "sub", "aud", "exp", "iat", "nbf", "auth_time", "nonce", "azp", "sid", "at_hash", "amr", "roles", "groups", "email", "email_verified", "preferred_username", "given_name", "family_name", "birthdate", "address", "phone_number", "phone_number_verified", "zoneinfo", "locale"},
	})
}

func metadata(issuer string, options DiscoveryOptions) discoveryMetadata {
	metadata := discoveryMetadata{
		Issuer: issuer, AuthorizationEndpoint: issuer + "/oidc/authorize", TokenEndpoint: issuer + "/oidc/token", JWKSURI: issuer + "/oidc/jwks.json",
		IntrospectionEndpoint: issuer + "/oidc/introspect", RevocationEndpoint: issuer + "/oidc/revoke", DeviceAuthorizationEndpoint: issuer + "/oidc/device",
		GrantTypesSupported: []string{"authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange"}, ResponseTypesSupported: []string{"code"},
		CodeChallengeMethodsSupported: []string{"S256"}, TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic", "client_secret_post"},
		DPoPSigningAlgValuesSupported:     []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"},
		ClientIDMetadataDocumentSupported: options.ClientIDMetadataDocumentSupported,
	}
	if options.PasswordGrantEnabled {
		metadata.GrantTypesSupported = append(metadata.GrantTypesSupported, "password")
	}
	if options.RegistrationEnabled {
		metadata.RegistrationEndpoint = issuer + "/oidc/register"
	}
	return metadata
}
