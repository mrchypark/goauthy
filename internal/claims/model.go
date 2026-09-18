// Package claims stores Rauthy-compatible custom attribute and scope policy.
package claims

import (
	"encoding/json"
	"errors"
)

var (
	ErrInvalid         = errors.New("invalid custom claim input")
	ErrNotFound        = errors.New("custom claim resource not found")
	ErrConflict        = errors.New("custom claim revision conflict")
	ErrReserved        = errors.New("reserved OpenID Connect scope")
	ErrUnauthorized    = errors.New("custom claim administrator required")
	ErrInactiveSubject = errors.New("inactive custom claim subject")
)

var defaultScopes = map[string]struct{}{
	"address": {}, "email": {}, "groups": {}, "openid": {}, "phone": {}, "profile": {},
}

type Attribute struct {
	Name         string          `json:"name"`
	Description  string          `json:"desc,omitempty"`
	Default      json.RawMessage `json:"default_value,omitempty"`
	Type         string          `json:"typ,omitempty"`
	UserEditable bool            `json:"user_editable"`
	Revision     int64           `json:"revision"`
}

type Scope struct {
	Name                   string   `json:"scope"`
	AttributeIncludeAccess []string `json:"attr_include_access,omitempty"`
	AttributeIncludeID     []string `json:"attr_include_id,omitempty"`
	ClaimsAtRoot           bool     `json:"claims_at_root"`
	Revision               int64    `json:"revision"`
}

type ClientScopes struct {
	ClientID string   `json:"client_id"`
	Allowed  []string `json:"allowed_scopes"`
	Default  []string `json:"default_scopes"`
	Revision int64    `json:"revision"`
}

// ClientCredentialsClaims is the narrow, administrator-managed claim object
// issued for one configured client_credentials client. Values is nil when the
// policy was explicitly cleared; an empty map is a valid, distinct object.
type ClientCredentialsClaims struct {
	ClientID string
	Values   map[string]json.RawMessage
	AtRoot   bool
	Revision int64
}

// Resolved is a current custom-claims snapshot for a granted scope set.
type Resolved struct {
	ID              map[string]json.RawMessage
	IDRoot          map[string]json.RawMessage
	Access          map[string]json.RawMessage
	AccessRoot      map[string]json.RawMessage
	CatalogRevision int64
}
