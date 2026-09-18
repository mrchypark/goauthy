package upstreamprovider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/rhiza"
)

// ErrProviderExists indicates the provider ID is already taken during create.
var ErrProviderExists = errors.New("upstream provider: already exists")

// authProvidersGroup is the exact apikey authorization group for auth-provider
// mutations. It must match the valid group string in apikey.validGroup.
const authProvidersGroup = "AuthProviders"

// CreateAuthorized persists a new auth provider row atomically. The caller
// supplies the apikey.Store and authenticated principal for the authorization
// guard. When req.ClientSecret is non-nil the secret is sealed through the
// keyring and the mutation routes through ExecuteEnvelope for the master-key
// retirement fence. The provider ID is caller-assigned and must be unique.
func (s *RegistryStore) CreateAuthorized(ctx context.Context, providerID, requestID string, req ProviderRequest, keys *apikey.Store, principal *apikey.Principal) (ProviderDocument, error) {
	if s == nil || s.db == nil || keys == nil || providerID == "" || requestID == "" {
		return ProviderDocument{}, ErrInvalidConfig
	}
	if err := req.Validate(); err != nil {
		return ProviderDocument{}, err
	}
	req = req.Normalize()
	exists, err := providerRowExists(ctx, s.db, providerID)
	if err != nil {
		return ProviderDocument{}, err
	}
	if exists {
		return ProviderDocument{}, ErrProviderExists
	}

	var encryptedSecret []byte
	var writerKeyID string
	if req.ClientSecret != nil {
		purpose := ProviderSecretPurpose(providerID)
		encryptedSecret, err = s.keyring.SealEnvelope(purpose, []byte(*req.ClientSecret))
		if err != nil {
			return ProviderDocument{}, fmt.Errorf("seal provider secret: %w", err)
		}
		writerKeyID, err = s.keyring.PurposeEnvelopeKeyID(purpose, encryptedSecret)
		if err != nil {
			return ProviderDocument{}, fmt.Errorf("authenticate sealed secret: %w", err)
		}
	}


	doc, err := req.ToDocument(providerID, encryptedSecret)
	if err != nil {
		return ProviderDocument{}, err
	}
	stmt := providerInsertStatement(providerID, req, encryptedSecret, requestID)
	version, err := generateRuntimeVersion()
	if err != nil {
		return ProviderDocument{}, fmt.Errorf("generate runtime version: %w", err)
	}
	versionStmt := providerVersionInsertStatement(providerID, version, requestID)

	if writerKeyID != "" {
		response, authorized, err := keys.RunEnvelopeMutation(ctx, writerKeyID, principal, authProvidersGroup, apikey.Create, requestID, []rhiza.SQLStatement{stmt, versionStmt})
		if err != nil {
			return ProviderDocument{}, err
		}
		if !authorized {
			return ProviderDocument{}, apikey.ErrForbidden
		}
		if response.RowsAffected < 4 {
			return ProviderDocument{}, ErrProviderExists
		}
	} else {
		response, authorized, err := keys.RunMutation(ctx, principal, authProvidersGroup, apikey.Create, requestID, []rhiza.SQLStatement{stmt, versionStmt})
		if err != nil {
			return ProviderDocument{}, err
		}
		if !authorized {
			return ProviderDocument{}, apikey.ErrForbidden
		}
		if response.RowsAffected < 4 {
			return ProviderDocument{}, ErrProviderExists
		}
	}

	return doc, nil
}

// UpdateAuthorized replaces all columns of an existing auth provider row
// atomically. The secret is cleared to NULL when req.ClientSecret is nil;
// when non-nil the plaintext is sealed through the keyring. The existence of
// the provider row is verified inside the guarded SQL statement.
func (s *RegistryStore) UpdateAuthorized(ctx context.Context, providerID, requestID string, req ProviderRequest, keys *apikey.Store, principal *apikey.Principal) (ProviderDocument, error) {
	if s == nil || s.db == nil || keys == nil || providerID == "" || requestID == "" {
		return ProviderDocument{}, ErrInvalidConfig
	}
	if err := req.Validate(); err != nil {
		return ProviderDocument{}, err
	}
	req = req.Normalize()

	var encryptedSecret []byte
	var writerKeyID string
	var err error
	if req.ClientSecret != nil {
		purpose := ProviderSecretPurpose(providerID)
		encryptedSecret, err = s.keyring.SealEnvelope(purpose, []byte(*req.ClientSecret))
		if err != nil {
			return ProviderDocument{}, fmt.Errorf("seal provider secret: %w", err)
		}
		writerKeyID, err = s.keyring.PurposeEnvelopeKeyID(purpose, encryptedSecret)
		if err != nil {
			return ProviderDocument{}, fmt.Errorf("authenticate sealed secret: %w", err)
		}
	}


	doc, err := req.ToDocument(providerID, encryptedSecret)
	if err != nil {
		return ProviderDocument{}, err
	}
	stmt := providerUpdateStatement(providerID, req, encryptedSecret, requestID)
	version, err := generateRuntimeVersion()
	if err != nil {
		return ProviderDocument{}, fmt.Errorf("generate runtime version: %w", err)
	}
	versionStmt := providerVersionUpsertStatement(providerID, version, requestID)

	if writerKeyID != "" {
		response, authorized, err := keys.RunEnvelopeMutation(ctx, writerKeyID, principal, authProvidersGroup, apikey.Update, requestID, []rhiza.SQLStatement{stmt, versionStmt})
		if err != nil {
			return ProviderDocument{}, err
		}
		if !authorized {
			return ProviderDocument{}, apikey.ErrForbidden
		}
		if response.RowsAffected < 4 {
			return ProviderDocument{}, ErrProviderNotFound
		}
	} else {
		response, authorized, err := keys.RunMutation(ctx, principal, authProvidersGroup, apikey.Update, requestID, []rhiza.SQLStatement{stmt, versionStmt})
		if err != nil {
			return ProviderDocument{}, err
		}
		if !authorized {
			return ProviderDocument{}, apikey.ErrForbidden
		}
		if response.RowsAffected < 4 {
			return ProviderDocument{}, ErrProviderNotFound
		}
	}

	return doc, nil
}

// providerInsertStatement builds the guarded INSERT for all 21 auth_providers
// columns. The WHERE clause ensures uniqueness and the authorization guard.
func providerInsertStatement(providerID string, req ProviderRequest, encryptedSecret []byte, requestID string) rhiza.SQLStatement {
	return rhiza.SQLStatement{
		SQL: `INSERT INTO auth_providers(id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,secret,scope,admin_claim_path,admin_claim_value,mfa_claim_path,mfa_claim_value,use_pkce,client_secret_basic,client_secret_post,jwks_endpoint,auto_onboarding,auto_link) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM auth_providers WHERE id=?) AND ` + apikey.GuardExistsSQL(),
		Args: []any{
			providerID,
			boolInt64(req.Enabled),
			req.Name,
			string(req.Typ),
			req.Issuer,
			req.AuthorizationEndpoint,
			req.TokenEndpoint,
			req.UserinfoEndpoint,
			req.ClientID,
			nullableSecret(encryptedSecret),
			req.Scope,
			optionalArg(req.AdminClaimPath),
			optionalArg(req.AdminClaimValue),
			optionalArg(req.MFAClaimPath),
			optionalArg(req.MFAClaimValue),
			boolInt64(req.UsePKCE),
			boolInt64(req.ClientSecretBasic),
			boolInt64(req.ClientSecretPost),
			optionalArg(req.JWKS),
			boolInt64(req.AutoOnboarding),
			boolInt64(req.AutoLink),
			providerID,
			requestID,
		},
	}
}

// providerUpdateStatement builds the guarded UPDATE for all 20 non-ID
// auth_providers columns. The WHERE clause verifies existence and the
// authorization guard. Secret is set to NULL when encryptedSecret is nil.
func providerUpdateStatement(providerID string, req ProviderRequest, encryptedSecret []byte, requestID string) rhiza.SQLStatement {
	return rhiza.SQLStatement{
		SQL: `UPDATE auth_providers SET enabled=?,name=?,typ=?,issuer=?,authorization_endpoint=?,token_endpoint=?,userinfo_endpoint=?,client_id=?,secret=?,scope=?,admin_claim_path=?,admin_claim_value=?,mfa_claim_path=?,mfa_claim_value=?,use_pkce=?,client_secret_basic=?,client_secret_post=?,jwks_endpoint=?,auto_onboarding=?,auto_link=? WHERE id=? AND EXISTS (SELECT 1 FROM auth_providers WHERE id=?) AND ` + apikey.GuardExistsSQL(),
		Args: []any{
			boolInt64(req.Enabled),
			req.Name,
			string(req.Typ),
			req.Issuer,
			req.AuthorizationEndpoint,
			req.TokenEndpoint,
			req.UserinfoEndpoint,
			req.ClientID,
			nullableSecret(encryptedSecret),
			req.Scope,
			optionalArg(req.AdminClaimPath),
			optionalArg(req.AdminClaimValue),
			optionalArg(req.MFAClaimPath),
			optionalArg(req.MFAClaimValue),
			boolInt64(req.UsePKCE),
			boolInt64(req.ClientSecretBasic),
			boolInt64(req.ClientSecretPost),
			optionalArg(req.JWKS),
			boolInt64(req.AutoOnboarding),
			boolInt64(req.AutoLink),
			providerID,
			providerID,
			requestID,
		},
	}
}

func providerRowExists(ctx context.Context, db *rhiza.DB, id string) (bool, error) {
	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT 1 FROM auth_providers WHERE id=?`,
		Args:        []any{id},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return false, err
	}
	return len(result.Rows) > 0, nil
}

func nullableSecret(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}

func boolInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// providerMutationRequestID generates a deterministic-looking request ID for
// callers that do not supply their own.
func providerMutationRequestID(prefix, providerID string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + "/" + providerID + "/" + base64.RawURLEncoding.EncodeToString(b), nil
}

func optionalArg(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// generateRuntimeVersion returns a fresh opaque 22-character base64url
// string backed by 128 bits of cryptographic entropy. Each call produces
// a unique value suitable for the runtime version metadata.
func generateRuntimeVersion() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// providerVersionInsertStatement builds a guarded INSERT for the runtime
// version metadata. The WHERE clause ensures the provider row exists
// (created earlier in the same transaction) and the authorization guard.
func providerVersionInsertStatement(providerID, version, requestID string) rhiza.SQLStatement {
	return rhiza.SQLStatement{
		SQL:  "INSERT INTO auth_provider_runtime_versions(provider_id,version) SELECT ?,? WHERE EXISTS (SELECT 1 FROM auth_providers WHERE id=?) AND " + apikey.GuardExistsSQL(),
		Args: []any{providerID, version, providerID, requestID},
	}
}

// providerVersionUpsertStatement builds a guarded INSERT with ON CONFLICT
// that creates or updates the runtime version metadata. The WHERE EXISTS
// subquery ensures no version row is created for a missing provider; the
// authorization guard fences the mutation. This replaces a plain UPDATE
// so that UpdateAuthorized succeeds even when seeded providers lack a
// version row.
func providerVersionUpsertStatement(providerID, version, requestID string) rhiza.SQLStatement {
	return rhiza.SQLStatement{
		SQL: "INSERT INTO auth_provider_runtime_versions(provider_id,version) SELECT ?,? " +
			"WHERE EXISTS (SELECT 1 FROM auth_providers WHERE id=?) AND " + apikey.GuardExistsSQL() +
			" ON CONFLICT(provider_id) DO UPDATE SET version=excluded.version",
		Args: []any{providerID, version, providerID, requestID},
	}
}
