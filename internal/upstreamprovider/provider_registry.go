package upstreamprovider

import (
	"errors"
	"fmt"
	"strings"
	"context"

	"github.com/mrchypark/rhiza"
)

var (
	ErrProviderNotFound = errors.New("upstream provider: not found")
	ErrInvalidProviderRow = errors.New("upstream provider: invalid registry row")
	ErrVersionMissing    = errors.New("upstream provider: runtime version missing")
)

const providerSecretPurposePrefix = "upstream-provider-secret/v1/"

// ProviderSecretPurpose is the stable purpose used for one provider's
// encrypted client secret. The provider ID is authenticated as part of the
// purpose, so an envelope cannot be replayed for another provider.
func ProviderSecretPurpose(id string) string { return providerSecretPurposePrefix + id }

// RegistryStore reads the persisted upstream-provider registry. It has no
// mutation methods; callers receive the secret column as opaque ciphertext.
type RegistryStore struct {
	db      *rhiza.DB
	keyring EnvelopeKeyring
}

func NewRegistryStore(db *rhiza.DB, keyring EnvelopeKeyring) (*RegistryStore, error) {
	if db == nil || keyring == nil {
		return nil, ErrInvalidConfig
	}
	return &RegistryStore{db: db, keyring: keyring}, nil
}

const providerRegistryColumns = `id,enabled,name,typ,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,client_id,secret,scope,admin_claim_path,admin_claim_value,mfa_claim_path,mfa_claim_value,use_pkce,client_secret_basic,client_secret_post,jwks_endpoint,auto_onboarding,auto_link`

func (s *RegistryStore) Get(ctx context.Context, id string) (ProviderDocument, error) {
	if s == nil || s.db == nil || id == "" {
		return ProviderDocument{}, ErrInvalidConfig
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT ` + providerRegistryColumns + ` FROM auth_providers WHERE id=?`,
		Args: []any{id}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return ProviderDocument{}, err
	}
	if len(result.Rows) == 0 {
		return ProviderDocument{}, ErrProviderNotFound
	}
	if len(result.Rows) != 1 {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	return decodeProviderDocument(result.Rows[0])
}

func (s *RegistryStore) List(ctx context.Context) ([]ProviderDocument, error) {
	if s == nil || s.db == nil {
		return nil, ErrInvalidConfig
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT ` + providerRegistryColumns + ` FROM auth_providers ORDER BY name,id`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return nil, err
	}
	providers := make([]ProviderDocument, 0, len(result.Rows))
	for _, row := range result.Rows {
		provider, err := decodeProviderDocument(row)
		if err != nil {
			return nil, err
		}
		providers = append(providers, provider)
	}
	return providers, nil
}

// SecretCleartext opens the opaque secret from doc using the provider-bound
// purpose. A NULL secret remains nil; this method performs no response shaping.
func (s *RegistryStore) SecretCleartext(doc ProviderDocument) (*string, error) {
	if s == nil || s.keyring == nil {
		return nil, ErrInvalidConfig
	}
	if doc.Secret == nil {
		return nil, nil
	}
	purpose := ProviderSecretPurpose(doc.ID)
	if !validProviderSecretPurpose(purpose) {
		return nil, ErrInvalidProviderRow
	}
	plaintext, err := s.keyring.OpenEnvelope(purpose, doc.Secret)
	if err != nil {
		return nil, err
	}
	cleartext := string(plaintext)
	return &cleartext, nil
}

// GetRuntime returns the provider document and its current runtime version
// from one linearizable joined query. Disabled, missing, or version-missing
// providers fail closed. Secret decryption is not performed; the caller
// decides when cleartext is needed.
func (s *RegistryStore) GetRuntime(ctx context.Context, id string) (ProviderDocument, string, error) {
	if s == nil || s.db == nil || id == "" {
		return ProviderDocument{}, "", ErrInvalidConfig
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT p." + providerRegistryColumns + ", rv.version FROM auth_providers p LEFT JOIN auth_provider_runtime_versions rv ON rv.provider_id=p.id WHERE p.id=? AND p.enabled=1",
		Args:        []any{id},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return ProviderDocument{}, "", err
	}
	if len(result.Rows) == 0 {
		return ProviderDocument{}, "", ErrProviderNotFound
	}
	if len(result.Rows) != 1 {
		return ProviderDocument{}, "", ErrInvalidProviderRow
	}
	row := result.Rows[0]
	if len(row) != ProviderPersistedFieldCount+1 {
		return ProviderDocument{}, "", ErrInvalidProviderRow
	}
	ver := row[ProviderPersistedFieldCount]
	if ver == nil {
		return ProviderDocument{}, "", ErrVersionMissing
	}
	version, ok := ver.(string)
	if !ok || version == "" {
		return ProviderDocument{}, "", ErrVersionMissing
	}
	doc, err := decodeProviderDocument(row[:ProviderPersistedFieldCount])
	if err != nil {
		return ProviderDocument{}, "", err
	}
	return doc, version, nil
}

func validProviderSecretPurpose(purpose string) bool {
	if purpose == "" || len(purpose) > 64 {
		return false
	}
	for _, char := range purpose {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("._/-", char) {
			continue
		}
		return false
	}
	return true
}

func decodeProviderDocument(row []any) (ProviderDocument, error) {
	if len(row) != ProviderPersistedFieldCount {
		return ProviderDocument{}, fmt.Errorf("%w: want %d columns, got %d", ErrInvalidProviderRow, ProviderPersistedFieldCount, len(row))
	}
	id, ok := row[0].(string)
	if !ok || id == "" {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	enabled, ok := providerBool(row[1])
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	name, ok := row[2].(string)
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	typ, ok := row[3].(string)
	if !ok || !AuthProviderType(typ).valid() {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	issuer, ok := row[4].(string)
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	authorizationEndpoint, ok := row[5].(string)
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	tokenEndpoint, ok := row[6].(string)
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	userinfoEndpoint, ok := row[7].(string)
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	clientID, ok := row[8].(string)
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	secret, ok := providerNullableBytes(row[9])
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	scope, ok := row[10].(string)
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	adminClaimPath, ok := providerNullableString(row[11])
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	adminClaimValue, ok := providerNullableString(row[12])
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	mfaClaimPath, ok := providerNullableString(row[13])
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	mfaClaimValue, ok := providerNullableString(row[14])
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	usePKCE, ok := providerBool(row[15])
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	clientSecretBasic, ok := providerBool(row[16])
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	clientSecretPost, ok := providerBool(row[17])
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	jwks, ok := providerNullableString(row[18])
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	autoOnboarding, ok := providerBool(row[19])
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	autoLink, ok := providerBool(row[20])
	if !ok {
		return ProviderDocument{}, ErrInvalidProviderRow
	}
	return ProviderDocument{
		ID: id, Enabled: enabled, Name: name, Typ: AuthProviderType(typ),
		Issuer: issuer, AuthorizationEndpoint: authorizationEndpoint,
		TokenEndpoint: tokenEndpoint, UserinfoEndpoint: userinfoEndpoint,
		ClientID: clientID, Secret: secret, Scope: scope,
		AdminClaimPath: adminClaimPath, AdminClaimValue: adminClaimValue,
		MFAClaimPath: mfaClaimPath, MFAClaimValue: mfaClaimValue,
		UsePKCE: usePKCE, ClientSecretBasic: clientSecretBasic,
		ClientSecretPost: clientSecretPost, JWKS: jwks,
		AutoOnboarding: autoOnboarding, AutoLink: autoLink,
	}, nil
}

func providerBool(value any) (bool, bool) {
	integer, ok := value.(int64)
	return integer == 1, ok && (integer == 0 || integer == 1)
}

func providerNullableString(value any) (*string, bool) {
	if value == nil {
		return nil, true
	}
	text, ok := value.(string)
	if !ok {
		return nil, false
	}
	return &text, true
}

func providerNullableBytes(value any) ([]byte, bool) {
	if value == nil {
		return nil, true
	}
	secret, ok := value.([]byte)
	if !ok {
		return nil, false
	}
	return append([]byte(nil), secret...), true
}
