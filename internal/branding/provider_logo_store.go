package branding

import (
	"context"
	"errors"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/rhiza"
)

var ErrProviderNotFound = errors.New("auth provider not found")

// ProviderLogoStore persists independently replaceable logo resolutions for
// upstream auth providers. It reuses the LogoAsset and StoredLogo types from
// the client logo store but targets the auth_provider_logos table.
type ProviderLogoStore struct {
	db  *rhiza.DB
	now func() time.Time
}

func NewProviderLogoStore(db *rhiza.DB) (*ProviderLogoStore, error) {
	if db == nil {
		return nil, errors.New("provider logo store requires database")
	}
	return &ProviderLogoStore{db: db, now: time.Now}, nil
}

// Find returns the stored asset for the requested resolution. When the exact
// raster resolution is absent, it falls back to the provider's SVG asset
// within the same provider row set. There is no global or client logo
// fallback.
func (s *ProviderLogoStore) Find(ctx context.Context, providerID, resolution string) (StoredLogo, error) {
	if s == nil || s.db == nil || !validProviderID(providerID) || !validProviderLogoResolution(resolution) {
		return StoredLogo{}, ErrLogoNotFound
	}
	query := "SELECT res,content_type,data,updated FROM auth_provider_logos WHERE auth_provider_id=? AND res=?"
	args := []any{providerID, resolution}
	if resolution != "svg" {
		query = "SELECT res,content_type,data,updated FROM auth_provider_logos WHERE auth_provider_id=? AND res IN (?, 'svg') ORDER BY CASE WHEN res=? THEN 0 ELSE 1 END LIMIT 1"
		args = []any{providerID, resolution, resolution}
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: query, Args: args, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return StoredLogo{}, err
	}
	if len(result.Rows) == 0 {
		return StoredLogo{}, ErrLogoNotFound
	}
	return storedLogoFromRow(result.Rows[0])
}

// ReplaceAuthorized validates the complete already-processed asset batch before
// atomically replacing all stored resolutions for the provider. The provider
// must exist in auth_providers and the API key must carry AuthProviders:Update.
func (s *ProviderLogoStore) ReplaceAuthorized(ctx context.Context, providerID string, assets []LogoAsset, keys *apikey.Store, principal *apikey.Principal) error {
	if s == nil || s.db == nil || !validProviderID(providerID) {
		return ErrInvalidLogo
	}
	if keys == nil {
		return apikey.ErrForbidden
	}
	validated, err := validateProviderLogoBatch(assets)
	if err != nil {
		return err
	}
	requestID, err := clientFaviconRequestID("branding-provider-logo-replace")
	if err != nil {
		return err
	}
	exists, existsArgs := providerExists(providerID)
	proofArgs := append([]any{requestID}, existsArgs...)
	proofArgs = append(proofArgs, requestID)
	statements := []rhiza.SQLStatement{{
		SQL:  "UPDATE api_key_mutation_guards SET request_id=request_id WHERE request_id=? AND " + exists + " AND " + apikey.GuardExistsSQL(),
		Args: proofArgs,
	}, {
		SQL:  "DELETE FROM auth_provider_logos WHERE auth_provider_id=? AND " + exists + " AND " + apikey.GuardExistsSQL(),
		Args: append([]any{providerID}, append(existsArgs, requestID)...),
	}}
	updated := s.now().UTC().UnixMilli()
	for _, asset := range validated {
		statements = append(statements, rhiza.SQLStatement{
			SQL:  "INSERT INTO auth_provider_logos(auth_provider_id,res,content_type,data,updated) SELECT ?,?,?,?,? WHERE " + exists + " AND " + apikey.GuardExistsSQL(),
			Args: append([]any{providerID, asset.Resolution, asset.ContentType, append([]byte(nil), asset.Data...), updated}, append(existsArgs, requestID)...),
		})
	}
	response, authorized, err := keys.RunMutation(ctx, principal, "AuthProviders", apikey.Update, requestID, statements)
	if err != nil {
		return err
	}
	if !authorized {
		return apikey.ErrForbidden
	}
	if response.RowsAffected < 3 {
		return ErrProviderNotFound
	}
	return nil
}

// DeleteAuthorized removes all stored resolutions for the provider in one
// guarded mutation.
func (s *ProviderLogoStore) DeleteAuthorized(ctx context.Context, providerID string, keys *apikey.Store, principal *apikey.Principal) error {
	if s == nil || s.db == nil || !validProviderID(providerID) {
		return ErrLogoNotFound
	}
	if keys == nil {
		return apikey.ErrForbidden
	}
	requestID, err := clientFaviconRequestID("branding-provider-logo-delete")
	if err != nil {
		return err
	}
	exists, existsArgs := providerExists(providerID)
	proofArgs := append([]any{requestID}, existsArgs...)
	proofArgs = append(proofArgs, requestID)
	statements := []rhiza.SQLStatement{{
		SQL:  "UPDATE api_key_mutation_guards SET request_id=request_id WHERE request_id=? AND " + exists + " AND " + apikey.GuardExistsSQL(),
		Args: proofArgs,
	}, {
		SQL:  "DELETE FROM auth_provider_logos WHERE auth_provider_id=? AND " + exists + " AND " + apikey.GuardExistsSQL(),
		Args: append([]any{providerID}, append(existsArgs, requestID)...),
	}}
	response, authorized, err := keys.RunMutation(ctx, principal, "AuthProviders", apikey.Update, requestID, statements)
	if err != nil {
		return err
	}
	if !authorized {
		return apikey.ErrForbidden
	}
	if response.RowsAffected < 3 {
		return ErrProviderNotFound
	}
	return nil
}

// validateProviderLogoBatch validates all assets before any mutation. Favicon
// is rejected. SVG and raster batches must not be mixed.
func validateProviderLogoBatch(assets []LogoAsset) ([]LogoAsset, error) {
	if len(assets) == 0 {
		return nil, ErrInvalidLogo
	}
	seen := make(map[string]bool, len(assets))
	validated := make([]LogoAsset, 0, len(assets))
	hasSVG := false
	hasRaster := false
	for _, asset := range assets {
		if !validProviderLogoResolution(asset.Resolution) || seen[asset.Resolution] || len(asset.Data) == 0 {
			return nil, ErrInvalidLogo
		}
		if (asset.Resolution == "svg") != (asset.ContentType == "image/svg+xml") || asset.Resolution != "svg" && asset.ContentType != "image/webp" {
			return nil, ErrInvalidLogo
		}
		seen[asset.Resolution] = true
		if asset.Resolution == "svg" {
			hasSVG = true
		} else {
			hasRaster = true
		}
		asset.Data = append([]byte(nil), asset.Data...)
		validated = append(validated, asset)
	}
	if hasSVG && hasRaster {
		return nil, ErrInvalidLogo
	}
	return validated, nil
}

func validProviderLogoResolution(value string) bool {
	switch value {
	case "small", "medium", "svg":
		return true
	default:
		return false
	}
}

func validProviderID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func providerExists(providerID string) (string, []any) {
	return "EXISTS(SELECT 1 FROM auth_providers WHERE id=?)", []any{providerID}
}

