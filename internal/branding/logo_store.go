package branding

import (
	"context"
	"errors"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/rhiza"
)

var (
	ErrLogoNotFound = errors.New("logo not found")
	ErrInvalidLogo  = errors.New("invalid logo")
)

// StoredLogo is a validated logo asset together with its durable update time.
type StoredLogo struct {
	LogoAsset
	Updated int64
}

// ClientLogoStore persists independently replaceable logo resolutions.
type ClientLogoStore struct {
	db  *rhiza.DB
	now func() time.Time
}

func NewClientLogoStore(db *rhiza.DB) (*ClientLogoStore, error) {
	if db == nil {
		return nil, errors.New("client logo store requires database")
	}
	return &ClientLogoStore{db: db, now: time.Now}, nil
}

// Find returns the requested client asset. Nonfavicon requests fall back to
// the client's SVG asset when the requested raster resolution is absent.
func (s *ClientLogoStore) Find(ctx context.Context, clientID, resolution string) (StoredLogo, error) {
	if s == nil || s.db == nil || !validClientID(clientID) || !validLogoResolution(resolution) {
		return StoredLogo{}, ErrLogoNotFound
	}
	query := `SELECT res,content_type,data,updated FROM client_logos WHERE client_id=? AND res=?`
	args := []any{clientID, resolution}
	if resolution != "favicon" {
		query = `SELECT res,content_type,data,updated FROM client_logos WHERE client_id=? AND res IN (?, 'svg') ORDER BY CASE WHEN res=? THEN 0 ELSE 1 END LIMIT 1`
		args = []any{clientID, resolution, resolution}
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: query, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return StoredLogo{}, err
	}
	if len(result.Rows) == 0 {
		return StoredLogo{}, ErrLogoNotFound
	}
	return storedLogoFromRow(result.Rows[0])
}

// GetFallback returns the public client logo: small for the requested client,
// then small for the global rauthy client.
func (s *ClientLogoStore) GetFallback(ctx context.Context, clientID string) (StoredLogo, error) {
	if s == nil || s.db == nil || !validClientID(clientID) {
		return StoredLogo{}, ErrLogoNotFound
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:  `SELECT res,content_type,data,updated FROM client_logos WHERE client_id IN (?, 'rauthy') AND res IN ('small', 'svg') ORDER BY CASE WHEN client_id=? THEN 0 ELSE 1 END LIMIT 1`,
		Args: []any{clientID, clientID}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return StoredLogo{}, err
	}
	if len(result.Rows) == 0 {
		return StoredLogo{}, ErrLogoNotFound
	}
	return storedLogoFromRow(result.Rows[0])
}

// ReplaceAuthorized validates the complete already-processed asset batch
// before atomically replacing all nonfavicon resolutions. Existing favicons
// are intentionally outside this replacement set.
func (s *ClientLogoStore) ReplaceAuthorized(ctx context.Context, clientID string, assets []LogoAsset, keys *apikey.Store, principal *apikey.Principal) error {
	if s == nil || s.db == nil || !validClientID(clientID) {
		return ErrInvalidLogo
	}
	if keys == nil {
		return apikey.ErrForbidden
	}
	validated, err := validateLogoBatch(assets)
	if err != nil {
		return err
	}
	requestID, err := clientFaviconRequestID("branding-logo-replace")
	if err != nil {
		return err
	}
	exists, existsArgs := logoClientExists(clientID)
	proofArgs := append([]any{requestID}, existsArgs...)
	proofArgs = append(proofArgs, requestID)
	statements := []rhiza.SQLStatement{{
		SQL:  `UPDATE api_key_mutation_guards SET request_id=request_id WHERE request_id=? AND ` + exists + ` AND ` + apikey.GuardExistsSQL(),
		Args: proofArgs,
	}, {
		SQL:  `DELETE FROM client_logos WHERE client_id=? AND res!='favicon' AND ` + exists + ` AND ` + apikey.GuardExistsSQL(),
		Args: append([]any{clientID}, append(existsArgs, requestID)...),
	}}
	updated := s.now().UTC().UnixMilli()
	for _, asset := range validated {
		statements = append(statements, rhiza.SQLStatement{
			SQL:  `INSERT INTO client_logos(client_id,res,content_type,data,updated) SELECT ?,?,?,?,? WHERE ` + exists + ` AND ` + apikey.GuardExistsSQL(),
			Args: append([]any{clientID, asset.Resolution, asset.ContentType, append([]byte(nil), asset.Data...), updated}, append(existsArgs, requestID)...),
		})
	}
	response, authorized, err := keys.RunMutation(ctx, principal, "Clients", apikey.Update, requestID, statements)
	if err != nil {
		return err
	}
	if !authorized {
		return apikey.ErrForbidden
	}
	if response.RowsAffected < 3 {
		return clients.ErrNotFound
	}
	return nil
}

// DeleteAuthorized removes all nonfavicon resolutions while preserving the
// independently managed favicon.
func (s *ClientLogoStore) DeleteAuthorized(ctx context.Context, clientID string, keys *apikey.Store, principal *apikey.Principal) error {
	if s == nil || s.db == nil || !validClientID(clientID) {
		return ErrLogoNotFound
	}
	if keys == nil {
		return apikey.ErrForbidden
	}
	requestID, err := clientFaviconRequestID("branding-logo-delete")
	if err != nil {
		return err
	}
	exists, existsArgs := logoClientExists(clientID)
	proofArgs := append([]any{requestID}, existsArgs...)
	proofArgs = append(proofArgs, requestID)
	statements := []rhiza.SQLStatement{{
		SQL:  `UPDATE api_key_mutation_guards SET request_id=request_id WHERE request_id=? AND ` + exists + ` AND ` + apikey.GuardExistsSQL(),
		Args: proofArgs,
	}, {
		SQL:  `DELETE FROM client_logos WHERE client_id=? AND res!='favicon' AND ` + exists + ` AND ` + apikey.GuardExistsSQL(),
		Args: append([]any{clientID}, append(existsArgs, requestID)...),
	}}
	response, authorized, err := keys.RunMutation(ctx, principal, "Clients", apikey.Update, requestID, statements)
	if err != nil {
		return err
	}
	if !authorized {
		return apikey.ErrForbidden
	}
	if response.RowsAffected < 3 {
		return clients.ErrNotFound
	}
	return nil
}

func storedLogoFromRow(row []any) (StoredLogo, error) {
	if len(row) != 4 {
		return StoredLogo{}, errors.New("invalid logo result")
	}
	resolution, ok := row[0].(string)
	if !ok || !validLogoResolution(resolution) {
		return StoredLogo{}, errors.New("invalid logo resolution")
	}
	contentType, ok := row[1].(string)
	if !ok {
		return StoredLogo{}, errors.New("invalid logo content type")
	}
	data, ok := row[2].([]byte)
	if !ok || len(data) == 0 {
		return StoredLogo{}, errors.New("invalid logo data")
	}
	updated, ok := row[3].(int64)
	if !ok || updated < 0 {
		return StoredLogo{}, errors.New("invalid logo update time")
	}
	return StoredLogo{LogoAsset: LogoAsset{Resolution: resolution, ContentType: contentType, Data: append([]byte(nil), data...)}, Updated: updated}, nil
}

func validateLogoBatch(assets []LogoAsset) ([]LogoAsset, error) {
	if len(assets) == 0 {
		return nil, ErrInvalidLogo
	}
	seen := make(map[string]bool, len(assets))
	validated := make([]LogoAsset, 0, len(assets))
	hasSVG := false
	hasRaster := false
	for _, asset := range assets {
		if !validLogoResolution(asset.Resolution) || seen[asset.Resolution] || len(asset.Data) == 0 {
			return nil, ErrInvalidLogo
		}
		if asset.Resolution == "favicon" {
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

func validLogoResolution(value string) bool {
	switch value {
	case "small", "medium", "large", "custom", "svg", "favicon":
		return true
	default:
		return false
	}
}

func logoClientExists(clientID string) (string, []any) {
	return `(EXISTS(SELECT 1 FROM managed_oauth_clients WHERE id=? AND deleted=0) OR EXISTS(SELECT 1 FROM managed_oauth_client_bootstrap WHERE id=?) OR EXISTS(SELECT 1 FROM dynamic_oauth_clients WHERE client_id=?))`, []any{clientID, clientID, clientID}
}
