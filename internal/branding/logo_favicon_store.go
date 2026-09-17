package branding

import (
	"context"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/rhiza"
)

// ReplaceFaviconAuthorized replaces only the unified favicon asset and removes
// the legacy favicon row in the same guarded mutation. The caller owns any
// raster processing or SVG sanitization; this boundary accepts only the
// resulting WebP or sanitized SVG bytes.
func (s *ClientLogoStore) ReplaceFaviconAuthorized(ctx context.Context, clientID string, asset LogoAsset, keys *apikey.Store, principal *apikey.Principal) error {
	if s == nil || s.db == nil || !validClientID(clientID) {
		return ErrInvalidLogo
	}
	if keys == nil {
		return apikey.ErrForbidden
	}
	if err := validateFaviconAsset(asset); err != nil {
		return err
	}
	requestID, err := clientFaviconRequestID("branding-favicon-replace")
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
		SQL:  `DELETE FROM client_logos WHERE client_id=? AND res='favicon' AND ` + exists + ` AND ` + apikey.GuardExistsSQL(),
		Args: append([]any{clientID}, append(existsArgs, requestID)...),
	}, {
		SQL:  `DELETE FROM client_favicons WHERE client_id=? AND ` + exists + ` AND ` + apikey.GuardExistsSQL(),
		Args: append([]any{clientID}, append(existsArgs, requestID)...),
	}}
	updated := s.now().UTC().UnixMilli()
	statements = append(statements, rhiza.SQLStatement{
		SQL:  `INSERT INTO client_logos(client_id,res,content_type,data,updated) SELECT ?,?,?,?,? WHERE ` + exists + ` AND ` + apikey.GuardExistsSQL(),
		Args: append([]any{clientID, asset.Resolution, asset.ContentType, append([]byte(nil), asset.Data...), updated}, append(existsArgs, requestID)...),
	})
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

// DeleteFaviconAuthorized removes the unified and legacy favicon rows for a
// client in one guarded mutation while preserving every nonfavicon asset.
func (s *ClientLogoStore) DeleteFaviconAuthorized(ctx context.Context, clientID string, keys *apikey.Store, principal *apikey.Principal) error {
	if s == nil || s.db == nil || !validClientID(clientID) {
		return ErrLogoNotFound
	}
	if keys == nil {
		return apikey.ErrForbidden
	}
	requestID, err := clientFaviconRequestID("branding-favicon-delete")
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
		SQL:  `DELETE FROM client_logos WHERE client_id=? AND res='favicon' AND ` + exists + ` AND ` + apikey.GuardExistsSQL(),
		Args: append([]any{clientID}, append(existsArgs, requestID)...),
	}, {
		SQL:  `DELETE FROM client_favicons WHERE client_id=? AND ` + exists + ` AND ` + apikey.GuardExistsSQL(),
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

func validateFaviconAsset(asset LogoAsset) error {
	if asset.Resolution != "favicon" || len(asset.Data) == 0 {
		return ErrInvalidLogo
	}
	if asset.ContentType != "image/webp" && asset.ContentType != "image/svg+xml" {
		return ErrInvalidLogo
	}
	return nil
}
