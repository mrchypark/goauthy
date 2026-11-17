package branding

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type ThemeStore struct {
	db  *rhiza.DB
	now func() time.Time
}

func NewThemeStore(db *rhiza.DB) (*ThemeStore, error) {
	if db == nil {
		return nil, errors.New("theme store requires database")
	}
	return &ThemeStore{db: db, now: time.Now}, nil
}

// GetDefault is the admin JSON contract: a missing client uses built-in defaults.
func (s *ThemeStore) GetDefault(ctx context.Context, clientID string) (Theme, error) {
	return s.get(ctx, clientID, false, false, false)
}

// GetFallback is the public CSS contract: try the client, then the global theme.
func (s *ThemeStore) GetFallback(ctx context.Context, clientID string) (Theme, error) {
	return s.get(ctx, clientID, true, false, false)
}

// GetGlobal returns only the explicitly stored common theme.
func (s *ThemeStore) GetGlobal(ctx context.Context) (Theme, error) {
	return s.get(ctx, GlobalBrandID, false, true, false)
}

func (s *ThemeStore) get(ctx context.Context, clientID string, fallback, global, inspectLegacy bool) (Theme, error) {
	query := `SELECT client_id,version,document_json FROM client_themes WHERE client_id=?`
	args := []any{clientID}
	if global {
		query = `SELECT client_id,version,document_json FROM global_brand_themes WHERE client_id=?`
	} else if !inspectLegacy {
		query += ` AND (client_id!='goauthy' OR EXISTS(SELECT 1 FROM branding_legacy_resolution WHERE singleton=1))`
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: query, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Theme{}, err
	}
	if len(result.Rows) == 0 {
		if fallback {
			return s.GetGlobal(ctx)
		}
		return DefaultTheme(GlobalBrandID), nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 3 {
		return Theme{}, errors.New("invalid theme result")
	}
	row := result.Rows[0]
	id, ok := row[0].(string)
	if !ok {
		return Theme{}, errors.New("invalid theme client")
	}
	version, ok := row[1].(int64)
	if !ok {
		return Theme{}, errors.New("invalid theme version")
	}
	document, ok := row[2].(string)
	if !ok {
		return Theme{}, errors.New("invalid theme document")
	}
	theme, err := decodeStoredTheme(id, version, document)
	if err != nil {
		return Theme{}, err
	}
	if err := theme.Validate(); err != nil {
		return Theme{}, err
	}
	return theme, nil
}

func decodeStoredTheme(id string, version int64, document string) (Theme, error) {
	var theme Theme
	if version == 1 {
		if err := json.Unmarshal([]byte(document), &theme); err != nil {
			return Theme{}, err
		}
		if theme.ClientID != id {
			return Theme{}, errors.New("theme client mismatch")
		}
	} else {
		var metadata struct {
			BorderRadius string `json:"border_radius"`
		}
		if err := json.Unmarshal([]byte(document), &metadata); err != nil {
			return Theme{}, err
		}
		theme = DefaultTheme(id)
		theme.BorderRadius = metadata.BorderRadius
	}
	return theme, nil
}

func (s *ThemeStore) Put(ctx context.Context, theme Theme) error {
	if err := theme.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(theme)
	if err != nil {
		return err
	}
	requestID, err := clientFaviconRequestID("theme-put")
	if err != nil {
		return err
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, SQL: `INSERT INTO client_themes(client_id,version,updated_at_unix_ms,document_json) VALUES(?,1,?,?) ON CONFLICT(client_id) DO UPDATE SET version=excluded.version,updated_at_unix_ms=excluded.updated_at_unix_ms,document_json=excluded.document_json`, Args: []any{theme.ClientID, s.now().UTC().UnixMilli(), string(data)}})
	return err
}

func (s *ThemeStore) Delete(ctx context.Context, clientID string) error {
	requestID, err := clientFaviconRequestID("theme-delete")
	if err != nil {
		return err
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, SQL: `DELETE FROM client_themes WHERE client_id=?`, Args: []any{clientID}})
	return err
}

// PutAuthorized fences API-key authorization in the same transaction as the write.
// A nil principal requires the caller's existing browser-admin boundary.
func (s *ThemeStore) PutAuthorized(ctx context.Context, theme Theme, keys *apikey.Store, principal *apikey.Principal) error {
	return s.putAuthorized(ctx, theme, keys, principal, false, false, nil)
}

var ErrThemeConflict = errors.New("theme revision conflict")

func (s *ThemeStore) PutIfAbsentAuthorized(ctx context.Context, theme Theme, keys *apikey.Store, principal *apikey.Principal) error {
	return s.putAuthorized(ctx, theme, keys, principal, false, true, nil)
}

func (s *ThemeStore) PutGlobalAuthorized(ctx context.Context, theme Theme, keys *apikey.Store, principal *apikey.Principal) error {
	if theme.ClientID != GlobalBrandID {
		return errors.New("invalid global theme id")
	}
	return s.putAuthorized(ctx, theme, keys, principal, true, false, nil)
}

type globalThemeState struct {
	theme            Theme
	etag             string
	version, updated int64
	document         string
	present          bool
}

func (s *ThemeStore) globalState(ctx context.Context) (globalThemeState, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT client_id,version,updated_at_unix_ms,document_json FROM global_brand_themes WHERE client_id=?`, Args: []any{GlobalBrandID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return globalThemeState{}, err
	}
	state := globalThemeState{theme: DefaultTheme(GlobalBrandID)}
	if len(result.Rows) == 1 {
		row := result.Rows[0]
		if len(row) != 4 {
			return globalThemeState{}, errors.New("invalid global theme result")
		}
		id, idOK := row[0].(string)
		version, versionOK := row[1].(int64)
		updated, updatedOK := row[2].(int64)
		document, documentOK := row[3].(string)
		if !idOK || id != GlobalBrandID || !versionOK || !updatedOK || !documentOK {
			return globalThemeState{}, errors.New("invalid global theme row")
		}
		theme, err := decodeStoredTheme(id, version, document)
		if err != nil {
			return globalThemeState{}, err
		}
		if err := theme.Validate(); err != nil {
			return globalThemeState{}, err
		}
		state.theme, state.version, state.updated, state.document, state.present = theme, version, updated, document, true
	} else if len(result.Rows) != 0 {
		return globalThemeState{}, errors.New("invalid global theme result")
	}
	state.etag, err = themeETag(state.theme)
	return state, err
}

func themeETag(theme Theme) (string, error) {
	data, err := json.Marshal(theme)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return `"sha256:` + hex.EncodeToString(digest[:]) + `"`, nil
}

// PutGlobalIfMatchAuthorized commits only when the stored common theme still
// matches the representation the caller read. The state fence and write share
// one transaction, so concurrent editors cannot silently overwrite each other.
func (s *ThemeStore) PutGlobalIfMatchAuthorized(ctx context.Context, theme Theme, keys *apikey.Store, principal *apikey.Principal, ifMatch string) error {
	if theme.ClientID != GlobalBrandID {
		return errors.New("invalid global theme id")
	}
	state, err := s.globalState(ctx)
	if err != nil {
		return err
	}
	if ifMatch != state.etag {
		return ErrThemeConflict
	}
	return s.putAuthorized(ctx, theme, keys, principal, true, false, &state)
}

func (s *ThemeStore) putAuthorized(ctx context.Context, theme Theme, keys *apikey.Store, principal *apikey.Principal, global, ifAbsent bool, expected *globalThemeState) error {
	if keys == nil {
		return apikey.ErrForbidden
	}
	if err := theme.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(theme)
	if err != nil {
		return err
	}
	id, err := clientFaviconRequestID("theme-put")
	if err != nil {
		return err
	}
	exists, existsArgs := logoClientExists(theme.ClientID)
	table := "client_themes"
	if global {
		table, exists, existsArgs = "global_brand_themes", "1", nil
	}
	if ifAbsent {
		exists += ` AND NOT EXISTS(SELECT 1 FROM client_themes WHERE client_id=?)`
		existsArgs = append(existsArgs, theme.ClientID)
	}
	if expected != nil {
		if expected.present {
			exists += ` AND EXISTS(SELECT 1 FROM global_brand_themes WHERE client_id=? AND version=? AND updated_at_unix_ms=? AND document_json=?)`
			existsArgs = append(existsArgs, GlobalBrandID, expected.version, expected.updated, expected.document)
		} else {
			exists += ` AND NOT EXISTS(SELECT 1 FROM global_brand_themes)`
		}
	}
	statement := rhiza.SQLStatement{SQL: `INSERT INTO ` + table + `(client_id,version,updated_at_unix_ms,document_json) SELECT ?,1,?,? WHERE ` + exists + ` AND ` + apikey.GuardExistsSQL() + ` ON CONFLICT(client_id) DO UPDATE SET version=excluded.version,updated_at_unix_ms=excluded.updated_at_unix_ms,document_json=excluded.document_json`, Args: append([]any{theme.ClientID, s.now().UTC().UnixMilli(), string(data)}, append(existsArgs, id)...)}
	statements := []rhiza.SQLStatement{statement}
	if !global && theme.ClientID == GlobalBrandID {
		statements = append([]rhiza.SQLStatement{claimEmptyBranding(exists, existsArgs, id)}, statements...)
	}
	response, authorized, err := keys.RunMutation(ctx, principal, "Clients", apikey.Update, id, statements)
	if err != nil {
		return err
	}
	if !authorized {
		return apikey.ErrForbidden
	}
	if response.RowsAffected < 3 {
		if ifAbsent {
			return ErrThemeConflict
		}
		if expected != nil {
			return ErrThemeConflict
		}
		return clients.ErrNotFound
	}
	return nil
}

func (s *ThemeStore) DeleteAuthorized(ctx context.Context, clientID string, keys *apikey.Store, principal *apikey.Principal) error {
	return s.deleteAuthorized(ctx, clientID, keys, principal, false, nil)
}

func (s *ThemeStore) DeleteGlobalAuthorized(ctx context.Context, keys *apikey.Store, principal *apikey.Principal) error {
	return s.deleteAuthorized(ctx, GlobalBrandID, keys, principal, true, nil)
}

func (s *ThemeStore) DeleteGlobalIfMatchAuthorized(ctx context.Context, keys *apikey.Store, principal *apikey.Principal, ifMatch string) error {
	state, err := s.globalState(ctx)
	if err != nil {
		return err
	}
	if ifMatch != state.etag {
		return ErrThemeConflict
	}
	return s.deleteAuthorized(ctx, GlobalBrandID, keys, principal, true, &state)
}

func (s *ThemeStore) deleteAuthorized(ctx context.Context, clientID string, keys *apikey.Store, principal *apikey.Principal, global bool, expected *globalThemeState) error {
	if keys == nil {
		return apikey.ErrForbidden
	}
	id, err := clientFaviconRequestID("theme-delete")
	if err != nil {
		return err
	}
	exists, existsArgs := logoClientExists(clientID)
	table := "client_themes"
	if global {
		table, exists, existsArgs = "global_brand_themes", "1", nil
	}
	if expected != nil {
		if expected.present {
			exists += ` AND EXISTS(SELECT 1 FROM global_brand_themes WHERE client_id=? AND version=? AND updated_at_unix_ms=? AND document_json=?)`
			existsArgs = append(existsArgs, GlobalBrandID, expected.version, expected.updated, expected.document)
		} else {
			exists += ` AND NOT EXISTS(SELECT 1 FROM global_brand_themes)`
		}
	}
	statements := []rhiza.SQLStatement{{SQL: `UPDATE api_key_mutation_guards SET request_id=request_id WHERE request_id=? AND ` + exists + ` AND ` + apikey.GuardExistsSQL(), Args: append([]any{id}, append(existsArgs, id)...)}, {SQL: `DELETE FROM ` + table + ` WHERE client_id=? AND ` + exists + ` AND ` + apikey.GuardExistsSQL(), Args: append([]any{clientID}, append(existsArgs, id)...)}}
	if !global && clientID == GlobalBrandID {
		statements = append([]rhiza.SQLStatement{claimEmptyBranding(exists, existsArgs, id)}, statements...)
	}
	response, authorized, err := keys.RunMutation(ctx, principal, "Clients", apikey.Delete, id, statements)
	if err != nil {
		return err
	}
	if !authorized {
		return apikey.ErrForbidden
	}
	if response.RowsAffected < 3 {
		if expected != nil {
			return ErrThemeConflict
		}
		return clients.ErrNotFound
	}
	return nil
}

// StylesheetURL versions the public CSS URL by the effective stylesheet. This
// also invalidates built-in defaults when a new binary changes their CSS.
func (s *ThemeStore) StylesheetURL(ctx context.Context, clientID string) (string, error) {
	var theme Theme
	var err error
	if clientID == "" {
		theme, err = s.GetGlobal(ctx)
	} else {
		theme, err = s.GetFallback(ctx, clientID)
	}
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(theme.CSS()))
	version := binary.BigEndian.Uint64(digest[:8]) & ((1 << 63) - 1)
	if clientID == "" {
		return "/auth/v1/branding/theme/" + strconv.FormatUint(version, 10), nil
	}
	return "/auth/v1/theme/" + url.PathEscape(clientID) + "/" + strconv.FormatUint(version, 10), nil
}
