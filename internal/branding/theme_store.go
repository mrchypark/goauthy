package branding

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
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
	return s.get(ctx, clientID, false)
}

// GetFallback is the public CSS contract: try the client, then the global theme.
func (s *ThemeStore) GetFallback(ctx context.Context, clientID string) (Theme, error) {
	return s.get(ctx, clientID, true)
}

func (s *ThemeStore) get(ctx context.Context, clientID string, fallback bool) (Theme, error) {
	query := `SELECT client_id,version,document_json FROM client_themes WHERE client_id=?`
	args := []any{clientID}
	if fallback {
		query = `SELECT client_id,version,document_json FROM client_themes WHERE client_id IN (?, 'rauthy') ORDER BY CASE WHEN client_id=? THEN 0 ELSE 1 END LIMIT 1`
		args = append(args, clientID)
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: query, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return Theme{}, err
	}
	if len(result.Rows) == 0 {
		return DefaultTheme("rauthy"), nil
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
	if err := theme.Validate(); err != nil {
		return Theme{}, err
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
	statement := rhiza.SQLStatement{SQL: `INSERT INTO client_themes(client_id,version,updated_at_unix_ms,document_json) SELECT ?,1,?,? WHERE (EXISTS(SELECT 1 FROM managed_oauth_clients WHERE id=? AND deleted=0) OR EXISTS(SELECT 1 FROM managed_oauth_client_bootstrap WHERE id=?) OR EXISTS(SELECT 1 FROM dynamic_oauth_clients WHERE client_id=?)) AND ` + apikey.GuardExistsSQL() + ` ON CONFLICT(client_id) DO UPDATE SET version=excluded.version,updated_at_unix_ms=excluded.updated_at_unix_ms,document_json=excluded.document_json`, Args: []any{theme.ClientID, s.now().UTC().UnixMilli(), string(data), theme.ClientID, theme.ClientID, theme.ClientID, id}}
	response, authorized, err := keys.RunMutation(ctx, principal, "Clients", apikey.Update, id, []rhiza.SQLStatement{statement})
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

func (s *ThemeStore) DeleteAuthorized(ctx context.Context, clientID string, keys *apikey.Store, principal *apikey.Principal) error {
	if keys == nil {
		return apikey.ErrForbidden
	}
	id, err := clientFaviconRequestID("theme-delete")
	if err != nil {
		return err
	}
	statement := rhiza.SQLStatement{SQL: `DELETE FROM client_themes WHERE client_id=? AND ` + apikey.GuardExistsSQL(), Args: []any{clientID, id}}
	_, authorized, err := keys.RunMutation(ctx, principal, "Clients", apikey.Delete, id, []rhiza.SQLStatement{statement})
	if err != nil {
		return err
	}
	if !authorized {
		return apikey.ErrForbidden
	}
	return nil
}

// StylesheetURL versions the public CSS URL by the effective stylesheet. This
// also invalidates built-in defaults when a new binary changes their CSS.
func (s *ThemeStore) StylesheetURL(ctx context.Context, clientID string) (string, error) {
	theme, err := s.GetFallback(ctx, clientID)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(theme.CSS()))
	version := binary.BigEndian.Uint64(digest[:8]) & ((1 << 63) - 1)
	return "/auth/v1/theme/" + url.PathEscape(clientID) + "/" + strconv.FormatUint(version, 10), nil
}
