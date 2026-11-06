package branding

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/rhiza"
)

func (h *ThemeHandler) LegacyStatus(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, ok := h.authorize(w, r, apikey.Read); !ok {
		return
	}
	result, err := h.store.db.Query(r.Context(), rhiza.QueryRequest{SQL: `SELECT EXISTS(SELECT 1 FROM branding_legacy_resolution WHERE singleton=1), EXISTS(SELECT 1 FROM client_themes WHERE client_id='goauthy'), EXISTS(SELECT 1 FROM client_logos WHERE client_id='goauthy' AND res!='favicon'), EXISTS(SELECT 1 FROM global_brand_themes), EXISTS(SELECT 1 FROM global_brand_logos)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 5 {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"resolved": result.Rows[0][0] == int64(1), "legacy_theme": result.Rows[0][1] == int64(1), "legacy_logo": result.Rows[0][2] == int64(1), "global_theme": result.Rows[0][3] == int64(1), "global_logo": result.Rows[0][4] == int64(1)})
}

func (h *ThemeHandler) LegacyTheme(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, ok := h.authorize(w, r, apikey.Read); !ok {
		return
	}
	theme, err := h.store.get(r.Context(), GlobalBrandID, false, false, true)
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeThemeJSON(w, theme)
}

func (h *ClientLogoHandler) LegacyLogo(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, ok := h.authorize(w, r); !ok {
		return
	}
	logo, err := h.store.find(r.Context(), GlobalBrandID, "small", true)
	if errors.Is(err, ErrLogoNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeClientImage(w, logo, false)
}

// ResolveLegacy records an explicit operator decision and optionally copies
// legacy common settings without deleting or overwriting either namespace.
func (h *ThemeHandler) ResolveLegacy(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	principal, ok := h.authorize(w, r, apikey.Update)
	if !ok {
		return
	}
	var choice struct {
		CopyTheme *bool `json:"copy_theme"`
		CopyLogo  *bool `json:"copy_logo"`
		Confirm   bool  `json:"confirm_client_ownership"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&choice) != nil || !choice.Confirm || choice.CopyTheme == nil || choice.CopyLogo == nil || decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	id, err := clientFaviconRequestID("branding-legacy-resolve")
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	guard := apikey.GuardExistsSQL()
	statements := []rhiza.SQLStatement{}
	one := int64(1)
	if *choice.CopyTheme {
		statements = append(statements, rhiza.SQLStatement{SQL: `SELECT 1 WHERE (NOT EXISTS(SELECT 1 FROM global_brand_themes) OR NOT EXISTS(SELECT 1 FROM client_themes WHERE client_id='goauthy')) AND ` + guard, Args: []any{id}, WantRows: true, ExpectedReturnedRows: &one})
	}
	if *choice.CopyLogo {
		statements = append(statements, rhiza.SQLStatement{SQL: `SELECT 1 WHERE (NOT EXISTS(SELECT 1 FROM global_brand_logos) OR NOT EXISTS(SELECT 1 FROM client_logos WHERE client_id='goauthy' AND res!='favicon')) AND ` + guard, Args: []any{id}, WantRows: true, ExpectedReturnedRows: &one})
	}
	if *choice.CopyTheme {
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO global_brand_themes(client_id,version,updated_at_unix_ms,document_json) SELECT client_id,version,updated_at_unix_ms,document_json FROM client_themes WHERE client_id='goauthy' AND ` + guard, Args: []any{id}})
	}
	if *choice.CopyLogo {
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO global_brand_logos(client_id,res,content_type,data,updated) SELECT client_id,res,content_type,data,updated FROM client_logos WHERE client_id='goauthy' AND res!='favicon' AND ` + guard, Args: []any{id}})
	}
	statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO branding_legacy_resolution(singleton) SELECT 1 WHERE ` + guard + ` RETURNING singleton`, Args: []any{id}, WantRows: true, ExpectedReturnedRows: &one})
	_, authorized, err := h.apiKeys.RunMutation(r.Context(), principal, "Clients", apikey.Update, id, statements)
	if !authorized && err == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if err != nil {
		http.Error(w, "Resolution unavailable; inspect state before retrying", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
