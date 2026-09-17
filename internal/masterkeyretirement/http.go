// Package masterkeyretirement exposes the authenticated operator surface for
// the replicated master-key retirement barrier.
package masterkeyretirement

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	basePath  = "/auth/v1/master_key_retirement"
	bodyLimit = 8 << 10
)

var validActions = map[string]struct{}{
	"prepare": {}, "fence": {}, "ready": {}, "abort": {},
}

// Handler serves the operator API using API keys only. members is copied at
// construction so requests cannot supply or alter barrier membership.
type Handler struct {
	db      *rhiza.DB
	keys    *apikey.Store
	members []string
	now     func() time.Time
}

// NewHandler creates the retirement handler. A valid topology has exactly
// one standalone member or exactly three cluster members.
func NewHandler(db *rhiza.DB, keys *apikey.Store, members []string) *Handler {
	copyMembers := append([]string(nil), members...)
	return &Handler{db: db, keys: keys, members: copyMembers, now: func() time.Time { return time.Now().UTC() }}
}

// ServeHTTP handles GET /auth/v1/master_key_retirement and POST action
// subpaths. It is also safe to register as the catch-all exact base path so
// unsupported methods receive 405 instead of an accidental 404.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.headers(w)
	if r == nil || r.URL == nil || len(r.URL.Path) > len(basePath)+32 {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	if r.URL.RawQuery != "" {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	fetchSite := r.Header.Values("Sec-Fetch-Site")
	if !safeFetchSite(fetchSite) {
		writeStatus(w, http.StatusForbidden)
		return
	}

	if r.Method == http.MethodGet {
		if r.URL.Path != basePath {
			action := strings.TrimPrefix(r.URL.Path, basePath+"/")
			if _, known := validActions[action]; known {
				w.Header().Set("Allow", "POST")
				writeStatus(w, http.StatusMethodNotAllowed)
				return
			}
			writeStatus(w, http.StatusNotFound)
			return
		}
		h.get(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeStatus(w, http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(r.URL.Path, basePath+"/") {
		w.Header().Set("Allow", "GET, POST")
		writeStatus(w, http.StatusMethodNotAllowed)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, basePath+"/")
	if _, ok := validActions[action]; !ok || strings.Contains(action, "/") || action == "" {
		writeStatus(w, http.StatusNotFound)
		return
	}
	h.mutate(w, r, action)
}

func safeFetchSite(values []string) bool {
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(values[0])) {
	case "same-origin", "same-site", "none":
		return true
	default:
		return false
	}
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authenticate(w, r, apikey.Read)
	if !ok {
		return
	}
	if !h.ready(w) {
		return
	}
	now := h.now().UTC().Truncate(time.Millisecond)
	if now.IsZero() {
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	authorization := h.keys.AuthorizationSnapshotAt(principal, "Secrets", apikey.Read, now)
	barrier, err := storage.LoadMasterKeyRetirementGuarded(r.Context(), h.db, authorization)
	if errors.Is(err, storage.ErrMasterKeyRetirementNotPrepared) {
		// The guarded read intentionally uses one result for both an absent
		// barrier and a denied predicate. Recheck only to map a denied request
		// to 403 without replacing the atomic read.
		if authErr := h.keys.Authorize(r.Context(), principal, "Secrets", apikey.Read); authErr != nil {
			if errors.Is(authErr, apikey.ErrForbidden) {
				writeStatus(w, http.StatusForbidden)
			} else {
				writeStatus(w, http.StatusServiceUnavailable)
			}
			return
		}
		writeStatus(w, http.StatusNotFound)
		return
	}
	if err != nil {
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, barrierResponse(barrier))
}

type prepareRequest struct {
	Epoch            int64  `json:"epoch"`
	OldKeyID         string `json:"old_key_id"`
	ReplacementKeyID string `json:"replacement_key_id"`
}

type epochRequest struct {
	Epoch int64 `json:"epoch"`
}

func (h *Handler) mutate(w http.ResponseWriter, r *http.Request, action string) {
	right := map[string]apikey.Right{"prepare": apikey.Create, "fence": apikey.Update, "ready": apikey.Update, "abort": apikey.Delete}[action]
	principal, ok := h.authenticate(w, r, right)
	if !ok {
		return
	}
	if !h.ready(w) {
		return
	}
	var requestEpoch epochRequest
	var requestPrepare prepareRequest
	if action == "prepare" {
		if !decodeJSON(w, r, &requestPrepare) {
			return
		}
	} else if !decodeJSON(w, r, &requestEpoch) {
		return
	}
	now := h.now().UTC().Truncate(time.Millisecond)
	if now.IsZero() {
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	var (
		barrier storage.MasterKeyRetirement
		err     error
	)
	auth := h.keys.AuthorizationSnapshotAt(principal, "Secrets", right, now)
	switch action {
	case "prepare":
		if requestPrepare.Epoch <= 0 || requestPrepare.OldKeyID == "" || requestPrepare.ReplacementKeyID == "" {
			writeStatus(w, http.StatusBadRequest)
			return
		}
		barrier, err = storage.PrepareMasterKeyRetirementGuarded(r.Context(), h.db, storage.MasterKeyRetirementPrepareRequest{
			Epoch: requestPrepare.Epoch, OldKeyID: requestPrepare.OldKeyID, ReplacementKeyID: requestPrepare.ReplacementKeyID,
			MemberIDs: h.members, PreparedAt: now,
		}, auth)
	case "fence":
		barrier, err = storage.FenceMasterKeyRetirementGuarded(r.Context(), h.db, requestEpoch.Epoch, now, auth)
	case "ready":
		barrier, err = storage.ReadyMasterKeyRetirementGuarded(r.Context(), h.db, requestEpoch.Epoch, now, auth)
	case "abort":
		barrier, err = storage.AbortMasterKeyRetirementGuarded(r.Context(), h.db, requestEpoch.Epoch, now, auth)
	}
	if err != nil {
		h.mutationError(w, r, principal, right, err)
		return
	}
	writeJSON(w, barrierResponse(barrier))
}

func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request, right apikey.Right) (apikey.Principal, bool) {
	authorization, ok := apikey.Authorization(r)
	if !ok {
		writeStatus(w, http.StatusUnauthorized)
		return apikey.Principal{}, false
	}
	if h == nil || h.keys == nil {
		writeStatus(w, http.StatusServiceUnavailable)
		return apikey.Principal{}, false
	}
	principal, err := h.keys.Authenticate(r.Context(), authorization)
	if err != nil {
		writeStatus(w, http.StatusUnauthorized)
		return apikey.Principal{}, false
	}
	if err := h.keys.Authorize(r.Context(), principal, "Secrets", right); err != nil {
		if errors.Is(err, apikey.ErrForbidden) {
			writeStatus(w, http.StatusForbidden)
		} else {
			writeStatus(w, http.StatusServiceUnavailable)
		}
		return apikey.Principal{}, false
	}
	return principal, true
}

func (h *Handler) mutationError(w http.ResponseWriter, r *http.Request, principal apikey.Principal, right apikey.Right, err error) {
	// A key can be revoked after the initial read. Rechecking only chooses the
	// HTTP status; the guarded storage call remains the authorization boundary.
	authorizationErr := h.keys.Authorize(r.Context(), principal, "Secrets", right)
	if errors.Is(authorizationErr, apikey.ErrForbidden) {
		writeStatus(w, http.StatusForbidden)
		return
	}
	if authorizationErr != nil {
		writeStatus(w, http.StatusServiceUnavailable)
		return
	}
	if errors.Is(err, storage.ErrMasterKeyRetirementConflict) {
		writeStatus(w, http.StatusConflict)
		return
	}
	if errors.Is(err, storage.ErrMasterKeyRetirementNotPrepared) {
		writeStatus(w, http.StatusNotFound)
		return
	}
	if strings.Contains(err.Error(), "invalid master-key retirement") || strings.Contains(err.Error(), "requires exactly") {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	writeStatus(w, http.StatusServiceUnavailable)
}

func (h *Handler) ready(w http.ResponseWriter) bool {
	if h == nil || h.db == nil || h.keys == nil || (len(h.members) != 1 && len(h.members) != 3) {
		writeStatus(w, http.StatusServiceUnavailable)
		return false
	}
	return true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	if len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/json" {
		writeStatus(w, http.StatusBadRequest)
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bodyLimit))
	allowed := map[string]struct{}{}
	switch value.(type) {
	case *prepareRequest:
		allowed = map[string]struct{}{"epoch": {}, "old_key_id": {}, "replacement_key_id": {}}
	case *epochRequest:
		allowed = map[string]struct{}{"epoch": {}}
	}
	trimmed := bytes.TrimSpace(body)
	if err != nil || len(trimmed) == 0 || trimmed[0] != '{' || rejectDuplicateFields(body, allowed) != nil {
		writeStatus(w, http.StatusBadRequest)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		writeStatus(w, http.StatusBadRequest)
		return false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		writeStatus(w, http.StatusBadRequest)
		return false
	}
	return true
}

func rejectDuplicateFields(body []byte, allowed map[string]struct{}) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := walkJSON(decoder, 0, allowed); err != nil {
		return err
	}
	_, err := decoder.Token()
	if err != io.EOF {
		return errors.New("trailing json")
	}
	return nil
}

func walkJSON(decoder *json.Decoder, depth int, allowed map[string]struct{}) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		seenFolded := map[string]struct{}{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if _, exists := seen[name]; exists {
				return errors.New("duplicate field")
			}
			if depth == 0 {
				if _, valid := allowed[name]; !valid {
					return errors.New("unknown or non-canonical field")
				}
				folded := strings.ToLower(name)
				if _, collision := seenFolded[folded]; collision {
					return errors.New("case-insensitive field collision")
				}
				seenFolded[folded] = struct{}{}
			}
			seen[name] = struct{}{}
			if err := walkJSON(decoder, depth+1, allowed); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid object")
		}
	case '[':
		for decoder.More() {
			if err := walkJSON(decoder, depth+1, allowed); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid array")
		}
	default:
		return errors.New("invalid JSON root")
	}
	return nil
}

type barrierJSON struct {
	Epoch            int64             `json:"epoch"`
	OldKeyID         string            `json:"old_key_id"`
	ReplacementKeyID string            `json:"replacement_key_id"`
	Membership       []string          `json:"membership"`
	MembershipDigest string            `json:"membership_digest"`
	State            string            `json:"state"`
	PreparedAt       int64             `json:"prepared_at_unix_ms"`
	FencedAt         *int64            `json:"fenced_at_unix_ms,omitempty"`
	ReadyAt          *int64            `json:"ready_at_unix_ms,omitempty"`
	AbortedAt        *int64            `json:"aborted_at_unix_ms,omitempty"`
	Attestations     []attestationJSON `json:"attestations"`
}

type attestationJSON struct {
	NodeID              string     `json:"node_id"`
	BootID              string     `json:"boot_id"`
	ActiveKeyID         string     `json:"active_key_id"`
	AttestationSequence int64      `json:"attestation_sequence"`
	AttestedAt          int64      `json:"attested_at_unix_ms"`
	Status              statusJSON `json:"status"`
}

type statusJSON struct {
	OldReferences       int64 `json:"old_references"`
	NonActiveReferences int64 `json:"non_active_references"`
	LegacyReferences    int64 `json:"legacy_references"`
	TamperReferences    int64 `json:"tamper_references"`
	OIDCReferences      int64 `json:"oidc_references"`
	DCRReferences       int64 `json:"dcr_references"`
	UpstreamReferences  int64 `json:"upstream_references"`
	PasskeyEnabled      bool  `json:"passkey_enabled"`
	PasskeyReferences   int64 `json:"passkey_references"`
}

func barrierResponse(value storage.MasterKeyRetirement) barrierJSON {
	response := barrierJSON{Epoch: value.Epoch, OldKeyID: value.OldKeyID, ReplacementKeyID: value.ReplacementKeyID, Membership: append([]string(nil), value.Membership...), MembershipDigest: value.MembershipDigest, State: value.State, PreparedAt: value.PreparedAt.UnixMilli(), Attestations: make([]attestationJSON, 0, len(value.Attestations))}
	for _, timestamp := range []struct {
		value time.Time
		out   **int64
	}{{value.FencedAt, &response.FencedAt}, {value.ReadyAt, &response.ReadyAt}, {value.AbortedAt, &response.AbortedAt}} {
		if !timestamp.value.IsZero() {
			millis := timestamp.value.UnixMilli()
			*timestamp.out = &millis
		}
	}
	for _, attestation := range value.Attestations {
		response.Attestations = append(response.Attestations, attestationJSON{NodeID: attestation.NodeID, BootID: attestation.BootID, ActiveKeyID: attestation.ActiveKeyID, AttestationSequence: attestation.AttestationSequence, AttestedAt: attestation.AttestedAt.UnixMilli(), Status: statusJSON{OldReferences: attestation.Status.OldReferences, NonActiveReferences: attestation.Status.NonActiveReferences, LegacyReferences: attestation.Status.LegacyReferences, TamperReferences: attestation.Status.TamperReferences, OIDCReferences: attestation.Status.OIDCReferences, DCRReferences: attestation.Status.DCRReferences, UpstreamReferences: attestation.Status.UpstreamReferences, PasskeyEnabled: attestation.Status.PasskeyEnabled, PasskeyReferences: attestation.Status.PasskeyReferences}})
	}
	return response
}

func (h *Handler) headers(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func writeStatus(w http.ResponseWriter, status int) { w.WriteHeader(status) }

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
