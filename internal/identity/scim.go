package identity

import (
	"context"
	"encoding/base64"
	"errors"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/scim"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const maxSCIMTombstoneCleanup = 128

var (
	ErrInvalidSCIMTombstoneCleanup        = errors.New("invalid identity SCIM tombstone cleanup request")
	ErrSCIMTombstoneCleanupUnavailable    = errors.New("identity SCIM tombstone cleanup entropy is unavailable")
	ErrSCIMTombstoneGenerationUnavailable = errors.New("identity SCIM tombstone generation entropy is unavailable")
)

type SCIMGroup struct {
	ExternalID  string
	DisplayName string
	Members     []string
}

// ListSCIMGroups projects the live RBAC graph, including roles as groups.
// Rows are ordered by kind/name/id and members by subject for stable digests.
func (s *Store) ListSCIMGroups(ctx context.Context) ([]SCIMGroup, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, errors.New("identity SCIM projection is not configured")
	}
	r, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `
		SELECT 'role',e.id,e.name,m.subject FROM rbac_roles e LEFT JOIN rbac_user_roles m ON m.role_id=e.id
		UNION ALL
		SELECT 'group',e.id,e.name,m.subject FROM rbac_groups e LEFT JOIN rbac_user_groups m ON m.group_id=e.id
		ORDER BY 1,3,2,4`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	groups := make([]SCIMGroup, 0)
	for _, row := range r.Rows {
		if len(row) != 4 {
			return nil, errors.New("invalid identity SCIM group row")
		}
		kind, ok1 := row[0].(string)
		id, ok2 := row[1].(string)
		name, ok3 := row[2].(string)
		if !ok1 || !ok2 || !ok3 || (kind != "role" && kind != "group") || !validSCIMProjectionIdentifier(id) || !validSCIMProjectionIdentifier(name) {
			return nil, errors.New("invalid identity SCIM group row")
		}
		external := kind + ":" + id
		if len(groups) == 0 || groups[len(groups)-1].ExternalID != external {
			groups = append(groups, SCIMGroup{ExternalID: external, DisplayName: name})
		}
		if row[3] != nil {
			subject, ok := row[3].(string)
			if !ok || !validSCIMProjectionIdentifier(subject) {
				return nil, errors.New("invalid identity SCIM group member")
			}
			groups[len(groups)-1].Members = append(groups[len(groups)-1].Members, subject)
		}
	}
	return groups, nil
}

// SCIMUser is the complete local identity projection used by outbound SCIM
// reconciliation. It intentionally contains no profile, credential, or
// recovery data.
type SCIMUser struct {
	ExternalID string
	UserName   string
	Active     bool
}

// SCIMDeletedUser is the non-secret deletion snapshot used for SCIM
// reconciliation.
type SCIMDeletedUser struct {
	ExternalID               string
	UserName                 string
	Active                   bool
	HardDelete               bool
	ProviderSnapshotComplete bool
	Generation               string
	Providers                []SCIMTombstoneProvider
	DeletedAtUnixMS          int64
}

// SCIMTombstoneProvider is one currently configured SCIM provider and its
// normal user-delete policy. A hard local deletion always requires
// scim.DeleteRemote; a non-hard tombstone uses DeletePolicy.
type SCIMTombstoneProvider struct {
	ID           string
	DeletePolicy scim.DeletePolicy
}

// ConfigureSCIMTombstoneProviders freezes the provider set used by future
// deletions. It is a startup-only setting; the first deletion or abandoned
// registration cleanup also freezes an
// empty default so a late configuration cannot change an existing snapshot.
func (s *Store) ConfigureSCIMTombstoneProviders(providers []SCIMTombstoneProvider) error {
	if s == nil || s.db == nil {
		return errors.New("identity SCIM projection is not configured")
	}
	providers = append([]SCIMTombstoneProvider(nil), providers...)
	sort.Slice(providers, func(i, j int) bool { return providers[i].ID < providers[j].ID })
	for i, provider := range providers {
		if !validSCIMTombstoneProviderID(provider.ID) || (provider.DeletePolicy != scim.DeleteRemote && provider.DeletePolicy != scim.UnlinkRemote) || (i > 0 && provider.ID == providers[i-1].ID) {
			return ErrInvalidSCIMTombstoneCleanup
		}
	}
	s.tombstoneProvidersMu.Lock()
	defer s.tombstoneProvidersMu.Unlock()
	if s.tombstoneProvidersFrozen {
		return ErrInvalidSCIMTombstoneCleanup
	}
	s.tombstoneProviders = providers
	s.tombstoneProvidersFrozen = true
	return nil
}

func (s *Store) freezeSCIMTombstoneProviders() []SCIMTombstoneProvider {
	s.tombstoneProvidersMu.Lock()
	defer s.tombstoneProvidersMu.Unlock()
	s.tombstoneProvidersFrozen = true
	return append([]SCIMTombstoneProvider(nil), s.tombstoneProviders...)
}

// CleanupSCIMDeletedUsers removes at most limit oldest snapshot-complete
// tombstones once every snapshotted provider has succeeded its exact delete.
func (s *Store) CleanupSCIMDeletedUsers(ctx context.Context, limit int) (int, error) {
	if s == nil || s.db == nil || ctx == nil || limit < 1 || limit > maxSCIMTombstoneCleanup {
		return 0, ErrInvalidSCIMTombstoneCleanup
	}

	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT local_external_id FROM scim_user_tombstones ORDER BY deleted_at_unix_ms ASC, local_external_id ASC LIMIT ?`, Args: []any{int64(limit)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return 0, err
	}
	requestParts := make([]string, 0, 2+len(result.Rows))
	requestParts = append(requestParts, "scim-tombstone-cleanup", strconv.Itoa(limit))
	for _, row := range result.Rows {
		if len(row) != 1 {
			return 0, errors.New("invalid identity SCIM tombstone cleanup row")
		}
		externalID, ok := row[0].(string)
		if !ok || !validSCIMProjectionIdentifier(externalID) {
			return 0, errors.New("invalid identity SCIM tombstone cleanup row")
		}
		requestParts = append(requestParts, externalID)
	}
	if len(result.Rows) == 0 {
		return 0, nil
	}
	nonce := make([]byte, 16)
	if s.random == nil {
		return 0, ErrSCIMTombstoneCleanupUnavailable
	}
	if n, err := s.random(nonce); err != nil || n != len(nonce) {
		return 0, ErrSCIMTombstoneCleanupUnavailable
	}
	requestParts = append(requestParts, base64.RawURLEncoding.EncodeToString(nonce))

	const deleteTombstones = `DELETE FROM scim_user_tombstones WHERE local_external_id IN (
	SELECT t.local_external_id FROM scim_user_tombstones t
		WHERE t.provider_snapshot_complete=1
		AND t.generation<>''
		AND (t.hard_delete=0 OR EXISTS (
			SELECT 1 FROM scim_user_tombstone_providers p
			WHERE p.local_external_id=t.local_external_id AND p.delete_policy=?))
		AND NOT EXISTS (
			SELECT 1 FROM scim_user_tombstone_providers p WHERE p.local_external_id=t.local_external_id
			AND ((t.hard_delete=1 AND p.delete_policy<>?) OR NOT EXISTS (
		SELECT 1 FROM scim_user_outbox o WHERE o.client_id=p.client_id AND o.status='succeeded'
		AND json_type(o.request_json,'$.user')='object'
		AND json_type(o.request_json,'$.group') IS NULL
		AND json_extract(o.request_json,'$.operation')='delete'
		AND json_extract(o.request_json,'$.delete')=1
		AND json_extract(o.request_json,'$.user.externalId')=t.local_external_id
		AND json_extract(o.request_json,'$.deletePolicy')=p.delete_policy
		AND json_extract(o.request_json,'$.tombstoneGeneration')=t.generation)))
		ORDER BY t.deleted_at_unix_ms ASC, t.local_external_id ASC LIMIT ?)
		RETURNING local_external_id`
	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: mutationID(requestParts...), Statements: []rhiza.SQLStatement{
		{SQL: deleteTombstones, Args: []any{int64(scim.DeleteRemote), int64(scim.DeleteRemote), int64(limit)}, WantRows: true},
		{SQL: `DELETE FROM scim_user_tombstone_providers WHERE NOT EXISTS (SELECT 1 FROM scim_user_tombstones t WHERE t.local_external_id=scim_user_tombstone_providers.local_external_id)`},
	}})
	if err != nil {
		return 0, err
	}
	if len(response.Statements) != 2 || len(response.Statements[0].Rows) > limit {
		return 0, errors.New("invalid identity SCIM tombstone cleanup result")
	}
	return len(response.Statements[0].Rows), nil
}

func validSCIMTombstoneProviderID(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n") && utf8.ValidString(value)
}

// ListSCIMDeletedUsers returns tombstones in stable deletion-time order.
func (s *Store) ListSCIMDeletedUsers(ctx context.Context) ([]SCIMDeletedUser, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, errors.New("identity SCIM projection is not configured")
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT t.local_external_id,t.user_name,t.active,t.hard_delete,t.provider_snapshot_complete,t.generation,t.deleted_at_unix_ms,p.client_id,p.delete_policy
		FROM scim_user_tombstones t LEFT JOIN scim_user_tombstone_providers p ON p.local_external_id=t.local_external_id
		ORDER BY t.deleted_at_unix_ms ASC,t.local_external_id ASC,p.client_id ASC`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return nil, err
	}
	users := make([]SCIMDeletedUser, 0, len(result.Rows))
	for _, row := range result.Rows {
		if len(row) != 9 {
			return nil, errors.New("invalid identity SCIM tombstone row")
		}
		externalID, externalOK := row[0].(string)
		userName, usernameOK := row[1].(string)
		active, activeOK := row[2].(int64)
		hardDelete, hardDeleteOK := row[3].(int64)
		complete, completeOK := row[4].(int64)
		generation, generationOK := row[5].(string)
		deletedAt, deletedOK := row[6].(int64)
		if !externalOK || !usernameOK || !activeOK || !hardDeleteOK || !completeOK || !generationOK || !deletedOK || !validSCIMProjectionIdentifier(externalID) || ValidateUsername(userName) != nil || !validSCIMTombstoneGeneration(generation) || (active != 0 && active != 1) || (hardDelete != 0 && hardDelete != 1) || (complete != 0 && complete != 1) || deletedAt < 0 {
			return nil, errors.New("invalid identity SCIM tombstone row")
		}
		if len(users) == 0 || users[len(users)-1].ExternalID != externalID {
			users = append(users, SCIMDeletedUser{ExternalID: externalID, UserName: userName, Active: active == 1, HardDelete: hardDelete == 1, ProviderSnapshotComplete: complete == 1, Generation: generation, DeletedAtUnixMS: deletedAt})
		}
		if row[7] == nil && row[8] == nil {
			continue
		}
		clientID, clientOK := row[7].(string)
		policy, policyOK := row[8].(int64)
		if !clientOK || !policyOK || !validSCIMTombstoneProviderID(clientID) || (policy != int64(scim.DeleteRemote) && policy != int64(scim.UnlinkRemote)) {
			return nil, errors.New("invalid identity SCIM tombstone provider row")
		}
		users[len(users)-1].Providers = append(users[len(users)-1].Providers, SCIMTombstoneProvider{ID: clientID, DeletePolicy: scim.DeletePolicy(policy)})
	}
	return users, nil
}

func validSCIMTombstoneGeneration(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 22 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 16 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

// ListSCIMUsers returns every local identity in stable subject order. A
// password-mode identity with no password is the schema's pending
// password-first state; passkey-only identities also have no password but
// remain active because their authentication mode is explicit.
func (s *Store) ListSCIMUsers(ctx context.Context) ([]SCIMUser, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, errors.New("identity SCIM projection is not configured")
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT u.subject,u.username,u.disabled,u.password_phc,m.mode
			FROM identity_users u
			LEFT JOIN identity_authentication_modes m ON m.subject = u.subject
			ORDER BY u.subject ASC`,
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return nil, err
	}
	users := make([]SCIMUser, 0, len(result.Rows))
	for _, row := range result.Rows {
		if len(row) != 5 {
			return nil, errors.New("invalid identity SCIM row")
		}
		subject, subjectOK := row[0].(string)
		username, usernameOK := row[1].(string)
		disabled, disabledOK := row[2].(int64)
		passwordPHC, passwordOK := row[3].(string)
		mode, modeOK := row[4].(string)
		if !subjectOK || !usernameOK || !disabledOK || !passwordOK || !modeOK ||
			validateSubject(subject) != nil || !validSCIMProjectionIdentifier(subject) || ValidateUsername(username) != nil ||
			(disabled != 0 && disabled != 1) || (mode != "password" && mode != "passkey") {
			return nil, errors.New("invalid identity SCIM row")
		}
		users = append(users, SCIMUser{
			ExternalID: subject,
			UserName:   username,
			Active:     disabled == 0 && !(passwordPHC == "" && mode == "password"),
		})
	}
	return users, nil
}

func validSCIMProjectionIdentifier(value string) bool {
	if value == "" || len(value) > maxSubjectBytes || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
