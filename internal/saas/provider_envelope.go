package saas

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"golang.org/x/oauth2"
)

func providerSecretPurpose(id, generation string) string {
	h := sha256.Sum256([]byte(id + "\x00" + generation))
	return "saas/provider/v1/" + base64.RawURLEncoding.EncodeToString(h[:])
}

func (s *ProviderStore) LoadOAuth2(ctx context.Context, id string, authority func() (string, []any)) (*OAuth2, error) {
	p, err := s.get(ctx, id, authority)
	if err != nil || p.Kind != "oauth2" || !p.Enabled {
		return nil, ErrProviderNotFound
	}
	g, ga, err := providerGuard(authority)
	if err != nil {
		return nil, err
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT generation,secret_envelope FROM saas_providers WHERE id=? AND revision=? AND kind='oauth2' AND deleted=0 AND enabled=1 AND (` + g + `)`, Args: append([]any{id, p.Revision}, ga...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 {
		return nil, ErrProviderNotFound
	}
	gen, ok := q.Rows[0][0].(string)
	if !ok {
		return nil, ErrProviderInvalid
	}
	env, ok := q.Rows[0][1].([]byte)
	if !ok || len(env) == 0 {
		return nil, ErrProviderInvalid
	}
	plain, err := s.keys.OpenEnvelope(providerSecretPurpose(id, gen), env)
	if err != nil {
		return nil, ErrProviderInvalid
	}
	defer clear(plain)
	style := oauthStyle(p.AuthStyle)
	return NewOAuth2(OAuth2Config{ClientID: p.ClientID, AuthorizationURL: p.AuthorizationURL, TokenURL: p.TokenURL, CallbackURL: p.CallbackURI, Scopes: p.Scopes, AuthStyle: style, IdentityEndpoint: p.IdentityEndpoint, SubjectField: p.SubjectField}, string(plain))
}

func oauthStyle(style string) oauth2.AuthStyle {
	if style == "params" {
		return oauth2.AuthStyleInParams
	}
	return oauth2.AuthStyleInHeader
}

func InspectProviderEnvelopeReferences(ctx context.Context, db *rhiza.DB, keys *oidc.Keyring) (oidc.MasterKeyReferenceFamily, error) {
	f := oidc.MasterKeyReferenceFamily{ByKeyID: map[string]int64{}}
	if ctx == nil || db == nil || keys == nil {
		return f, errors.New("invalid SaaS provider reference scan")
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id,generation,secret_envelope FROM saas_providers WHERE secret_envelope IS NOT NULL ORDER BY id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return f, err
	}
	for _, row := range q.Rows {
		if len(row) != 3 {
			return oidc.MasterKeyReferenceFamily{}, errors.New("invalid SaaS provider envelope row")
		}
		id, a := row[0].(string)
		gen, b := row[1].(string)
		env, c := row[2].([]byte)
		if !a || !b || !c {
			return oidc.MasterKeyReferenceFamily{}, errors.New("invalid SaaS provider envelope row")
		}
		kid, err := keys.PurposeEnvelopeKeyID(providerSecretPurpose(id, gen), env)
		if err != nil {
			return oidc.MasterKeyReferenceFamily{}, err
		}
		f.ByKeyID[kid]++
		f.Total++
	}
	return f, nil
}

func RewrapProviderEnvelopeBatch(ctx context.Context, db *rhiza.DB, keys *oidc.Keyring, cursor string) (oidc.SigningKeyRewrapBatchResult, error) {
	if db == nil || keys == nil {
		return oidc.SigningKeyRewrapBatchResult{}, errors.New("invalid SaaS provider rewrap")
	}
	active, err := keys.ActiveMasterKeyID()
	if err != nil {
		return oidc.SigningKeyRewrapBatchResult{}, err
	}
	q, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id,generation,secret_envelope FROM saas_providers WHERE secret_envelope IS NOT NULL AND id>? ORDER BY id LIMIT 32`, Args: []any{cursor}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return oidc.SigningKeyRewrapBatchResult{}, err
	}
	if len(q.Rows) == 0 {
		return oidc.SigningKeyRewrapBatchResult{Cursor: cursor, Done: true}, nil
	}
	last := cursor
	changed := 0
	for _, row := range q.Rows {
		id, _ := row[0].(string)
		gen, _ := row[1].(string)
		env, _ := row[2].([]byte)
		last = id
		kid, err := keys.PurposeEnvelopeKeyID(providerSecretPurpose(id, gen), env)
		if err != nil {
			return oidc.SigningKeyRewrapBatchResult{}, err
		}
		if kid == active {
			continue
		}
		replacement, err := keys.RewrapEnvelope(providerSecretPurpose(id, gen), env)
		if err != nil {
			return oidc.SigningKeyRewrapBatchResult{}, err
		}
		requestID := randomCredentialClaim()
		if requestID == "" {
			return oidc.SigningKeyRewrapBatchResult{}, errors.New("invalid SaaS provider rewrap request")
		}
		r, err := storage.ExecuteEnvelope(ctx, db, active, rhiza.ExecuteRequest{RequestID: "saas-provider-rewrap-" + requestID, SQL: `UPDATE saas_providers SET secret_envelope=? WHERE id=? AND generation=? AND secret_envelope=?`, Args: []any{replacement, id, gen, env}})
		if err != nil {
			return oidc.SigningKeyRewrapBatchResult{}, err
		}
		changed += int(r.MutationReceipt.RowsAffected)
	}
	return oidc.SigningKeyRewrapBatchResult{Cursor: last, Rewrapped: changed, Done: len(q.Rows) < 32}, nil
}
