package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

// signedAccessTokenStrategy keeps the existing opaque HMAC token as the JWT
// jti and Rhiza index. The compact JWT is EdDSA-signed; revocation remains a
// stateful lookup by that jti-derived HMAC signature.
type signedAccessTokenStrategy struct {
	oauth2.CoreStrategy
	issuer       string
	loadKey      func(context.Context) (oidc.SigningKey, error)
	loadKeys     func(context.Context) ([]jose.JSONWebKey, error)
	now          func() time.Time
	mu           sync.RWMutex
	issuedPublic map[string]jose.JSONWebKey
}

var _ oauth2.CoreStrategy = (*signedAccessTokenStrategy)(nil)

const accessDefaultAudiencesExtra = "goauthy_default_audiences"

func newSignedAccessTokenStrategy(core oauth2.CoreStrategy, issuer string, loadKey func(context.Context) (oidc.SigningKey, error), loadKeys func(context.Context) ([]jose.JSONWebKey, error), now func() time.Time) *signedAccessTokenStrategy {
	return &signedAccessTokenStrategy{CoreStrategy: core, issuer: issuer, loadKey: loadKey, loadKeys: loadKeys, now: now, issuedPublic: make(map[string]jose.JSONWebKey)}
}

func (s *signedAccessTokenStrategy) GenerateAccessToken(ctx context.Context, request fosite.Requester) (string, string, error) {
	jti, signature, err := s.CoreStrategy.GenerateAccessToken(ctx, request)
	if err != nil {
		return "", "", err
	}
	key, err := s.loadKey(ctx)
	if err != nil {
		return "", "", err
	}
	// Capture only at new issuance, after Fosite's second authorization-code
	// session load. Missing snapshots on older tokens mean no added defaults.
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok || containsAccessAudience(customRootNames(session.Extra), accessDefaultAudiencesExtra) {
		return "", "", errors.New("invalid access audience session")
	}
	delete(session.Extra, accessDefaultAudiencesExtra)
	if client, ok := request.GetClient().(*clients.Client); ok {
		if session.Extra == nil {
			session.Extra = make(map[string]any)
		}
		session.Extra[accessDefaultAudiencesExtra] = append([]string{}, client.GetDefaultAudience()...)
	}
	claims, err := s.claims(request, jti)
	if err != nil {
		return "", "", err
	}
	token, err := oidc.SignAccessToken(key, claims)
	if err != nil {
		return "", "", err
	}
	s.rememberKey(key.PublicJWK)
	return token, signature, nil
}

func (s *signedAccessTokenStrategy) AccessTokenSignature(ctx context.Context, token string) string {
	claims, err := s.verify(ctx, token)
	if err != nil {
		return ""
	}
	return s.CoreStrategy.AccessTokenSignature(ctx, claims.ID)
}

func (s *signedAccessTokenStrategy) ValidateAccessToken(ctx context.Context, request fosite.Requester, token string) error {
	if request == nil || request.GetSession() == nil {
		return fosite.ErrRequestUnauthorized
	}
	claims, err := s.verify(ctx, token)
	if err != nil {
		return fosite.ErrRequestUnauthorized
	}
	if !s.matchesRequest(request, claims) {
		return fosite.ErrRequestUnauthorized
	}
	return nil
}

func (s *signedAccessTokenStrategy) verify(ctx context.Context, token string) (oidc.AccessTokenClaims, error) {
	keys, err := s.verificationKeys(ctx)
	if err != nil {
		return oidc.AccessTokenClaims{}, err
	}
	return oidc.VerifyAccessToken(token, jose.JSONWebKeySet{Keys: keys}, s.issuer, s.now().UTC())
}

func (s *signedAccessTokenStrategy) verificationKeys(ctx context.Context) ([]jose.JSONWebKey, error) {
	if s.loadKeys != nil {
		return s.loadKeys(ctx)
	}
	s.mu.RLock()
	keys := make([]jose.JSONWebKey, 0, len(s.issuedPublic))
	for _, key := range s.issuedPublic {
		keys = append(keys, key)
	}
	s.mu.RUnlock()
	if len(keys) != 0 {
		return keys, nil
	}
	key, err := s.loadKey(ctx)
	if err != nil {
		return nil, err
	}
	return []jose.JSONWebKey{key.PublicJWK}, nil
}

func (s *signedAccessTokenStrategy) rememberKey(key jose.JSONWebKey) {
	s.mu.Lock()
	s.issuedPublic[key.KeyID] = key
	s.mu.Unlock()
}

func (s *signedAccessTokenStrategy) matchesRequest(request fosite.Requester, claims oidc.AccessTokenClaims) bool {
	session, ok := request.GetSession().(*fosite.DefaultSession)
	subject, _, subjectErr := machineTokenSubject(request)
	if subjectErr != nil || !ok || !session.GetExpiresAt(fosite.AccessToken).After(s.now().UTC()) || claims.Subject != subject || claims.AuthorizedParty != request.GetClient().GetID() {
		return false
	}
	wantType, wantJKT := "Bearer", sessionDPoPJKT(session)
	if wantJKT != "" {
		wantType = "DPoP"
	}
	if claims.Type != wantType || claims.ConfirmationJKT != wantJKT || !sameAccessStrings(claims.Scope, request.GetGrantedScopes()) {
		return false
	}
	actor, err := accessSessionActor(session.Extra)
	if err != nil || !reflect.DeepEqual(claims.Actor, actor) {
		return false
	}
	resources, err := accessResourceAudiences(request)
	if err != nil {
		return false
	}
	wantAudience := []string{request.GetClient().GetID()}
	for _, audience := range resources {
		if !containsAccessAudience(wantAudience, audience) {
			wantAudience = append(wantAudience, audience)
		}
	}
	return sameAccessStrings(claims.Audience, wantAudience)
}

func sameAccessStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func (s *signedAccessTokenStrategy) claims(request fosite.Requester, jti string) (oidc.AccessTokenClaims, error) {
	if request == nil || request.GetClient() == nil {
		return oidc.AccessTokenClaims{}, errors.New("access token request is missing")
	}
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok {
		return oidc.AccessTokenClaims{}, errors.New("access token session is invalid")
	}
	now := s.now().UTC()
	expires := session.GetExpiresAt(fosite.AccessToken).UTC()
	if expires.IsZero() || !expires.After(now) {
		return oidc.AccessTokenClaims{}, errors.New("access token expiry is invalid")
	}
	audience := []string{request.GetClient().GetID()}
	resources, err := accessResourceAudiences(request)
	if err != nil {
		return oidc.AccessTokenClaims{}, err
	}
	for _, value := range resources {
		if !containsAccessAudience(audience, value) {
			audience = append(audience, value)
		}
	}
	roles, err := accessSessionStrings(session.Extra, "roles")
	if err != nil {
		return oidc.AccessTokenClaims{}, err
	}
	groups, err := accessSessionStrings(session.Extra, "groups")
	if err != nil {
		return oidc.AccessTokenClaims{}, err
	}
	custom, err := accessSessionCustomClaims(session.Extra)
	if err != nil {
		return oidc.AccessTokenClaims{}, err
	}
	if clientCustom, present, err := accessSessionClientCredentialsClaims(session.Extra); err != nil {
		return oidc.AccessTokenClaims{}, err
	} else if present {
		custom = clientCustom
	}
	actor, err := accessSessionActor(session.Extra)
	if err != nil {
		return oidc.AccessTokenClaims{}, err
	}
	scopes := append([]string(nil), request.GetGrantedScopes()...)
	if jti == "" {
		return oidc.AccessTokenClaims{}, errors.New("access token scope or ID is invalid")
	}
	typ, jkt := "Bearer", sessionDPoPJKT(session)
	if jkt != "" {
		typ = "DPoP"
	}
	if session.Subject == "" {
		roles, groups = nil, nil
	}
	subject, _, err := machineTokenSubject(request)
	if err != nil {
		return oidc.AccessTokenClaims{}, err
	}
	return oidc.AccessTokenClaims{Issuer: s.issuer, Subject: subject, Audience: audience, IssuedAt: now, NotBefore: now, ExpiresAt: expires, ID: jti, AuthorizedParty: request.GetClient().GetID(), Scope: scopes, Type: typ, ConfirmationJKT: jkt, Roles: roles, Groups: groups, CustomClaims: custom, Actor: actor}, nil
}

// Keep always-on defaults separate from Fosite's explicit resource grants:
// its refresh handler rechecks those grants against the resource allowlist.
func accessResourceAudiences(request fosite.Requester) ([]string, error) {
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok || containsAccessAudience(customRootNames(session.Extra), accessDefaultAudiencesExtra) {
		return nil, errors.New("invalid access audience session")
	}
	if value, present := session.Extra[accessDefaultAudiencesExtra]; present && value == nil {
		return nil, errors.New("invalid default audience snapshot")
	}
	values, err := accessSessionStrings(session.Extra, accessDefaultAudiencesExtra)
	if err != nil || len(values) > 32 {
		return nil, errors.New("invalid default audience snapshot")
	}
	for _, value := range values {
		if !validResourceURL(value) {
			return nil, errors.New("invalid default audience snapshot")
		}
	}
	for _, value := range request.GetGrantedAudience() {
		if value == "" {
			return nil, errors.New("invalid access token audience")
		}
		if !containsAccessAudience(values, value) {
			values = append(values, value)
		}
	}
	return values, nil
}

func containsAccessAudience(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func accessSessionStrings(extra map[string]interface{}, name string) ([]string, error) {
	if extra == nil || extra[name] == nil {
		return nil, nil
	}
	var values []string
	switch raw := extra[name].(type) {
	case []string:
		values = append([]string(nil), raw...)
	case []interface{}:
		values = make([]string, len(raw))
		for i, value := range raw {
			var ok bool
			values[i], ok = value.(string)
			if !ok {
				return nil, fmt.Errorf("invalid access token %s claim", name)
			}
		}
	default:
		return nil, fmt.Errorf("invalid access token %s claim", name)
	}
	sort.Strings(values)
	for i := 1; i < len(values); i++ {
		if values[i-1] == values[i] {
			return nil, fmt.Errorf("invalid access token %s claim", name)
		}
	}
	return values, nil
}

func accessSessionActor(extra map[string]interface{}) (*oidc.ActorClaims, error) {
	if extra == nil {
		return nil, nil
	}
	value, found := extra["act"]
	if !found || value == nil {
		return nil, nil
	}
	actor, err := oidc.ParseActorClaims(value)
	if err != nil {
		return nil, errors.New("invalid access token actor claim")
	}
	return actor, nil
}

func actorClaimsExtra(actor *oidc.ActorClaims) map[string]any {
	if actor == nil {
		return nil
	}
	value := map[string]any{"sub": actor.Subject}
	if nested := actorClaimsExtra(actor.Actor); nested != nil {
		value["act"] = nested
	}
	return value
}

func appendActorSubjects(subjects []string, actor *oidc.ActorClaims) []string {
	seen := make(map[string]struct{}, len(subjects))
	for _, subject := range subjects {
		seen[subject] = struct{}{}
	}
	for actor != nil {
		if _, found := seen[actor.Subject]; !found {
			subjects = append(subjects, actor.Subject)
			seen[actor.Subject] = struct{}{}
		}
		actor = actor.Actor
	}
	return subjects
}

func accessSessionCustomClaims(extra map[string]interface{}) (oidc.CustomClaims, error) {
	if extra == nil {
		return oidc.CustomClaims{}, nil
	}
	nested := map[string]json.RawMessage(nil)
	if value, found := extra["custom"]; found {
		raw, err := json.Marshal(value)
		if err != nil || json.Unmarshal(raw, &nested) != nil {
			return oidc.CustomClaims{}, errors.New("invalid access token custom claims")
		}
	}
	root := make(map[string]json.RawMessage)
	for _, name := range customRootNames(extra) {
		value, found := extra[name]
		if !found {
			return oidc.CustomClaims{}, errors.New("missing access token root custom claim")
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return oidc.CustomClaims{}, errors.New("invalid access token root custom claim")
		}
		root[name] = raw
	}
	return oidc.NormalizeCustomClaims(oidc.CustomClaims{Nested: nested, Root: root})
}

func accessSessionClientCredentialsClaims(extra map[string]interface{}) (oidc.CustomClaims, bool, error) {
	if extra == nil || extra[clientCredentialsClaimsExtra] == nil {
		return oidc.CustomClaims{}, false, nil
	}
	raw, err := json.Marshal(extra[clientCredentialsClaimsExtra])
	if err != nil {
		return oidc.CustomClaims{}, false, errors.New("invalid client credentials access claims")
	}
	values := map[string]json.RawMessage{}
	if json.Unmarshal(raw, &values) != nil {
		return oidc.CustomClaims{}, false, errors.New("invalid client credentials access claims")
	}
	atRoot, ok := extra[clientCredentialsClaimsAtRootExtra].(bool)
	if !ok {
		return oidc.CustomClaims{}, false, errors.New("invalid client credentials access claims")
	}
	custom, err := oidc.NormalizeCustomClaims(oidc.CustomClaims{Values: values, AtRoot: atRoot})
	return custom, true, err
}
