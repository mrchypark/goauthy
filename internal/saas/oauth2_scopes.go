package saas

import (
	"strings"

	"golang.org/x/oauth2"
)

func googleOAuth2Profile(authorizationURL, tokenURL, identityEndpoint string) bool {
	return authorizationURL == "https://accounts.google.com/o/oauth2/v2/auth" && tokenURL == "https://oauth2.googleapis.com/token" && identityEndpoint == "https://openidconnect.googleapis.com/v1/userinfo"
}

func githubPublicOAuth2Profile(authorizationURL, tokenURL, identityEndpoint, subjectField string) bool {
	return authorizationURL == githubAuthorizeURL && tokenURL == githubTokenURL && identityEndpoint == githubAPIURL+"/user" && subjectField == "id"
}

func (o *OAuth2) grantedScopes(token *oauth2.Token, requested []string) ([]string, error) {
	if len(o.config.Scopes) == 0 && githubPublicOAuth2Profile(o.config.Endpoint.AuthURL, o.config.Endpoint.TokenURL, o.identityEndpoint, o.subjectField) {
		if token == nil || len(requested) != 0 {
			return nil, ErrOAuth2Exchange
		}
		if raw := token.Extra("scope"); raw != nil {
			scope, ok := raw.(string)
			if !ok || scope != "" {
				return nil, ErrOAuth2Exchange
			}
		}
		return []string{}, nil
	}
	return oauthGrantedScopes(token, requested, googleOAuth2Profile(o.config.Endpoint.AuthURL, o.config.Endpoint.TokenURL, o.identityEndpoint))
}

func oauthGrantedScopes(token *oauth2.Token, requested []string, googleProfile bool) ([]string, error) {
	if token == nil {
		return nil, ErrOAuth2Exchange
	}
	raw := token.Extra("scope")
	if raw == nil {
		return append([]string(nil), requested...), nil
	}
	scope, ok := raw.(string)
	if !ok || scope == "" {
		return nil, ErrOAuth2Exchange
	}
	parts := strings.Split(scope, " ")
	if len(parts) > 64 {
		return nil, ErrOAuth2Exchange
	}
	canonical := func(value string) string {
		if googleProfile {
			switch value {
			case "https://www.googleapis.com/auth/userinfo.email":
				return "email"
			case "https://www.googleapis.com/auth/userinfo.profile":
				return "profile"
			}
		}
		return value
	}
	allowed := make(map[string]string, len(requested))
	for _, value := range requested {
		if _, ok := allowed[canonical(value)]; !ok {
			allowed[canonical(value)] = value
		}
	}
	seen := make(map[string]struct{}, len(parts))
	granted := make(map[string]struct{}, len(parts))
	result := make([]string, 0, len(parts))
	for _, value := range parts {
		if !oauthScopeToken(value) || len(value) > 256 {
			return nil, ErrOAuth2Exchange
		}
		if _, ok := seen[value]; ok {
			return nil, ErrOAuth2Exchange
		}
		seen[value] = struct{}{}
		key := canonical(value)
		configured, ok := allowed[key]
		if !ok {
			return nil, ErrOAuth2Exchange
		}
		if _, ok := granted[key]; !ok {
			granted[key] = struct{}{}
			result = append(result, configured)
		}
	}
	return result, nil
}

func oauthScopeToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}
