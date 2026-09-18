package saas

import (
	"strings"

	"golang.org/x/oauth2"
)

func oauthGrantedScopes(token *oauth2.Token, requested []string) ([]string, error) {
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
	allowed := make(map[string]struct{}, len(requested))
	for _, value := range requested {
		allowed[value] = struct{}{}
	}
	seen := make(map[string]struct{}, len(parts))
	for _, value := range parts {
		if !oauthScopeToken(value) || len(value) > 256 {
			return nil, ErrOAuth2Exchange
		}
		if _, ok := seen[value]; ok {
			return nil, ErrOAuth2Exchange
		}
		if _, ok := allowed[value]; !ok {
			return nil, ErrOAuth2Exchange
		}
		seen[value] = struct{}{}
	}
	return append([]string(nil), parts...), nil
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
