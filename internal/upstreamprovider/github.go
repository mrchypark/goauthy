package upstreamprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode"

	"golang.org/x/oauth2"
)

const (
	githubAPIVersion   = "2022-11-28"
	githubAccept       = "application/vnd.github+json"
	githubUserMaxBytes = 64 << 10
)

func (e *OAuth2TokenExchanger) exchangeGitHubUser(ctx context.Context, providerID string, cfg Config, token *oauth2.Token) (*TokenExchangeResult, error) {
	if token == nil || token.AccessToken == "" || token.Extra("id_token") != nil {
		return nil, errTokenExchange
	}
	if !hasGitHubScope(token.Extra("scope")) || cfg.UserInfoEndpoint == "" {
		return nil, errTokenExchange
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.UserInfoEndpoint, nil)
	if err != nil {
		return nil, errTokenExchange
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	req.Header.Set("Accept", githubAccept)
	resp, err := e.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errTokenExchange
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errTokenExchange
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, githubUserMaxBytes+1))
	if err != nil || len(body) > githubUserMaxBytes {
		return nil, errTokenExchange
	}
	id, err := parseGitHubUserID(body)
	if err != nil {
		return nil, errTokenExchange
	}
	subject := SubjectResult{ProviderID: providerID, Subject: id}
	if err := subject.Validate(); err != nil {
		return nil, errTokenExchange
	}
	return &TokenExchangeResult{Subject: &subject}, nil
}

func hasGitHubScope(raw any) bool {
	scope, ok := raw.(string)
	if !ok {
		return false
	}
	for _, part := range strings.FieldsFunc(scope, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	}) {
		if part == "read:user" {
			return true
		}
	}
	return false
}

func parseGitHubUserID(body []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return "", errors.New("invalid github user object")
	}

	var id string
	seenID := false
	for dec.More() {
		keyToken, err := dec.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return "", errors.New("invalid github user key")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return "", errors.New("invalid github user value")
		}
		if key == "id" {
			if seenID || len(raw) == 0 || len(raw) > maxSubjectLen || !isCanonicalPositiveDecimal(raw) {
				return "", errors.New("invalid github user id")
			}
			seenID = true
			id = string(raw)
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') || !seenID {
		return "", errors.New("missing github user id")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return "", errors.New("trailing github user data")
	}
	return id, nil
}

func isCanonicalPositiveDecimal(raw []byte) bool {
	if len(raw) == 0 || raw[0] < '1' || raw[0] > '9' {
		return false
	}
	for _, b := range raw[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}
