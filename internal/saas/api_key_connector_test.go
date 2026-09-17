package saas

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func TestAPIKeyConnectorInfoMatchesExecutionAndIsDetached(t *testing.T) {
	c, err := NewAPIKeyConnector(validAPIKeyConnectorConfig())
	if err != nil {
		t.Fatal(err)
	}
	info := c.Info()
	if info.ID != c.id || info.Digest != c.Digest() || info.Header != c.header || info.Prefix != c.prefix || len(info.Operations) != len(c.operations) {
		t.Fatal("consent metadata differs from connector")
	}
	for i, op := range info.Operations {
		actual := c.operations[op.ID]
		want, _ := json.Marshal(actual.ResponseFields)
		got, _ := json.Marshal(op.ResponseFields)
		if op.Method != http.MethodGet || op.URL != actual.URL || string(got) != string(want) || (i > 0 && info.Operations[i-1].ID >= op.ID) {
			t.Fatal("operation metadata differs from execution or is unsorted")
		}
	}
	before, _ := json.Marshal(c.Info())
	info.Operations[0].URL = "https://other.example.com/"
	info.Operations[0].ResponseFields["id"] = "boolean"
	info.Operations = nil
	after, _ := json.Marshal(c.Info())
	if string(before) != string(after) {
		t.Fatal("metadata mutation changed connector")
	}
	var absent *APIKeyConnector
	if absent.Info().ID != "" {
		t.Fatal("nil connector has metadata")
	}
}

func validAPIKeyConnectorConfig() APIKeyConnectorConfig {
	return APIKeyConnectorConfig{ID: "billing", Header: "authorization", Prefix: "Bearer ", Operations: []APIKeyOperationConfig{
		{ID: "account", URL: "https://api.example.com/account", ResponseFields: map[string]string{"id": "string", "active": "boolean"}},
		{ID: "balance", URL: "https://api.example.com/balance", ResponseFields: map[string]string{"amount": "integer"}},
	}}
}

func TestNewAPIKeyConnectorDeterministicAndImmutable(t *testing.T) {
	cfg := validAPIKeyConnectorConfig()
	a, err := NewAPIKeyConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reordered := validAPIKeyConnectorConfig()
	reordered.Operations[0], reordered.Operations[1] = reordered.Operations[1], reordered.Operations[0]
	reordered.Operations[0].ResponseFields = map[string]string{"amount": "integer"}
	reordered.Operations[1].ResponseFields = map[string]string{"active": "boolean", "id": "string"}
	b, err := NewAPIKeyConnector(reordered)
	if err != nil || a.Digest() != b.Digest() {
		t.Fatalf("reordering changed digest: %v %q %q", err, a.Digest(), b.Digest())
	}

	cfg.Operations[0].ResponseFields["id"] = "boolean"
	if a.operations["account"].ResponseFields["id"] != "string" {
		t.Fatal("constructor retained caller-owned map")
	}
	if a.Digest() != b.Digest() {
		t.Fatal("digest changed after caller mutation")
	}
}

func TestAPIKeyConnectorDigestSemanticChanges(t *testing.T) {
	base := validAPIKeyConnectorConfig()
	a, _ := NewAPIKeyConnector(base)
	for name, mutate := range map[string]func(*APIKeyConnectorConfig){
		"id":     func(c *APIKeyConnectorConfig) { c.ID = "other" },
		"header": func(c *APIKeyConnectorConfig) { c.Header = "X-API-Key"; c.Prefix = "" },
		"prefix": func(c *APIKeyConnectorConfig) { c.Prefix = "Token " },
		"url":    func(c *APIKeyConnectorConfig) { c.Operations[0].URL += "/v2" },
		"field":  func(c *APIKeyConnectorConfig) { c.Operations[0].ResponseFields["id"] = "integer" },
	} {
		cfg := validAPIKeyConnectorConfig()
		mutate(&cfg)
		b, err := NewAPIKeyConnector(cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if a.Digest() == b.Digest() {
			t.Fatalf("%s did not change digest", name)
		}
	}
}

func TestAPIKeyConnectorRejectsInvalidConfig(t *testing.T) {
	cases := []func(*APIKeyConnectorConfig){
		func(c *APIKeyConnectorConfig) { c.ID = "Billing" },
		func(c *APIKeyConnectorConfig) { c.Operations[0].ID = "Read" },
		func(c *APIKeyConnectorConfig) { c.Operations[0].URL = "https://api.example.com:/x" },
		func(c *APIKeyConnectorConfig) { c.Operations[0].URL = "https://api.example.com/x#" },
		func(c *APIKeyConnectorConfig) { c.ID = "bad id" },
		func(c *APIKeyConnectorConfig) { c.Header = "Content-Type" },
		func(c *APIKeyConnectorConfig) { c.Prefix = "Basic " },
		func(c *APIKeyConnectorConfig) { c.Operations[0].URL = "http://api.example.com/x" },
		func(c *APIKeyConnectorConfig) { c.Operations[0].URL = "https://API.example.com/x" },
		func(c *APIKeyConnectorConfig) { c.Operations[0].URL = "https://127.0.0.1/x" },
		func(c *APIKeyConnectorConfig) { c.Operations[0].URL = "https://api.example.com/x?q=1" },
		func(c *APIKeyConnectorConfig) {
			c.Operations[0].ResponseFields = map[string]string{"bad-name": "string"}
		},
		func(c *APIKeyConnectorConfig) { c.Operations[0].ResponseFields = map[string]string{"id": "object"} },
	}
	for i, mutate := range cases {
		cfg := validAPIKeyConnectorConfig()
		mutate(&cfg)
		if _, err := NewAPIKeyConnector(cfg); !errors.Is(err, ErrAPIKeyConnectorConfig) {
			t.Errorf("case %d: got %v", i, err)
		}
	}
}

func TestAPIKeyConnectorRawAuthorizationIsDistinct(t *testing.T) {
	cfg := validAPIKeyConnectorConfig()
	bearer, err := NewAPIKeyConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Prefix = ""
	raw, err := NewAPIKeyConnector(cfg)
	if err != nil || raw.Info().Prefix != "" || raw.Digest() == bearer.Digest() {
		t.Fatal("raw Authorization must retain a distinct reviewed binding")
	}
	for _, prefix := range []string{" ", "Basic ", "\r\nX-Key: ", "Bearer\t"} {
		cfg.Prefix = prefix
		if _, err := NewAPIKeyConnector(cfg); !errors.Is(err, ErrAPIKeyConnectorConfig) {
			t.Fatal("unsupported prefix accepted")
		}
	}
}
