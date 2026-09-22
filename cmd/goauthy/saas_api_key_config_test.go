package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validSaaSAPIKeyConnectorJSON = `{"connectors":[{"id":"billing","header":"Authorization","prefix":"Bearer ","operations":[{"id":"account","url":"https://api.example.com/account","response_fields":{"id":"integer"}}]}]}`

func writeSaaSAPIKeyConnectorConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "connectors.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSaaSAPIKeyConnectors(t *testing.T) {
	t.Parallel()
	connectors, err := loadSaaSAPIKeyConnectors(writeSaaSAPIKeyConnectorConfig(t, validSaaSAPIKeyConnectorJSON))
	if err != nil || len(connectors) != 1 || connectors["billing"] == nil || connectors["billing"].Digest() == "" {
		t.Fatalf("connectors=%v err=%v", connectors, err)
	}
	info := connectors["billing"].Info()
	if info.Header != "Authorization" || info.Prefix != "Bearer " || len(info.Operations) != 1 || info.Operations[0].URL != "https://api.example.com/account" || info.Operations[0].ResponseFields["id"] != "integer" {
		t.Fatal("file contract differs from compiled connector")
	}
}

func TestLoadSaaSAPIKeyConnectorsEmptyPath(t *testing.T) {
	t.Parallel()
	connectors, err := loadSaaSAPIKeyConnectors("")
	if err != nil || connectors == nil || len(connectors) != 0 {
		t.Fatalf("connectors=%v err=%v", connectors, err)
	}
}

func TestLoadSaaSAPIKeyConnectorsRejectsInvalidFiles(t *testing.T) {
	t.Parallel()
	var document map[string][]json.RawMessage
	if err := json.Unmarshal([]byte(validSaaSAPIKeyConnectorJSON), &document); err != nil {
		t.Fatal(err)
	}
	entry := string(document["connectors"][0])
	tests := map[string]string{
		"null document":     `null`,
		"null list":         `{"connectors":null}`,
		"null entry":        `{"connectors":[null]}`,
		"empty list":        `{"connectors":[]}`,
		"too many":          `{"connectors":[` + strings.Repeat(entry+",", maxSaaSProviders) + entry + `]}`,
		"malformed":         `{"connectors":[`,
		"unknown field":     strings.Replace(validSaaSAPIKeyConnectorJSON, `"header"`, `"unknown":true,"header"`, 1),
		"trailing document": validSaaSAPIKeyConnectorJSON + `{}`,
		"duplicate id":      `{"connectors":[` + entry + `,` + entry + `]}`,
		"invalid URL":       strings.Replace(validSaaSAPIKeyConnectorJSON, "https://api.example.com/account", "http://api.example.com/account", 1),
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := loadSaaSAPIKeyConnectors(writeSaaSAPIKeyConnectorConfig(t, content)); !errors.Is(err, errInvalidSaaSAPIKeyConnectors) {
				t.Fatalf("expected generic configuration error, got %v", err)
			}
		})
	}

	oversize := writeSaaSAPIKeyConnectorConfig(t, strings.Repeat("x", maxUpstreamProvidersFileSize+1))
	if _, err := loadSaaSAPIKeyConnectors(oversize); err == nil {
		t.Fatal("accepted oversized connector file")
	}
}
