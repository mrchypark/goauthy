package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/mrchypark/goauthy/internal/saas"
)

type saasAPIKeyConnectorsDocument struct {
	Connectors []saasAPIKeyConnectorFileConfig `json:"connectors"`
}

type saasAPIKeyConnectorFileConfig struct {
	ID         string                          `json:"id"`
	Header     string                          `json:"header"`
	Prefix     string                          `json:"prefix"`
	Operations []saasAPIKeyOperationFileConfig `json:"operations"`
}

type saasAPIKeyOperationFileConfig struct {
	ID             string            `json:"id"`
	URL            string            `json:"url"`
	ResponseFields map[string]string `json:"response_fields"`
}

var errInvalidSaaSAPIKeyConnectors = errors.New("invalid SaaS API-key connectors configuration")

func loadSaaSAPIKeyConnectors(path string) (map[string]*saas.APIKeyConnector, error) {
	if path == "" {
		return map[string]*saas.APIKeyConnector{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errInvalidSaaSAPIKeyConnectors
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxUpstreamProvidersFileSize+1))
	if err != nil || len(data) > maxUpstreamProvidersFileSize {
		return nil, errInvalidSaaSAPIKeyConnectors
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document saasAPIKeyConnectorsDocument
	if decoder.Decode(&document) != nil {
		return nil, errInvalidSaaSAPIKeyConnectors
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errInvalidSaaSAPIKeyConnectors
	}
	if len(document.Connectors) < 1 || len(document.Connectors) > maxSaaSProviders {
		return nil, errInvalidSaaSAPIKeyConnectors
	}
	connectors := make(map[string]*saas.APIKeyConnector, len(document.Connectors))
	for _, cfg := range document.Connectors {
		if _, exists := connectors[cfg.ID]; exists {
			return nil, errInvalidSaaSAPIKeyConnectors
		}
		operations := make([]saas.APIKeyOperationConfig, len(cfg.Operations))
		for i, op := range cfg.Operations {
			operations[i] = saas.APIKeyOperationConfig{ID: op.ID, URL: op.URL, ResponseFields: op.ResponseFields}
		}
		connector, err := saas.NewAPIKeyConnector(saas.APIKeyConnectorConfig{
			ID: cfg.ID, Header: cfg.Header, Prefix: cfg.Prefix, Operations: operations,
		})
		if err != nil {
			return nil, errInvalidSaaSAPIKeyConnectors
		}
		connectors[cfg.ID] = connector
	}
	return connectors, nil
}
