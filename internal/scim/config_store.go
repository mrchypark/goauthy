package scim

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const scimClientConfigEnvelopePurpose = "scim/client-config"

type ClientConfig struct {
	Endpoint    string
	BearerToken string
	CACertPEM   []byte
	Enabled     bool
}

type EnvelopeKeyring interface {
	SealEnvelope(purpose string, plaintext []byte) ([]byte, error)
	OpenEnvelope(purpose string, envelope []byte) ([]byte, error)
	ActiveMasterKeyID() (string, error)
}

type ConfigStore struct {
	DB      *rhiza.DB
	Keyring EnvelopeKeyring
}

func NewConfigStore(db *rhiza.DB, keyring EnvelopeKeyring) *ConfigStore {
	return &ConfigStore{DB: db, Keyring: keyring}
}

func (s *ConfigStore) GetClientConfig(ctx context.Context, clientID string) (ClientConfig, bool, error) {
	if s == nil || s.DB == nil || ctx == nil || clientID == "" {
		return ClientConfig{}, false, errors.New("scim config store is not configured")
	}
	result, err := s.DB.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT endpoint,bearer_envelope,ca_cert,enabled FROM scim_client_config WHERE client_id=?`,
		Args:        []any{clientID},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return ClientConfig{}, false, err
	}
	if len(result.Rows) == 0 {
		return ClientConfig{}, false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 4 {
		return ClientConfig{}, false, errors.New("invalid scim client config row")
	}
	row := result.Rows[0]
	endpoint, ok := row[0].(string)
	if !ok || endpoint == "" {
		return ClientConfig{}, false, errors.New("invalid scim client config endpoint")
	}
	bearerToken := ""
	if row[1] != nil {
		envelope, ok := row[1].([]byte)
		if !ok || len(envelope) == 0 {
			return ClientConfig{}, false, errors.New("invalid scim client config bearer envelope")
		}
		if s.Keyring == nil {
			return ClientConfig{}, false, errors.New("scim config keyring is not configured")
		}
		plain, err := s.Keyring.OpenEnvelope(scimClientConfigEnvelopePurpose, envelope)
		if err != nil {
			return ClientConfig{}, false, fmt.Errorf("decrypt scim bearer token: %w", err)
		}
		bearerToken = string(plain)
	}
	var caCertPEM []byte
	if row[2] != nil {
		data, ok := row[2].([]byte)
		if !ok || len(data) == 0 {
			return ClientConfig{}, false, errors.New("invalid scim client config ca cert")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return ClientConfig{}, false, errors.New("invalid scim client config ca certificate PEM")
		}
		caCertPEM = data
	}
	enabled, ok := row[3].(int64)
	if !ok {
		return ClientConfig{}, false, errors.New("invalid scim client config enabled")
	}
	return ClientConfig{Endpoint: endpoint, BearerToken: bearerToken, CACertPEM: caCertPEM, Enabled: enabled == 1}, true, nil
}

func (s *ConfigStore) PutClientConfig(ctx context.Context, clientID string, config ClientConfig) error {
	if s == nil || s.DB == nil || ctx == nil || clientID == "" {
		return errors.New("scim config store is not configured")
	}
	if config.Endpoint == "" || config.BearerToken == "" {
		return errors.New("scim client config endpoint and bearer token are required")
	}
	if s.Keyring == nil {
		return errors.New("scim config keyring is not configured")
	}
	envelope, err := s.Keyring.SealEnvelope(scimClientConfigEnvelopePurpose, []byte(config.BearerToken))
	if err != nil {
		return fmt.Errorf("encrypt scim bearer token: %w", err)
	}
	keyID, err := s.Keyring.ActiveMasterKeyID()
	if err != nil {
		return fmt.Errorf("get active master key: %w", err)
	}
	now := time.Now().UTC().UnixMilli()
	enabledInt := int64(0)
	if config.Enabled {
		enabledInt = 1
	}
	_, err = storage.ExecuteEnvelope(ctx, s.DB, keyID, rhiza.ExecuteRequest{
		RequestID: fmt.Sprintf("scim-config/%s/%d", digestString(clientID), now),
		SQL:       `INSERT INTO scim_client_config (client_id,endpoint,bearer_envelope,ca_cert,enabled,created_at_unix_ms,updated_at_unix_ms) VALUES (?,?,?,?,?,?,?) ON CONFLICT(client_id) DO UPDATE SET endpoint=excluded.endpoint,bearer_envelope=excluded.bearer_envelope,ca_cert=excluded.ca_cert,enabled=excluded.enabled,updated_at_unix_ms=excluded.updated_at_unix_ms`,
		Args:      []any{clientID, config.Endpoint, envelope, config.CACertPEM, enabledInt, now, now},
	})
	return err
}
