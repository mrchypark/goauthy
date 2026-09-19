package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/recovery"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/tlsconfig"
	"github.com/mrchypark/rhiza"
)

type applicationConfig struct {
	Issuer                     string
	Swagger                    swaggerConfig
	TLS                        *tls.Config
	TLSReloader                *tlsconfig.Reloader
	Favicon                    *branding.Asset
	CIMDEnabled                bool
	CIMDIgnoreUnknownAuthFlows bool
	CIMDDangerUnvalidated      bool
	RecoveryEnabled            bool
	OpenRegistration           recovery.RegistrationConfig
	PasswordNewExpiry          time.Duration
	UserValuesPolicy           identity.UserValuesPolicy
	Passkey                    *passkey.Config
	ForwardAuthHeaders         bool
	SelfDeleteEnabled          bool
	WebIDEnabled               bool
	Notifications              notificationsConfig
	Rhiza                      rhiza.Config
}

func loadApplicationConfig(getenv func(string) string) (applicationConfig, error) {
	if getenv == nil {
		return applicationConfig{}, errors.New("configuration requires environment reader")
	}

	var c applicationConfig
	var err error
	if c.Issuer, err = oidc.NormalizeIssuer(envValue(getenv, "GOAUTHY_ISSUER", "http://localhost:8080")); err != nil {
		return applicationConfig{}, err
	}
	if c.Swagger, err = swaggerConfigFromEnv(getenv); err != nil {
		return applicationConfig{}, err
	}
	if c.TLS, c.TLSReloader, err = tlsConfigFromEnv(getenv); err != nil {
		return applicationConfig{}, err
	}
	if err := validateIssuerTLS(c.Issuer, c.TLSReloader != nil); err != nil {
		return applicationConfig{}, err
	}
	if c.Favicon, err = faviconFromEnv(getenv); err != nil {
		return applicationConfig{}, fmt.Errorf("configure favicon: %w", err)
	}
	if c.CIMDEnabled, err = cimdEnabled(getenv); err != nil {
		return applicationConfig{}, err
	}
	if c.CIMDIgnoreUnknownAuthFlows, err = cimdIgnoreUnknownAuthFlowsFromEnv(getenv); err != nil {
		return applicationConfig{}, err
	}
	if c.CIMDDangerUnvalidated, err = cimdDangerAllowUnvalidatedResourceFromEnv(getenv); err != nil {
		return applicationConfig{}, err
	}
	if c.RecoveryEnabled, err = passwordRecoveryEnabled(getenv); err != nil {
		return applicationConfig{}, err
	}
	if c.OpenRegistration, c.PasswordNewExpiry, err = openRegistrationFromEnv(getenv, c.RecoveryEnabled, c.Issuer); err != nil {
		return applicationConfig{}, err
	}
	if c.UserValuesPolicy, err = userValuesPolicyFromEnv(getenv); err != nil {
		return applicationConfig{}, err
	}
	c.OpenRegistration.UserValuesPolicy = c.UserValuesPolicy
	if c.Passkey, err = passkeyConfigFromEnv(getenv); err != nil {
		return applicationConfig{}, err
	}
	if c.ForwardAuthHeaders, err = forwardAuthHeadersFromEnv(getenv); err != nil {
		return applicationConfig{}, err
	}
	if c.SelfDeleteEnabled, err = selfDeleteEnabledFromEnv(getenv); err != nil {
		return applicationConfig{}, err
	}
	if c.WebIDEnabled, err = webIDEnabledFromEnv(getenv); err != nil {
		return applicationConfig{}, err
	}
	if c.Notifications, err = notificationsFromEnv(getenv); err != nil {
		return applicationConfig{}, fmt.Errorf("configure event notifications: %w", err)
	}
	if c.Rhiza, err = storage.RhizaConfigFromEnv(getenv); err != nil {
		return applicationConfig{}, fmt.Errorf("configure rhiza: %w", err)
	}
	return c, nil
}

func runConfigCommand(args []string, getenv func(string) string, out io.Writer) error {
	if len(args) != 1 || (args[0] != "check" && args[0] != "dump-effective") {
		return errors.New("usage: goauthy config {check|dump-effective}")
	}
	cfg, err := loadApplicationConfig(getenv)
	if err != nil {
		return err
	}
	if args[0] == "check" {
		_, err = io.WriteString(out, "configuration valid\n")
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(effectiveConfigFrom(cfg, getenv))
}

type effectiveConfig struct {
	Issuer string `json:"issuer"`
	HTTP   struct {
		TLS            bool `json:"tls"`
		SwaggerEnabled bool `json:"swagger_enabled"`
		SwaggerPublic  bool `json:"swagger_public"`
		Favicon        bool `json:"favicon"`
	} `json:"http"`
	Identity struct {
		PasswordRecovery bool `json:"password_recovery"`
		OpenRegistration bool `json:"open_registration"`
		Passkey          bool `json:"passkey"`
		SelfDelete       bool `json:"self_delete"`
	} `json:"identity"`
	OAuth struct {
		CIMD                       bool `json:"cimd"`
		CIMDIgnoreUnknownAuthFlows bool `json:"cimd_ignore_unknown_auth_flows"`
		ForwardAuthHeaders         bool `json:"forward_auth_headers"`
		WebID                      bool `json:"webid"`
	} `json:"oauth"`
	Storage struct {
		Profile             string `json:"profile"`
		ClusterID           string `json:"cluster_id"`
		NodeID              string `json:"node_id"`
		DataDir             string `json:"data_dir"`
		ObjectStoreProvider string `json:"object_store_provider,omitempty"`
		ObjectStoreBucket   string `json:"object_store_bucket,omitempty"`
		ObjectStorePrefix   string `json:"object_store_prefix,omitempty"`
		StaticCredentials   bool   `json:"static_credentials"`
	} `json:"storage"`
	Integrations struct {
		SaaSProviderFile bool `json:"saas_provider_file"`
		UpstreamFile     bool `json:"upstream_provider_file"`
		SCIMFile         bool `json:"scim_provider_file"`
		FedCMFile        bool `json:"fedcm_config_file"`
	} `json:"integrations"`
	Notifications struct {
		Enabled bool `json:"enabled"`
		Count   int  `json:"count"`
	} `json:"notifications"`
}

func effectiveConfigFrom(c applicationConfig, getenv func(string) string) effectiveConfig {
	var out effectiveConfig
	out.Issuer = c.Issuer
	out.HTTP.TLS = c.TLSReloader != nil
	out.HTTP.SwaggerEnabled = c.Swagger.Enabled
	out.HTTP.SwaggerPublic = c.Swagger.Public
	out.HTTP.Favicon = c.Favicon != nil
	out.Identity.PasswordRecovery = c.RecoveryEnabled
	out.Identity.OpenRegistration = c.OpenRegistration.Enabled
	out.Identity.Passkey = c.Passkey != nil
	out.Identity.SelfDelete = c.SelfDeleteEnabled
	out.OAuth.CIMD = c.CIMDEnabled
	out.OAuth.CIMDIgnoreUnknownAuthFlows = c.CIMDIgnoreUnknownAuthFlows
	out.OAuth.ForwardAuthHeaders = c.ForwardAuthHeaders
	out.OAuth.WebID = c.WebIDEnabled
	out.Storage.Profile = getenv("GOAUTHY_RHIZA_PROFILE")
	out.Storage.ClusterID = c.Rhiza.ClusterID
	out.Storage.NodeID = c.Rhiza.NodeID
	out.Storage.DataDir = c.Rhiza.DataDir
	out.Storage.ObjectStoreProvider = c.Rhiza.ObjStoreProvider
	out.Storage.ObjectStoreBucket = c.Rhiza.ObjStoreBucket
	out.Storage.ObjectStorePrefix = c.Rhiza.ObjStorePrefix
	out.Storage.StaticCredentials = c.Rhiza.ObjStoreAccessKey != "" || c.Rhiza.ObjStoreSecretKey != "" || c.Rhiza.ObjStoreSessionToken != ""
	out.Integrations.SaaSProviderFile = getenv("GOAUTHY_SAAS_PROVIDERS_FILE") != ""
	out.Integrations.UpstreamFile = getenv("GOAUTHY_UPSTREAM_PROVIDERS_FILE") != ""
	out.Integrations.SCIMFile = getenv("GOAUTHY_SCIM_PROVIDERS_FILE") != ""
	out.Integrations.FedCMFile = getenv("GOAUTHY_FEDCM_CONFIG_FILE") != ""
	out.Notifications.Enabled = len(c.Notifications.Targets) != 0
	out.Notifications.Count = len(c.Notifications.Targets)
	return out
}
