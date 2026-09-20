package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/backchannel"
	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/geoblock"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oauth"
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
	if err := validateRuntimeConfig(getenv, c); err != nil {
		return applicationConfig{}, err
	}
	return c, nil
}

// validateRuntimeConfig runs the startup configuration parsers that used to run
// only after Rhiza was opened, bootstrap mutations had committed or workers had
// started. Callers reach it through loadApplicationConfig, so `config check`
// rejects exactly the configuration startup would reject, and startup rejects
// that configuration before any store, mutation or listener side effect.
//
// Conditions mirror startup: a parser that startup only runs for an enabled
// feature is only run here for that feature. Deployment key material read from
// default paths (master keys, the OAuth HMAC and bootstrap client secrets) stays
// out of the preflight because the configuration command must not require
// mounted secrets; an explicitly configured path is content-validated.
func validateRuntimeConfig(getenv func(string) string, cfg applicationConfig) error {
	if _, err := scheduledBackupFromEnv(getenv, cfg.Rhiza); err != nil {
		return err
	}
	if _, err := ipBlacklistEnabled(getenv); err != nil {
		return err
	}
	if _, err := generatedBootstrapConfigFromEnv(getenv); err != nil {
		return err
	}
	registrationToken, err := dcrRegistrationToken(getenv)
	if err != nil {
		return err
	}
	anonymousDCR, _, err := dcrAnonymousConfig(getenv)
	if err != nil {
		return err
	}
	if registrationToken != "" && anonymousDCR {
		return errors.New("GOAUTHY_DCR_REGISTRATION_TOKEN_FILE and GOAUTHY_DCR_ANONYMOUS cannot both be configured")
	}
	if anonymousDCR {
		if _, err := dcrAnonymousCleanupConfigFromEnv(getenv); err != nil {
			return err
		}
	}
	if _, err := rfc8252LoopbackRedirects(getenv); err != nil {
		return err
	}
	if _, err := dcrScopePolicy(getenv); err != nil {
		return err
	}
	if _, err := dcrSoftwareStatementConfig(getenv); err != nil {
		return err
	}
	allowedResources, err := bootstrapAllowedResources(getenv)
	if err != nil {
		return err
	}
	for _, name := range []string{"GOAUTHY_CONNECTIONS_RESOURCE", "GOAUTHY_PROVIDERS_RESOURCE"} {
		if _, err := resourceFromEnv(getenv, name, allowedResources); err != nil {
			return err
		}
	}

	argonPolicy, err := argonPolicyFromEnv(getenv)
	if err != nil {
		return err
	}
	passwordHasher, err := credential.NewHasher(argonPolicy)
	if err != nil {
		return fmt.Errorf("configure Argon2 password policy: %w", err)
	}
	if _, err := passwordRulesFromEnvWithRecovery(getenv, cfg.RecoveryEnabled); err != nil {
		return err
	}
	if cfg.RecoveryEnabled {
		if _, err := loadPasswordResetKey(getenv); err != nil {
			return err
		}
	}
	if path := getenv("GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE"); path != "" {
		encoded, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read bootstrap user password credential: %w", err)
		}
		if err := passwordHasher.ValidateCurrentPHC(strings.TrimSpace(string(encoded))); err != nil {
			return fmt.Errorf("bootstrap user password credential: %w", err)
		}
	}

	bootstrapForceMFAValue, err := bootstrapForceMFA(getenv)
	if err != nil {
		return err
	}
	if err := validateBootstrapPasskeyConfig(bootstrapForceMFAValue, cfg.Passkey); err != nil {
		return err
	}
	bootstrapRoles, bootstrapGroups, err := bootstrapPrincipalFromEnv(getenv)
	if err != nil {
		return err
	}
	bootstrapConfigured := getenv("GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE") != ""
	if !bootstrapConfigured && (len(bootstrapRoles) != 0 || len(bootstrapGroups) != 0) {
		return errors.New("GOAUTHY_BOOTSTRAP_USER_ROLES and GOAUTHY_BOOTSTRAP_USER_GROUPS require GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE")
	}
	if cfg.RecoveryEnabled {
		if bootstrapConfigured && getenv("GOAUTHY_BOOTSTRAP_USER_EMAIL") == "" {
			return errors.New("GOAUTHY_BOOTSTRAP_USER_EMAIL is required for an enabled bootstrap user when password recovery is enabled")
		}
		if _, _, err := passwordProofConfig(getenv); err != nil {
			return err
		}
	}
	if getenv("GOAUTHY_SMTP_HOST") != "" || cfg.RecoveryEnabled {
		if _, err := smtpSenderFromEnv(getenv); err != nil {
			return err
		}
	}

	if _, err := signingKeyRotationPeriod(getenv); err != nil {
		return err
	}
	if _, err := eventRetentionFromEnv(getenv); err != nil {
		return err
	}
	if _, _, err := tokenIssuedConfigFromEnv(getenv); err != nil {
		return err
	}
	if _, err := userExpirySettingsFromEnv(getenv); err != nil {
		return err
	}
	if _, err := userListThresholdFromEnv(getenv); err != nil {
		return err
	}
	if _, err := browserIDPolicyFromEnv(getenv, cfg.Issuer); err != nil {
		return err
	}
	if strings.ContainsAny(envValue(getenv, "GOAUTHY_EMAIL_SUB_PREFIX", "Rauthy IAM"), "\r\n") {
		return errors.New("GOAUTHY_EMAIL_SUB_PREFIX must not contain line breaks")
	}

	if _, err := loadSaaSProviders(getenv("GOAUTHY_SAAS_PROVIDERS_FILE")); err != nil {
		return fmt.Errorf("configure SaaS providers: %w", err)
	}
	if path := getenv("GOAUTHY_UPSTREAM_PROVIDERS_FILE"); path != "" {
		if _, err := loadUpstreamProviders(path, cfg.Issuer); err != nil {
			return err
		}
	}
	if path := getenv("GOAUTHY_SCIM_PROVIDERS_FILE"); path != "" {
		if _, err := loadSCIMProviders(path); err != nil {
			return err
		}
	}
	if path := getenv("GOAUTHY_FEDCM_CONFIG_FILE"); path != "" {
		fedcmConfig, err := loadFedCMConfig(path)
		if err != nil {
			return err
		}
		if err := validateFedCMLoginURL(fedcmConfig.LoginURL); err != nil {
			return err
		}
		if err := validateFedCMLandingPath(fedcmConfig.LoginURL); err != nil {
			return err
		}
	}

	if _, err := browserSessionIdleTimeout(getenv); err != nil {
		return err
	}
	if _, err := clientCredentialsTokenLifetime(getenv); err != nil {
		return err
	}
	if _, err := clientCredentialsMapSubFromEnv(getenv); err != nil {
		return err
	}
	if _, err := bootstrapDefaultAudience(getenv); err != nil {
		return err
	}
	if _, err := bootstrapPostLogoutRedirectURIs(getenv); err != nil {
		return err
	}
	backchannelURI, _, _, _, err := backchannelSettings(getenv)
	if err != nil {
		return err
	}
	if caFile := getenv("GOAUTHY_BOOTSTRAP_BACKCHANNEL_CA_FILE"); caFile != "" {
		if backchannelURI == "" {
			return errors.New("GOAUTHY_BOOTSTRAP_BACKCHANNEL_CA_FILE requires a back-channel logout URI")
		}
		if _, err := backchannel.NewRootCAReloader(caFile); err != nil {
			return err
		}
	}
	trustedProxies, err := trustedProxiesFromEnv(getenv)
	if err != nil {
		return err
	}
	geoConfig, err := geoblockConfigFromEnv(getenv)
	if err != nil {
		return err
	}
	if err := validateGeoblockRuntime(geoConfig, trustedProxies); err != nil {
		return err
	}
	if geoConfig.MaxMindPath != "" {
		reader, err := geoblock.OpenMaxMind(geoConfig.MaxMindPath)
		if err != nil {
			return fmt.Errorf("open geoblock MaxMind database: %w", err)
		}
		if err := reader.Close(); err != nil {
			return err
		}
	}
	metricsAddr, err := metricsListenAddrFromEnv(getenv)
	if err != nil {
		return err
	}
	if metricsAddr != "" {
		if _, err := loadMetricsToken(getenv); err != nil {
			return err
		}
	}
	if path := getenv("GOAUTHY_OAUTH_HMAC_SECRET_FILE"); path != "" {
		if _, err := oauth.LoadSecret(path); err != nil {
			return err
		}
	}
	if path := getenv("GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE"); path != "" {
		if _, err := oauth.LoadClientSecret(path); err != nil {
			return err
		}
	}
	return nil
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
