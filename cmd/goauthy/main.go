package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ory/fosite"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/account"
	"github.com/mrchypark/goauthy/internal/admin"
	"github.com/mrchypark/goauthy/internal/apidocs"
	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/authcollection"
	"github.com/mrchypark/goauthy/internal/backchannel"
	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/captcha"
	"github.com/mrchypark/goauthy/internal/cimd"
	"github.com/mrchypark/goauthy/internal/claims"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/fedcm"
	"github.com/mrchypark/goauthy/internal/geoblock"
	"github.com/mrchypark/goauthy/internal/housekeeping"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/ipblacklist"
	"github.com/mrchypark/goauthy/internal/kv"
	"github.com/mrchypark/goauthy/internal/login"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/logout"
	"github.com/mrchypark/goauthy/internal/masterkeyretirement"
	"github.com/mrchypark/goauthy/internal/metrics"
	"github.com/mrchypark/goauthy/internal/oauth"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/rbac"
	"github.com/mrchypark/goauthy/internal/recovery"
	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/tlsconfig"
	"github.com/mrchypark/goauthy/internal/tracing"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/goauthy/internal/webid"
	"github.com/mrchypark/rhiza"
	"golang.org/x/net/http/httpguts"
)

const (
	serverWriteTimeout              = time.Minute
	openRegistrationCleanupInterval = time.Hour
	scimWorkerInterval              = 5 * time.Minute
)

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "config" {
		err = runConfigCommand(os.Args[2:], os.Getenv, os.Stdout)
	} else {
		err = run()
	}
	if err != nil {
		slog.Error("goauthy stopped", "error", err)
		os.Exit(1)
	}
}

func run() (err error) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	tracingShutdown, tracingErr := tracing.Init(ctx)
	if tracingErr != nil {
		slog.Warn("tracing initialization failed", "error", tracingErr)
	}
	if tracingShutdown != nil {
		defer func() { _ = tracingShutdown(context.Background()) }()
	}
	appConfig, err := loadApplicationConfig(os.Getenv)
	if err != nil {
		return err
	}
	issuer := appConfig.Issuer
	swaggerConfig := appConfig.Swagger
	tlsConfig := appConfig.TLS
	tlsReloader := appConfig.TLSReloader
	favicon := appConfig.Favicon
	cimdConfigured := appConfig.CIMDEnabled
	cimdIgnoreUnknownAuthFlows := appConfig.CIMDIgnoreUnknownAuthFlows
	cimdDangerAllowUnvalidatedResource := appConfig.CIMDDangerUnvalidated
	recoveryEnabled := appConfig.RecoveryEnabled
	openRegistration := appConfig.OpenRegistration
	passwordNewExpiry := appConfig.PasswordNewExpiry
	userValuesPolicy := appConfig.UserValuesPolicy
	passkeyConfig := appConfig.Passkey
	forwardAuthHeaders := appConfig.ForwardAuthHeaders
	selfDeleteEnabled := appConfig.SelfDeleteEnabled
	webIDEnabled := appConfig.WebIDEnabled
	notificationConfig := appConfig.Notifications
	masterKeyDir := env("GOAUTHY_MASTER_KEY_DIR", "./secrets/master-keys")
	keyring, err := oidc.LoadKeyring(
		masterKeyDir,
		env("GOAUTHY_ACTIVE_MASTER_KEY_ID", "dev-1"),
	)
	if err != nil {
		return err
	}
	bootID, err := newMasterKeyBootID()
	if err != nil {
		return err
	}

	rhizaConfig := appConfig.Rhiza
	backupConfig, err := scheduledBackupFromEnv(os.Getenv, rhizaConfig)
	if err != nil {
		return err
	}
	db, err := rhiza.Open(ctx, rhizaConfig)
	if err != nil {
		return fmt.Errorf("open rhiza: %w", err)
	}
	dbCloseAllowed := false
	defer func() { err = closeRhizaAfterStartupComplete(db, dbCloseAllowed, err) }()
	startupCtx, cancelStartup := context.WithTimeout(ctx, 30*time.Second)
	defer cancelStartup()
	for !db.Ready() {
		select {
		case <-startupCtx.Done():
			return fmt.Errorf("wait for rhiza readiness: %w", startupCtx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err := storage.Migrate(ctx, db); err != nil {
		return err
	}
	if err := admitMasterKeyRuntime(ctx, db, keyring); err != nil {
		return err
	}
	blacklistEnabled, err := ipBlacklistEnabled(os.Getenv)
	if err != nil {
		return err
	}
	apiKeyStore, err := apikey.NewStore(db)
	if err != nil {
		return fmt.Errorf("configure API-key store: %w", err)
	}
	generatedBootstrap, err := generatedBootstrapConfigFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	if err := bootstrapAPIKeys(ctx, apiKeyStore, keyring, os.Getenv("GOAUTHY_API_KEY_BOOTSTRAP_FILE"), masterKeyDir, generatedBootstrap, time.Now()); err != nil {
		return fmt.Errorf("bootstrap API keys: %w", err)
	}
	cimdResolver, err := configureCIMD(db, cimdConfigured, cimd.Policy{IgnoreUnknownAuthFlows: cimdIgnoreUnknownAuthFlows, DangerAllowUnvalidatedResource: cimdDangerAllowUnvalidatedResource})
	if err != nil {
		return err
	}
	registrationToken, err := dcrRegistrationToken(os.Getenv)
	if err != nil {
		return err
	}
	dcrAnonymous, dcrRateLimitWindow, err := dcrAnonymousConfig(os.Getenv)
	if err != nil {
		return err
	}
	var dcrCleanupConfig dcr.AnonymousCleanupConfig
	if dcrAnonymous {
		dcrCleanupConfig, err = dcrAnonymousCleanupConfigFromEnv(os.Getenv)
		if err != nil {
			return err
		}
	}
	if registrationToken != "" && dcrAnonymous {
		return errors.New("GOAUTHY_DCR_REGISTRATION_TOKEN_FILE and GOAUTHY_DCR_ANONYMOUS cannot both be configured")
	}
	loopbackRedirects, err := rfc8252LoopbackRedirects(os.Getenv)
	if err != nil {
		return err
	}
	dynamicClientScopePolicy, err := dcrScopePolicy(os.Getenv)
	if err != nil {
		return err
	}
	softwareStatementConfig, err := dcrSoftwareStatementConfig(os.Getenv)
	if err != nil {
		return err
	}
	allowedResources, err := bootstrapAllowedResources(os.Getenv)
	if err != nil {
		return err
	}
	softwareStatementDigest, err := softwareStatementConfig.CanonicalDigest()
	if err != nil {
		return fmt.Errorf("canonicalize DCR software-statement trust: %w", err)
	}
	retirementMembers := rhizaMemberIDs(rhizaConfig)
	if err := storage.EnsureDCRSoftwareStatementTrust(ctx, db, softwareStatementDigest, retirementMembers); err != nil {
		return fmt.Errorf("fence DCR software-statement trust: %w", err)
	}
	clientID := env("GOAUTHY_BOOTSTRAP_CLIENT_ID", "goauthy-dev")
	var registrationHandler http.Handler
	var dynamicClientStore *dcr.Store
	if registrationToken != "" || dcrAnonymous {
		dynamicClientStore = dcr.NewStore(db, dcr.Config{AllowRFC8252LoopbackRedirects: loopbackRedirects, ScopePolicy: dynamicClientScopePolicy, ReservedClientIDs: []string{clientID}, Keyring: keyring})
		registrationHandler, err = dcr.NewHandler(dynamicClientStore, issuer, registrationToken, dcr.HandlerConfig{Anonymous: dcrAnonymous, AnonymousRateLimitWindow: dcrRateLimitWindow, SoftwareStatements: softwareStatementConfig, AllowedResources: allowedResources})
		if err != nil {
			return fmt.Errorf("configure DCR handler: %w", err)
		}
	}
	argonPolicy, err := argonPolicyFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	passwordHasher, err := credential.NewHasher(argonPolicy)
	if err != nil {
		return fmt.Errorf("configure Argon2 password policy: %w", err)
	}
	passwordRules, err := passwordRulesFromEnvWithRecovery(os.Getenv, recoveryEnabled)
	if err != nil {
		return err
	}
	var resetKey []byte
	if recoveryEnabled {
		resetKey, err = loadPasswordResetKey(os.Getenv)
		if err != nil {
			return err
		}
	}
	identityStore, err := newIdentityStore(db, passwordHasher, passwordRules, resetKey)
	if err != nil {
		return err
	}
	webIDHandler, err := webid.NewHandler(issuer, identityStore)
	if err != nil {
		return fmt.Errorf("configure WebID handler: %w", err)
	}
	scimRuntime, err := scimRuntimeFromEnv(os.Getenv, db, identityStore, keyring)
	if err != nil {
		return fmt.Errorf("configure SCIM runtime: %w", err)
	}
	userExpiryConfig, err := userExpirySettingsFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	if err := bootstrapUser(ctx, identityStore, os.Getenv); err != nil {
		return err
	}
	bootstrapRoles, bootstrapGroups, err := bootstrapPrincipalFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	bootstrapSubject := envValue(os.Getenv, "GOAUTHY_BOOTSTRAP_USER_SUBJECT", "bootstrap-admin")
	bootstrapConfigured := os.Getenv("GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE") != ""
	if !bootstrapConfigured && (len(bootstrapRoles) != 0 || len(bootstrapGroups) != 0) {
		return errors.New("GOAUTHY_BOOTSTRAP_USER_ROLES and GOAUTHY_BOOTSTRAP_USER_GROUPS require GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE")
	}
	rbacStore := rbac.NewStore(db)
	managedClients := clients.NewStore(db, keyring, clientID)
	if err := managedClients.EnsureBootstrap(ctx, clientID); err != nil {
		return fmt.Errorf("reserve bootstrap client: %w", err)
	}
	claimsStore := claims.NewStore(db)
	rbacStore.BindAPIKeys(apiKeyStore)
	claimsStore.BindAPIKeys(apiKeyStore)
	if bootstrapConfigured {
		if err := identityStore.ValidateSubject(ctx, bootstrapSubject); err != nil {
			return fmt.Errorf("validate bootstrap RBAC principal: %w", err)
		}
		if _, err := rbacStore.EnsureBootstrapPrincipal(ctx, bootstrapSubject, bootstrapRoles, bootstrapGroups); err != nil {
			return fmt.Errorf("bootstrap RBAC principal: %w", err)
		}
	}
	blacklistStore := ipblacklist.NewStore(db, 0)
	var automaticBlacklist *ipblacklist.Store
	if blacklistEnabled {
		automaticBlacklist = blacklistStore
	}
	loginPolicyStore := loginpolicy.NewStoreWithBlacklist(db, automaticBlacklist)
	lockdownStore := loginpolicy.NewLockdownStore(db)
	var recoveryService *recovery.Service
	var loginLocationSender *recovery.SMTPSender
	var emailOutbox *recovery.EmailOutbox
	captchaVerifier := captcha.NewVerifier(os.Getenv)
	if recoveryEnabled {
		sender, senderErr := smtpSenderFromEnv(os.Getenv)
		if senderErr != nil {
			return senderErr
		}
		var outboxErr error
		emailOutbox, outboxErr = recovery.NewEmailOutbox(db, recovery.SMTPSendFunc(sender), recovery.WithEnvelopeKeyring(keyring))
		if outboxErr != nil {
			return fmt.Errorf("configure email outbox: %w", outboxErr)
		}
		sender.OnDeliveryFailure = func(recipient, mailType, subject, textBody, htmlBody string, err error) {
			slog.Error("email delivery failed", "mail_type", mailType, "recipient", recipient, "error", err)
			operation := "email-error/" + rand.Text()
			event := eventlog.EmailSendErrorEvent(operation, mailType, recipient, time.Now())
			if stmt, stmtErr := event.Statement("1=1"); stmtErr == nil {
				storage.Execute(ctx, db, rhiza.ExecuteRequest{Statements: []rhiza.SQLStatement{stmt}})
			}
			if emailOutbox != nil {
				if qErr := emailOutbox.Enqueue(ctx, recipient, mailType, subject, htmlBody, textBody); qErr != nil {
					slog.Error("email outbox enqueue failed", "error", qErr)
				}
			}
		}
		loginLocationSender = sender
		powDifficulty, powTTL, powErr := passwordProofConfig(os.Getenv)
		if powErr != nil {
			return powErr
		}
		pow, powErr := recovery.NewProofOfWork(db, resetKey)
		if powErr != nil {
			return fmt.Errorf("configure password proof of work: %w", powErr)
		}
		var options []recovery.ServiceOption
		if openRegistration.Enabled {
			bootstrapRedirect := env("GOAUTHY_BOOTSTRAP_REDIRECT_URI", "http://localhost:5555/callback")
			options = append(options, recovery.WithOpenRegistration(openRegistration, passwordNewExpiry, func(ctx context.Context, uri string) (bool, error) {
				if uri == bootstrapRedirect {
					return true, nil
				}
				if dynamicClientStore == nil {
					return false, nil
				}
				return dynamicClientStore.HasExactRedirectURI(ctx, uri)
			}))
		}
		recoveryService, err = recovery.NewService(db, identityStore, sender, issuer, passwordRules, loginPolicyStore, pow, powDifficulty, powTTL, options...)
		if err != nil {
			return fmt.Errorf("configure password recovery: %w", err)
		}
		recoveryService.OnError = func(error) {
			slog.Error("account email delivery failed")
		}
		recoveryService.SetCaptchaVerifier(captchaVerifier)
		if scimRuntime != nil {
			recoveryService.OnUserCreated = scimRuntime.Wake
		}
		if email := os.Getenv("GOAUTHY_BOOTSTRAP_USER_EMAIL"); email != "" {
			if err := recoveryService.BindEmail(ctx, envValue(os.Getenv, "GOAUTHY_BOOTSTRAP_USER_SUBJECT", "bootstrap-admin"), email); err != nil {
				return fmt.Errorf("bind bootstrap recovery email: %w", err)
			}
		} else if os.Getenv("GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE") != "" {
			return errors.New("GOAUTHY_BOOTSTRAP_USER_EMAIL is required for an enabled bootstrap user when password recovery is enabled")
		}
	}
	if _, err := oidc.EnsureSigningKey(ctx, db, keyring, issuer, time.Now()); err != nil {
		return err
	}
	rotationPeriod, err := signingKeyRotationPeriod(os.Getenv)
	if err != nil {
		return err
	}
	rotationWorker := oidc.SigningKeyRotationWorker{
		DB: db, Keyring: keyring, Issuer: issuer, TickInterval: oidc.JWKSCacheMaxAge, RotationPeriod: rotationPeriod,
		OnError: func(err error) { slog.Error("signing key rotation failed", "error", err) },
	}
	rewrapWorker, err := newMasterKeyRewrapWorker(db, keyring, issuer)
	if err != nil {
		return fmt.Errorf("configure master-key rewrap worker: %w", err)
	}
	rewrapWorker.onError = func(error) { slog.Error("master-key rewrap failed") }
	eventStore, err := eventlog.NewStore(db)
	if err != nil {
		return err
	}
	apiKeyStore.OnAuthFailure = func(keyName, ip string) {
		op := "suspicious-api-scan/" + rand.Text()
		event := eventlog.SuspiciousApiScanEvent(op, keyName, ip, time.Now())
		if stmt, stmtErr := event.Statement("1=1"); stmtErr == nil {
			storage.Execute(ctx, db, rhiza.ExecuteRequest{Statements: []rhiza.SQLStatement{stmt}})
		}
	}
	eventRetention, err := eventRetentionFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	notifications, err := newNotificationRuntime(ctx, db, notificationConfig)
	if err != nil {
		return fmt.Errorf("configure event notification worker: %w", err)
	}
	backups, err := newScheduledBackupRuntime(ctx, backupConfig)
	if err != nil {
		return err
	}
	defer func() {
		if err := backups.Close(); err != nil {
			slog.Error("backup object-store client shutdown failed")
		}
	}()
	workerCtx, cancelWorker := context.WithCancel(ctx)
	var workers sync.WaitGroup
	if backups != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := backups.Run(workerCtx, db); err != nil && workerCtx.Err() == nil {
				slog.Error("scheduled backup worker stopped")
			}
		}()
	}

	if generatedBootstrap.artifact != "" {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runGeneratedBootstrapPurge(workerCtx, apiKeyStore, keyring, generatedBootstrap, masterKeyDir, func(error) { slog.Error("generated bootstrap purge failed") })
		}()
	}
	if notifications != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runNotifications(workerCtx, notifications, time.Now, func(error) { slog.Error("event notification worker step failed") })
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		if err := runEventCleanup(workerCtx, eventStore, eventCleanupInterval, eventRetention, time.Now, func(error) {
			slog.Error("lifecycle event cleanup failed")
		}); err != nil {
			slog.Error("lifecycle event cleanup stopped")
		}
	}()
	workers.Add(1)
	go func() {
		defer workers.Done()
		if err := runUserExpiry(workerCtx, identityStore, userExpiryConfig, time.Now, func(error) {
			slog.Error("account expiry cleanup failed")
		}); err != nil {
			slog.Error("account expiry worker stopped")
		}
	}()
	workers.Add(1)
	go func() {
		defer workers.Done()
		if err := rotationWorker.Run(workerCtx); err != nil {
			slog.Error("signing key rotation stopped", "error", err)
		}
	}()
	if scimRuntime != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := scimRuntime.Run(workerCtx, scimWorkerInterval, time.Now, func(error) {
				slog.Error("SCIM synchronization failed")
			}); err != nil {
				slog.Error("SCIM worker stopped")
			}
		}()
	}
	if recoveryService != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := runOpenRegistrationCleanup(workerCtx, identityStore, openRegistrationCleanupInterval, time.Now, func(err error) {
				slog.Error("open registration cleanup failed", "error", err)
			}); err != nil {
				slog.Error("open registration cleanup stopped", "error", err)
			}
		}()
	}
	if dcrAnonymous {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := runDCRAnonymousCleanup(workerCtx, db, dcrCleanupConfig, dcrAnonymousCleanupInterval, time.Now, func(err error) {
				slog.Error("anonymous dynamic client cleanup failed", "error", err)
			}); err != nil {
				slog.Error("anonymous dynamic client cleanup stopped", "error", err)
			}
		}()
	}
	housekeepingJobs := buildHousekeepingJobs(
		eventStore,
		eventRetention,
		identityStore,
		userExpiryConfig,
		db,
		dcrAnonymous,
		dcrCleanupConfig,
		recoveryService,
		loginPolicyStore,
		keyring,
		emailOutbox,
	)
	if scheduler := housekeeping.New(housekeepingJobs, housekeepingErrorHandler); len(housekeepingJobs) > 0 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			scheduler.Run(workerCtx)
		}()
	}
	defer func() {
		cancelWorker()
		workers.Wait()
	}()
	hmacSecret, err := oauth.LoadSecret(env("GOAUTHY_OAUTH_HMAC_SECRET_FILE", "./secrets/oauth-hmac"))
	if err != nil {
		return err
	}
	clientSecret, err := oauth.LoadClientSecret(env("GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE", "./secrets/bootstrap-client"))
	if err != nil {
		return err
	}
	defaultAudience, err := bootstrapDefaultAudience(os.Getenv)
	if err != nil {
		return err
	}
	var defaultAudiences map[string]string
	if defaultAudience != "" {
		defaultAudiences = map[string]string{clientID: defaultAudience}
	}
	postLogoutRedirectURIs, err := bootstrapPostLogoutRedirectURIs(os.Getenv)
	if err != nil {
		return err
	}
	bootstrapForceMFA, err := bootstrapForceMFA(os.Getenv)
	if err != nil {
		return err
	}
	if err := validateBootstrapPasskeyConfig(bootstrapForceMFA, passkeyConfig); err != nil {
		return err
	}
	idleTimeout, err := browserSessionIdleTimeout(os.Getenv)
	if err != nil {
		return err
	}
	clientCredentialsTokenLifetime, err := clientCredentialsTokenLifetime(os.Getenv)
	if err != nil {
		return err
	}
	clientCredentialsMapSub, err := clientCredentialsMapSubFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	backchannelURI, allowPrivateBackchannel, allowHTTPBackchannel, retryBase, err := backchannelSettings(os.Getenv)
	if err != nil {
		return err
	}
	backchannelCAFile := os.Getenv("GOAUTHY_BOOTSTRAP_BACKCHANNEL_CA_FILE")
	if backchannelURI == "" && backchannelCAFile != "" {
		return errors.New("GOAUTHY_BOOTSTRAP_BACKCHANNEL_CA_FILE requires a back-channel logout URI")
	}
	var backchannelRootCAReloader *backchannel.RootCAReloader
	if backchannelCAFile != "" {
		backchannelRootCAReloader, err = backchannel.NewRootCAReloader(backchannelCAFile)
		if err != nil {
			return err
		}
	}
	trustedProxies, err := trustedProxiesFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	geoConfig, err := geoblockConfigFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	if err := validateGeoblockRuntime(geoConfig, trustedProxies); err != nil {
		return err
	}
	var geoReader *geoblock.MaxMindReader
	if geoConfig.MaxMindPath != "" {
		geoReader, err = geoblock.OpenMaxMind(geoConfig.MaxMindPath)
		if err != nil {
			return fmt.Errorf("open geoblock MaxMind database: %w", err)
		}
		defer func() { err = errors.Join(err, geoReader.Close()) }()
	}
	var locationLookup func(netip.Addr) (*string, error)
	if geoReader != nil {
		locationLookup = geoReader.Location
	}
	var passkeyService *passkey.Service
	if passkeyConfig != nil {
		passkeyConfig.SessionIdleTimeout = idleTimeout
		passkeyConfig.Keyring = keyring
		passkeyService, err = passkey.New(db, *passkeyConfig)
		if err != nil {
			return fmt.Errorf("configure passkeys: %w", err)
		}
	}
	var expiredRecovery func(context.Context, string) error
	if recoveryService != nil {
		expiredRecovery = recoveryService.IssueForSubject
	}
	oauthServer, err := oauth.NewServerWithOIDC(ctx, db, hmacSecret,
		clientID, clientSecret,
		env("GOAUTHY_BOOTSTRAP_REDIRECT_URI", "http://localhost:5555/callback"),
		allowedResources,
		oauth.OIDCConfig{Issuer: issuer, PasswordUsers: identityStore, PasswordExpired: expiredRecovery, ManagedClients: managedClients, DefaultAudiences: defaultAudiences, CIMDDangerAllowUnvalidatedResource: cimdDangerAllowUnvalidatedResource, LoadSigningKey: func(ctx context.Context) (oidc.SigningKey, error) {
			return oidc.LoadActiveSigningKey(ctx, db, keyring, issuer)
		}, LoadVerificationKeys: func(ctx context.Context) ([]jose.JSONWebKey, error) {
			return oidc.LoadJWKSKeys(ctx, db, time.Now().UTC())
		}, ValidateSubject: identityStore.ValidateSubject, ResolveProfile: func(ctx context.Context, subject string) (oidc.ProfileClaims, error) {
			profile, err := identityStore.ProfileClaimsBySubject(ctx, subject)
			if err != nil {
				return oidc.ProfileClaims{}, err
			}
			return oidcProfileClaims(profile, userValuesPolicy.PreferredUsername.EmailFallback()), nil
		}, ResolvePrincipal: func(ctx context.Context, subject string) (oauth.PrincipalClaims, error) {
			principal, err := rbacStore.ResolvePrincipal(ctx, subject)
			if err != nil {
				return oauth.PrincipalClaims{}, err
			}
			claims := oauth.PrincipalClaims{Roles: make([]string, len(principal.Roles)), Groups: make([]string, len(principal.Groups)), Revision: principal.Revision}
			for i, role := range principal.Roles {
				claims.Roles[i] = role.Name
			}
			for i, group := range principal.Groups {
				claims.Groups[i] = group.Name
			}
			return claims, nil
		}, ForwardAuthEnabled: forwardAuthHeaders, ResolveForwardAuthProfile: func(ctx context.Context, subject string) (oauth.ForwardAuthProfile, error) {
			profile, err := identityStore.AccountProfileBySubject(ctx, subject)
			if err != nil {
				return oauth.ForwardAuthProfile{}, err
			}
			return oauth.ForwardAuthProfile{Email: profile.Email, EmailVerified: profile.EmailVerified, PreferredUsername: profile.PreferredUsername, GivenName: profile.GivenName, FamilyName: profile.FamilyName}, nil
		}, ResolveForwardAuthPasskeyEnrollment: forwardAuthPasskeyEnrollment(passkeyService), ResolveCustomClaims: claimsStore.Resolve, BootstrapClientScopes: claimsStore.BootstrapClientScopes, ResolveClientCredentialsClaims: claimsStore.BootstrapClientCredentialsClaims, DynamicClientScopePolicy: dynamicClientScopePolicy, CustomScopeExists: claimsStore.ScopeExists, ClientGroupPolicy: func(ctx context.Context, requestedClientID string) (oauth.ClientGroupPolicy, error) {
			if requestedClientID != clientID {
				return oauth.ClientGroupPolicy{}, nil
			}
			policy, err := rbacStore.GetBootstrapClientLoginRestriction(ctx, requestedClientID)
			if err != nil {
				return oauth.ClientGroupPolicy{}, err
			}
			prefix := ""
			if policy.RestrictGroupPrefix != nil {
				prefix = *policy.RestrictGroupPrefix
			}
			return oauth.ClientGroupPolicy{Managed: true, Prefix: prefix, Revision: policy.Revision}, nil
		}, BrowserSessionIdleTimeout: idleTimeout, ClientCredentialsTokenLifespan: clientCredentialsTokenLifetime, ClientCredentialsMapSub: clientCredentialsMapSub, BootstrapForceMFA: bootstrapForceMFA, RFC8252LoopbackRedirects: loopbackRedirects, CIMD: cimdResolver,
			BackChannelLogoutURI: backchannelURI, BackChannelLogoutAllowPrivate: allowPrivateBackchannel, BackChannelLogoutAllowHTTP: allowHTTPBackchannel},
	)
	if err != nil {
		return err
	}
	tokenEvents, tokenEventLevel, err := tokenIssuedConfigFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	if tokenEvents {
		oauthServer.SetTokenIssued(func(ctx context.Context, flow, clientID, subject string) error {
			return recordTokenIssued(ctx, db, identityStore, tokenEventLevel, flow, clientID, subject)
		})
	}
	if backchannelURI != "" {
		deliveryWorker := backchannel.Worker{
			DB: db, Issuer: issuer, WorkerID: rhizaConfig.NodeID, RetryBase: retryBase,
			TickInterval: max(time.Second, min(retryBase/4, 5*time.Second)), LeaseDuration: 30 * time.Second,
			RequestTimeout: 10 * time.Second, MaxAttempts: 100, TokenLifetime: 30 * time.Second, RootCAReloader: backchannelRootCAReloader,
			AllowPrivate: allowPrivateBackchannel, AllowHTTP: allowHTTPBackchannel,
			LoadSigningKey: func(ctx context.Context) (oidc.SigningKey, error) {
				return oidc.LoadActiveSigningKey(ctx, db, keyring, issuer)
			},
			OnError: func(err error) { slog.Error("back-channel logout delivery failed", "error", err) },
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := deliveryWorker.Run(workerCtx); err != nil {
				slog.Error("back-channel logout worker stopped", "error", err)
			}
		}()
	}
	browserStore, err := browser.NewStore(db, idleTimeout)
	if err != nil {
		return err
	}
	browserAdmin := browserAdministrator(rbacStore, browserStore, identityStore, issuer)
	kvStore, err := kv.NewStore(db, keyring)
	if err != nil {
		return fmt.Errorf("configure KV store: %w", err)
	}
	kvHandler := kv.NewHandler(kvStore, browserAdmin)
	apiKeyHandler := apikey.NewHandler(apiKeyStore, browserAdmin)
	retirementHandler := masterkeyretirement.NewHandler(db, apiKeyStore, retirementMembers)
	clientLogoStore, err := branding.NewClientLogoStore(db)
	if err != nil {
		return fmt.Errorf("configure client logo store: %w", err)
	}
	clientLogoHandler, err := branding.NewClientLogoHandler(clientLogoStore, apiKeyStore, browserAdmin)
	if err != nil {
		return fmt.Errorf("configure client logo handler: %w", err)
	}
	providerLogoStore, err := branding.NewProviderLogoStore(db)
	if err != nil {
		return fmt.Errorf("configure provider logo store: %w", err)
	}
	providerLogoHandler, err := branding.NewProviderLogoHandler(providerLogoStore, apiKeyStore, browserAdmin)
	if err != nil {
		return fmt.Errorf("configure provider logo handler: %w", err)
	}
	providerRegistryStore, err := upstreamprovider.NewRegistryStore(db, keyring)
	if err != nil {
		return fmt.Errorf("configure provider registry store: %w", err)
	}
	providerRegistryHandler, err := upstreamprovider.NewRegistryHandler(providerRegistryStore, apiKeyStore, browserAdmin)
	if err != nil {
		return fmt.Errorf("configure provider registry handler: %w", err)
	}

	themeStore, err := branding.NewThemeStore(db)
	if err != nil {
		return fmt.Errorf("configure theme store: %w", err)
	}
	themeHandler, err := branding.NewThemeHandler(themeStore, apiKeyStore, browserAdmin, func(ctx context.Context, id string) error {
		if id == clientID {
			return nil
		}
		_, err := managedClients.GetWithGuard(ctx, id, func() (string, []any) { return "1", nil })
		if !errors.Is(err, clients.ErrNotFound) || dynamicClientStore == nil {
			return err
		}
		_, err = dynamicClientStore.GetClient(ctx, id)
		if errors.Is(err, fosite.ErrNotFound) {
			return clients.ErrNotFound
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("configure theme handler: %w", err)
	}
	blacklistHandler := ipblacklist.NewAdminHandler(blacklistStore, apiKeyStore, browserAdmin)
	lockdownHandler := loginpolicy.NewLockdownHandler(lockdownStore, browserAdmin)
	adminRoutes := []admin.Route{
		{Label: "Manage users", Path: "/auth/v1/admin/users"},
		{Label: "Manage roles", Path: "/auth/v1/admin/roles"},
		{Label: "Manage groups", Path: "/auth/v1/admin/groups"},
		{Label: "Manage authentication collections", Path: "/auth/v1/admin/collections"},
		{Label: "Manage OAuth clients", Path: "/auth/v1/admin/clients"},
		{Label: "Roles", Path: "/auth/v1/roles"},
		{Label: "Groups", Path: "/auth/v1/groups"},
		{Label: "Scopes", Path: "/auth/v1/scopes"},
		{Label: "User attributes", Path: "/auth/v1/users/attr"},
		{Label: "Users", Path: "/auth/v1/users"},
		{Label: "API keys", Path: "/auth/v1/api_keys"},
		{Label: "Lockdown", Path: "/auth/v1/lockdown"},
	}
	if blacklistEnabled {
		adminRoutes = append(adminRoutes, admin.Route{Label: "IP blacklist", Path: "/auth/v1/blacklist"})
	}
	adminHandler, err := admin.NewIndexHandler(browserAdmin, adminRoutes...)
	if err != nil {
		return fmt.Errorf("configure admin index: %w", err)
	}
	adminUI, err := admin.NewUI(browserAdmin)
	if err != nil {
		return fmt.Errorf("configure admin UI: %w", err)
	}
	adminUI.SetCSRFTokenProvider(adminCSRFTokenProvider(issuer))
	if emailTemplates, tplErr := recovery.LoadEmailTemplates(os.Getenv("GOAUTHY_EMAIL_TEMPLATES_FILE")); tplErr == nil {
		adminUI.SetTemplateProvider(&emailTemplateAdapter{templates: emailTemplates})
	}
	rbacHandler, err := rbac.NewHandler(rbacStore, browserStore, identityStore, issuer, clientID)
	if err != nil {
		return fmt.Errorf("configure RBAC handler: %w", err)
	}
	if err := rbacHandler.SetUserValuesPolicy(userValuesPolicy); err != nil {
		return fmt.Errorf("configure user values policy: %w", err)
	}
	if err := rbacHandler.BindClients(managedClients); err != nil {
		return fmt.Errorf("configure managed clients: %w", err)
	}
	rbacHandler.SetPasskeyService(passkeyService)
	if err := rbacHandler.BindAuthCollections(authcollection.NewStore(db)); err != nil {
		return fmt.Errorf("configure authentication collections: %w", err)
	}
	saasProviders, err := loadSaaSProviders(os.Getenv("GOAUTHY_SAAS_PROVIDERS_FILE"))
	if err != nil {
		return fmt.Errorf("configure SaaS providers: %w", err)
	}
	saasCatalog := make([]rbac.SaaSProviderInfo, 0, len(saasProviders))
	for id, provider := range saasProviders {
		saasCatalog = append(saasCatalog, rbac.SaaSProviderInfo{ID: id, Kind: provider.Kind, CallbackURI: provider.CallbackURI, Scopes: provider.Scopes})
	}
	if err := rbacHandler.BindSaaSProviders(saasCatalog); err != nil {
		return fmt.Errorf("configure SaaS provider catalog: %w", err)
	}
	providerStore, err := saas.NewProviderStore(db, keyring)
	if err != nil {
		return fmt.Errorf("configure SaaS provider store: %w", err)
	}
	registeredProviders, err := providerStore.List(ctx, func() (string, []any) { return "1", nil })
	if err != nil {
		return fmt.Errorf("inspect registered SaaS providers: %w", err)
	}
	for _, provider := range registeredProviders {
		if _, exists := saasProviders[provider.ID]; exists {
			return errors.New("SaaS provider ID is configured both in file and database")
		}
	}
	if err := rbacHandler.BindSaaSProviderStore(providerStore); err != nil {
		return fmt.Errorf("configure SaaS provider HTTP: %w", err)
	}
	saasCredentials, err := saas.NewCredentialStore(db, keyring)
	if err != nil {
		return fmt.Errorf("configure SaaS credential store: %w", err)
	}
	if err := rbacHandler.BindSaaSCredentials(saasCredentials); err != nil {
		return fmt.Errorf("configure SaaS credential HTTP: %w", err)
	}
	connectionsResource, err := resourceFromEnv(os.Getenv, "GOAUTHY_CONNECTIONS_RESOURCE", allowedResources)
	if err != nil {
		return err
	}
	if connectionsResource != "" {
		if err := rbacHandler.BindConnectionUseResource(connectionsResource); err != nil {
			return fmt.Errorf("configure connection use resource: %w", err)
		}
	}
	if err := rbacHandler.BindConnectionUseAuthorizer(func(r *http.Request) (string, string, func() (string, []any), error) {
		return oauthServer.AuthorizeConnectionUse(r, connectionsResource)
	}); err != nil {
		return fmt.Errorf("configure connection use authorization: %w", err)
	}
	if err := rbacHandler.BindConnectionHandoffAuthorizer(func(r *http.Request) (string, string, func() (string, []any), error) {
		return oauthServer.AuthorizeConnectionHandoff(r, connectionsResource)
	}); err != nil {
		return fmt.Errorf("configure connection handoff authorization: %w", err)
	}
	if err := rbacHandler.BindConnectionResourceAuthorizer(func(r *http.Request, scope string) (string, func() (string, []any), error) {
		return oauthServer.AuthorizeUserResource(r, scope, connectionsResource)
	}); err != nil {
		return fmt.Errorf("configure connection resource authorization: %w", err)
	}
	providersResource, err := resourceFromEnv(os.Getenv, "GOAUTHY_PROVIDERS_RESOURCE", allowedResources)
	if err != nil {
		return err
	}
	if err := rbacHandler.BindProviderResourceAuthorizer(func(r *http.Request, scope string) (string, func() (string, []any), error) {
		return oauthServer.AuthorizeUserResource(r, scope, providersResource)
	}); err != nil {
		return fmt.Errorf("configure provider resource authorization: %w", err)
	}
	userListThreshold, err := userListThresholdFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	if err := rbacHandler.SetUserListThreshold(userListThreshold); err != nil {
		return fmt.Errorf("configure user list: %w", err)
	}
	if recoveryService != nil {
		if err := rbacHandler.BindUserCreation(recoveryService, passwordNewExpiry); err != nil {
			return fmt.Errorf("configure user creation: %w", err)
		}
	}
	rbacHandler.OnUserUpdated = func(ctx context.Context, result identity.UserUpdateResult) {
		if scimRuntime != nil {
			scimRuntime.Wake()
		}
		if recoveryService != nil {
			recoveryService.NotifyUserUpdate(ctx, result)
		}
	}
	claimsHandler, err := claims.NewHandler(claimsStore, browserStore, identityStore, issuer, clientID)
	if err != nil {
		return fmt.Errorf("configure claims handler: %w", err)
	}
	rewrapWorker.attachPasskey(passkeyService)
	retirementWorker, err := newMasterKeyRetirementWorker(db, keyring, issuer, rhizaConfig.NodeID, bootID, passkeyService)
	if err != nil {
		return fmt.Errorf("configure master-key retirement worker: %w", err)
	}
	retirementWorker.onError = func(error) { slog.Error("master-key retirement attestation failed") }
	statusCtx, cancelStatus := context.WithTimeout(workerCtx, 10*time.Second)
	logMasterKeyStatus(statusCtx, db, keyring, issuer, passkeyService, time.Now().UTC())
	cancelStatus()
	workers.Add(1)
	go func() {
		defer workers.Done()
		if err := rewrapWorker.Run(workerCtx); err != nil {
			slog.Error("master-key rewrap worker stopped")
		}
	}()
	workers.Add(1)
	go func() {
		defer workers.Done()
		if err := retirementWorker.Run(workerCtx); err != nil {
			slog.Error("master-key retirement worker stopped", "error", err)
		}
	}()
	var accountHandler *account.Handler
	if passkeyService != nil {
		accountHandler, err = account.NewWithPasskeys(issuer, browserStore, identityStore, passwordRules, passkeyService)
	} else {
		accountHandler, err = account.New(issuer, browserStore, identityStore, passwordRules)
	}
	if err != nil {
		return fmt.Errorf("configure account handler: %w", err)
	}
	accountHandler.ConfigurePasskeyAdministrators(apiKeyStore, rbacStore.IsAdmin)
	accountHandler.ConfigureAdminForceMFA(bootstrapForceMFA)
	accountHandler.ConfigureSelfDelete(selfDeleteEnabled)
	deviceStore := device.NewStore(db)
	if err := rbacHandler.BindDeviceSessions(deviceStore); err != nil {
		return fmt.Errorf("configure account devices: %w", err)
	}
	deviceHandler, err := device.NewHandler(deviceStore, issuer, oauthServer.AuthenticateDeviceClient, deviceSessionSubject(browserStore, issuer, bootstrapForceMFA))
	if err != nil {
		return fmt.Errorf("configure device handler: %w", err)
	}
	var loginHandler *login.Handler
	if passkeyService != nil {
		if len(trustedProxies) > 0 {
			loginHandler, err = login.NewWithPolicyRecoveryPasskeysAndTrustedProxies(issuer, browserStore, identityStore, oauthServer, loginPolicyStore, expiredRecovery, passkeyService, trustedProxies)
		} else {
			loginHandler, err = login.NewWithPolicyRecoveryAndPasskeys(issuer, browserStore, identityStore, oauthServer, loginPolicyStore, expiredRecovery, passkeyService)
		}
	} else {
		if len(trustedProxies) > 0 {
			loginHandler, err = login.NewWithPolicyAndTrustedProxies(issuer, browserStore, identityStore, oauthServer, loginPolicyStore, expiredRecovery, trustedProxies)
		} else {
			loginHandler, err = login.NewWithPolicyAndRecovery(issuer, browserStore, identityStore, oauthServer, loginPolicyStore, expiredRecovery)
		}
	}
	if err != nil {
		return err
	}
	loginHandler.SetLockdownStore(lockdownStore)
	if err := loginHandler.SetUserValuesPolicy(userValuesPolicy); err != nil {
		return fmt.Errorf("configure login user values policy: %w", err)
	}
	if err := oauthServer.SetUserValuesPolicy(userValuesPolicy, identityStore.NeedsProfileUpdate); err != nil {
		return fmt.Errorf("configure oauth user values policy: %w", err)
	}
	if loginLocationSender == nil && os.Getenv("GOAUTHY_SMTP_HOST") != "" {
		loginLocationSender, err = smtpSenderFromEnv(os.Getenv)
		if err != nil {
			return err
		}
		loginLocationSender.OnDeliveryFailure = func(recipient, mailType, subject, textBody, htmlBody string, err error) {
			slog.Error("email delivery failed", "mail_type", mailType, "recipient", recipient, "error", err)
			operation := "email-error/" + rand.Text()
			event := eventlog.EmailSendErrorEvent(operation, mailType, recipient, time.Now())
			if stmt, stmtErr := event.Statement("1=1"); stmtErr == nil {
				storage.Execute(ctx, db, rhiza.ExecuteRequest{Statements: []rhiza.SQLStatement{stmt}})
			}
			if emailOutbox != nil {
				if qErr := emailOutbox.Enqueue(ctx, recipient, mailType, subject, htmlBody, textBody); qErr != nil {
					slog.Error("email outbox enqueue failed", "error", qErr)
				}
			}
		}
	}
	emailSubjectPrefix, prefixConfigured := os.LookupEnv("GOAUTHY_EMAIL_SUB_PREFIX")
	if !prefixConfigured {
		emailSubjectPrefix = "Rauthy IAM"
	}
	if strings.ContainsAny(emailSubjectPrefix, "\r\n") {
		return errors.New("GOAUTHY_EMAIL_SUB_PREFIX must not contain line breaks")
	}
	notifyLoginLocation := func(r *http.Request, subject, browserID, ip, userAgent string) error {
		lookup := func(address netip.Addr) (*string, error) {
			return geoblock.RequestLocation(r, geoConfig.Header, trustedProxies, address, locationLookup)
		}
		return loginLocationObserver(db, identityStore, keyring, loginLocationSender, issuer, emailSubjectPrefix, lookup)(r.Context(), subject, browserID, ip, userAgent)
	}
	browserIDPolicy, err := browserIDPolicyFromEnv(os.Getenv, issuer)
	if err != nil {
		return err
	}
	loginHandler.SetThemeURLResolver(themeStore.StylesheetURL)
	loginHandler.SetBrowserIDPolicy(browserIDPolicy)
	loginHandler.SetLoginLocationObserver(notifyLoginLocation)
	loginHandler.SetCaptchaSiteKey(captchaVerifier.SiteKey())
	var otpHandler *recovery.OTPHandler
	if emailOTPEnabled(os.Getenv) && recoveryService != nil && loginLocationSender != nil {
		otpService, otpErr := recovery.NewOTPService(db)
		if otpErr != nil {
			return fmt.Errorf("configure email OTP: %w", otpErr)
		}
		interactStore := recovery.NewOTPInteractionStore()
		otpHandler = recovery.NewOTPHandler(otpService, loginLocationSender, true, interactStore)
		loginHandler.SetOTPHandler(otpHandler)
	}
	oauthServer.SetPasswordLoginObserver(passwordLoginLocationObserver(issuer, browserIDPolicy, notifyLoginLocation))
	upstreamRuntime, err := upstreamHandlerFromEnv(os.Getenv, db, keyring, issuer, loginHandler, accountHandler, identityStore)
	if err != nil {
		return err
	}
	loginHandler.SetUpstreamProviderCatalog(func(ctx context.Context) ([]login.UpstreamProvider, error) {
		var providers []login.UpstreamProvider
		if upstreamRuntime != nil {
			for _, id := range upstreamRuntime.providerIDs() {
				providers = append(providers, login.UpstreamProvider{
					ID:          id,
					Name:        id,
					CallbackURI: upstreamRuntime.callbacks[id],
				})
			}
		}
		docs, err := providerRegistryStore.List(ctx)
		if err != nil {
			return providers, err
		}
		for _, doc := range docs {
			if !doc.Enabled {
				continue
			}
			providers = append(providers, login.UpstreamProvider{
				ID:          doc.ID,
				Name:        doc.Name,
				CallbackURI: issuer + "/upstream/" + doc.ID + "/callback",
			})
		}
		return providers, nil
	})
	// Build static provider ID set for the dynamic dispatcher.
	var staticIDs []string
	var staticLinkStart http.Handler
	var localHooks upstreamprovider.LocalLoginHooks
	var linkHooks upstreamprovider.LinkHooks
	if upstreamRuntime != nil {
		staticIDs = upstreamRuntime.providerIDs()
		staticLinkStart = upstreamRuntime.handler.LinkStartHandler()
		localHooks = upstreamRuntime.localHooks
		linkHooks = upstreamRuntime.linkHooks
	} else {
		localHooks = upstreamprovider.LocalLoginHooks{
			Prepare: loginHandler.PrepareExternalAuthentication,
			Current: loginHandler.CurrentExternalInitSession,
			Resolve: func(ctx context.Context, external upstreamprovider.SubjectResult) (string, error) {
				subject, found, err := identityStore.FindExternalLink(ctx, external)
				if err != nil || !found {
					return "", errors.New("upstream identity unavailable")
				}
				return subject, nil
			},
			ResolveVerified: staticResolveVerified(&FederatedIdentityResolver{IdentityStore: identityStore}),
			Complete: func(w http.ResponseWriter, r *http.Request, token, interaction, subject string, upstream *upstreamprovider.OIDCSession) {
				var binding *browser.UpstreamSessionBinding
				if upstream != nil {
					binding = &browser.UpstreamSessionBinding{Issuer: upstream.Issuer, ClientID: upstream.ClientID, Subject: upstream.Subject, SessionID: upstream.SessionID, MFAPassed: upstream.MFAPassed}
				}
				loginHandler.CompleteUpstreamAuthentication(w, r, token, interaction, subject, binding)
			},
		}
		linkHooks = upstreamprovider.LinkHooks{
			Current: accountHandler.CurrentExternalLinkSession,
			Link: func(ctx context.Context, localSubject string, external upstreamprovider.SubjectResult, now time.Time) (upstreamprovider.LinkDecision, error) {
				return identityStore.LinkExternal(ctx, localSubject, external, now)
			},
		}
	}
	dynamicRhizaStore, err := upstreamprovider.NewRhizaStore(db, keyring)
	if err != nil {
		return fmt.Errorf("configure upstream transaction store: %w", err)
	}
	dynamicDispatcher := newDynamicUpstreamDispatcher(issuer,
		providerRegistryStore, dynamicRhizaStore, staticIDs, staticLinkStart,
		localHooks, linkHooks,
		oauthServer.RevokeUpstreamSessions,
	)
	if upstreamRuntime != nil {
		if err := accountHandler.ConfigureExternalLinks(upstreamRuntime.handler.LinkStartHandler(), upstreamRuntime.providerIDs()); err != nil {
			return fmt.Errorf("configure upstream account links: %w", err)
		}
	}
	if err := accountHandler.ConfigureDynamicExternalLinks(dynamicDispatcher.linkStartHandler(), dynamicDispatcher.exists); err != nil {
		return fmt.Errorf("configure dynamic upstream account links: %w", err)
	}
	logoutHandler, err := logout.NewHandler(issuer, db, browserStore, oauthServer, []logout.Client{{ID: clientID, PostLogoutRedirectURIs: postLogoutRedirectURIs}})
	if err != nil {
		return err
	}
	fedcmRuntime, err := fedcmRuntimeFromEnv(os.Getenv, db, keyring, issuer, browserStore, identityStore)
	if err != nil {
		return err
	}
	var fedcmLanding http.Handler
	if fedcmRuntime != nil {
		if err := validateFedCMLandingPath(fedcmRuntime.loginURL); err != nil {
			return err
		}
		if bootstrapForceMFA {
			return errors.New("FedCM cannot be enabled while bootstrap forced-MFA is active without a passkey landing")
		}
		fedcmLanding = http.HandlerFunc(loginHandler.FedCMLanding)
		if err := fedcmRuntime.enableBrowserCookies(loginHandler, logoutHandler); err != nil {
			return fmt.Errorf("enable FedCM browser cookies: %w", err)
		}
	}
	var registry *metrics.Registry
	handler := newHandlerWithReadiness(db, func(ok bool) {
		if registry != nil {
			registry.DBReadiness(ok)
		}
	}, func(ctx context.Context) error {
		return storage.CheckDCRSoftwareStatementTrust(ctx, db, softwareStatementDigest, retirementMembers)
	})
	handler.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = fmt.Fprintln(w, "GoAuthy")
	})
	handler.Handle("GET /favicon.ico", branding.Handler(favicon))
	mountWebIDRoutes(handler, webIDEnabled, webIDHandler)
	discoveryOptions := oidc.DiscoveryOptions{PasswordGrantEnabled: identityStore != nil, RegistrationEnabled: registrationHandler != nil, ClientIDMetadataDocumentSupported: cimdResolver != nil}
	handler.Handle("GET /.well-known/oauth-authorization-server", oidc.DiscoveryHandlerWithOptions(issuer, discoveryOptions))
	if issuerURL, parseErr := url.Parse(issuer); parseErr == nil && issuerURL.Path != "" {
		handler.Handle("GET /.well-known/oauth-authorization-server"+issuerURL.Path, oidc.DiscoveryHandlerWithOptions(issuer, discoveryOptions))
	}
	handler.Handle("GET /.well-known/openid-configuration", oidc.OpenIDDiscoveryHandlerWithOptions(issuer, discoveryOptions))
	handler.Handle("GET /oidc/jwks.json", oidc.JWKSHandler(db, keyring, issuer))
	handler.Handle("POST /oidc/token", oauthServer.TokenHandler())
	handler.Handle("POST /oidc/introspect", oauthServer.IntrospectionHandler())
	handler.Handle("POST /oidc/revoke", oauthServer.RevocationHandler())
	handler.Handle("GET /oidc/userinfo", oauthServer.UserInfoHandler())
	handler.Handle("POST /oidc/userinfo", oauthServer.UserInfoHandler())
	handler.Handle("GET /oidc/forward_auth", oauthServer.ForwardAuthHandler())
	handler.Handle("GET /oidc/logout", logoutHandler)
	handler.Handle("POST /oidc/logout", logoutHandler)
	if registrationHandler != nil {
		mountDCRRoutes(handler, registrationHandler)
	}
	mountDeviceRoutes(handler, deviceHandler)
	deviceLogin := loginHandler.DeviceLoginHandler(bootstrapForceMFA)
	handler.Handle("GET /oidc/device/login", deviceLogin)
	handler.Handle("POST /oidc/device/login", deviceLogin)
	connectionLogin := loginHandler.ConnectionHandoffLoginHandler(bootstrapForceMFA)
	handler.Handle("GET /account/connection-login", connectionLogin)
	handler.Handle("POST /account/connection-login", connectionLogin)
	handler.HandleFunc("GET /oidc/authorize", loginHandler.Authorize)
	if fedcmRuntime != nil && fedcmRuntime.loginURL == "/auth/login" {
		handler.HandleFunc("POST /auth/login", fedCMAwareLogin(fedcmLanding, loginHandler.Login))
	} else {
		handler.HandleFunc("POST /auth/login", loginHandler.Login)
	}
	handler.HandleFunc("GET /auth/profile", loginHandler.Profile)
	handler.HandleFunc("POST /auth/profile", loginHandler.Profile)
	if fedcmRuntime != nil {
		handler.Handle(fedcm.ManifestPath, fedcmRuntime.handler)
		handler.Handle(fedcm.ConfigPath, fedcmRuntime.handler)
		handler.Handle(fedcm.AccountsPath, fedcmRuntime.handler)
		handler.Handle(fedcm.ClientMetadataPath, fedcmRuntime.handler)
		handler.Handle(fedcm.AssertionPath, fedcmRuntime.handler)
		handler.Handle(fedcm.StatusPath, fedcmRuntime.handler)
		handler.Handle("GET "+fedcmRuntime.loginURL, fedcmLanding)
		if fedcmRuntime.loginURL != "/auth/login" {
			handler.Handle("POST "+fedcmRuntime.loginURL, fedcmLanding)
		}
	}
	mountUpstreamRoutes(handler, upstreamRuntime, accountHandler, oauthServer.RevokeUpstreamSessions)
	// When static upstream is present the static mount already registers the
	// POST/DELETE link routes; pass nil to avoid a ServeMux duplicate-pattern
	// panic.  The accountHandler is already wired via ConfigureDynamicExternalLinks
	// so dynamic provider IDs still resolve through StartExternalLink/UnlinkExternal.
	dynamicLinkAccount := accountHandler
	if upstreamRuntime != nil {
		dynamicLinkAccount = nil
	}
	mountDynamicUpstreamRoutes(handler, dynamicDispatcher, dynamicLinkAccount)
	if passkeyService != nil {
		handler.HandleFunc("POST /auth/v1/users/webauthn_start", loginHandler.WebAuthnStart)
		handler.HandleFunc("POST /auth/v1/users/webauthn_finish", loginHandler.WebAuthnFinish)
		handler.HandleFunc("GET /auth/v1/users/{subject}/webauthn", accountHandler.ListPasskeys)
		handler.HandleFunc("POST /auth/v1/users/{subject}/webauthn/register/start", accountHandler.BeginPasskeyRegistration)
		handler.HandleFunc("POST /auth/v1/users/{subject}/webauthn/register/finish", accountHandler.FinishPasskeyRegistration)
		handler.HandleFunc("DELETE /auth/v1/users/{subject}/webauthn/delete/{name}", accountHandler.DeletePasskey)
	}
	mountPasskeyAccountRoutes(handler, passkeyService != nil,
		accountHandler.IssueModificationToken, accountHandler.BeginMFAWebAuthn, accountHandler.FinishMFAWebAuthn, accountHandler.ConvertSelfPasskey)
	if otpHandler != nil {
		handler.HandleFunc("POST /auth/v1/users/otp/start", otpHandler.Start)
		handler.HandleFunc("POST /auth/v1/users/otp/verify", loginHandler.OTPVerify)
	}
	handler.Handle("GET /auth/v1/users/{subject}/revoke/{code}", recovery.NewLoginRevokeHandler(identityStore, keyring, locationLookup))
	if recoveryService != nil {
		handler.HandleFunc("POST /auth/v1/users/request_reset", recoveryService.RequestReset)
		handler.HandleFunc("GET /auth/v1/users/{subject}/reset/{token}", recoveryService.GetReset)
		handler.HandleFunc("PUT /auth/v1/users/{subject}/reset", recoveryService.PutReset)
		handler.HandleFunc("POST /auth/v1/pow", recoveryService.ProofOfWork)
		if openRegistration.Enabled {
			handler.HandleFunc("POST /auth/v1/users/register", recoveryService.RegisterOpen)
			handler.HandleFunc("OPTIONS /auth/v1/users/register", recoveryService.RegisterOpen)
		}
		if openRegistration.Enabled && openRegistration.PasskeyEnabled && passkeyService != nil {
			recoveryService.SetPasskeyService(passkeyService)
			handler.HandleFunc("POST /auth/v1/register/passkey/start", recoveryService.RegisterPasskeyStart)
			handler.HandleFunc("OPTIONS /auth/v1/register/passkey/start", recoveryService.RegisterPasskeyStart)
			handler.HandleFunc("POST /auth/v1/register/passkey/finish", recoveryService.RegisterPasskeyFinish)
			handler.HandleFunc("OPTIONS /auth/v1/register/passkey/finish", recoveryService.RegisterPasskeyFinish)
		}
	}
	mountAccountRoutes(handler, accountHandler.DeleteUser, accountHandler.SelfDelete)
	handler.HandleFunc("GET /auth/v1/admin", adminHandler.Index)
	handler.Handle("/auth/v1/admin/", adminUI)
	handler.HandleFunc("GET /auth/v1/roles", rbacHandler.Roles)
	handler.HandleFunc("POST /auth/v1/roles", rbacHandler.Roles)
	handler.HandleFunc("PUT /auth/v1/roles/{id}", rbacHandler.Role)
	handler.HandleFunc("DELETE /auth/v1/roles/{id}", rbacHandler.Role)
	handler.HandleFunc("GET /auth/v1/groups", rbacHandler.Groups)
	handler.HandleFunc("POST /auth/v1/groups", rbacHandler.Groups)
	handler.HandleFunc("PUT /auth/v1/groups/{id}", rbacHandler.Group)
	handler.HandleFunc("DELETE /auth/v1/groups/{id}", rbacHandler.Group)
	handler.HandleFunc("GET /auth/v1/scopes", claimsHandler.Scopes)
	handler.HandleFunc("POST /auth/v1/scopes", claimsHandler.Scopes)
	handler.HandleFunc("PUT /auth/v1/scopes/{id}", claimsHandler.Scope)
	handler.HandleFunc("DELETE /auth/v1/scopes/{id}", claimsHandler.Scope)
	handler.HandleFunc("GET /auth/v1/users/attr", claimsHandler.Attributes)
	handler.HandleFunc("POST /auth/v1/users/attr", claimsHandler.Attributes)
	handler.HandleFunc("PUT /auth/v1/users/{first}/{second}", claimsHandler.UserAttributePut)
	handler.HandleFunc("DELETE /auth/v1/users/attr/{name}", claimsHandler.Attribute)
	handler.HandleFunc("GET /auth/v1/users/{subject}/attr/editable", claimsHandler.EditableUserAttributes)
	handler.HandleFunc("GET /auth/v1/users/{subject}/attr", claimsHandler.UserAttributes)
	handler.HandleFunc("GET /auth/v1/api_keys", apiKeyHandler.Keys)
	handler.HandleFunc("POST /auth/v1/api_keys", apiKeyHandler.Keys)
	handler.HandleFunc("PUT /auth/v1/api_keys/{name}", apiKeyHandler.Key)
	handler.HandleFunc("DELETE /auth/v1/api_keys/{name}", apiKeyHandler.Key)
	handler.HandleFunc("PUT /auth/v1/api_keys/{name}/secret", apiKeyHandler.Secret)
	handler.HandleFunc("GET /auth/v1/api_keys/{name}/test", apiKeyHandler.Test)
	handler.HandleFunc("GET /auth/v1/events", apiKeyHandler.Events)
	handler.HandleFunc("POST /auth/v1/events", rbacHandler.EventsQuery)
	handler.HandleFunc("GET /auth/v1/events/stream", rbacHandler.EventsStream)
	handler.HandleFunc("POST /auth/v1/events/test", rbacHandler.EventsTest)
	handler.HandleFunc("DELETE /auth/v1/sessions/{subject}", rbacHandler.ForceLogoutUser)
	handler.HandleFunc("GET /auth/v1/sessions", rbacHandler.Sessions)
	handler.HandleFunc("DELETE /auth/v1/sessions", rbacHandler.LogoutAllSessions)
	handler.HandleFunc("DELETE /auth/v1/sessions/id/{session_id}", rbacHandler.DeleteSessionByID)
	mountMasterKeyRetirementRoutes(handler, retirementHandler)
	kvHandler.Routes(handler)
	mountBlacklistRoutes(handler, blacklistEnabled, blacklistHandler)
	handler.Handle("/auth/v1/lockdown", lockdownHandler)
	handler.HandleFunc("GET /auth/v1/clients", rbacHandler.Clients)
	handler.HandleFunc("POST /auth/v1/clients", rbacHandler.Clients)
	handler.HandleFunc("GET /auth/v1/clients/{id}", rbacHandler.Client)
	handler.HandleFunc("PUT /auth/v1/clients/{id}", rbacHandler.Client)
	handler.HandleFunc("DELETE /auth/v1/clients/{id}", rbacHandler.Client)
	handler.HandleFunc("POST /auth/v1/clients/{id}/secret", rbacHandler.ClientSecret)
	handler.HandleFunc("PUT /auth/v1/clients/{id}/secret", rbacHandler.RotateClientSecret)
	handler.HandleFunc("GET /auth/v1/auth-collections", rbacHandler.AuthCollections)
	handler.HandleFunc("GET /auth/v1/saas/providers", rbacHandler.SaaSProviders)
	handler.HandleFunc("POST /auth/v1/saas/providers", rbacHandler.SaaSProviders)
	handler.HandleFunc("GET /auth/v1/saas/providers/{provider_id}", rbacHandler.SaaSProvider)
	handler.HandleFunc("PUT /auth/v1/saas/providers/{provider_id}", rbacHandler.SaaSProvider)
	handler.HandleFunc("DELETE /auth/v1/saas/providers/{provider_id}", rbacHandler.SaaSProvider)
	handler.HandleFunc("POST /auth/v1/auth-collections", rbacHandler.AuthCollections)
	handler.HandleFunc("GET /auth/v1/auth-collections/{collection_id}", rbacHandler.AuthCollection)
	handler.HandleFunc("PUT /auth/v1/auth-collections/{collection_id}", rbacHandler.AuthCollection)
	handler.HandleFunc("DELETE /auth/v1/auth-collections/{collection_id}", rbacHandler.AuthCollection)
	handler.HandleFunc("GET /auth/v1/account/auth-collections", rbacHandler.AccountAuthCollections)
	handler.HandleFunc("GET /auth/v1/connection-collections", rbacHandler.UserResourceAuthCollections)
	handler.HandleFunc("GET /auth/v1/connections/{collection_id}", rbacHandler.UserResourceConnections)
	handler.HandleFunc("POST /auth/v1/connections/{collection_id}", rbacHandler.UserResourceConnections)
	handler.HandleFunc("GET /auth/v1/connections/{collection_id}/{connection_id}", rbacHandler.UserResourceConnection)
	handler.HandleFunc("GET /auth/v1/connections/{collection_id}/{connection_id}/grants/{grant_id}", rbacHandler.UserResourceConnectionUseGrant)
	handler.HandleFunc("PUT /auth/v1/connections/{collection_id}/{connection_id}", rbacHandler.UserResourceConnection)
	handler.HandleFunc("DELETE /auth/v1/connections/{collection_id}/{connection_id}", rbacHandler.UserResourceConnection)
	handler.HandleFunc("GET /auth/v1/account/devices", rbacHandler.AccountDevices)
	handler.HandleFunc("DELETE /auth/v1/account/devices/{id}", rbacHandler.AccountDevices)
	handler.HandleFunc("GET /auth/v1/account/connections/{collection_id}", rbacHandler.AccountConnections)
	handler.HandleFunc("POST /auth/v1/account/connections/{collection_id}", rbacHandler.AccountConnections)
	handler.HandleFunc("GET /auth/v1/account/connections/{collection_id}/{connection_id}", rbacHandler.AccountConnection)
	handler.HandleFunc("GET /auth/v1/account/connections/{collection_id}/{connection_id}/api-key", rbacHandler.AccountConnectionAPIKey)
	handler.HandleFunc("POST /auth/v1/connection-grants/{grant_id}/invoke", rbacHandler.InvokeConnectionGrant)
	handler.HandleFunc("POST /auth/v1/connection-handoffs", rbacHandler.CreateConnectionHandoff)
	handler.HandleFunc("POST /auth/v1/connection-grants/{grant_id}/credential", rbacHandler.DeliverConnectionCredential)
	handler.HandleFunc("POST /auth/v1/connection-grants/{grant_id}/refresh", rbacHandler.RefreshConnectionCredential)
	handler.HandleFunc("GET /auth/v1/connection-grants/{grant_id}/credential-status", rbacHandler.ConnectionCredentialStatus)
	handler.HandleFunc("GET /account/connection-handoffs/{handoff_id}", rbacHandler.ConnectionHandoffPage)
	handler.HandleFunc("POST /account/connection-handoffs/{handoff_id}", rbacHandler.ConnectionHandoffPage)
	handler.HandleFunc("GET /auth/v1/account/connection-handoffs/{handoff_id}", rbacHandler.OwnerConnectionHandoff)
	handler.HandleFunc("POST /auth/v1/account/connection-handoffs/{handoff_id}", rbacHandler.OwnerConnectionHandoff)
	handler.HandleFunc("GET /auth/v1/account/connections/{collection_id}/{connection_id}/api-key/connector", rbacHandler.AccountConnectionAPIKeyConnector)
	handler.HandleFunc("POST /auth/v1/account/connections/{collection_id}/{connection_id}/oauth2", rbacHandler.AccountConnectionOAuth2Start)
	handler.HandleFunc("GET /auth/v1/account/connections/{collection_id}/{connection_id}/oauth2", rbacHandler.AccountConnectionOAuth2Status)
	handler.HandleFunc("DELETE /auth/v1/account/connections/{collection_id}/{connection_id}/oauth2", rbacHandler.AccountConnectionOAuth2Revoke)
	handler.HandleFunc("POST /auth/v1/account/connections/{collection_id}/{connection_id}/oauth2/reconnect", rbacHandler.AccountConnectionOAuth2Reconnect)
	handler.HandleFunc("POST /auth/v1/account/connections/{collection_id}/{connection_id}/oauth2/refresh", rbacHandler.AccountConnectionOAuth2Refresh)
	handler.HandleFunc("POST /auth/v1/account/connections/{collection_id}/{connection_id}/grants", rbacHandler.AccountConnectionUseGrants)
	handler.HandleFunc("GET /auth/v1/account/connections/{collection_id}/{connection_id}/grants", rbacHandler.AccountConnectionUseGrants)
	handler.HandleFunc("DELETE /auth/v1/account/connections/{collection_id}/{connection_id}/grants/{grant_id}", rbacHandler.AccountConnectionUseGrant)
	handler.HandleFunc("GET /auth/v1/saas/callback/{provider_id}", rbacHandler.AccountConnectionOAuth2Callback)
	handler.HandleFunc("PUT /auth/v1/account/connections/{collection_id}/{connection_id}/api-key", rbacHandler.AccountConnectionAPIKey)
	handler.HandleFunc("DELETE /auth/v1/account/connections/{collection_id}/{connection_id}/api-key", rbacHandler.AccountConnectionAPIKey)
	handler.HandleFunc("PUT /auth/v1/account/connections/{collection_id}/{connection_id}", rbacHandler.AccountConnection)
	handler.HandleFunc("DELETE /auth/v1/account/connections/{collection_id}/{connection_id}", rbacHandler.AccountConnection)
	handler.HandleFunc("GET /auth/v1/clients/{id}/scopes", claimsHandler.BootstrapClientScopes)
	handler.HandleFunc("PUT /auth/v1/clients/{id}/scopes", claimsHandler.BootstrapClientScopes)
	handler.HandleFunc("GET /auth/v1/clients/{id}/claims", claimsHandler.BootstrapClientCredentialsClaims)
	handler.HandleFunc("PUT /auth/v1/clients/{id}/claims", claimsHandler.BootstrapClientCredentialsClaims)
	handler.HandleFunc("GET /auth/v1/users", rbacHandler.Users)
	handler.Handle("GET /auth/v1/users/values_config", rbacHandler.UserValuesConfigHandler(openRegistration.Enabled))
	if recoveryService != nil {
		handler.HandleFunc("POST /auth/v1/users", rbacHandler.CreateUser)
	}
	handler.HandleFunc("POST /auth/v1/users/{subject}/webauthn/admin_register", rbacHandler.AdminRegisterPasskey)
	handler.HandleFunc("POST /auth/v1/users/{subject}/convert_password", rbacHandler.AdminConvertPassword)
	handler.HandleFunc("GET /auth/v1/users/{subject}", rbacHandler.User)
	handler.HandleFunc("PUT /auth/v1/users/{subject}", rbacHandler.UpdateUser)
	handler.HandleFunc("PUT /auth/v1/users/{subject}/self/preferred_username", rbacHandler.UpdatePreferredUsername)
	handler.HandleFunc("PATCH /auth/v1/users/{subject}", rbacHandler.PatchUserMembership)
	handler.HandleFunc("GET /auth/v1/clients/{id}/login-restriction", rbacHandler.LoginRestriction)
	handler.HandleFunc("PUT /auth/v1/clients/{id}/login-restriction", rbacHandler.LoginRestriction)
	handler.Handle("GET /auth/v1/theme/global.css", branding.GlobalCSSHandler())
	handler.HandleFunc("GET /auth/v1/theme/{client_id}/{timestamp}", themeHandler.Theme)
	handler.HandleFunc("POST /auth/v1/theme/{client_id}", themeHandler.Theme)
	handler.HandleFunc("PUT /auth/v1/theme/{client_id}", themeHandler.Theme)
	handler.HandleFunc("DELETE /auth/v1/theme/{client_id}", themeHandler.Theme)
	handler.HandleFunc("GET /auth/v1/clients/{id}/logo", clientLogoHandler.Logo)
	handler.HandleFunc("PUT /auth/v1/clients/{id}/logo", clientLogoHandler.Logo)
	handler.HandleFunc("DELETE /auth/v1/clients/{id}/logo", clientLogoHandler.Logo)
	handler.HandleFunc("GET /auth/v1/clients/{id}/favicon", clientLogoHandler.Favicon)
	handler.HandleFunc("PUT /auth/v1/clients/{id}/favicon", clientLogoHandler.Favicon)
	handler.HandleFunc("DELETE /auth/v1/clients/{id}/favicon", clientLogoHandler.Favicon)
	mountProviderLogoRoutes(handler, providerLogoHandler)
	mountProviderRegistryRoutes(handler, providerRegistryHandler)
	handler.HandleFunc("GET /account/password", accountHandler.GetPassword)
	handler.HandleFunc("GET /account", accountHandler.Dashboard)
	handler.HandleFunc("GET /account/data", accountHandler.Dashboard)
	handler.HandleFunc("GET /account/app.js", accountHandler.Dashboard)
	handler.HandleFunc("GET /account/connections.js", accountHandler.Dashboard)
	handler.HandleFunc("GET /account/connection-grants.js", accountHandler.Dashboard)
	handler.HandleFunc("GET /account/devices.js", accountHandler.Dashboard)
	handler.HandleFunc("GET /account/account.css", accountHandler.Dashboard)
	handler.HandleFunc("PUT /auth/v1/users/{subject}/self", accountHandler.PutSelfPassword)
	docFeatures := apidocs.Features{
		DCR: registrationHandler != nil, DCRAnonymous: dcrAnonymous, Passkeys: passkeyService != nil,
		Recovery: recoveryService != nil, OpenRegistration: openRegistration.Enabled,
		Blacklist: blacklistEnabled, WebID: webIDEnabled,
		FedCM: fedcmRuntime != nil, Upstream: true,
	}
	if fedcmRuntime != nil {
		docFeatures.FedCMLanding = fedcmRuntime.loginURL
	}
	if err := mountSwaggerRoutes(handler, swaggerConfig, issuer, docFeatures, browserAdmin); err != nil {
		return fmt.Errorf("configure API documentation: %w", err)
	}

	// --- Metrics server (opt-in, disabled by default) -----------------------
	var metricsServer *http.Server
	var appHandler http.Handler = handler
	if geoConfig.Enabled {
		appHandler = geoblock.Middleware(geoConfig.Policy, geoConfig.Header, trustedProxies, geoReader, appHandler)
	}
	if blacklistEnabled {
		appHandler = ipblacklist.Middleware(blacklistStore, func(r *http.Request) (netip.Addr, error) {
			return netip.ParseAddr(browser.PeerIPFromContext(r.Context()))
		})(appHandler)
	}
	appHandler = tracing.Middleware(appHandler)
	appHandler = admissionBypass(appHandler, handler)
	var metricsErrCh chan error
	metricsAddr, metricsAddrErr := metricsListenAddrFromEnv(os.Getenv)
	if metricsAddrErr != nil {
		return metricsAddrErr
	}
	if metricsAddr != "" {
		metricsToken, tokErr := loadMetricsToken(os.Getenv)
		if tokErr != nil {
			return tokErr
		}
		registry = metrics.NewRegistry()
		oauthServer.SetMetrics(registry)
		loginHandler.SetMetrics(registry)
		appHandler = registry.Instrument(appHandler)

		metricsMux := http.NewServeMux()
		metricsMux.Handle("GET /metrics", registry.Handler(metricsToken))
		metricsServer = &http.Server{
			Addr:              metricsAddr,
			Handler:           metricsMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    16 << 10,
		}
		metricsLn, lnErr := net.Listen("tcp", metricsAddr)
		if lnErr != nil {
			return fmt.Errorf("listen metrics %s: %w", metricsAddr, lnErr)
		}
		metricsErrCh = make(chan error, 1)
		workers.Add(1)
		go func() {
			defer workers.Done()
			metricsErrCh <- metricsServer.Serve(metricsLn)
		}()
	}

	server := &http.Server{
		BaseContext:       func(net.Listener) context.Context { return ctx },
		Addr:              env("GOAUTHY_LISTEN_ADDR", ":8080"),
		Handler:           healthBypass(issuerPathMiddleware(peerIPMiddleware(appHandler, trustedProxies), issuer), handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         tlsConfig,
	}
	if tlsReloader != nil {
		go reloadTLS(ctx, tlsReloader)
	}
	// No startup path below this point can fail before the server lifecycle
	// owns shutdown, so it is now safe to close Rhiza on return.
	dbCloseAllowed = true
	errCh := make(chan error, 1)
	go func() {
		if tlsReloader != nil {
			errCh <- server.ListenAndServeTLS("", "")
			return
		}
		errCh <- server.ListenAndServe()
	}()

	return lifecycle(ctx, server, metricsServer, errCh, metricsErrCh)
}

// metricsListenAddrFromEnv validates the optional metrics TCP bind address
// before opening a listener. Port zero is allowed for OS-assigned test and
// development listeners; production deployments should configure a fixed
// port.
func metricsListenAddrFromEnv(getenv func(string) string) (string, error) {
	if getenv == nil {
		return "", errors.New("metrics listen address requires environment reader")
	}
	address := getenv("GOAUTHY_METRICS_LISTEN_ADDR")
	if address == "" {
		return "", nil
	}
	if strings.TrimSpace(address) != address || strings.ContainsAny(address, "\r\n\t") {
		return "", errors.New("GOAUTHY_METRICS_LISTEN_ADDR must be a trimmed host:port address")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return "", errors.New("GOAUTHY_METRICS_LISTEN_ADDR must be a host:port address")
	}
	if port != "0" && strings.HasPrefix(port, "0") {
		return "", errors.New("GOAUTHY_METRICS_LISTEN_ADDR port must be canonical decimal")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 0 || portNumber > 65535 {
		return "", errors.New("GOAUTHY_METRICS_LISTEN_ADDR port must be between 0 and 65535")
	}
	if host == "" {
		return address, nil
	}
	if strings.ContainsAny(host, " \t\r\n/") {
		return "", errors.New("GOAUTHY_METRICS_LISTEN_ADDR host is invalid")
	}
	return address, nil
}

// issuerPathMiddleware keeps the public issuer namespace separate from the
// internal root mux. The health endpoints remain the only root routes.
func issuerPathMiddleware(next http.Handler, issuer string) http.Handler {
	u, err := url.Parse(issuer)
	if err != nil {
		return next
	}
	base := strings.TrimRight(u.Path, "/")
	rfc8414 := "/.well-known/oauth-authorization-server" + base
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawPath != "" {
			http.NotFound(w, r)
			return
		}
		if base == "" {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == rfc8414 {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == base+"/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != base && !strings.HasPrefix(r.URL.Path, base+"/") {
			http.NotFound(w, r)
			return
		}
		clone := r.Clone(r.Context())
		urlCopy := *r.URL
		clone.URL = &urlCopy
		if clone.URL.Path == base {
			clone.URL.Path = "/"
		} else {
			clone.URL.Path = strings.TrimPrefix(clone.URL.Path, base)
		}
		if clone.URL.Path == "/livez" || clone.URL.Path == "/readyz" {
			http.NotFound(w, r)
			return
		}
		clone.URL.RawPath = ""
		next.ServeHTTP(w, clone)
	})
}

func mountDeviceRoutes(mux *http.ServeMux, handler http.Handler) {
	mux.Handle("POST /oidc/device", handler)
	mux.Handle("GET /oidc/device/verify", handler)
	mux.Handle("POST /oidc/device/verify", handler)
}

func mountWebIDRoutes(mux *http.ServeMux, enabled bool, handler http.Handler) {
	if enabled {
		mux.Handle("GET /auth/{subject}/profile", handler)
	}
}

func mountDCRRoutes(mux *http.ServeMux, handler http.Handler) {
	mux.Handle("POST /oidc/register", handler)
	mux.Handle("GET /oidc/register/{id}", handler)
	mux.Handle("PUT /oidc/register/{id}", handler)
	mux.Handle("DELETE /oidc/register/{id}", handler)
}

func mountBlacklistRoutes(mux *http.ServeMux, enabled bool, handler http.Handler) {
	if !enabled {
		return
	}
	mux.Handle("/auth/v1/blacklist", handler)
	mux.Handle("/auth/v1/blacklist/", handler)
}

func mountMasterKeyRetirementRoutes(mux *http.ServeMux, handler http.Handler) {
	mux.Handle("GET /auth/v1/master_key_retirement", handler)
	mux.Handle("POST /auth/v1/master_key_retirement/{action}", handler)
	// Keep the exact base path registered for unsupported methods (for example
	// POST without an action) so the handler can return 405 deterministically.
	mux.Handle("/auth/v1/master_key_retirement", handler)
}

func mountPasskeyAccountRoutes(mux *http.ServeMux, enabled bool, mfaToken, authStart, authFinish, convert http.HandlerFunc) {
	if !enabled {
		return
	}
	mux.HandleFunc("POST /auth/v1/users/{subject}/mfa_token", mfaToken)
	mux.HandleFunc("POST /auth/v1/users/{subject}/webauthn/auth/start", authStart)
	mux.HandleFunc("POST /auth/v1/users/{subject}/webauthn/auth/finish", authFinish)
	mux.HandleFunc("POST /auth/v1/users/{subject}/self/convert_passkey", convert)
}

func mountAccountRoutes(mux *http.ServeMux, deleteUser, selfDelete http.HandlerFunc) {
	mux.HandleFunc("DELETE /auth/v1/users/{subject}", deleteUser)
	mux.HandleFunc("GET /auth/v1/users/{subject}/self/delete", selfDelete)
	mux.HandleFunc("DELETE /auth/v1/users/{subject}/self/delete", selfDelete)
}

func deviceSessionSubject(store *browser.Store, issuer string, requireMFA ...bool) device.Subject {
	cookieName, err := browser.CookieName(issuer)
	if err != nil {
		return func(*http.Request) (string, bool) { return "", false }
	}
	return func(r *http.Request) (string, bool) {
		cookie, err := r.Cookie(cookieName)
		if err != nil || cookie.Value == "" {
			return "", false
		}
		session, err := store.LoadSessionReadOnlyForPeer(r.Context(), cookie.Value, browser.PeerIPFromContext(r.Context()))
		if err != nil || session.Subject == "" {
			return "", false
		}
		if len(requireMFA) != 0 && requireMFA[0] && session.AuthenticationMethod != "mfa" {
			return "", false
		}
		return session.Subject, true
	}
}

func bootstrapUser(ctx context.Context, store *identity.Store, getenv func(string) string) error {
	path := getenv("GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE")
	if path == "" {
		return nil
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read bootstrap user password credential: %w", err)
	}
	if _, err := store.BootstrapUser(ctx,
		envValue(getenv, "GOAUTHY_BOOTSTRAP_USER_SUBJECT", "bootstrap-admin"),
		envValue(getenv, "GOAUTHY_BOOTSTRAP_USER", "admin"),
		strings.TrimSpace(string(encoded)),
	); err != nil {
		return fmt.Errorf("bootstrap user: %w", err)
	}
	return nil
}

func bootstrapPrincipalFromEnv(getenv func(string) string) ([]string, []string, error) {
	roles, err := bootstrapPrincipalValues(getenv("GOAUTHY_BOOTSTRAP_USER_ROLES"), "GOAUTHY_BOOTSTRAP_USER_ROLES", rbac.ValidateRoleName)
	if err != nil {
		return nil, nil, err
	}
	groups, err := bootstrapPrincipalValues(getenv("GOAUTHY_BOOTSTRAP_USER_GROUPS"), "GOAUTHY_BOOTSTRAP_USER_GROUPS", rbac.ValidateGroupName)
	if err != nil {
		return nil, nil, err
	}
	return roles, groups, nil
}

func bootstrapPrincipalValues(raw, name string, validate func(string) error) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var values []string
	if json.Unmarshal([]byte(raw), &values) != nil || values == nil || len(values) > 64 {
		return nil, fmt.Errorf("%s must be a JSON string array with at most 64 values", name)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists || validate(value) != nil {
			return nil, fmt.Errorf("%s contains an invalid or duplicate value", name)
		}
		seen[value] = struct{}{}
	}
	return values, nil
}

func dcrRegistrationToken(getenv func(string) string) (string, error) {
	path := getenv("GOAUTHY_DCR_REGISTRATION_TOKEN_FILE")
	if path == "" {
		return "", nil
	}
	token, err := dcr.LoadRegistrationToken(path)
	if err != nil {
		return "", fmt.Errorf("load DCR registration token: %w", err)
	}
	return token, nil
}

func dcrSoftwareStatementConfig(getenv func(string) string) (dcr.SoftwareStatementConfig, error) {
	path := getenv("GOAUTHY_DCR_SOFTWARE_STATEMENT_TRUST_FILE")
	if path == "" {
		return dcr.SoftwareStatementConfig{}, nil
	}
	config, err := dcr.LoadSoftwareStatementConfig(path)
	if err != nil {
		return dcr.SoftwareStatementConfig{}, fmt.Errorf("load DCR software-statement trust: %w", err)
	}
	return config, nil
}

func dcrAnonymousConfig(getenv func(string) string) (bool, time.Duration, error) {
	enabled, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_DCR_ANONYMOUS", "false"))
	if err != nil {
		return false, 0, errors.New("GOAUTHY_DCR_ANONYMOUS must be a boolean")
	}
	if !enabled {
		return false, 0, nil
	}
	seconds, err := strconv.ParseInt(envValue(getenv, "GOAUTHY_DCR_RATE_LIMIT_SECONDS", "60"), 10, 64)
	if err != nil || seconds < 1 || seconds > 24*60*60 {
		return false, 0, errors.New("GOAUTHY_DCR_RATE_LIMIT_SECONDS must be an integer from 1 to 86400")
	}
	return true, time.Duration(seconds) * time.Second, nil
}

func rfc8252LoopbackRedirects(getenv func(string) string) (bool, error) {
	value, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_RFC8252_LOOPBACK_REDIRECTS", "false"))
	if err != nil {
		return false, errors.New("GOAUTHY_RFC8252_LOOPBACK_REDIRECTS must be a boolean")
	}
	return value, nil
}

func dcrScopePolicy(getenv func(string) string) (dcr.ScopePolicy, error) {
	allowed := strings.Fields(envValue(getenv, "GOAUTHY_DCR_ALLOWED_SCOPES", "openid profile email groups"))
	defaults := strings.Fields(envValue(getenv, "GOAUTHY_DCR_DEFAULT_SCOPES", "openid"))
	policy, err := dcr.NewScopePolicy(allowed, defaults)
	if err != nil {
		return dcr.ScopePolicy{}, fmt.Errorf("GOAUTHY_DCR_ALLOWED_SCOPES and GOAUTHY_DCR_DEFAULT_SCOPES must be unique valid scopes with defaults allowed: %w", err)
	}
	return policy, nil
}

func browserAdministrator(rbacStore *rbac.Store, browserStore *browser.Store, identityStore *identity.Store, issuer string) func(http.ResponseWriter, *http.Request, bool) bool {
	return func(w http.ResponseWriter, r *http.Request, mutation bool) bool {
		if r.URL.RawQuery != "" || apikey.HasAuthorization(r) || strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		name, err := browser.CookieName(issuer)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return false
		}
		cookie, err := r.Cookie(name)
		if err != nil || cookie.Value == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		session, err := browserStore.LoadSessionForPeer(r.Context(), cookie.Value, browser.PeerIPFromContext(r.Context()))
		if err != nil || !session.Authenticated() || identityStore.ValidateSubject(r.Context(), session.Subject) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		admin, err := rbacStore.IsAdmin(r.Context(), session.Subject)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return false
		}
		if !admin || mutation && browser.ValidateCSRFToken(cookie.Value, r.Header.Get("X-CSRF-Token")) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}
}

func bootstrapForceMFA(getenv func(string) string) (bool, error) {
	value, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_BOOTSTRAP_FORCE_MFA", "false"))
	if err != nil {
		return false, errors.New("GOAUTHY_BOOTSTRAP_FORCE_MFA must be a boolean")
	}
	return value, nil
}

// validateBootstrapPasskeyConfig rejects an impossible forced-MFA deployment.
// Passkeys remain opt-in when bootstrap MFA is not forced; when it is forced,
// startup must provide the service that can actually complete the UV flow.
func validateBootstrapPasskeyConfig(forceMFA bool, config *passkey.Config) error {
	if forceMFA && config == nil {
		return errors.New("GOAUTHY_BOOTSTRAP_FORCE_MFA requires passkey configuration")
	}
	return nil
}

func forwardAuthPasskeyEnrollment(service *passkey.Service) func(context.Context, string) (bool, error) {
	return func(ctx context.Context, subject string) (bool, error) {
		if service == nil {
			// Forward-auth remains useful without the optional passkey feature.
			// The MFA header must accurately report that no passkey factor is
			// enrolled; it must not turn an unrelated identity-header option
			// into an implicit passkey requirement.
			return false, nil
		}
		return service.HasCredentials(ctx, subject)
	}
}

func cimdEnabled(getenv func(string) string) (bool, error) {
	value, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_CIMD_ENABLED", "false"))
	if err != nil {
		return false, errors.New("GOAUTHY_CIMD_ENABLED must be a boolean")
	}
	return value, nil
}

func cimdIgnoreUnknownAuthFlowsFromEnv(getenv func(string) string) (bool, error) {
	value, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_CIMD_IGNORE_UNKNOWN_AUTH_FLOWS", "false"))
	if err != nil {
		return false, errors.New("GOAUTHY_CIMD_IGNORE_UNKNOWN_AUTH_FLOWS must be a boolean")
	}
	return value, nil
}

func cimdDangerAllowUnvalidatedResourceFromEnv(getenv func(string) string) (bool, error) {
	value, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_CIMD_DANGER_ALLOW_UNVALIDATED_RESOURCE", "false"))
	if err != nil {
		return false, errors.New("GOAUTHY_CIMD_DANGER_ALLOW_UNVALIDATED_RESOURCE must be a boolean")
	}
	return value, nil
}

func webIDEnabledFromEnv(getenv func(string) string) (bool, error) {
	value, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_WEB_ID_ENABLED", "false"))
	if err != nil {
		return false, errors.New("GOAUTHY_WEB_ID_ENABLED must be a boolean")
	}
	return value, nil
}

func emailOTPEnabled(getenv func(string) string) bool {
	value, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_EMAIL_OTP_ENABLED", "false"))
	return err == nil && value
}

func argonPolicyFromEnv(getenv func(string) string) (credential.Policy, error) {
	policy := credential.DefaultPolicy()
	var err error
	if policy.MemoryKiB, err = argonEnvUint32(getenv, "GOAUTHY_ARGON2_MEMORY_KIB", policy.MemoryKiB); err != nil {
		return credential.Policy{}, err
	}
	if policy.Iterations, err = argonEnvUint32(getenv, "GOAUTHY_ARGON2_ITERATIONS", policy.Iterations); err != nil {
		return credential.Policy{}, err
	}
	if policy.Parallelism, err = argonEnvUint8(getenv, "GOAUTHY_ARGON2_PARALLELISM", policy.Parallelism); err != nil {
		return credential.Policy{}, err
	}
	if policy.MaxConcurrency, err = argonEnvInt(getenv, "GOAUTHY_ARGON2_MAX_CONCURRENCY", policy.MaxConcurrency); err != nil {
		return credential.Policy{}, err
	}
	if _, err := credential.NewHasher(policy); err != nil {
		return credential.Policy{}, fmt.Errorf("invalid Argon2 password policy: %w", err)
	}
	return policy, nil
}

func passwordRecoveryEnabled(getenv func(string) string) (bool, error) {
	value, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_PASSWORD_RECOVERY_ENABLED", "false"))
	if err != nil {
		return false, errors.New("GOAUTHY_PASSWORD_RECOVERY_ENABLED must be a boolean")
	}
	return value, nil
}

func openRegistrationFromEnv(getenv func(string) string, recoveryEnabled bool, issuer string) (recovery.RegistrationConfig, time.Duration, error) {
	enabled, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_OPEN_USER_REG", "false"))
	if err != nil {
		return recovery.RegistrationConfig{}, 0, errors.New("GOAUTHY_OPEN_USER_REG must be a boolean")
	}
	ttl, err := time.ParseDuration(envValue(getenv, "GOAUTHY_PASSWORD_NEW_EXPIRY", "72h"))
	if err != nil || ttl < time.Minute || ttl > 7*24*time.Hour {
		return recovery.RegistrationConfig{}, 0, errors.New("GOAUTHY_PASSWORD_NEW_EXPIRY must be between 1m and 168h")
	}
	if !enabled {
		return recovery.RegistrationConfig{}, ttl, nil
	}
	if !recoveryEnabled {
		return recovery.RegistrationConfig{}, 0, errors.New("GOAUTHY_PASSWORD_RECOVERY_ENABLED must be true when GOAUTHY_OPEN_USER_REG is enabled")
	}
	allowed, err := openRegistrationDomains(getenv("GOAUTHY_USER_REG_DOMAIN_RESTRICTION"), false)
	if err != nil {
		return recovery.RegistrationConfig{}, 0, err
	}
	blacklisted, err := openRegistrationDomains(getenv("GOAUTHY_USER_REG_DOMAIN_BLACKLIST"), true)
	if err != nil {
		return recovery.RegistrationConfig{}, 0, err
	}
	if len(allowed) != 0 && len(blacklisted) != 0 {
		return recovery.RegistrationConfig{}, 0, errors.New("GOAUTHY_USER_REG_DOMAIN_RESTRICTION and GOAUTHY_USER_REG_DOMAIN_BLACKLIST cannot both be set")
	}
	parsedIssuer, err := url.Parse(issuer)
	if err != nil {
		return recovery.RegistrationConfig{}, 0, errors.New("invalid issuer")
	}
	passkeyEnabled, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_PASSKEY_REGISTRATION_ENABLED", "false"))
	if err != nil {
		return recovery.RegistrationConfig{}, 0, errors.New("GOAUTHY_PASSKEY_REGISTRATION_ENABLED must be a boolean")
	}
	config := recovery.RegistrationConfig{Enabled: true, PasskeyEnabled: passkeyEnabled, AllowedDomains: allowed, BlacklistedDomains: blacklisted, AllowHTTPRedirectURI: parsedIssuer.Scheme == "http", RedirectValidator: func(string) bool { return true }}
	if err := config.Validate(); err != nil {
		return recovery.RegistrationConfig{}, 0, fmt.Errorf("invalid open registration configuration: %w", err)
	}
	return config, ttl, nil
}

func openRegistrationDomains(raw string, multiline bool) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	if !multiline && strings.Contains(raw, "\n") {
		return nil, errors.New("GOAUTHY_USER_REG_DOMAIN_RESTRICTION must be one exact domain")
	}
	parts := []string{raw}
	if multiline {
		parts = strings.Split(raw, "\n")
	}
	for _, part := range parts {
		if part == "" || strings.TrimSpace(part) != part {
			return nil, errors.New("open registration domains must be newline-separated exact lower-case domains")
		}
	}
	return parts, nil
}

func passwordRulesFromEnvWithRecovery(getenv func(string) string, enabled bool) (credential.Rules, error) {
	rules := credential.DefaultRules()
	if !enabled {
		rules.ValidDays = 0
	}
	values := []struct {
		name string
		out  *int
	}{
		{"GOAUTHY_PASSWORD_LENGTH_MIN", &rules.LengthMin}, {"GOAUTHY_PASSWORD_LENGTH_MAX", &rules.LengthMax},
		{"GOAUTHY_PASSWORD_LOWER_CASE", &rules.LowerCase}, {"GOAUTHY_PASSWORD_UPPER_CASE", &rules.UpperCase},
		{"GOAUTHY_PASSWORD_DIGITS", &rules.Digits}, {"GOAUTHY_PASSWORD_SPECIAL", &rules.Special},
		{"GOAUTHY_PASSWORD_HISTORY", &rules.History}, {"GOAUTHY_PASSWORD_VALID_DAYS", &rules.ValidDays},
	}
	for _, value := range values {
		parsed, err := passwordRuleInt(getenv, value.name, *value.out)
		if err != nil {
			return credential.Rules{}, err
		}
		if !enabled && value.name == "GOAUTHY_PASSWORD_VALID_DAYS" && parsed != 0 {
			return credential.Rules{}, errors.New("GOAUTHY_PASSWORD_VALID_DAYS must be 0: password reset flow unavailable")
		}
		*value.out = parsed
	}
	if err := rules.Validate(); err != nil {
		return credential.Rules{}, fmt.Errorf("invalid password rules: %w", err)
	}
	return rules, nil
}

func newIdentityStore(db *rhiza.DB, hasher *credential.Hasher, rules credential.Rules, resetKey []byte) (*identity.Store, error) {
	if len(resetKey) == 0 {
		return identity.NewStoreWithPolicies(db, hasher, rules)
	}
	return identity.NewStoreWithPasswordReset(db, hasher, rules, resetKey)
}

func loadPasswordResetKey(getenv func(string) string) ([]byte, error) {
	path := getenv("GOAUTHY_PASSWORD_RESET_KEY_FILE")
	if path == "" {
		return nil, errors.New("GOAUTHY_PASSWORD_RESET_KEY_FILE is required when password recovery is enabled")
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read password reset key: %w", err)
	}
	if len(key) != 32 {
		return nil, errors.New("password reset key must be exactly 32 bytes")
	}
	return key, nil
}

func passwordProofConfig(getenv func(string) string) (uint8, time.Duration, error) {
	difficulty := uint64(19)
	if getenv("GOAUTHY_POW_DIFFICULTY") != "" {
		parsed, err := argonEnvUint(getenv, "GOAUTHY_POW_DIFFICULTY", 8)
		if err != nil {
			return 0, 0, err
		}
		difficulty = parsed
	}
	if difficulty < 10 || difficulty > 98 {
		return 0, 0, errors.New("GOAUTHY_POW_DIFFICULTY must be between 10 and 98")
	}
	ttl, err := time.ParseDuration(envValue(getenv, "GOAUTHY_POW_EXPIRY", "30s"))
	if err != nil || ttl < time.Second || ttl > recovery.MaxProofTTL {
		return 0, 0, fmt.Errorf("GOAUTHY_POW_EXPIRY must be a duration between 1s and %s", recovery.MaxProofTTL)
	}
	return uint8(difficulty), ttl, nil
}

func passkeyConfigFromEnv(getenv func(string) string) (*passkey.Config, error) {
	rpID := getenv("GOAUTHY_PASSKEY_RP_ID")
	originsRaw := getenv("GOAUTHY_PASSKEY_ORIGINS")
	keyPath := getenv("GOAUTHY_PASSKEY_KEY_FILE")
	configured := 0
	for _, value := range []string{rpID, originsRaw, keyPath} {
		if value != "" {
			configured++
		}
	}
	if configured == 0 {
		return nil, nil
	}
	if configured != 3 {
		return nil, errors.New("GOAUTHY_PASSKEY_RP_ID, GOAUTHY_PASSKEY_ORIGINS, and GOAUTHY_PASSKEY_KEY_FILE must be set together")
	}
	origins, err := passkeyOrigins(originsRaw)
	if err != nil {
		return nil, err
	}
	key, err := loadPasskeyCookieKey(keyPath)
	if err != nil {
		return nil, err
	}
	forceUV, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_PASSKEY_FORCE_UV", "false"))
	if err != nil {
		return nil, errors.New("GOAUTHY_PASSKEY_FORCE_UV must be a boolean")
	}
	cfg := &passkey.Config{
		RPID:          rpID,
		RPDisplayName: envValue(getenv, "GOAUTHY_PASSKEY_DISPLAY_NAME", "GoAuthy"),
		Origins:       origins,
		ForceUV:       forceUV,
		CookieKey:     key,
	}
	if prevPath := getenv("GOAUTHY_PASSKEY_COOKIE_KEY_FILE_PREVIOUS"); prevPath != "" {
		prevKey, err := loadPasskeyCookieKey(prevPath)
		if err != nil {
			return nil, fmt.Errorf("GOAUTHY_PASSKEY_COOKIE_KEY_FILE_PREVIOUS: %w", err)
		}
		cfg.PreviousCookieKey = prevKey
	}
	return cfg, nil
}

// loadPasskeyCookieKey accepts only a regular, owner-only key file. Lstat
// rejects symlinks; comparing it with the opened descriptor also fails closed
// if the pathname is replaced between inspection and open.
func loadPasskeyCookieKey(path string) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect passkey key file: %w", err)
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("passkey key file must be a regular file")
	}
	if pathInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("passkey key file must be owner-only")
	}
	if pathInfo.Size() != 32 {
		return nil, errors.New("passkey key must be exactly 32 bytes")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open passkey key file: %w", err)
	}
	defer f.Close()
	fileInfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat passkey key file: %w", err)
	}
	if !fileInfo.Mode().IsRegular() || !os.SameFile(pathInfo, fileInfo) {
		return nil, errors.New("passkey key file changed during open")
	}
	if fileInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("passkey key file must be owner-only")
	}
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil {
		return nil, fmt.Errorf("read passkey key file: %w", err)
	}
	if len(key) != 32 {
		return nil, errors.New("passkey key must be exactly 32 bytes")
	}
	return key, nil
}

func forwardAuthHeadersFromEnv(getenv func(string) string) (bool, error) {
	enabled, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_FORWARD_AUTH_HEADERS", "false"))
	if err != nil {
		return false, errors.New("GOAUTHY_FORWARD_AUTH_HEADERS must be a boolean")
	}
	return enabled, nil
}

func selfDeleteEnabledFromEnv(getenv func(string) string) (bool, error) {
	enabled, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_ENABLE_SELF_DELETE", "false"))
	if err != nil {
		return false, errors.New("GOAUTHY_ENABLE_SELF_DELETE must be a boolean")
	}
	return enabled, nil
}

func passkeyOrigins(raw string) ([]string, error) {
	if raw == "" {
		return nil, errors.New("GOAUTHY_PASSKEY_ORIGINS must contain exact origins")
	}
	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, origin := range parts {
		if origin == "" || strings.TrimSpace(origin) != origin {
			return nil, errors.New("GOAUTHY_PASSKEY_ORIGINS must be comma-separated exact origins")
		}
		parsed, err := url.ParseRequestURI(origin)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != origin {
			return nil, errors.New("GOAUTHY_PASSKEY_ORIGINS must be comma-separated exact origins")
		}
		if _, duplicate := seen[origin]; duplicate {
			return nil, errors.New("GOAUTHY_PASSKEY_ORIGINS contains a duplicate origin")
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}
	return origins, nil
}

func smtpSenderFromEnv(getenv func(string) string) (*recovery.SMTPSender, error) {
	templates, err := recovery.LoadEmailTemplates(getenv("GOAUTHY_EMAIL_TEMPLATES_FILE"))
	if err != nil {
		return nil, fmt.Errorf("load email templates: %w", err)
	}
	template, passwordNewTemplate, alreadyRegisteredTemplate, err := emailTemplatesForLanguage(templates, envValue(getenv, "GOAUTHY_EMAIL_TEMPLATE_LANG", "en"))
	if err != nil {
		return nil, err
	}
	cfg, err := smtpConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	cfg.Templates, cfg.Template = templates, template
	cfg.PasswordNewTemplate, cfg.AlreadyRegisteredTemplate = passwordNewTemplate, alreadyRegisteredTemplate
	sender, err := recovery.NewSMTPSender(cfg)
	if err != nil {
		return nil, fmt.Errorf("configure SMTP sender: %w", err)
	}
	return sender, nil
}

func smtpConfigFromEnv(getenv func(string) string) (recovery.SMTPConfig, error) {
	port, err := strconv.Atoi(envValue(getenv, "GOAUTHY_SMTP_PORT", "587"))
	if err != nil {
		return recovery.SMTPConfig{}, errors.New("GOAUTHY_SMTP_PORT must be a port")
	}
	timeout, err := time.ParseDuration(envValue(getenv, "GOAUTHY_SMTP_TIMEOUT", "10s"))
	if err != nil {
		return recovery.SMTPConfig{}, errors.New("GOAUTHY_SMTP_TIMEOUT must be a duration")
	}
	implicitTLS, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_SMTP_IMPLICIT_TLS", "false"))
	if err != nil {
		return recovery.SMTPConfig{}, errors.New("GOAUTHY_SMTP_IMPLICIT_TLS must be a boolean")
	}
	allowInsecure, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_SMTP_ALLOW_INSECURE", "false"))
	if err != nil {
		return recovery.SMTPConfig{}, errors.New("GOAUTHY_SMTP_ALLOW_INSECURE must be a boolean")
	}
	return recovery.SMTPConfig{Host: getenv("GOAUTHY_SMTP_HOST"), Port: port, From: getenv("GOAUTHY_SMTP_FROM"), Username: getenv("GOAUTHY_SMTP_USERNAME"), Password: getenv("GOAUTHY_SMTP_PASSWORD"), Timeout: timeout, ImplicitTLS: implicitTLS, AllowInsecure: allowInsecure}, nil
}

func emailTemplateFromEnv(getenv func(string) string) (recovery.EmailTemplate, error) {
	template, _, _, err := emailTemplatesFromEnv(getenv)
	return template, err
}

type emailTemplateAdapter struct {
	templates recovery.EmailTemplates
}

func (a *emailTemplateAdapter) Types() []string { return a.templates.TemplateTypes() }
func (a *emailTemplateAdapter) Languages(typ string) []string {
	return a.templates.TemplateLanguages(typ)
}
func (a *emailTemplateAdapter) Render(typ, lang string) (admin.EmailTemplateInfo, error) {
	var t recovery.EmailTemplate
	var err error
	switch typ {
	case "password_reset":
		t, err = a.templates.PasswordResetExact(lang)
	case "password_new":
		t, err = a.templates.PasswordNewExact(lang)
	case "registered_already":
		t, err = a.templates.AlreadyRegisteredExact(lang)
	case "email_change_confirm":
		t, err = a.templates.EmailChangeConfirmExact(lang)
	default:
		return admin.EmailTemplateInfo{}, fmt.Errorf("unknown template type %q", typ)
	}
	if err != nil {
		return admin.EmailTemplateInfo{}, err
	}
	return admin.EmailTemplateInfo{
		Subject:   t.Subject,
		Header:    t.Header,
		Text:      t.Text,
		ClickLink: t.ClickLink,
		Validity:  t.Validity,
		Expires:   t.Expires,
		Button:    t.Button,
		Footer:    t.Footer,
	}, nil
}

func emailTemplatesFromEnv(getenv func(string) string) (recovery.EmailTemplate, recovery.EmailTemplate, recovery.EmailTemplate, error) {
	templates, err := recovery.LoadEmailTemplates(getenv("GOAUTHY_EMAIL_TEMPLATES_FILE"))
	if err != nil {
		return recovery.EmailTemplate{}, recovery.EmailTemplate{}, recovery.EmailTemplate{}, fmt.Errorf("load email templates: %w", err)
	}
	return emailTemplatesForLanguage(templates, envValue(getenv, "GOAUTHY_EMAIL_TEMPLATE_LANG", "en"))
}

func emailTemplatesForLanguage(templates recovery.EmailTemplates, lang string) (recovery.EmailTemplate, recovery.EmailTemplate, recovery.EmailTemplate, error) {
	template, err := templates.PasswordResetExact(lang)
	if err != nil {
		return recovery.EmailTemplate{}, recovery.EmailTemplate{}, recovery.EmailTemplate{}, err
	}
	passwordNew, err := templates.PasswordNewExact(lang)
	if err != nil {
		return recovery.EmailTemplate{}, recovery.EmailTemplate{}, recovery.EmailTemplate{}, err
	}
	alreadyRegistered, err := templates.AlreadyRegisteredExact(lang)
	if err != nil {
		return recovery.EmailTemplate{}, recovery.EmailTemplate{}, recovery.EmailTemplate{}, err
	}
	return template, passwordNew, alreadyRegistered, nil
}

func passwordRulesFromEnv(getenv func(string) string) (credential.Rules, error) {
	return passwordRulesFromEnvWithRecovery(getenv, false)
}

func passwordRuleInt(getenv func(string) string, name string, fallback int) (int, error) {
	if getenv(name) == "" {
		return fallback, nil
	}
	value, err := argonEnvUint(getenv, name, strconv.IntSize)
	if err != nil {
		return 0, err
	}
	return int(value), nil
}

func argonEnvUint32(getenv func(string) string, name string, fallback uint32) (uint32, error) {
	value, err := argonEnvUint(getenv, name, 32)
	if err != nil {
		return 0, err
	}
	if value == 0 && getenv(name) == "" {
		return fallback, nil
	}
	return uint32(value), nil
}

func argonEnvUint8(getenv func(string) string, name string, fallback uint8) (uint8, error) {
	value, err := argonEnvUint(getenv, name, 8)
	if err != nil {
		return 0, err
	}
	if value == 0 && getenv(name) == "" {
		return fallback, nil
	}
	return uint8(value), nil
}

func argonEnvInt(getenv func(string) string, name string, fallback int) (int, error) {
	value, err := argonEnvUint(getenv, name, strconv.IntSize)
	if err != nil {
		return 0, err
	}
	if value == 0 && getenv(name) == "" {
		return fallback, nil
	}
	return int(value), nil
}

func argonEnvUint(getenv func(string) string, name string, bits int) (uint64, error) {
	raw := getenv(name)
	if raw == "" {
		return 0, nil
	}
	for i := range len(raw) {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, fmt.Errorf("%s must be an unsigned decimal integer", name)
		}
	}
	value, err := strconv.ParseUint(raw, 10, bits)
	if err != nil || strconv.FormatUint(value, 10) != raw {
		return 0, fmt.Errorf("%s must be an unsigned decimal integer", name)
	}
	return value, nil
}

func configureCIMD(db *rhiza.DB, enabled bool, policy cimd.Policy) (*cimd.Resolver, error) {
	if !enabled {
		return nil, nil
	}
	resolver, err := cimd.NewResolver(db, cimd.NewFetcherWithPolicy(policy))
	if err != nil {
		return nil, fmt.Errorf("configure CIMD resolver: %w", err)
	}
	return resolver, nil
}

func bootstrapAllowedResources(getenv func(string) string) ([]string, error) {
	raw := getenv("GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES")
	if raw == "" {
		return nil, nil
	}
	var resources []string
	if err := json.Unmarshal([]byte(raw), &resources); err != nil || resources == nil {
		return nil, fmt.Errorf("GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES must be a JSON array of HTTPS resource URLs")
	}
	return resources, nil
}

// An unset resource disables Bearer access, without affecting owner browser access.
func resourceFromEnv(getenv func(string) string, name string, allowedResources []string) (string, error) {
	resource := getenv(name)
	if resource == "" {
		return "", nil
	}
	for _, allowed := range allowedResources {
		if resource == allowed {
			return resource, nil
		}
	}
	return "", fmt.Errorf("%s must match a resource in GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES", name)
}

func bootstrapDefaultAudience(getenv func(string) string) (string, error) {
	raw := getenv("GOAUTHY_BOOTSTRAP_DEFAULT_AUD")
	if raw == "" {
		return "", nil
	}
	if len(raw) > 2048 || strings.TrimSpace(raw) != raw {
		return "", fmt.Errorf("GOAUTHY_BOOTSTRAP_DEFAULT_AUD must be one absolute HTTPS resource URL")
	}
	return raw, nil
}

func bootstrapPostLogoutRedirectURIs(getenv func(string) string) ([]string, error) {
	raw := getenv("GOAUTHY_BOOTSTRAP_POST_LOGOUT_REDIRECT_URIS")
	if raw == "" {
		return nil, nil
	}
	var redirects []string
	if err := json.Unmarshal([]byte(raw), &redirects); err != nil || redirects == nil {
		return nil, fmt.Errorf("GOAUTHY_BOOTSTRAP_POST_LOGOUT_REDIRECT_URIS must be a JSON array of registered redirect URLs")
	}
	return redirects, nil
}

func signingKeyRotationPeriod(getenv func(string) string) (time.Duration, error) {
	const defaultPeriod = 30 * 24 * time.Hour
	raw := getenv("GOAUTHY_SIGNING_KEY_ROTATION_PERIOD")
	if raw == "" {
		return defaultPeriod, nil
	}
	period, err := time.ParseDuration(raw)
	if err != nil || period < oidc.JWKSCacheMaxAge || period > 366*24*time.Hour {
		return 0, fmt.Errorf("GOAUTHY_SIGNING_KEY_ROTATION_PERIOD must be between %s and 8784h", oidc.JWKSCacheMaxAge)
	}
	return period, nil
}

func browserSessionIdleTimeout(getenv func(string) string) (time.Duration, error) {
	raw := getenv("GOAUTHY_BROWSER_SESSION_IDLE_TIMEOUT")
	if raw == "" {
		return browser.DefaultIdleTimeout, nil
	}
	timeout, err := time.ParseDuration(raw)
	if err != nil || timeout < 10*time.Second || timeout > 4*time.Hour {
		return 0, errors.New("GOAUTHY_BROWSER_SESSION_IDLE_TIMEOUT must be between 10s and 4h")
	}
	return timeout, nil
}

func clientCredentialsTokenLifetime(getenv func(string) string) (time.Duration, error) {
	raw := getenv("GOAUTHY_BOOTSTRAP_CLIENT_CREDENTIALS_TOKEN_LIFETIME")
	if raw == "" {
		return time.Hour, nil
	}
	lifetime, err := time.ParseDuration(raw)
	if err != nil || lifetime < 2*time.Second || lifetime > oidc.MaxAccessTokenLifetime {
		return 0, errors.New("GOAUTHY_BOOTSTRAP_CLIENT_CREDENTIALS_TOKEN_LIFETIME must be between 2s and 24h")
	}
	return lifetime, nil
}

func clientCredentialsMapSubFromEnv(getenv func(string) string) (bool, error) {
	value, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_CLIENT_CREDENTIALS_MAP_SUB", "false"))
	if err != nil {
		return false, errors.New("GOAUTHY_CLIENT_CREDENTIALS_MAP_SUB must be a boolean")
	}
	return value, nil
}

func backchannelSettings(getenv func(string) string) (string, bool, bool, time.Duration, error) {
	uri := getenv("GOAUTHY_BOOTSTRAP_BACKCHANNEL_LOGOUT_URI")
	allowPrivate, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_PRIVATE", "false"))
	if err != nil {
		return "", false, false, 0, errors.New("GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_PRIVATE must be a boolean")
	}
	allowHTTP, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_HTTP", "false"))
	if err != nil {
		return "", false, false, 0, errors.New("GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_HTTP must be a boolean")
	}
	retryBase, err := time.ParseDuration(envValue(getenv, "GOAUTHY_BACKCHANNEL_RETRY_BASE", "60s"))
	if err != nil || retryBase < time.Second || retryBase > time.Hour {
		return "", false, false, 0, errors.New("GOAUTHY_BACKCHANNEL_RETRY_BASE must be between 1s and 1h")
	}
	if uri == "" && (allowPrivate || allowHTTP) {
		return "", false, false, 0, errors.New("GOAUTHY_BOOTSTRAP_BACKCHANNEL_LOGOUT_URI is required when network exceptions are enabled")
	}
	return uri, allowPrivate, allowHTTP, retryBase, nil
}

func tlsConfigFromEnv(getenv func(string) string) (*tls.Config, *tlsconfig.Reloader, error) {
	certificateFile, keyFile := getenv("GOAUTHY_TLS_CERT_FILE"), getenv("GOAUTHY_TLS_KEY_FILE")
	if certificateFile == "" && keyFile == "" {
		return nil, nil, nil
	}
	if certificateFile == "" || keyFile == "" {
		return nil, nil, errors.New("GOAUTHY_TLS_CERT_FILE and GOAUTHY_TLS_KEY_FILE must be set together")
	}
	reloader, err := tlsconfig.New(certificateFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: reloader.GetCertificate}, reloader, nil
}

func validateIssuerTLS(issuer string, directTLS bool) error {
	if directTLS && !strings.HasPrefix(issuer, "https://") {
		return errors.New("GOAUTHY_ISSUER must use HTTPS when direct TLS is enabled")
	}
	return nil
}

func reloadTLS(ctx context.Context, reloader *tlsconfig.Reloader) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := reloader.Reload(); err != nil {
				slog.Error("TLS certificate reload failed", "error", err)
			}
		}
	}
}

// runOpenRegistrationCleanup reconciles immediately, then periodically. The
// clock is an argument so a scheduler tick is directly testable without time
// passing; cleanup itself is a bounded, replicated identity-store operation.
func runOpenRegistrationCleanup(ctx context.Context, store *identity.Store, interval time.Duration, now func() time.Time, onError func(error)) error {
	if store == nil || interval <= 0 || now == nil {
		return errors.New("open registration cleanup is not configured")
	}
	step := func() {
		if err := cleanupOpenRegistrationTick(ctx, store, now()); err != nil && ctx.Err() == nil && onError != nil {
			onError(err)
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	step()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			step()
		}
	}
}

func cleanupOpenRegistrationTick(ctx context.Context, store *identity.Store, now time.Time) error {
	if store == nil || now.IsZero() {
		return errors.New("open registration cleanup requires store and time")
	}
	return store.CleanupExpiredOpenRegistrations(ctx, now.UTC())
}

// shutdownServer gracefully shuts down an http.Server with a 10-second
// timeout. Nil servers return nil immediately.
func shutdownServer(s *http.Server) error {
	if s == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.Shutdown(ctx)
}

// lifecycle waits for one of three terminal events (context cancellation,
// app server error, or metrics server error), shuts down both servers, and
// returns the appropriate error. When metrics is nil, only the app and
// context paths are live.
//
// The select covers every combination:
//   - ctx Done first: shut down both, return app shutdown error directly
//   - app error first: shut down metrics, return app error
//   - metrics error first: shut down app, wait for app to finish, return metrics error
//   - metrics error (ErrServerClosed) first: app still live, wait for app
//
// Each path shuts down both servers. Nil channel sends are never selected
// (a nil channel blocks forever), so metrics=nil safely disables the
// metrics case. Nil servers are no-ops.
func lifecycle(ctx context.Context, appServer *http.Server, metricsServer *http.Server, appErr <-chan error, metricsErr <-chan error) error {
	select {
	case <-ctx.Done():
		_ = shutdownServer(metricsServer)
		return shutdownServer(appServer)

	case err := <-appErr:
		_ = shutdownServer(metricsServer)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err

	case err := <-metricsErr:
		_ = shutdownServer(appServer)
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		// Metrics stopped gracefully (e.g. from ctx cancellation or app
		// failure); drain app server for clean exit.
		select {
		case <-ctx.Done():
			err := <-appErr
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case err := <-appErr:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		}
	}
}

// maxMetricsTokenFileSize is the upper bound for GOAUTHY_METRICS_TOKEN_FILE
// reads. Tokens larger than this are rejected at startup to prevent
// accidental memory exhaustion from a misconfigured path.
const maxMetricsTokenFileSize = 64 << 10

// loadMetricsToken reads a bearer token for the metrics endpoint from the
// file at GOAUTHY_METRICS_TOKEN_FILE. It trims exactly one trailing LF or
// CRLF, then rejects the token if it is empty, contains only whitespace,
// or contains a comma. The file must exist, be readable, and be at most
// maxMetricsTokenFileSize bytes. The raw token is never logged.
func loadMetricsToken(getenv func(string) string) (string, error) {
	path := getenv("GOAUTHY_METRICS_TOKEN_FILE")
	if path == "" {
		return "", errors.New("GOAUTHY_METRICS_LISTEN_ADDR requires GOAUTHY_METRICS_TOKEN_FILE")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open metrics token: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxMetricsTokenFileSize+1))
	if err != nil {
		return "", fmt.Errorf("read metrics token: %w", err)
	}
	if len(data) > maxMetricsTokenFileSize {
		return "", fmt.Errorf("metrics token file exceeds %d bytes", maxMetricsTokenFileSize)
	}
	token := strings.TrimSuffix(string(data), "\r\n")
	token = strings.TrimSuffix(token, "\n")
	if token == "" || strings.ContainsAny(token, " \t\r\n,") {
		return "", errors.New("metrics token must be non-empty, contain no whitespace or comma")
	}
	return token, nil
}

// closeRhizaAfterStartupComplete avoids a Rhiza v0.10.0 early-close
// checkpoint hazard. Rhiza is closed only after all startup work has
// succeeded and the server lifecycle is about to begin.
func closeRhizaAfterStartupComplete(db *rhiza.DB, startupComplete bool, current error) error {
	if !startupComplete || db == nil {
		return current
	}
	return errors.Join(current, db.Close())
}

func newHandler(db *rhiza.DB) *http.ServeMux {
	return newHandlerWithReadiness(db, nil)
}

func newHandlerWithReadiness(db *rhiza.DB, readiness func(bool), validators ...func(context.Context) error) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		// Local Ready does not imply quorum. Bound the linearizable read and
		// validators below Kubernetes' default one-second probe timeout.
		ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		defer cancel()
		if err := storage.Ready(ctx, db); err != nil || !readinessValidatorsOK(ctx, validators) {
			if readiness != nil {
				readiness(false)
			}
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		if readiness != nil {
			readiness(true)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func readinessValidatorsOK(ctx context.Context, validators []func(context.Context) error) bool {
	for _, validator := range validators {
		if validator != nil && validator(ctx) != nil {
			return false
		}
	}
	return true
}

func rhizaMemberIDs(config rhiza.Config) []string {
	if len(config.Members) == 0 {
		return []string{config.NodeID}
	}
	members := make([]string, 0, len(config.Members))
	for _, member := range config.Members {
		members = append(members, string(member.ID))
	}
	return members
}

func env(name, fallback string) string {
	return envValue(os.Getenv, name, fallback)
}

func envValue(getenv func(string) string, name, fallback string) string {
	if value := getenv(name); value != "" {
		return value
	}
	return fallback
}

// peerIPMiddleware resolves the canonical peer IP once at the HTTP boundary
// for every request. With trusted proxies it uses PeerIPFromRequest; in direct
// mode it falls back to the raw TCP peer via loginpolicy.PeerIP. The resolved
// IP is stored in request context and retrieved by handlers via
// browser.PeerIPFromContext.
func peerIPMiddleware(next http.Handler, trustedProxies []netip.Prefix) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var peerIP string
		var ok bool
		if len(trustedProxies) > 0 {
			peerIP, ok = loginpolicy.PeerIPFromRequest(r.RemoteAddr, r.Header, trustedProxies)
		} else {
			peerIP, ok = loginpolicy.PeerIP(r.RemoteAddr)
		}
		if !ok {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r.WithContext(browser.ContextWithPeerIP(r.Context(), peerIP)))
	})
}

func trustedProxiesFromEnv(getenv func(string) string) ([]netip.Prefix, error) {
	raw := getenv("GOAUTHY_TRUSTED_PROXIES")
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	prefixes, err := loginpolicy.ParseTrustedProxyCIDRs(parts)
	if err != nil {
		return nil, errors.New("GOAUTHY_TRUSTED_PROXIES must be a comma-separated list of CIDR prefixes")
	}
	return prefixes, nil
}

func ipBlacklistEnabled(getenv func(string) string) (bool, error) {
	enabled, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_IP_BLACKLIST_ENABLED", "false"))
	if err != nil {
		return false, errors.New("GOAUTHY_IP_BLACKLIST_ENABLED must be a boolean")
	}
	return enabled, nil
}

type geoblockConfig struct {
	Enabled     bool
	Policy      geoblock.Policy
	Header      string
	MaxMindPath string
}

func geoblockConfigFromEnv(getenv func(string) string) (geoblockConfig, error) {
	header := getenv("GOAUTHY_GEOBLOCK_COUNTRY_HEADER")
	if header != "" && !httpguts.ValidHeaderFieldName(header) {
		return geoblockConfig{}, errors.New("GOAUTHY_GEOBLOCK_COUNTRY_HEADER must be a valid non-empty header name")
	}
	enabled, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_GEOBLOCK_ENABLED", "false"))
	if err != nil {
		return geoblockConfig{}, errors.New("GOAUTHY_GEOBLOCK_ENABLED must be a boolean")
	}
	if !enabled {
		// Location notifications use the database even without country admission rules.
		return geoblockConfig{Header: header, MaxMindPath: getenv("GOAUTHY_GEOBLOCK_MAXMIND_DB")}, nil
	}
	kind := geoblock.ListType(envValue(getenv, "GOAUTHY_GEOBLOCK_TYPE", ""))
	rawCountries := getenv("GOAUTHY_GEOBLOCK_COUNTRIES")
	if kind == "" || rawCountries == "" {
		return geoblockConfig{}, errors.New("GOAUTHY_GEOBLOCK_TYPE and GOAUTHY_GEOBLOCK_COUNTRIES are required when geoblock is enabled")
	}
	parts := strings.Split(rawCountries, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
		if parts[i] == "" {
			return geoblockConfig{}, errors.New("GOAUTHY_GEOBLOCK_COUNTRIES must be comma-separated ISO country codes")
		}
	}
	blockUnknown, err := strconv.ParseBool(envValue(getenv, "GOAUTHY_GEOBLOCK_BLOCK_UNKNOWN", "false"))
	if err != nil {
		return geoblockConfig{}, errors.New("GOAUTHY_GEOBLOCK_BLOCK_UNKNOWN must be a boolean")
	}
	policy, err := geoblock.NewPolicy(kind, parts, blockUnknown)
	if err != nil {
		return geoblockConfig{}, fmt.Errorf("invalid geoblock policy: %w", err)
	}
	path := getenv("GOAUTHY_GEOBLOCK_MAXMIND_DB")
	if path == "" && header == "" {
		return geoblockConfig{}, errors.New("GOAUTHY_GEOBLOCK_COUNTRY_HEADER or GOAUTHY_GEOBLOCK_MAXMIND_DB is required when geoblock is enabled")
	}
	return geoblockConfig{Enabled: true, Policy: policy, Header: header, MaxMindPath: path}, nil
}

func validateGeoblockRuntime(config geoblockConfig, trustedProxies []netip.Prefix) error {
	if config.Enabled && config.MaxMindPath == "" && config.Header != "" && len(trustedProxies) == 0 {
		return errors.New("GOAUTHY_GEOBLOCK_COUNTRY_HEADER requires GOAUTHY_TRUSTED_PROXIES when no MaxMind database is configured")
	}
	return nil
}

func healthBypass(next, health http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawPath != "" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/livez" || r.URL.Path == "/readyz" {
			health.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func admissionBypass(next, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/v1/blacklist" || strings.HasPrefix(r.URL.Path, "/auth/v1/blacklist/") {
			handler.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
