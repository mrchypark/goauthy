package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/mrchypark/goauthy/internal/kv"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

// masterKeyStatusFamily is the sanitized, local evidence exposed to the
// command. It deliberately contains counts and state only; no envelope,
// ciphertext, or plaintext is retained.
type masterKeyStatusFamily struct {
	Total     int64
	NonActive int64
	Legacy    int64
}

// masterKeyStatus is a read-only local operator snapshot. Safe is an
// advisory retirement gate only: every pod's active ID and the rollout/TTL
// conditions still require independent operator verification.
type masterKeyStatus struct {
	ActiveMasterKeyID string
	CheckedAt         time.Time
	PasskeyEnabled    bool

	SigningKeys              masterKeyStatusFamily
	DCRIdempotency           masterKeyStatusFamily
	Upstream                 masterKeyStatusFamily
	ManagedClients           masterKeyStatusFamily
	LoginRevoke              masterKeyStatusFamily
	GeneratedAPIKeyBootstrap masterKeyStatusFamily
	KVAccess                 masterKeyStatusFamily
	KVValues                 masterKeyStatusFamily
	SaaSCredentials          masterKeyStatusFamily
	SaaSProviders            masterKeyStatusFamily
	SaaSAuthorizations       masterKeyStatusFamily
	AuthProviderSecrets      masterKeyStatusFamily

	PasskeyCredentials   masterKeyStatusFamily
	PasskeyCeremonies    masterKeyStatusFamily
	PasskeyMFACeremonies masterKeyStatusFamily

	// ScanError is true when either underlying inspector failed closed (for
	// example, on malformed, tampered, or unknown-key durable state).
	ScanError bool
	Safe      bool
}

// inspectMasterKeyStatus combines the existing read-only OIDC and passkey
// inspectors. Disabled passkeys are represented explicitly by zero-valued
// passkey families and are not probed.
func inspectMasterKeyStatus(ctx context.Context, db *rhiza.DB, keyring *oidc.Keyring, issuer string, passkeyService *passkey.Service, now time.Time) (masterKeyStatus, error) {
	store, err := kv.NewStore(db, keyring)
	if err != nil {
		return masterKeyStatus{ScanError: true}, err
	}
	return inspectMasterKeyStatusWithKV(ctx, db, keyring, issuer, passkeyService, store, now)
}

func inspectMasterKeyStatusWithKV(ctx context.Context, db *rhiza.DB, keyring *oidc.Keyring, issuer string, passkeyService *passkey.Service, kvStore *kv.Store, now time.Time) (masterKeyStatus, error) {
	status := masterKeyStatus{PasskeyEnabled: passkeyService != nil}
	if ctx == nil || db == nil || keyring == nil || now.IsZero() {
		status.ScanError = true
		return status, errors.New("master-key status is not configured")
	}
	activeID, err := keyring.ActiveMasterKeyID()
	if err != nil {
		status.ScanError = true
		return status, err
	}
	status.ActiveMasterKeyID = activeID
	status.CheckedAt = now.UTC().Truncate(time.Millisecond)

	oidcStatus, oidcErr := oidc.InspectMasterKeyReferences(ctx, db, keyring, issuer, status.CheckedAt)
	status.SigningKeys = summarizeOIDCFamily(oidcStatus.SigningKeys, activeID)
	status.DCRIdempotency = summarizeOIDCFamily(oidcStatus.DCRIdempotency, activeID)
	status.Upstream = summarizeOIDCFamily(oidcStatus.Upstream, activeID)

	var passkeyStatus passkey.EnvelopeReferenceStatus
	var passkeyErr error
	if passkeyService != nil {
		passkeyStatus, passkeyErr = passkeyService.InspectEnvelopeReferences(ctx)
	}
	var kvStatus kv.EnvelopeReferences
	var kvErr error
	if kvStore != nil {
		kvStatus, kvErr = kvStore.InspectEnvelopeReferences(ctx)
	}
	status, aggregateErr := aggregateMasterKeyStatusWithKV(activeID, status.CheckedAt, passkeyService != nil, oidcStatus, oidcErr, passkeyStatus, passkeyErr, kvStatus, kvErr)
	credentials, credentialErr := saas.InspectCredentialEnvelopeReferences(ctx, db, keyring)
	status.SaaSCredentials = summarizeOIDCFamily(credentials, activeID)
	providers, providerErr := saas.InspectProviderEnvelopeReferences(ctx, db, keyring)
	status.SaaSProviders = summarizeOIDCFamily(providers, activeID)
	authorizations, authorizationErr := saas.InspectAuthorizationEnvelopeReferences(ctx, db, keyring)
	status.SaaSAuthorizations = summarizeOIDCFamily(authorizations, activeID)
	authProviderSecrets, authProviderSecretErr := upstreamprovider.InspectAuthProviderSecretReferences(ctx, db, keyring)
	status.AuthProviderSecrets = summarizeOIDCFamily(authProviderSecrets, activeID)
	status.ScanError = status.ScanError || credentialErr != nil
	status.ScanError = status.ScanError || providerErr != nil
	status.ScanError = status.ScanError || authorizationErr != nil
	status.ScanError = status.ScanError || authProviderSecretErr != nil
	status.Safe = status.Safe && credentialErr == nil && providerErr == nil && authorizationErr == nil && authProviderSecretErr == nil && status.SaaSCredentials.NonActive == 0 && status.SaaSProviders.NonActive == 0 && status.SaaSAuthorizations.NonActive == 0 && status.AuthProviderSecrets.NonActive == 0
	return status, errors.Join(aggregateErr, credentialErr, providerErr, authorizationErr, authProviderSecretErr)
}

// logMasterKeyStatus emits only sanitized local evidence during startup. It
// intentionally omits inspector errors, key maps, envelopes, and plaintext.
func logMasterKeyStatus(ctx context.Context, db *rhiza.DB, keyring *oidc.Keyring, issuer string, passkeyService *passkey.Service, now time.Time) {
	status, err := inspectMasterKeyStatus(ctx, db, keyring, issuer, passkeyService, now)
	attrs := []any{
		"active_master_key_id", status.ActiveMasterKeyID,
		"safe", status.Safe,
		"scan_error", status.ScanError,
		"passkey_enabled", status.PasskeyEnabled,
		"signing_total", status.SigningKeys.Total,
		"signing_non_active", status.SigningKeys.NonActive,
		"dcr_total", status.DCRIdempotency.Total,
		"dcr_non_active", status.DCRIdempotency.NonActive,
		"upstream_total", status.Upstream.Total,
		"upstream_non_active", status.Upstream.NonActive,
		"login_revoke_total", status.LoginRevoke.Total,
		"login_revoke_non_active", status.LoginRevoke.NonActive,
		"generated_api_key_bootstrap_total", status.GeneratedAPIKeyBootstrap.Total,
		"generated_api_key_bootstrap_non_active", status.GeneratedAPIKeyBootstrap.NonActive,
		"kv_access_total", status.KVAccess.Total,
		"kv_access_non_active", status.KVAccess.NonActive,
		"kv_values_total", status.KVValues.Total,
		"kv_values_non_active", status.KVValues.NonActive,
		"saas_credentials_total", status.SaaSCredentials.Total,
		"saas_credentials_non_active", status.SaaSCredentials.NonActive,
		"saas_providers_total", status.SaaSProviders.Total,
		"saas_providers_non_active", status.SaaSProviders.NonActive,
		"saas_authorizations_total", status.SaaSAuthorizations.Total,
		"saas_authorizations_non_active", status.SaaSAuthorizations.NonActive,
		"auth_provider_secrets_total", status.AuthProviderSecrets.Total,
		"auth_provider_secrets_non_active", status.AuthProviderSecrets.NonActive,
		"passkey_total", status.PasskeyCredentials.Total + status.PasskeyCeremonies.Total + status.PasskeyMFACeremonies.Total,
		"passkey_non_active", status.PasskeyCredentials.NonActive + status.PasskeyCeremonies.NonActive + status.PasskeyMFACeremonies.NonActive,
		"passkey_legacy", status.PasskeyCredentials.Legacy + status.PasskeyCeremonies.Legacy + status.PasskeyMFACeremonies.Legacy,
	}
	if err != nil {
		slog.Warn("master-key reference status unsafe", attrs...)
		return
	}
	slog.Info("master-key reference status", attrs...)
}

func aggregateMasterKeyStatus(activeID string, checkedAt time.Time, passkeyEnabled bool, oidcStatus oidc.MasterKeyReferenceStatus, oidcErr error, passkeyStatus passkey.EnvelopeReferenceStatus, passkeyErr error) (masterKeyStatus, error) {
	return aggregateMasterKeyStatusWithKV(activeID, checkedAt, passkeyEnabled, oidcStatus, oidcErr, passkeyStatus, passkeyErr, kv.EnvelopeReferences{}, nil)
}

func aggregateMasterKeyStatusWithKV(activeID string, checkedAt time.Time, passkeyEnabled bool, oidcStatus oidc.MasterKeyReferenceStatus, oidcErr error, passkeyStatus passkey.EnvelopeReferenceStatus, passkeyErr error, kvStatus kv.EnvelopeReferences, kvErr error) (masterKeyStatus, error) {
	status := masterKeyStatus{
		ActiveMasterKeyID:        activeID,
		CheckedAt:                checkedAt,
		PasskeyEnabled:           passkeyEnabled,
		SigningKeys:              summarizeOIDCFamily(oidcStatus.SigningKeys, activeID),
		DCRIdempotency:           summarizeOIDCFamily(oidcStatus.DCRIdempotency, activeID),
		Upstream:                 summarizeOIDCFamily(oidcStatus.Upstream, activeID),
		ManagedClients:           summarizeOIDCFamily(oidcStatus.ManagedClients, activeID),
		LoginRevoke:              summarizeOIDCFamily(oidcStatus.LoginRevoke, activeID),
		GeneratedAPIKeyBootstrap: summarizeOIDCFamily(oidcStatus.GeneratedAPIKeyBootstrap, activeID),
		KVAccess:                 summarizeOIDCFamily(kvStatus.Access, activeID),
		KVValues:                 summarizeOIDCFamily(kvStatus.Values, activeID),
	}
	if passkeyEnabled {
		status.PasskeyCredentials = summarizePasskeyFamily(passkeyStatus.Credentials, activeID)
		status.PasskeyCeremonies = summarizePasskeyFamily(passkeyStatus.Ceremonies, activeID)
		status.PasskeyMFACeremonies = summarizePasskeyFamily(passkeyStatus.MFACeremonies, activeID)
	}
	status.ScanError = oidcErr != nil || passkeyErr != nil || kvErr != nil ||
		(oidcStatus.ActiveMasterKeyID != "" && oidcStatus.ActiveMasterKeyID != activeID) ||
		(passkeyEnabled && passkeyStatus.ActiveMasterKeyID != "" && passkeyStatus.ActiveMasterKeyID != activeID) ||
		(kvStatus.ActiveMasterKeyID != "" && kvStatus.ActiveMasterKeyID != activeID)
	kvConfigured := kvErr != nil || kvStatus.ActiveMasterKeyID != "" || kvStatus.Access.Total != 0 || kvStatus.Values.Total != 0
	status.Safe = !status.ScanError && oidcStatus.Safe && (!passkeyEnabled || passkeyStatus.Safe) && (!kvConfigured || kvStatus.Safe)
	return status, errors.Join(oidcErr, passkeyErr, kvErr)
}

func summarizeOIDCFamily(family oidc.MasterKeyReferenceFamily, activeID string) masterKeyStatusFamily {
	status := masterKeyStatusFamily{Total: family.Total}
	for keyID, count := range family.ByKeyID {
		if keyID != activeID {
			status.NonActive += count
		}
	}
	return status
}

func summarizePasskeyFamily(family passkey.EnvelopeReferenceFamily, activeID string) masterKeyStatusFamily {
	status := masterKeyStatusFamily{Total: family.Total, Legacy: family.Legacy}
	for keyID, count := range family.ByKeyID {
		if keyID != activeID {
			status.NonActive += count
		}
	}
	return status
}
