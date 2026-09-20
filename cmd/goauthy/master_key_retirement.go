package main

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mrchypark/goauthy/internal/kv"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

const masterKeyRetirementInterval = time.Minute

// newMasterKeyBootID creates an opaque process identity. It is intentionally
// independent of the node ID: a restart on the same node must not reuse an
// attestation identity.
func newMasterKeyBootID() (string, error) {
	return newMasterKeyBootIDFrom(cryptorand.Reader)
}

func newMasterKeyBootIDFrom(random io.Reader) (string, error) {
	if random == nil {
		return "", errors.New("master-key boot ID random source is required")
	}
	value := make([]byte, 32)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", fmt.Errorf("generate master-key boot ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// admitMasterKeyRuntime is the one linearizable startup check. It runs after
// migration and before any bootstrap writer is called.
func admitMasterKeyRuntime(ctx context.Context, db *rhiza.DB, keyring *oidc.Keyring) error {
	if ctx == nil || db == nil || keyring == nil {
		return errors.New("master-key runtime admission is not configured")
	}
	activeID, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return err
	}
	barrier, err := storage.LoadMasterKeyRetirement(ctx, db)
	if errors.Is(err, storage.ErrMasterKeyRetirementNotPrepared) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load master-key retirement barrier: %w", err)
	}
	if (barrier.State == storage.MasterKeyRetirementFenced || barrier.State == storage.MasterKeyRetirementReady) && activeID != barrier.ReplacementKeyID {
		return fmt.Errorf("master-key runtime admission denied: barrier is %s for replacement key %q, active key is %q", barrier.State, barrier.ReplacementKeyID, activeID)
	}
	return nil
}

type masterKeyRetirementWorker struct {
	db       *rhiza.DB
	keyring  *oidc.Keyring
	issuer   string
	passkey  *passkey.Service
	nodeID   string
	bootID   string
	now      func() time.Time
	onError  func(error)
	load     func(context.Context, *rhiza.DB) (storage.MasterKeyRetirement, error)
	inspect  func(context.Context, *rhiza.DB, *oidc.Keyring, string, *passkey.Service, string, time.Time) (storage.MasterKeyRetirementStatus, error)
	attest   func(context.Context, *rhiza.DB, storage.MasterKeyRetirementAttestationRequest) (storage.MasterKeyRetirement, error)
	sequence int64
}

func newMasterKeyRetirementWorker(db *rhiza.DB, keyring *oidc.Keyring, issuer, nodeID, bootID string, passkeyService *passkey.Service) (*masterKeyRetirementWorker, error) {
	if db == nil || keyring == nil || issuer == "" || nodeID == "" || bootID == "" {
		return nil, errors.New("master-key retirement worker is not configured")
	}
	return &masterKeyRetirementWorker{
		db: db, keyring: keyring, issuer: issuer, nodeID: nodeID, bootID: bootID, passkey: passkeyService,
		now:     time.Now,
		load:    storage.LoadMasterKeyRetirement,
		inspect: inspectMasterKeyRetirement,
		attest: func(ctx context.Context, db *rhiza.DB, req storage.MasterKeyRetirementAttestationRequest) (storage.MasterKeyRetirement, error) {
			return storage.AttestMasterKeyRetirement(ctx, db, req)
		},
	}, nil
}

// Step performs one post-fence attestation attempt. Unsafe evidence is a
// normal skip while rewrap is converging; malformed/tampered state is reported
// and never attested.
func (w *masterKeyRetirementWorker) Step(ctx context.Context) error {
	if w == nil || w.db == nil || w.keyring == nil || w.nodeID == "" || w.bootID == "" || w.now == nil || w.load == nil || w.inspect == nil || w.attest == nil || ctx == nil {
		return errors.New("master-key retirement worker is not configured")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	barrier, err := w.load(ctx, w.db)
	if errors.Is(err, storage.ErrMasterKeyRetirementNotPrepared) {
		return nil
	}
	if err != nil {
		return err
	}
	if barrier.State == storage.MasterKeyRetirementReady {
		// Deletion belongs to the housekeeping cleanup owner, which waits out
		// the retired-key overlap period and requires an acknowledged archival
		// receipt for this exact epoch (GA-STOR-002).
		return nil
	}
	if barrier.State != storage.MasterKeyRetirementFenced {
		return nil
	}
	activeID, err := w.keyring.ActiveMasterKeyID()
	if err != nil {
		return err
	}
	if activeID != barrier.ReplacementKeyID {
		return fmt.Errorf("master-key retirement attestation requires replacement key %q, active key is %q", barrier.ReplacementKeyID, activeID)
	}
	now := w.now().UTC().Truncate(time.Millisecond)
	status, err := w.inspect(ctx, w.db, w.keyring, w.issuer, w.passkey, barrier.OldKeyID, now)
	if err != nil {
		return err
	}
	if status.OldReferences != 0 || status.NonActiveReferences != 0 || status.LegacyReferences != 0 || status.TamperReferences != 0 || status.OIDCReferences != 0 || status.DCRReferences != 0 || status.UpstreamReferences != 0 || status.PasskeyReferences != 0 {
		return nil
	}
	sequence := w.nextSequence(barrier)
	if sequence <= 0 {
		return errors.New("master-key retirement attestation sequence exhausted")
	}
	_, err = w.attest(ctx, w.db, storage.MasterKeyRetirementAttestationRequest{
		Epoch: barrier.Epoch, NodeID: w.nodeID, BootID: w.bootID, ActiveKeyID: activeID,
		AttestationSequence: sequence, AttestedAt: now, Status: status,
	})
	if err == nil {
		w.sequence = sequence
	}
	return err
}

func (w *masterKeyRetirementWorker) nextSequence(barrier storage.MasterKeyRetirement) int64 {
	sequence := w.sequence
	for _, attestation := range barrier.Attestations {
		if attestation.NodeID == w.nodeID && attestation.AttestationSequence > sequence {
			sequence = attestation.AttestationSequence
		}
	}
	if sequence >= 1<<63-1 {
		return 0
	}
	return sequence + 1
}

func (w *masterKeyRetirementWorker) Run(ctx context.Context) error {
	if w == nil || masterKeyRetirementInterval <= 0 {
		return errors.New("master-key retirement worker is not configured")
	}
	ticker := time.NewTicker(masterKeyRetirementInterval)
	defer ticker.Stop()
	return w.run(ctx, ticker.C)
}

// run accepts an injected trigger for deterministic tests and intentionally
// does no immediate inspection: rewrap gets a chance to make the first pass.
func (w *masterKeyRetirementWorker) run(ctx context.Context, ticks <-chan time.Time) error {
	if w == nil || ctx == nil || ticks == nil {
		return errors.New("master-key retirement worker is not configured")
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-ticks:
			if !ok {
				return nil
			}
			if err := w.Step(ctx); err != nil && ctx.Err() == nil && w.onError != nil {
				w.onError(err)
			}
		}
	}
}

func inspectMasterKeyRetirement(ctx context.Context, db *rhiza.DB, keyring *oidc.Keyring, issuer string, passkeyService *passkey.Service, oldID string, now time.Time) (storage.MasterKeyRetirementStatus, error) {
	store, err := kv.NewStore(db, keyring)
	if err != nil {
		return storage.MasterKeyRetirementStatus{}, err
	}
	return inspectMasterKeyRetirementWithKV(ctx, db, keyring, issuer, passkeyService, store, oldID, now)
}

func inspectMasterKeyRetirementWithKV(ctx context.Context, db *rhiza.DB, keyring *oidc.Keyring, issuer string, passkeyService *passkey.Service, kvStore *kv.Store, oldID string, now time.Time) (storage.MasterKeyRetirementStatus, error) {
	status := storage.MasterKeyRetirementStatus{PasskeyEnabled: passkeyService != nil}
	if passkeyService == nil {
		if err := requireEmptyDisabledPasskeyFamilies(ctx, db); err != nil {
			status.TamperReferences = 1
			return status, err
		}
	}
	oidcStatus, oidcErr := oidc.InspectMasterKeyReferences(ctx, db, keyring, issuer, now)
	status.OIDCReferences = oidcStatus.SigningKeys.Total - oidcReferenceCount(oidcStatus.SigningKeys, oidcStatus.ActiveMasterKeyID)
	status.DCRReferences = oidcStatus.DCRIdempotency.Total - oidcReferenceCount(oidcStatus.DCRIdempotency, oidcStatus.ActiveMasterKeyID)
	status.UpstreamReferences = oidcStatus.Upstream.Total - oidcReferenceCount(oidcStatus.Upstream, oidcStatus.ActiveMasterKeyID)
	status.OldReferences = oidcReferenceCount(oidcStatus.SigningKeys, oldID) + oidcReferenceCount(oidcStatus.DCRIdempotency, oldID) + oidcReferenceCount(oidcStatus.Upstream, oldID) + oidcReferenceCount(oidcStatus.ManagedClients, oldID) + oidcReferenceCount(oidcStatus.LoginRevoke, oldID) + oidcReferenceCount(oidcStatus.GeneratedAPIKeyBootstrap, oldID) + oidcReferenceCount(oidcStatus.EmailOutbox, oldID)
	unsafeReferences := status.OIDCReferences + status.DCRReferences + status.UpstreamReferences
	unsafeReferences += oidcStatus.ManagedClients.Total - oidcReferenceCount(oidcStatus.ManagedClients, oidcStatus.ActiveMasterKeyID)
	unsafeReferences += oidcStatus.LoginRevoke.Total - oidcReferenceCount(oidcStatus.LoginRevoke, oidcStatus.ActiveMasterKeyID)
	unsafeReferences += oidcStatus.GeneratedAPIKeyBootstrap.Total - oidcReferenceCount(oidcStatus.GeneratedAPIKeyBootstrap, oidcStatus.ActiveMasterKeyID)
	unsafeReferences += oidcStatus.EmailOutbox.Total - oidcReferenceCount(oidcStatus.EmailOutbox, oidcStatus.ActiveMasterKeyID)

	var passkeyStatus passkey.EnvelopeReferenceStatus
	var passkeyErr error
	if passkeyService != nil {
		passkeyStatus, passkeyErr = passkeyService.InspectEnvelopeReferences(ctx)
		for _, family := range []passkey.EnvelopeReferenceFamily{passkeyStatus.Credentials, passkeyStatus.Ceremonies, passkeyStatus.MFACeremonies} {
			status.LegacyReferences += family.Legacy
			unsafe := family.Total - passkeyReferenceCount(family, passkeyStatus.ActiveMasterKeyID)
			unsafeReferences += unsafe
			status.PasskeyReferences += unsafe
			status.OldReferences += passkeyReferenceCount(family, oldID)
		}
	}
	var kvUnsafe int64
	var kvOld int64
	var kvErr error
	if kvStore != nil {
		kvStatus, err := kvStore.InspectEnvelopeReferences(ctx)
		kvErr = err
		for _, family := range []oidc.MasterKeyReferenceFamily{kvStatus.Access, kvStatus.Values} {
			kvOld += oidcReferenceCount(family, oldID)
			kvUnsafe += family.Total - oidcReferenceCount(family, kvStatus.ActiveMasterKeyID)
		}
		status.OldReferences += kvOld
		unsafeReferences += kvUnsafe
		if kvErr != nil {
			status.TamperReferences++
		}
	}
	credentials, credentialErr := saas.InspectCredentialEnvelopeReferences(ctx, db, keyring)
	status.OldReferences += oidcReferenceCount(credentials, oldID)
	unsafeReferences += credentials.Total - oidcReferenceCount(credentials, oidcStatus.ActiveMasterKeyID)
	providers, providerErr := saas.InspectProviderEnvelopeReferences(ctx, db, keyring)
	status.OldReferences += oidcReferenceCount(providers, oldID)
	unsafeReferences += providers.Total - oidcReferenceCount(providers, oidcStatus.ActiveMasterKeyID)
	authorizations, authorizationErr := saas.InspectAuthorizationEnvelopeReferences(ctx, db, keyring)
	status.OldReferences += oidcReferenceCount(authorizations, oldID)
	unsafeReferences += authorizations.Total - oidcReferenceCount(authorizations, oidcStatus.ActiveMasterKeyID)
	authProviderSecrets, authProviderSecretErr := upstreamprovider.InspectAuthProviderSecretReferences(ctx, db, keyring)
	status.OldReferences += oidcReferenceCount(authProviderSecrets, oldID)
	unsafeReferences += authProviderSecrets.Total - oidcReferenceCount(authProviderSecrets, oidcStatus.ActiveMasterKeyID)
	status.NonActiveReferences = unsafeReferences - status.OldReferences
	if oidcErr != nil || passkeyErr != nil || (kvStore != nil && kvErr != nil) || credentialErr != nil || providerErr != nil || authorizationErr != nil || authProviderSecretErr != nil {
		status.TamperReferences = 1
		return status, errors.Join(oidcErr, passkeyErr, kvErr, credentialErr, providerErr, authorizationErr, authProviderSecretErr)
	}
	return status, nil
}

func oidcReferenceCount(family oidc.MasterKeyReferenceFamily, keyID string) int64 {
	return family.ByKeyID[keyID]
}

func passkeyReferenceCount(family passkey.EnvelopeReferenceFamily, keyID string) int64 {
	return family.ByKeyID[keyID]
}

// requireEmptyDisabledPasskeyFamilies fails closed when passkeys are disabled
// but retained rows exist (GA-STOR-001). Those rows may still be sealed under
// the retiring key, and reporting zero passkey references would let retirement
// remove a key they still need. The three tables are the durable passkey
// families whose envelope references and rewrap are owned by the optional
// passkey service configuration.
func requireEmptyDisabledPasskeyFamilies(ctx context.Context, db *rhiza.DB) error {
	for _, table := range []string{"identity_webauthn_credentials", "identity_webauthn_ceremonies", "identity_webauthn_mfa_ceremonies"} {
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM " + table, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return fmt.Errorf("inspect disabled passkey family %s: %w", table, err)
		}
		if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
			return fmt.Errorf("inspect disabled passkey family %s: unexpected row shape", table)
		}
		count, ok := result.Rows[0][0].(int64)
		if !ok || count < 0 {
			return fmt.Errorf("inspect disabled passkey family %s: unexpected count", table)
		}
		if count != 0 {
			return fmt.Errorf("passkey feature is disabled but %s retains %d rows that cannot be inspected or rewrapped", table, count)
		}
	}
	return nil
}
