package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/kv"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

const (
	masterKeyRewrapInterval      = time.Minute
	masterKeyRewrapFamilyTimeout = 10 * time.Second
)

// masterKeyRewrapWorker advances each independently cursor-scanned envelope
// family by one bounded batch per pass. CAS in each store makes concurrent pods
// converge safely.
type masterKeyRewrapWorker struct {
	rewrapSigning                  func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error)
	rewrapIdempotency              func(context.Context, string) (string, int, error)
	rewrapTransactions             func(context.Context, time.Time, string) (string, bool, int64, error)
	rewrapPasskey                  func(context.Context, string) (passkey.RewrapBatchResult, error)
	rewrapKV                       func(context.Context, string) (kv.RewrapResult, error)
	rewrapManaged                  func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error)
	rewrapLoginRevoke              func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error)
	rewrapGeneratedAPIKeyBootstrap func(context.Context) (oidc.SigningKeyRewrapBatchResult, error)
	rewrapSaaS                     func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error)
	rewrapSaaSProvider             func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error)
	rewrapSaaSAuthorization        func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error)
	rewrapAuthProviderSecret       func(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error)
	now                            func() time.Time
	onError                        func(error)
	newFamilyContext               func(context.Context) (context.Context, context.CancelFunc)

	signingCursor           string
	idempotencyCursor       string
	transactionCursor       string
	passkeyCursor           string
	kvCursor                string
	managedCursor           string
	loginRevokeCursor       string
	saasCursor              string
	saasProviderCursor      string
	saasAuthorizationCursor string
	authProviderSecretCursor string
}

func newMasterKeyRewrapWorker(db *rhiza.DB, keyring *oidc.Keyring, issuer string) (*masterKeyRewrapWorker, error) {
	if db == nil || keyring == nil {
		return nil, errors.New("master-key rewrap is not configured")
	}
	upstreamStore, err := upstreamprovider.NewRhizaStore(db, keyring)
	if err != nil {
		return nil, fmt.Errorf("configure upstream transaction rewrap: %w", err)
	}
	dcrStore := dcr.NewStore(db, dcr.Config{Keyring: keyring})
	kvStore, err := kv.NewStore(db, keyring)
	if err != nil {
		return nil, fmt.Errorf("configure KV rewrap: %w", err)
	}
	return &masterKeyRewrapWorker{
		rewrapSigning: func(ctx context.Context, cursor string) (oidc.SigningKeyRewrapBatchResult, error) {
			return oidc.RewrapSigningKeyEnvelopeBatch(ctx, db, keyring, issuer, cursor)
		},
		rewrapIdempotency:  dcrStore.RewrapIdempotencyBatch,
		rewrapTransactions: upstreamStore.RewrapTransactionBatch,
		rewrapPasskey:      noopPasskeyRewrap,
		rewrapKV:           kvStore.RewrapBatch,
		rewrapSaaS: func(ctx context.Context, cursor string) (oidc.SigningKeyRewrapBatchResult, error) {
			return saas.RewrapCredentialEnvelopeBatch(ctx, db, keyring, cursor)
		},
		rewrapSaaSProvider: func(ctx context.Context, cursor string) (oidc.SigningKeyRewrapBatchResult, error) {
			return saas.RewrapProviderEnvelopeBatch(ctx, db, keyring, cursor)
		},
		rewrapSaaSAuthorization: func(ctx context.Context, cursor string) (oidc.SigningKeyRewrapBatchResult, error) {
			return saas.RewrapAuthorizationEnvelopeBatch(ctx, db, keyring, cursor)
		},
		rewrapAuthProviderSecret: func(ctx context.Context, cursor string) (oidc.SigningKeyRewrapBatchResult, error) {
			return upstreamprovider.RewrapAuthProviderSecretBatch(ctx, db, keyring, cursor)
		},
		rewrapManaged: func(ctx context.Context, cursor string) (oidc.SigningKeyRewrapBatchResult, error) {
			return oidc.RewrapManagedClientSecretBatch(ctx, db, keyring, cursor)
		},
		rewrapLoginRevoke: func(ctx context.Context, cursor string) (oidc.SigningKeyRewrapBatchResult, error) {
			return oidc.RewrapLoginRevokeCodeBatch(ctx, db, keyring, cursor)
		},
		rewrapGeneratedAPIKeyBootstrap: func(ctx context.Context) (oidc.SigningKeyRewrapBatchResult, error) {
			return oidc.RewrapGeneratedAPIKeyBootstrapEnvelope(ctx, db, keyring)
		},
		now: func() time.Time { return time.Now().UTC() },
	}, nil
}

func noopKVRewrap(context.Context, string) (kv.RewrapResult, error) {
	return kv.RewrapResult{Done: true}, nil
}

func noopPasskeyRewrap(context.Context, string) (passkey.RewrapBatchResult, error) {
	return passkey.RewrapBatchResult{Done: true}, nil
}

func noopManagedRewrap(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
	return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
}

func noopLoginRevokeRewrap(context.Context, string) (oidc.SigningKeyRewrapBatchResult, error) {
	return oidc.SigningKeyRewrapBatchResult{Done: true}, nil
}

func (w *masterKeyRewrapWorker) attachPasskey(service *passkey.Service) {
	if service == nil {
		w.rewrapPasskey = noopPasskeyRewrap
		return
	}
	w.rewrapPasskey = service.RewrapBatch
}

func (w *masterKeyRewrapWorker) attachKV(store *kv.Store) {
	if store == nil {
		w.rewrapKV = noopKVRewrap
		return
	}
	w.rewrapKV = store.RewrapBatch
}

// Step advances every envelope family by at most one store-defined 32-row
// batch. A cursor changes only after its batch succeeds.
func (w *masterKeyRewrapWorker) Step(ctx context.Context) error {
	if ctx == nil || w == nil || w.rewrapSigning == nil || w.rewrapIdempotency == nil || w.rewrapTransactions == nil || w.now == nil {
		return errors.New("master-key rewrap worker is not configured")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	var errs []error
	signingCtx, cancel := w.familyContext(ctx)
	signing, err := w.rewrapSigning(signingCtx, w.signingCursor)
	cancel()
	if err != nil {
		errs = append(errs, fmt.Errorf("rewrap signing keys: %w", err))
	} else if signing.Done {
		w.signingCursor = ""
	} else {
		w.signingCursor = signing.Cursor
	}

	idempotencyCtx, cancel := w.familyContext(ctx)
	cursor, _, err := w.rewrapIdempotency(idempotencyCtx, w.idempotencyCursor)
	cancel()
	if err != nil {
		errs = append(errs, fmt.Errorf("rewrap DCR idempotency: %w", err))
	} else {
		w.idempotencyCursor = cursor
	}

	transactionCtx, cancel := w.familyContext(ctx)
	cursor, done, _, err := w.rewrapTransactions(transactionCtx, w.now().UTC(), w.transactionCursor)
	cancel()
	if err != nil {
		errs = append(errs, fmt.Errorf("rewrap upstream transactions: %w", err))
	} else if done {
		w.transactionCursor = ""
	} else {
		w.transactionCursor = cursor
	}

	passkeyRewrap := w.rewrapPasskey
	if passkeyRewrap == nil {
		passkeyRewrap = noopPasskeyRewrap
	}
	passkeyCtx, cancel := w.familyContext(ctx)
	result, err := passkeyRewrap(passkeyCtx, w.passkeyCursor)
	cancel()
	if err != nil {
		errs = append(errs, fmt.Errorf("rewrap passkeys: %w", err))
	} else if result.Done {
		w.passkeyCursor = ""
	} else {
		w.passkeyCursor = result.Cursor
	}
	if w.rewrapKV != nil {
		kvCtx, cancel := w.familyContext(ctx)
		resultKV, err := w.rewrapKV(kvCtx, w.kvCursor)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("rewrap KV: %w", err))
		} else if resultKV.Done {
			w.kvCursor = ""
		} else {
			w.kvCursor = resultKV.Cursor
		}
	}
	managedRewrap := w.rewrapManaged
	if managedRewrap == nil {
		managedRewrap = noopManagedRewrap
	}
	managedCtx, cancel := w.familyContext(ctx)
	managed, err := managedRewrap(managedCtx, w.managedCursor)
	cancel()
	if err != nil {
		errs = append(errs, fmt.Errorf("rewrap managed clients: %w", err))
	} else if managed.Done {
		w.managedCursor = ""
	} else {
		w.managedCursor = managed.Cursor
	}
	loginRevokeRewrap := w.rewrapLoginRevoke
	if loginRevokeRewrap == nil {
		loginRevokeRewrap = noopLoginRevokeRewrap
	}
	loginRevokeCtx, cancel := w.familyContext(ctx)
	loginRevoke, err := loginRevokeRewrap(loginRevokeCtx, w.loginRevokeCursor)
	cancel()
	if err != nil {
		errs = append(errs, fmt.Errorf("rewrap login-revoke codes: %w", err))
	} else if loginRevoke.Done {
		w.loginRevokeCursor = ""
	} else {
		w.loginRevokeCursor = loginRevoke.Cursor
	}
	if w.rewrapGeneratedAPIKeyBootstrap != nil {
		generatedCtx, cancel := w.familyContext(ctx)
		_, err := w.rewrapGeneratedAPIKeyBootstrap(generatedCtx)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("rewrap generated API-key bootstrap: %w", err))
		}
	}
	if w.rewrapSaaS != nil {
		saasCtx, cancel := w.familyContext(ctx)
		result, err := w.rewrapSaaS(saasCtx, w.saasCursor)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("rewrap SaaS credentials: %w", err))
		} else if result.Done {
			w.saasCursor = ""
		} else {
			w.saasCursor = result.Cursor
		}
	}
	if w.rewrapSaaSProvider != nil {
		providerCtx, cancel := w.familyContext(ctx)
		result, err := w.rewrapSaaSProvider(providerCtx, w.saasProviderCursor)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("rewrap SaaS providers: %w", err))
		} else if result.Done {
			w.saasProviderCursor = ""
		} else {
			w.saasProviderCursor = result.Cursor
		}
	}
	if w.rewrapSaaSAuthorization != nil {
		authorizationCtx, cancel := w.familyContext(ctx)
		result, err := w.rewrapSaaSAuthorization(authorizationCtx, w.saasAuthorizationCursor)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("rewrap SaaS authorization proofs: %w", err))
		} else if result.Done {
			w.saasAuthorizationCursor = ""
		} else {
			w.saasAuthorizationCursor = result.Cursor
		}
	}
	if w.rewrapAuthProviderSecret != nil {
		authCtx, cancel := w.familyContext(ctx)
		result, err := w.rewrapAuthProviderSecret(authCtx, w.authProviderSecretCursor)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("rewrap auth-provider secrets: %w", err))
		} else if result.Done {
			w.authProviderSecretCursor = ""
		} else {
			w.authProviderSecretCursor = result.Cursor
		}
	}
	return errors.Join(errs...)
}

func (w *masterKeyRewrapWorker) familyContext(parent context.Context) (context.Context, context.CancelFunc) {
	if w.newFamilyContext != nil {
		return w.newFamilyContext(parent)
	}
	return context.WithTimeout(parent, masterKeyRewrapFamilyTimeout)
}

func (w *masterKeyRewrapWorker) Run(ctx context.Context) error {
	if ctx == nil || w == nil || w.rewrapSigning == nil || w.rewrapIdempotency == nil || w.rewrapTransactions == nil || w.now == nil || masterKeyRewrapInterval <= 0 {
		return errors.New("master-key rewrap worker is not configured")
	}
	ticker := time.NewTicker(masterKeyRewrapInterval)
	defer ticker.Stop()
	return w.run(ctx, ticker.C)
}

func (w *masterKeyRewrapWorker) run(ctx context.Context, ticks <-chan time.Time) error {
	if ctx == nil || ticks == nil || w == nil || w.rewrapSigning == nil || w.rewrapIdempotency == nil || w.rewrapTransactions == nil || w.now == nil {
		return errors.New("master-key rewrap worker is not configured")
	}
	if ctx.Err() != nil {
		return nil
	}
	w.stepOrReport(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticks:
			w.stepOrReport(ctx)
		}
	}
}

func (w *masterKeyRewrapWorker) stepOrReport(ctx context.Context) {
	if err := w.Step(ctx); err != nil && ctx.Err() == nil && w.onError != nil {
		w.onError(err)
	}
}
