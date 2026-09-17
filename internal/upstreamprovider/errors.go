package upstreamprovider

import "errors"

var (
	// ErrInvalidConfig indicates the provider configuration is invalid.
	ErrInvalidConfig = errors.New("upstream provider: invalid configuration")

	// ErrTransactionNotFound indicates the state digest was not found.
	ErrTransactionNotFound = errors.New("upstream provider: transaction not found")

	// ErrTransactionAlreadyConsumed indicates a replay attempt.
	ErrTransactionAlreadyConsumed = errors.New("upstream provider: transaction already consumed")

	// ErrTransactionExpired indicates the transaction has expired.
	ErrTransactionExpired = errors.New("upstream provider: transaction expired")

	// ErrBindingMismatch indicates the browser or provider binding is wrong.
	ErrBindingMismatch = errors.New("upstream provider: binding mismatch")

	// ErrStateMismatch indicates the callback state does not match any
	// stored transaction. Returned for unknown or tampered state.
	ErrStateMismatch = errors.New("upstream provider: state mismatch")

	// ErrNonceMismatch indicates the id_token nonce does not match.
	ErrNonceMismatch = errors.New("upstream provider: nonce mismatch")

	// ErrNoSubject indicates the upstream returned no subject.
	ErrNoSubject = errors.New("upstream provider: no subject")
)
