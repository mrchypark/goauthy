// Package credential stores and verifies Argon2id password credentials.
package credential

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	maxPasswordBytes = 1024
	maxPHCBytes      = 512
	saltLength       = 16
	keyLength        = 32
)

var (
	ErrInvalidCredential = errors.New("invalid password credential")
	ErrWorkLimit         = errors.New("password work limit reached")
)

// Policy configures newly written password credentials and per-instance work limits.
type Policy struct {
	MemoryKiB      uint32
	Iterations     uint32
	Parallelism    uint8
	MaxConcurrency int
	// WaitTimeout is the maximum duration to wait for a hashing slot.
	// Zero means non-blocking (fail immediately). Negative means wait forever.
	WaitTimeout time.Duration
}

// DefaultPolicy follows OWASP's Argon2id baseline: 19 MiB, two iterations, one lane.
// MaxConcurrency is set to 4 to handle burst traffic while limiting memory usage.
func DefaultPolicy() Policy {
	return Policy{MemoryKiB: 19 * 1024, Iterations: 2, Parallelism: 1, MaxConcurrency: 4, WaitTimeout: 100 * time.Millisecond}
}

// Hasher hashes and verifies credentials using an immutable Policy.
type Hasher struct {
	policy Policy
	slots  chan struct{}
}

// NewHasher validates and snapshots policy. Its work limit is independent of other hashers.
func NewHasher(policy Policy) (*Hasher, error) {
	if !validWritePolicy(policy) {
		return nil, ErrInvalidCredential
	}
	return &Hasher{policy: policy, slots: make(chan struct{}, policy.MaxConcurrency)}, nil
}

var defaultHasher = mustNewHasher(DefaultPolicy())

func mustNewHasher(policy Policy) *Hasher {
	h, err := NewHasher(policy)
	if err != nil {
		panic(err)
	}
	return h
}

type parameters struct {
	memory      uint32
	time        uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func (h *Hasher) parameters() parameters {
	return parameters{memory: h.policy.MemoryKiB, time: h.policy.Iterations, parallelism: h.policy.Parallelism, saltLength: saltLength, keyLength: keyLength}
}

// Hash returns a PHC Argon2id v=19 credential.
func (h *Hasher) Hash(ctx context.Context, password []byte) (string, error) {
	if !validPassword(password) {
		return "", ErrInvalidCredential
	}
	release, err := h.tryAcquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	p := h.parameters()
	key := argon2.IDKey(password, salt, p.time, p.memory, p.parallelism, p.keyLength)
	return encode(p, salt, key), nil
}

// VerifyOrDummy verifies a credential, or performs configured dummy work for
// missing and malformed credentials. It never exposes credential parsing errors.
func (h *Hasher) VerifyOrDummy(ctx context.Context, password []byte, encoded string) (valid, upgradeEligible bool, err error) {
	release, err := h.tryAcquire(ctx)
	if err != nil {
		return false, false, err
	}
	defer release()
	if encoded == "" || !validPassword(password) {
		h.dummyWork(password)
		return false, false, nil
	}
	p, salt, expected, err := parse(encoded)
	if err != nil {
		h.dummyWork(password)
		return false, false, nil
	}
	actual := argon2.IDKey(password, salt, p.time, p.memory, p.parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, eligibleForUpgrade(h.parameters(), p, len(expected)), nil
}

// ValidateCurrentPHC accepts only a syntactically valid credential written by h.
func (h *Hasher) ValidateCurrentPHC(encoded string) error {
	p, salt, key, err := parse(encoded)
	if err != nil {
		return err
	}
	current := h.parameters()
	if p.memory != current.memory || p.time != current.time || p.parallelism != current.parallelism || len(salt) != saltLength || len(key) != keyLength {
		return ErrInvalidCredential
	}
	return nil
}

func (h *Hasher) dummyWork(password []byte) {
	if len(password) > maxPasswordBytes {
		password = password[:maxPasswordBytes]
	}
	p := h.parameters()
	key := argon2.IDKey(password, []byte("goauthy-dummy-v1"), p.time, p.memory, p.parallelism, p.keyLength)
	_ = subtle.ConstantTimeCompare(key, make([]byte, len(key)))
}

func (h *Hasher) tryAcquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Non-blocking fast path.
	select {
	case h.slots <- struct{}{}:
		return func() { <-h.slots }, nil
	default:
	}
	// If no wait timeout configured, fail immediately.
	if h.policy.WaitTimeout == 0 {
		return nil, ErrWorkLimit
	}
	// Wait with timeout for a slot to become available.
	var timer *time.Timer
	var timeout <-chan time.Time
	if h.policy.WaitTimeout > 0 {
		timer = time.NewTimer(h.policy.WaitTimeout)
		timeout = timer.C
		defer timer.Stop()
	}
	select {
	case h.slots <- struct{}{}:
		return func() { <-h.slots }, nil
	case <-timeout:
		return nil, ErrWorkLimit
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Hash uses DefaultPolicy for backwards compatibility.
func Hash(password []byte) (string, error) { return defaultHasher.Hash(context.Background(), password) }

// Verify checks an encoded PHC credential and reports whether it may be upgraded.
func Verify(password []byte, encoded string) (valid, upgradeEligible bool, err error) {
	if !validPassword(password) {
		return false, false, ErrInvalidCredential
	}
	p, salt, expected, err := parse(encoded)
	if err != nil {
		return false, false, err
	}
	release, err := defaultHasher.tryAcquire(context.Background())
	if err != nil {
		return false, false, err
	}
	defer release()
	actual := argon2.IDKey(password, salt, p.time, p.memory, p.parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, eligibleForUpgrade(defaultHasher.parameters(), p, len(expected)), nil
}

// ValidateCurrentPHC validates a credential written using DefaultPolicy.
func ValidateCurrentPHC(encoded string) error { return defaultHasher.ValidateCurrentPHC(encoded) }

// ValidatePHC validates a stored credential without performing password work.
func ValidatePHC(encoded string) error {
	_, _, _, err := parse(encoded)
	return err
}

// VerifyOrDummy has comparable default-policy Argon2 work for unknown users.
func VerifyOrDummy(password []byte, encoded string) (valid, upgradeEligible bool) {
	valid, upgradeEligible, _ = defaultHasher.VerifyOrDummy(context.Background(), password, encoded)
	return valid, upgradeEligible
}

// VerifyOrDummyContext uses DefaultPolicy and fails fast when its workers are occupied.
func VerifyOrDummyContext(ctx context.Context, password []byte, encoded string) (valid, upgradeEligible bool, err error) {
	return defaultHasher.VerifyOrDummy(ctx, password, encoded)
}

// Legacy test helpers retain the package's original default-policy slot behavior.
func acquireArgon() func() {
	defaultHasher.slots <- struct{}{}
	return func() { <-defaultHasher.slots }
}

func tryAcquireArgon(ctx context.Context) (func(), error) { return defaultHasher.tryAcquire(ctx) }

func eligibleForUpgrade(target, stored parameters, storedKeyLength int) bool {
	if target.memory < stored.memory || target.time < stored.time || target.parallelism < stored.parallelism || int(target.keyLength) < storedKeyLength {
		return false
	}
	return target.memory > stored.memory || target.time > stored.time || target.parallelism > stored.parallelism || int(target.keyLength) > storedKeyLength
}

func encode(p parameters, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", p.memory, p.time, p.parallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

func parse(encoded string) (parameters, []byte, []byte, error) {
	if len(encoded) == 0 || len(encoded) > maxPHCBytes {
		return parameters{}, nil, nil, ErrInvalidCredential
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return parameters{}, nil, nil, ErrInvalidCredential
	}
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return parameters{}, nil, nil, ErrInvalidCredential
	}
	p := parameters{}
	for i, name := range []string{"m", "t", "p"} {
		key, value, ok := strings.Cut(fields[i], "=")
		if !ok || key != name {
			return parameters{}, nil, nil, ErrInvalidCredential
		}
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != value {
			return parameters{}, nil, nil, ErrInvalidCredential
		}
		switch i {
		case 0:
			p.memory = uint32(n)
		case 1:
			p.time = uint32(n)
		case 2:
			if n > 255 {
				return parameters{}, nil, nil, ErrInvalidCredential
			}
			p.parallelism = uint8(n)
		}
	}
	if !validParameters(p) {
		return parameters{}, nil, nil, ErrInvalidCredential
	}
	salt, err := decodeCanonicalBase64(parts[4])
	if err != nil || len(salt) < saltLength || len(salt) > 64 {
		return parameters{}, nil, nil, ErrInvalidCredential
	}
	key, err := decodeCanonicalBase64(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return parameters{}, nil, nil, ErrInvalidCredential
	}
	return p, salt, key, nil
}

func decodeCanonicalBase64(value string) ([]byte, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || base64.RawStdEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidCredential
	}
	return decoded, nil
}

func validPassword(password []byte) bool {
	return len(password) > 0 && len(password) <= maxPasswordBytes
}

func validWritePolicy(p Policy) bool {
	return p.MemoryKiB >= 19*1024 && p.MemoryKiB <= 128*1024 && p.Iterations >= 2 && p.Iterations <= 5 && p.Parallelism >= 1 && p.Parallelism <= 8 && p.MaxConcurrency >= 1 && p.MaxConcurrency <= 8
}

func validParameters(p parameters) bool {
	return p.memory >= 8*1024 && p.memory <= 128*1024 && p.time >= 1 && p.time <= 5 && p.parallelism >= 1 && p.parallelism <= 8
}
