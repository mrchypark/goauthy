package credential

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

func TestHashVerifyAndNeedsRehash(t *testing.T) {
	hash, err := Hash([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash=%q", hash)
	}
	if valid, rehash, err := Verify([]byte("correct horse battery staple"), hash); err != nil || !valid || rehash {
		t.Fatalf("valid=%t rehash=%t err=%v", valid, rehash, err)
	}
	if valid, _, err := Verify([]byte("wrong"), hash); err != nil || valid {
		t.Fatalf("valid=%t err=%v", valid, err)
	}
	legacyParams := parameters{memory: 8192, time: 1, parallelism: 1, saltLength: 16, keyLength: 32}
	salt := []byte("1234567890abcdef")
	legacy := encode(legacyParams, salt, argon2.IDKey([]byte("correct horse battery staple"), salt, legacyParams.time, legacyParams.memory, legacyParams.parallelism, legacyParams.keyLength))
	if valid, rehash, err := Verify([]byte("correct horse battery staple"), legacy); err != nil || !valid || !rehash {
		t.Fatalf("legacy valid=%t rehash=%t err=%v", valid, rehash, err)
	}
	if err := ValidateCurrentPHC(hash); err != nil {
		t.Fatalf("current hash: %v", err)
	}
	if err := ValidateCurrentPHC(legacy); err == nil {
		t.Fatal("accepted legacy hash as current")
	}
}

func TestRejectsUnsafeInputsAndDummyPath(t *testing.T) {
	for _, value := range []string{"", "$argon2id$v=19$m=999999,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA", "$argon2id$v=19$m=8192,m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA", "$argon2i$v=19$m=8192,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA"} {
		if _, _, err := Verify([]byte("password"), value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	if _, err := Hash(make([]byte, maxPasswordBytes+1)); err == nil {
		t.Fatal("accepted oversized password")
	}
	if valid, rehash := VerifyOrDummy([]byte("password"), ""); valid || rehash {
		t.Fatal("dummy accepted password")
	}
	if err := ValidatePHC("$argon2id$v=19$m=19456,m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA"); err == nil {
		t.Fatal("accepted duplicate PHC parameter")
	}
}

func TestAcceptsRauthyDefaultParallelism(t *testing.T) {
	if err := ValidatePHC("$argon2id$v=19$m=8192,t=1,p=8$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA"); err != nil {
		t.Fatalf("p=8 PHC: %v", err)
	}
}

func TestArgonConcurrencyLimit(t *testing.T) {
	// Default policy now has MaxConcurrency=4, so acquire all 4 slots.
	releaseFirst := acquireArgon()
	releaseSecond := acquireArgon()
	releaseThird := acquireArgon()
	releaseFourth := acquireArgon()

	started := make(chan struct{})
	acquired := make(chan struct{})
	go func() {
		close(started)
		release := acquireArgon()
		close(acquired)
		release()
	}()
	<-started
	select {
	case <-acquired:
		t.Fatal("fifth Argon lease acquired while four slots were held")
	default:
	}

	releaseFirst()
	<-acquired
	releaseSecond()
	releaseThird()
	releaseFourth()
}

func TestContextWorkLimitFailsFast(t *testing.T) {
	// Default policy now has MaxConcurrency=4, so acquire all 4 slots.
	releaseFirst := acquireArgon()
	releaseSecond := acquireArgon()
	releaseThird := acquireArgon()
	releaseFourth := acquireArgon()
	defer releaseFirst()
	defer releaseSecond()
	defer releaseThird()
	defer releaseFourth()
	if _, _, err := VerifyOrDummyContext(context.Background(), []byte("password"), ""); !errors.Is(err, ErrWorkLimit) {
		t.Fatalf("work limit err=%v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := VerifyOrDummyContext(canceled, []byte("password"), ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled work err=%v", err)
	}
}

func TestPolicyValidationAndSnapshot(t *testing.T) {
	if got := DefaultPolicy(); got != (Policy{MemoryKiB: 19456, Iterations: 2, Parallelism: 1, MaxConcurrency: 4, WaitTimeout: 100 * time.Millisecond}) {
		t.Fatalf("default policy=%+v", got)
	}
	for _, policy := range []Policy{
		{MemoryKiB: 19455, Iterations: 2, Parallelism: 1, MaxConcurrency: 1},
		{MemoryKiB: 19456, Iterations: 1, Parallelism: 1, MaxConcurrency: 1},
		{MemoryKiB: 19456, Iterations: 2, Parallelism: 0, MaxConcurrency: 1},
		{MemoryKiB: 19456, Iterations: 2, Parallelism: 1, MaxConcurrency: 0},
		{MemoryKiB: 131073, Iterations: 2, Parallelism: 1, MaxConcurrency: 1},
		{MemoryKiB: 19456, Iterations: 6, Parallelism: 1, MaxConcurrency: 1},
		{MemoryKiB: 19456, Iterations: 2, Parallelism: 9, MaxConcurrency: 1},
		{MemoryKiB: 19456, Iterations: 2, Parallelism: 1, MaxConcurrency: 9},
	} {
		if _, err := NewHasher(policy); !errors.Is(err, ErrInvalidCredential) {
			t.Errorf("NewHasher(%+v) err=%v", policy, err)
		}
	}
	policy := DefaultPolicy()
	h, err := NewHasher(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.MemoryKiB = 131072
	policy.Iterations = 5
	policy.Parallelism = 8
	if got := h.parameters(); got.memory != 19456 || got.time != 2 || got.parallelism != 1 {
		t.Fatalf("hasher policy was mutated: %+v", got)
	}
}

func TestHasherSlotsAreIndependentAndContextAware(t *testing.T) {
	first, err := NewHasher(Policy{MemoryKiB: 19456, Iterations: 2, Parallelism: 1, MaxConcurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewHasher(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	release, err := first.tryAcquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := first.Hash(context.Background(), []byte("password")); !errors.Is(err, ErrWorkLimit) {
		t.Fatalf("occupied Hash error=%v", err)
	}
	if _, _, err := first.VerifyOrDummy(context.Background(), []byte("password"), ""); !errors.Is(err, ErrWorkLimit) {
		t.Fatalf("occupied VerifyOrDummy error=%v", err)
	}
	if releaseSecond, err := second.tryAcquire(context.Background()); err != nil {
		t.Fatalf("independent hasher acquire: %v", err)
	} else {
		releaseSecond()
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := second.Hash(canceled, []byte("password")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Hash error=%v", err)
	}
}

func TestStrictCanonicalPHCAndUpgradeEligibility(t *testing.T) {
	valid := "$argon2id$v=19$m=19456,t=2,p=1$MTIzNDU2Nzg5MGFiY2RlZg$MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY"
	for _, phc := range []string{
		strings.Replace(valid, "m=19456", "m=019456", 1),
		strings.Replace(valid, "m=19456,t=2,p=1", "t=2,m=19456,p=1", 1),
		valid + "=",
	} {
		if err := ValidatePHC(phc); err == nil {
			t.Errorf("accepted non-canonical PHC %q", phc)
		}
	}
	current := parameters{memory: 19456, time: 2, parallelism: 1, keyLength: 32}
	for _, tc := range []struct {
		name   string
		stored parameters
		keyLen int
		want   bool
	}{
		{"legacy weaker", parameters{memory: 8192, time: 1, parallelism: 1}, 32, true},
		{"same", current, 32, false},
		{"salt length irrelevant", current, 32, false},
		{"stored stronger memory", parameters{memory: 32768, time: 2, parallelism: 1}, 32, false},
		{"stored stronger lane", parameters{memory: 19456, time: 2, parallelism: 8}, 32, false},
		{"stored longer tag", current, 64, false},
		{"shorter tag", current, 16, true},
	} {
		if got := eligibleForUpgrade(current, tc.stored, tc.keyLen); got != tc.want {
			t.Errorf("%s: upgrade=%t want %t", tc.name, got, tc.want)
		}
	}
}

func FuzzVerify(f *testing.F) {
	f.Add([]byte("password"), "$argon2id$v=19$m=8192,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA")
	f.Fuzz(func(t *testing.T, password []byte, encoded string) { _, _, _ = Verify(password, encoded) })
}
