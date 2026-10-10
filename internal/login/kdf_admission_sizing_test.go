package login

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
)

const (
	kdfSizingSamples     = 64
	kdfSizingConcurrency = 16
	kdfSizingSeedDefault = int64(20261010)
)

func TestKDFAdmissionSizing(t *testing.T) {
	slotsText, slotsSet := os.LookupEnv("KDF_SIZE_SLOTS")
	waitText, waitSet := os.LookupEnv("KDF_SIZE_WAIT_MS")
	if !slotsSet && !waitSet {
		t.Skip("set KDF_SIZE_SLOTS and KDF_SIZE_WAIT_MS to run the opt-in sizing cohort")
	}
	if !slotsSet || !waitSet {
		t.Fatal("KDF_SIZE_SLOTS and KDF_SIZE_WAIT_MS must be set together")
	}
	slots, err := strconv.Atoi(slotsText)
	if err != nil || (slots != 4 && slots != 8) {
		t.Fatalf("KDF_SIZE_SLOTS must be 4 or 8")
	}
	waitMS, err := strconv.Atoi(waitText)
	if err != nil || (waitMS != 100 && waitMS != 250 && waitMS != 500) {
		t.Fatalf("KDF_SIZE_WAIT_MS must be 100, 250, or 500")
	}
	seed := kdfSizingSeedDefault
	if value := os.Getenv("KDF_SIZE_SEED"); value != "" {
		seed, err = strconv.ParseInt(value, 10, 64)
		if err != nil {
			t.Fatalf("KDF_SIZE_SEED must be an integer")
		}
	}

	policy := credential.DefaultPolicy()
	policy.MaxConcurrency = slots
	policy.WaitTimeout = time.Duration(waitMS) * time.Millisecond
	hasher, err := credential.NewHasher(policy)
	if err != nil {
		t.Fatal(err)
	}
	h, db := testHandlerWithDB(t, false)
	store, err := identity.NewStoreWithHasher(db, hasher)
	if err != nil {
		t.Fatal(err)
	}
	h.identity = store
	h.wait = waitContext
	phc, err := hasher.Hash(context.Background(), []byte(e2eLoginPassword))
	if err != nil {
		t.Fatal(err)
	}

	label := fmt.Sprintf("slots%d-wait%d-seed%d", slots, waitMS, seed)
	cases := make([]e2eLoginCase, kdfSizingSamples)
	for i := range cases {
		subject := fmt.Sprintf("%s-%s-%02d", e2eLoginSubjectLabel, label, i)
		username := fmt.Sprintf("%s-%s-%02d", e2eLoginUserLabel, label, i)
		if _, err := store.BootstrapUser(context.Background(), subject, username, phc); err != nil {
			t.Fatalf("seed synthetic account %d: %v", i, err)
		}
		state := fmt.Sprintf("%032x", i+1)
		cases[i] = e2eLoginCase{
			username:     username,
			subject:      subject,
			state:        state,
			peerIP:       fmt.Sprintf("%s%d", e2eLoginPeerPrefix, i+1),
			expectReject: i >= 56,
		}
	}

	warmup := e2eLoginCase{
		username: "e2e-cost-user-kdf-sizing-warmup",
		subject:  "e2e-cost-subject-kdf-sizing-warmup",
		state:    fmt.Sprintf("%032x", kdfSizingSamples+1),
		peerIP:   fmt.Sprintf("%s254", e2eLoginPeerPrefix),
	}
	if _, err := store.BootstrapUser(context.Background(), warmup.subject, warmup.username, phc); err != nil {
		t.Fatalf("seed warmup account: %v", err)
	}
	warmObservation := runMeasuredE2ELogin(h, warmup)
	warmObservations := []e2eLoginObservation{warmObservation}
	verifyE2ELoginSessions(h, []e2eLoginCase{warmup}, warmObservations)
	warmObservation = warmObservations[0]
	if warmObservation.outcome != e2eLoginSuccess {
		t.Fatalf("synthetic warmup login outcome=%q", warmObservation.outcome)
	}

	rand.New(rand.NewSource(seed)).Shuffle(len(cases), func(i, j int) {
		cases[i], cases[j] = cases[j], cases[i]
	})
	t.Logf("kdf_admission_candidate memory_kib=%d iterations=%d parallelism=%d slots=%d wait_ms=%d memory_budget_kib=%d theoretical_active_kdf_mib=%d seed=%d samples=%d correct=56 wrong=8 concurrency=%d",
		policy.MemoryKiB, policy.Iterations, policy.Parallelism, policy.MaxConcurrency, waitMS,
		policy.MemoryBudgetKiB, slots*int(policy.MemoryKiB)/1024, seed, len(cases), kdfSizingConcurrency)

	observations := make([]e2eLoginObservation, len(cases))
	start := make(chan struct{})
	jobs := make(chan int)
	ready := make(chan struct{}, kdfSizingConcurrency)
	var workers sync.WaitGroup
	workers.Add(kdfSizingConcurrency)
	for worker := 0; worker < kdfSizingConcurrency; worker++ {
		go func() {
			defer workers.Done()
			ready <- struct{}{}
			<-start
			for i := range jobs {
				observations[i] = runMeasuredE2ELogin(h, cases[i])
			}
		}()
	}
	for worker := 0; worker < kdfSizingConcurrency; worker++ {
		<-ready
	}
	cohortStart := time.Now()
	close(start)
	for i := range cases {
		jobs <- i
	}
	close(jobs)
	workers.Wait()
	verifyE2ELoginSessions(h, cases, observations)
	summary := summarizeE2ELogin(observations, cohortStart)
	reportE2ELogin(t, kdfSizingConcurrency, observations, summary.responseSpan)
	if violations := e2eLoginContractViolations(observations); len(violations) > 0 {
		t.Errorf("login E2E authentication contract violations: %v", violations)
	}
}
