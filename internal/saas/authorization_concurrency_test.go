package saas

import (
	"errors"
	"testing"
)

func TestAuthorizationConcurrentConsumersHaveOneWinner(t *testing.T) {
	ctx, store, _, binding := credentialStoreFixture(t)
	request := authorizationTestRequest(store, binding)
	if err := store.CreateAuthorization(ctx, request, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 8)
	for range 8 {
		go func() {
			<-start
			got, err := store.ConsumeAuthorization(ctx, request.StateDigest, request.VerifierDigest, request.SessionDigest, request.ProviderDigest, credentialAuthority())
			if err == nil && got != binding {
				err = errors.New("wrong consumed binding")
			}
			results <- err
		}()
	}
	close(start)
	winners := 0
	for range 8 {
		err := <-results
		if err == nil {
			winners++
			continue
		}
		if !errors.Is(err, ErrAuthorizationConflict) && !errors.Is(err, ErrAuthorizationNotFound) {
			t.Errorf("unexpected consumer error: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("successful consumers=%d want 1", winners)
	}
}
