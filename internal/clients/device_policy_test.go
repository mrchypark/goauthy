package clients

import (
	"errors"
	"testing"
)

func TestDevicePolicyRedirectCompatibility(t *testing.T) {
	for _, tt := range []struct {
		name             string
		flows, redirects []string
		valid            bool
	}{
		{"device without callback", []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"}, nil, true},
		{"existing service callback retained", []string{"client_credentials"}, []string{"https://rp.example/callback"}, true},
		{"code still requires callback", []string{"authorization_code"}, nil, false},
		{"unused callback still validated", []string{"client_credentials"}, []string{"javascript:alert(1)"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePolicy(true, tt.redirects, tt.flows, []string{"goauthy.read"}, []string{"goauthy.read"})
			if (err == nil) != tt.valid {
				t.Fatalf("policy error=%v, valid=%v", err, tt.valid)
			}
		})
	}
}

func TestReadSecretRevisionRejectsInterposedRotation(t *testing.T) {
	s, ctx := testStore(t)
	client, err := s.CreateWithGuard(ctx, newClient(true), auth())
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.RotateSecretWithGuard(ctx, client.ID, client.Revision, auth())
	if err != nil {
		t.Fatal(err)
	}
	firstSecret, err := s.ReadSecretWithRevisionWithGuard(ctx, client.ID, first.Revision, auth())
	if err != nil || firstSecret == "" {
		t.Fatalf("first revision read error=%v", err)
	}
	second, err := s.RotateSecretWithGuard(ctx, client.ID, first.Revision, auth())
	if err != nil {
		t.Fatal(err)
	}
	if secret, err := s.ReadSecretWithRevisionWithGuard(ctx, client.ID, first.Revision, auth()); !errors.Is(err, ErrConflict) || secret != "" {
		t.Fatalf("stale revision secret leaked=%v error=%v", secret != "", err)
	}
	secondSecret, err := s.ReadSecretWithRevisionWithGuard(ctx, client.ID, second.Revision, auth())
	if err != nil || secondSecret == "" || secondSecret == firstSecret {
		t.Fatalf("second revision read error=%v", err)
	}
	if secret, err := s.ReadSecretWithRevisionWithGuard(ctx, client.ID, second.Revision, denied()); !errors.Is(err, ErrUnauthorized) || secret != "" {
		t.Fatalf("revoked authority secret leaked=%v error=%v", secret != "", err)
	}
}
