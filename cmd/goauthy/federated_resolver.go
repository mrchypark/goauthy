package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
)

type FederatedIdentityResolver struct {
	IdentityStore *identity.Store
}

func (r *FederatedIdentityResolver) resolveVerified(ctx context.Context, vi upstreamprovider.VerifiedIdentity) (string, error) {
	if r == nil || r.IdentityStore == nil {
		return "", errors.New("upstream identity unavailable")
	}

	// 1. Evaluate admin mapping from signed claims BEFORE any writes.
	// AdminClaimPath configured + absent raw claims => fail closed.
	// AdminClaimPath configured + valid raw + malformed path => nil (no change).
	// AdminClaimPath nil => adminMapping stays nil.
	var adminMapping *bool
	if vi.Config.AdminClaimPath != nil {
		if vi.IDTokenClaims == nil || len(vi.IDTokenClaims.RawClaims()) == 0 {
			return "", errors.New("admin mapping configured but claims unavailable")
		}
		if vi.IDTokenClaims.Email == nil || *vi.IDTokenClaims.Email == "" {
			return "", errors.New("admin mapping configured but claims unavailable")
		}
		var evalErr error
		adminMapping, evalErr = upstreamprovider.EvaluateClaimMapping(vi.IDTokenClaims.RawClaims(), vi.Config.AdminClaimPath, vi.Config.AdminClaimValue)
		if evalErr != nil {
			slog.Warn("admin claim mapping failed")
			return "", errors.New("admin claim mapping failed")
		}
	}

	// Profile-update closure: deduplicates the updateProfile call for
	// existing links and successful auto-links.
	updateProfile := func(adminMapping *bool) error {
		emailVerified := vi.IDTokenClaims.EmailVerified != nil && *vi.IDTokenClaims.EmailVerified
		_, err := r.IdentityStore.UpdateFederatedProfile(ctx, identity.FederatedProfileUpdateInput{
			Subject:       vi.Subject,
			Config:        identity.FederatedConfigSnapshot{Source: vi.Config.ProviderSource, Version: vi.Config.RuntimeVersion, Issuer: vi.Config.Issuer, ClientID: vi.Config.ClientID, Kind: string(vi.Config.NormalizedKind()), AutoOnboarding: vi.Config.AutoOnboarding},
			Email:         *vi.IDTokenClaims.Email,
			EmailVerified: emailVerified,
			GivenName:     derefStr(vi.IDTokenClaims.GivenName),
			FamilyName:    derefStr(vi.IDTokenClaims.FamilyName),
			AdminMapping:  adminMapping,
		})
		return err
	}

	// 2. Check for existing active link.
	subject, err := r.IdentityStore.FindExternalLinkActive(ctx, vi.Subject)
	if err != nil {
		return "", err
	}
	if subject != "" {
		// Registry provider with signed claims: sync profile and admin mapping.
		if vi.Config.ProviderSource == "registry" && vi.IDTokenClaims != nil && vi.IDTokenClaims.Email != nil {
			if err := updateProfile(adminMapping); err != nil {
				return "", err
			}
		}
		return subject, nil
	}

	// 3. Auto-link: try binding to an existing local account by verified email.
	// Only ErrAutoLinkNoAccount permits fallthrough to onboarding.
	if vi.Config.AutoLink && vi.IDTokenClaims != nil && vi.IDTokenClaims.Email != nil && vi.IDTokenClaims.EmailVerified != nil && *vi.IDTokenClaims.EmailVerified {
		autoResult, autoErr := r.IdentityStore.AutoLinkExternal(ctx, identity.AutoLinkInput{
			Subject:       vi.Subject,
			Config:        identity.AutoLinkConfigSnapshot{Source: vi.Config.ProviderSource, Version: vi.Config.RuntimeVersion, Issuer: vi.Config.Issuer, ClientID: vi.Config.ClientID, Kind: string(vi.Config.NormalizedKind()), AutoLink: vi.Config.AutoLink},
			Email:         *vi.IDTokenClaims.Email,
			EmailVerified: *vi.IDTokenClaims.EmailVerified,
		})
		if autoErr != nil && !errors.Is(autoErr, identity.ErrAutoLinkNoAccount) {
			return "", autoErr
		}
		if autoErr == nil && autoResult.Subject != "" {
			// Successful auto-link: sync profile for registry providers.
			if vi.Config.ProviderSource == "registry" {
				if err := updateProfile(adminMapping); err != nil {
					return "", err
				}
			}
			return autoResult.Subject, nil
		}
	}

	// 4. Onboarding: create a new federated identity.
	if vi.Config.AutoOnboarding && vi.IDTokenClaims != nil && vi.IDTokenClaims.Email != nil && *vi.IDTokenClaims.Email != "" {
		emailVerified := vi.IDTokenClaims.EmailVerified != nil && *vi.IDTokenClaims.EmailVerified
		result, createErr := r.IdentityStore.CreateFederatedIdentity(ctx, identity.FederatedCreationInput{
			Subject:       vi.Subject,
			Config:        identity.FederatedConfigSnapshot{Source: vi.Config.ProviderSource, Version: vi.Config.RuntimeVersion, Issuer: vi.Config.Issuer, ClientID: vi.Config.ClientID, Kind: string(vi.Config.NormalizedKind()), AutoOnboarding: vi.Config.AutoOnboarding},
			Email:         *vi.IDTokenClaims.Email,
			EmailVerified: emailVerified,
			GivenName:     derefStr(vi.IDTokenClaims.GivenName),
			FamilyName:    derefStr(vi.IDTokenClaims.FamilyName),
			AdminMapping:  adminMapping,
		})
		if createErr != nil {
			return "", createErr
		}
		if result.Subject != "" {
			return result.Subject, nil
		}
	}

	return "", errors.New("upstream identity unavailable")
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func staticResolveVerified(r *FederatedIdentityResolver) func(ctx context.Context, vi upstreamprovider.VerifiedIdentity) (string, error) {
	return r.resolveVerified
}
