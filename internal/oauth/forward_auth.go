package oauth

import (
	"io"
	"net/http"
)

// ForwardAuthHandler verifies a browser access token for a reverse proxy and,
// when explicitly enabled, emits a current identity projection.
func (s *Server) ForwardAuthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clearForwardAuthHeaders(r.Header)
		clearForwardAuthHeaders(w.Header())
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" || !emptyForwardAuthBody(r) {
			writeForwardAuthUnauthorized(w)
			if s.metrics != nil {
				s.metrics.TokenReject()
			}
			return
		}
		scheme, token, ok := authorizationToken(r)
		if !ok || !sameAuthorizationScheme(scheme, "Bearer") || s.oidc == nil || s.oidc.ValidateSubject == nil {
			writeForwardAuthUnauthorized(w)
			if s.metrics != nil {
				s.metrics.TokenReject()
			}
			return
		}
		signature := s.accessTokens.AccessTokenSignature(r.Context(), token)
		request, err := s.store.GetAccessTokenSession(r.Context(), signature, nil)
		if err != nil || s.accessTokens.ValidateAccessToken(r.Context(), request, token) != nil || !request.GetGrantedScopes().Has(openidScope) || request.GetSession().GetSubject() == "" || sessionDPoPJKT(request.GetSession()) != "" {
			writeForwardAuthUnauthorized(w)
			if s.metrics != nil {
				s.metrics.TokenReject()
			}
			return
		}
		if _, err := s.store.GetClient(r.Context(), request.GetClient().GetID()); err != nil || s.oidc.ValidateSubject(r.Context(), request.GetSession().GetSubject()) != nil {
			writeForwardAuthUnauthorized(w)
			if s.metrics != nil {
				s.metrics.TokenReject()
			}
			return
		}
		policy, policySet, err := s.clientGroupPolicy(r.Context(), request.GetClient().GetID())
		if err != nil {
			writeForwardAuthUnauthorized(w)
			if s.metrics != nil {
				s.metrics.TokenReject()
			}
			return
		}
		var principal PrincipalClaims
		if policySet || s.oidc.ForwardAuthEnabled {
			principal, err = s.currentPrincipal(r.Context(), request.GetSession().GetSubject())
			if err != nil {
				writeForwardAuthUnauthorized(w)
				if s.metrics != nil {
					s.metrics.TokenReject()
				}
				return
			}
		}
		if policySet && enforceClientGroupPolicy(principal, policy) != nil {
			writeForwardAuthUnauthorized(w)
			if s.metrics != nil {
				s.metrics.TokenReject()
			}
			return
		}
		if s.oidc.ForwardAuthEnabled {
			if s.oidc.ResolvePrincipal == nil || s.oidc.ResolveForwardAuthProfile == nil || s.oidc.ResolveForwardAuthPasskeyEnrollment == nil {
				writeForwardAuthUnauthorized(w)
				if s.metrics != nil {
					s.metrics.TokenReject()
				}
				return
			}
			profile, profileErr := s.oidc.ResolveForwardAuthProfile(r.Context(), request.GetSession().GetSubject())
			passkey, passkeyErr := s.oidc.ResolveForwardAuthPasskeyEnrollment(r.Context(), request.GetSession().GetSubject())
			if err != nil || profileErr != nil || passkeyErr != nil {
				writeForwardAuthUnauthorized(w)
				if s.metrics != nil {
					s.metrics.TokenReject()
				}
				return
			}
			identity := ForwardAuthIdentity{
				Subject: request.GetSession().GetSubject(), Roles: principal.Roles, Groups: principal.Groups,
				Email: profile.Email, EmailVerified: profile.EmailVerified, FamilyName: profile.FamilyName,
				GivenName: profile.GivenName, PreferredUsername: profile.PreferredUsername, MFAEnabled: passkey,
			}
			if err := ApplyForwardAuthHeaders(w.Header(), identity, true); err != nil {
				writeForwardAuthUnauthorized(w)
				if s.metrics != nil {
					s.metrics.TokenReject()
				}
				return
			}
		}
		if s.store.validateTokenAccounts(r.Context(), request) != nil {
			clearForwardAuthHeaders(w.Header())
			writeForwardAuthUnauthorized(w)
			if s.metrics != nil {
				s.metrics.TokenReject()
			}
			return
		}
		if s.metrics != nil {
			s.metrics.TokenOK()
		}
		w.WriteHeader(http.StatusOK)
	})
}

func emptyForwardAuthBody(r *http.Request) bool {
	if r.ContentLength > 0 {
		return false
	}
	if r.Body == nil {
		return true
	}
	var byte [1]byte
	n, err := r.Body.Read(byte[:])
	return n == 0 && err == io.EOF
}

func writeForwardAuthUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.WriteHeader(http.StatusUnauthorized)
}
