package oauth

import (
	"context"
	"mime"
	"net/http"

	"github.com/ory/fosite"
)

const oauthFormLimit = 16 << 10

func formRequest(w http.ResponseWriter, r *http.Request) error {
	if len(r.Header.Values("Authorization")) > 1 {
		return fosite.ErrInvalidRequest.WithHint("Authorization must not be repeated.")
	}
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return fosite.ErrInvalidRequest.WithHint("Content-Type must be application/x-www-form-urlencoded.")
	}
	if mediaType, _, err := mime.ParseMediaType(contentTypes[0]); err != nil || mediaType != "application/x-www-form-urlencoded" {
		return fosite.ErrInvalidRequest.WithHint("Content-Type must be application/x-www-form-urlencoded.")
	}
	r.Body = http.MaxBytesReader(w, r.Body, oauthFormLimit)
	return nil
}

// IntrospectionHandler serves RFC 7662 to authenticated registered clients.
// Caller authentication does not currently impose an audience-specific ACL.
func (s *Server) IntrospectionHandler() http.Handler {
	return s.introspectionHandler(true)
}

// The false path keeps the pre-cache behavior available to the package benchmark.
func (s *Server) introspectionHandler(reuseVerification bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := formRequest(w, r); err != nil {
			s.provider.WriteIntrospectionError(r.Context(), w, err)
			return
		}
		if _, _, ok := r.BasicAuth(); !ok {
			s.provider.WriteIntrospectionError(r.Context(), w, fosite.ErrRequestUnauthorized.WithHint("HTTP Basic authentication is required."))
			return
		}
		if reuseVerification {
			r = r.WithContext(withAccessTokenVerificationCache(r.Context()))
		}
		response, err := s.provider.NewIntrospectionRequest(r.Context(), r, &fosite.DefaultSession{})
		if err != nil {
			if oauthBackendUnavailable(err) {
				writeOAuthServiceUnavailable(w)
				return
			}
			s.provider.WriteIntrospectionError(r.Context(), w, err)
			return
		}
		principalValid, err := s.refreshIntrospectionPrincipal(r.Context(), response)
		if oauthBackendUnavailable(err) {
			writeOAuthServiceUnavailable(w)
			return
		}
		accountErr := error(nil)
		if response.IsActive() && principalValid {
			accountErr = s.store.validateTokenAccounts(r.Context(), response.GetAccessRequester())
		}
		if oauthBackendUnavailable(accountErr) {
			writeOAuthServiceUnavailable(w)
			return
		}
		if !principalValid || accountErr != nil {
			// RFC 7662 requires a valid caller to receive an inactive response
			// when the subject is no longer eligible. Do not expose persisted
			// session Extra claims in that case.
			response = &fosite.IntrospectionResponse{}
		}
		if request := response.GetAccessRequester(); request != nil {
			if session, ok := request.GetSession().(*fosite.DefaultSession); ok {
				audiences, audienceErr := accessResourceAudiences(request)
				subject, _, err := machineTokenSubject(request)
				if err != nil || audienceErr != nil {
					response = &fosite.IntrospectionResponse{}
				} else {
					session.Subject = subject
					for _, audience := range audiences {
						request.GrantAudience(audience)
					}
				}
				delete(session.Extra, accessDefaultAudiencesExtra)
				delete(session.Extra, machineSubjectExtra)
				delete(session.Extra, actorMachineExtra)
				delete(session.Extra, "goauthy_custom_root")
				delete(session.Extra, clientCredentialsClaimsExtra)
				delete(session.Extra, clientCredentialsClaimsAtRootExtra)
				delete(session.Extra, deviceOIDCExtra)
				delete(session.Extra, passwordAuthTimeExtra)
			}
		}
		s.provider.WriteIntrospectionResponse(r.Context(), w, response)
	})
}

// refreshIntrospectionPrincipal makes persisted OAuth claims non-authoritative
// for end-user access tokens. Other grants deliberately retain their existing
// introspection behavior and never receive these claims here.
func (s *Server) refreshIntrospectionPrincipal(ctx context.Context, response fosite.IntrospectionResponder) (bool, error) {
	if !response.IsActive() || s.oidc == nil {
		return true, nil
	}
	request := response.GetAccessRequester()
	if request == nil {
		return true, nil
	}
	session, ok := request.GetSession().(*fosite.DefaultSession)
	// Stored Fosite requests do not retain token-endpoint grant types. An
	// authorization-code session does retain its authorization-code expiry;
	// device, client-credentials, and token-exchange sessions do not.
	if !ok {
		return true, nil
	}
	deviceOrigin, _ := session.Extra[deviceOIDCExtra].(bool)
	_, passwordOrigin := session.Extra[passwordAuthTimeExtra]
	if session.GetExpiresAt(fosite.AuthorizeCode).IsZero() && !deviceOrigin && !passwordOrigin {
		return true, nil
	}
	if session.Subject == "" {
		return false, nil
	}
	if s.oidc.ValidateSubject != nil {
		if err := s.oidc.ValidateSubject(ctx, session.Subject); err != nil {
			if oauthBackendUnavailable(err) {
				return false, err
			}
			return false, nil
		}
	}
	claims, err := s.currentPrincipal(ctx, session.Subject)
	if err != nil {
		if oauthBackendUnavailable(err) {
			return false, err
		}
		return false, nil
	}
	if !request.GetGrantedScopes().Has(groupsScope) {
		claims.Groups = nil
	}
	custom, err := s.currentCustomClaims(ctx, session.Subject, request.GetGrantedScopes())
	if err != nil {
		if oauthBackendUnavailable(err) {
			return false, err
		}
		return false, nil
	}
	return setPrincipalClaims(request, claims) == nil && setCustomAccessClaims(request, custom.access) == nil, nil
}

// RevocationHandler serves RFC 7009 to authenticated registered clients.
func (s *Server) RevocationHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := formRequest(w, r); err != nil {
			s.provider.WriteRevocationResponse(r.Context(), w, err)
			return
		}
		if _, _, ok := r.BasicAuth(); !ok {
			s.provider.WriteRevocationResponse(r.Context(), w, fosite.ErrInvalidClient)
			return
		}
		s.provider.WriteRevocationResponse(r.Context(), w, s.provider.NewRevocationRequest(r.Context(), r))
	})
}
