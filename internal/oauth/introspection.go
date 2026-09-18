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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := formRequest(w, r); err != nil {
			s.provider.WriteIntrospectionError(r.Context(), w, err)
			return
		}
		if _, _, ok := r.BasicAuth(); !ok {
			s.provider.WriteIntrospectionError(r.Context(), w, fosite.ErrRequestUnauthorized.WithHint("HTTP Basic authentication is required."))
			return
		}
		response, err := s.provider.NewIntrospectionRequest(r.Context(), r, &fosite.DefaultSession{})
		if err != nil {
			s.provider.WriteIntrospectionError(r.Context(), w, err)
			return
		}
		if !s.refreshIntrospectionPrincipal(r.Context(), response) ||
			(response.IsActive() && s.store.validateTokenAccounts(r.Context(), response.GetAccessRequester()) != nil) {
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
func (s *Server) refreshIntrospectionPrincipal(ctx context.Context, response fosite.IntrospectionResponder) bool {
	if !response.IsActive() || s.oidc == nil {
		return true
	}
	request := response.GetAccessRequester()
	if request == nil {
		return true
	}
	session, ok := request.GetSession().(*fosite.DefaultSession)
	// Stored Fosite requests do not retain token-endpoint grant types. An
	// authorization-code session does retain its authorization-code expiry;
	// device, client-credentials, and token-exchange sessions do not.
	if !ok {
		return true
	}
	deviceOrigin, _ := session.Extra[deviceOIDCExtra].(bool)
	_, passwordOrigin := session.Extra[passwordAuthTimeExtra]
	if session.GetExpiresAt(fosite.AuthorizeCode).IsZero() && !deviceOrigin && !passwordOrigin {
		return true
	}
	if session.Subject == "" {
		return false
	}
	if s.oidc.ValidateSubject != nil && s.oidc.ValidateSubject(ctx, session.Subject) != nil {
		return false
	}
	claims, err := s.currentPrincipal(ctx, session.Subject)
	if err != nil {
		return false
	}
	if !request.GetGrantedScopes().Has(groupsScope) {
		claims.Groups = nil
	}
	custom, err := s.currentCustomClaims(ctx, session.Subject, request.GetGrantedScopes())
	return err == nil && setPrincipalClaims(request, claims) == nil && setCustomAccessClaims(request, custom.access) == nil
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
