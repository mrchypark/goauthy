package oauth

import (
	"encoding/json"
	"errors"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/ory/fosite"
	"io"
	"mime"
	"net/http"
	"net/url"
)

// UserInfoHandler serves the minimal OpenID Connect UserInfo response.
func (s *Server) UserInfoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if len(r.URL.RawQuery) > oauthFormLimit || r.URL.Query().Has("access_token") || !validUserInfoBody(w, r) {
			writeUserInfoUnauthorized(w)
			return
		}
		_, token, ok := authorizationToken(r)
		if !ok || s.oidc == nil || s.oidc.ValidateSubject == nil {
			writeUserInfoUnauthorized(w)
			return
		}
		signature := s.accessTokens.AccessTokenSignature(r.Context(), token)
		request, err := s.store.GetAccessTokenSession(r.Context(), signature, &fosite.DefaultSession{})
		if err != nil {
			writeUserInfoUnauthorized(w)
			return
		}
		if s.accessTokens.ValidateAccessToken(r.Context(), request, token) != nil || !request.GetGrantedScopes().Has(openidScope) || request.GetSession().GetSubject() == "" {
			if sessionDPoPJKT(request.GetSession()) != "" {
				writeUserInfoDPoPUnauthorized(w)
			} else {
				writeUserInfoUnauthorized(w)
			}
			return
		}
		if err := s.verifyDPoPResourceRequest(r.Context(), r, request, token); err != nil {
			var nonceErr *dpopNonceError
			if errors.As(err, &nonceErr) {
				w.Header().Set("DPoP-Nonce", nonceErr.nonce)
				w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if sessionDPoPJKT(request.GetSession()) != "" {
				writeUserInfoDPoPUnauthorized(w)
				return
			}
			writeUserInfoUnauthorized(w)
			return
		}
		subject := request.GetSession().GetSubject()
		if _, err := s.store.GetClient(r.Context(), request.GetClient().GetID()); err != nil || s.oidc.ValidateSubject(r.Context(), subject) != nil {
			writeUserInfoUnauthorized(w)
			return
		}
		claims, err := s.currentPrincipal(r.Context(), subject)
		if err != nil {
			writeUserInfoUnauthorized(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		custom, err := s.currentCustomClaims(r.Context(), subject, request.GetGrantedScopes())
		if err != nil {
			writeUserInfoUnauthorized(w)
			return
		}
		response := map[string]any{"sub": subject, "roles": claims.Roles}
		if request.GetGrantedScopes().Has(groupsScope) {
			response["groups"] = claims.Groups
		}
		if s.oidc.ResolveProfile != nil && request.GetGrantedScopes().HasOneOf("profile", "email", "address", "phone") {
			profile, profileErr := s.oidc.ResolveProfile(r.Context(), subject)
			if profileErr != nil {
				writeUserInfoUnauthorized(w)
				return
			}
			profile = scopedProfile(profile, request.GetGrantedScopes())
			addProfileClaims(response, profile)
		}
		if err := addCustomClaims(response, custom.access); err != nil {
			writeUserInfoUnauthorized(w)
			return
		}
		if s.store.validateTokenAccounts(r.Context(), request) != nil {
			writeUserInfoUnauthorized(w)
			return
		}
		_ = json.NewEncoder(w).Encode(response)
	})
}

func addProfileClaims(response map[string]any, profile oidc.ProfileClaims) {
	if profile.Email != nil {
		response["email"] = *profile.Email
	}
	if profile.EmailVerified != nil {
		response["email_verified"] = *profile.EmailVerified
	}
	if profile.PreferredUsername != nil {
		response["preferred_username"] = *profile.PreferredUsername
	}
	if profile.GivenName != nil {
		response["given_name"] = *profile.GivenName
	}
	if profile.FamilyName != nil {
		response["family_name"] = *profile.FamilyName
	}
	if profile.Birthdate != nil {
		response["birthdate"] = *profile.Birthdate
	}
	if len(profile.Address) != 0 {
		response["address"] = profile.Address
	}
	if profile.PhoneNumber != nil {
		response["phone_number"] = *profile.PhoneNumber
	}
	if profile.PhoneNumberVerified != nil {
		response["phone_number_verified"] = *profile.PhoneNumberVerified
	}
	if profile.Zoneinfo != nil {
		response["zoneinfo"] = *profile.Zoneinfo
	}
	if profile.Locale != nil {
		response["locale"] = *profile.Locale
	}
}

func validUserInfoBody(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		return true
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, oauthFormLimit))
	if err != nil {
		return false
	}
	if len(body) == 0 {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return false
	}
	values, err := url.ParseQuery(string(body))
	return err == nil && len(values) == 0
}

func writeUserInfoUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.WriteHeader(http.StatusUnauthorized)
}

func writeUserInfoDPoPUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "DPoP")
	w.WriteHeader(http.StatusUnauthorized)
}
