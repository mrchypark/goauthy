package oauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/dpop"
	"github.com/ory/fosite"
)

const (
	dpopCNFExtra        = "cnf"
	dpopJKTClaim        = "jkt"
	dpopProofMaxAge     = time.Minute
	dpopProofFutureSkew = 10 * time.Second
)

var errUseDPoPNonce = &fosite.RFC6749Error{
	ErrorField:       "use_dpop_nonce",
	DescriptionField: "DPoP nonce required.",
	CodeField:        http.StatusBadRequest,
}

// RFC 9449 section 5 distinguishes invalid proofs from nonce challenges.
var errInvalidDPoPProof = &fosite.RFC6749Error{
	ErrorField:       "invalid_dpop_proof",
	DescriptionField: "Invalid DPoP proof.",
	CodeField:        http.StatusBadRequest,
}

// dpopNonceError is deliberately opaque: the nonce travels only in the
// response header and proof material never reaches an OAuth error body.
type dpopNonceError struct{ nonce string }

func (e *dpopNonceError) Error() string { return "DPoP nonce required" }

func dpopHeader(r *http.Request) (raw string, present, valid bool) {
	values := r.Header.Values("DPoP")
	if len(values) == 0 {
		return "", false, false
	}
	if len(values) != 1 || values[0] == "" || len(values[0]) > dpop.MaxProofSize {
		return "", true, false
	}
	return values[0], true, true
}

func sessionDPoPJKT(session fosite.Session) string {
	defaultSession, ok := session.(*fosite.DefaultSession)
	if !ok || defaultSession.Extra == nil {
		return ""
	}
	cnf, ok := defaultSession.Extra[dpopCNFExtra]
	if !ok {
		return ""
	}
	switch value := cnf.(type) {
	case map[string]string:
		return value[dpopJKTClaim]
	case map[string]any:
		jkt, _ := value[dpopJKTClaim].(string)
		return jkt
	default:
		return ""
	}
}

func setSessionDPoPJKT(session fosite.Session, jkt string) error {
	defaultSession, ok := session.(*fosite.DefaultSession)
	if !ok || jkt == "" {
		return errors.New("invalid DPoP session")
	}
	if defaultSession.Extra == nil {
		defaultSession.Extra = map[string]any{}
	}
	// Keep other OIDC session values (nonce, auth_time and sid) intact.
	defaultSession.Extra[dpopCNFExtra] = map[string]string{dpopJKTClaim: jkt}
	return nil
}

func sameDPoPJKT(left, right string) bool {
	return left != "" && right != "" && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func (s *Server) verifyDPoPTokenRequest(ctx context.Context, r *http.Request, request fosite.AccessRequester) (string, error) {
	boundJKT := sessionDPoPJKT(request.GetSession())
	raw, present, valid := dpopHeader(r)
	if present && !valid {
		return "", errInvalidDPoPProof
	}
	if !present {
		if boundJKT != "" {
			return "", fosite.ErrInvalidRequest
		}
		return "", nil
	}
	if s.oidc == nil || s.dpop == nil || (!request.GetGrantTypes().ExactOne("authorization_code") && !request.GetGrantTypes().ExactOne("refresh_token") && !request.GetGrantTypes().ExactOne("client_credentials") && !request.GetGrantTypes().ExactOne(DeviceGrantType) && !request.GetGrantTypes().ExactOne(TokenExchangeGrantType) && !request.GetGrantTypes().ExactOne("password")) {
		return "", fosite.ErrInvalidRequest
	}
	now := time.Now().UTC()
	proof, err := dpop.Validate(raw, r, dpop.Options{Issuer: s.oidc.Issuer, Now: now, MaxAge: dpopProofMaxAge, FutureSkew: dpopProofFutureSkew})
	if err != nil {
		return "", errInvalidDPoPProof
	}
	if boundJKT != "" && !sameDPoPJKT(boundJKT, proof.JKT) {
		return "", errInvalidDPoPProof
	}
	clientID := request.GetClient().GetID()
	if err := s.dpop.ConsumeNonce(ctx, proof.Nonce, clientID, proof.JKT, now); err != nil {
		if errors.Is(err, dpop.ErrInvalid) || errors.Is(err, dpop.ErrReplay) {
			nonce, issueErr := s.dpop.IssueNonce(ctx, clientID, proof.JKT, now)
			if issueErr != nil {
				return "", fosite.ErrServerError
			}
			return "", &dpopNonceError{nonce: nonce}
		}
		return "", fosite.ErrServerError
	}
	if err := s.dpop.MarkReplay(ctx, proof.JKT, proof.JTI, now, proof.IssuedAt.Add(dpopProofMaxAge)); err != nil {
		if errors.Is(err, dpop.ErrReplay) {
			nonce, issueErr := s.dpop.IssueNonce(ctx, clientID, proof.JKT, now)
			if issueErr != nil {
				return "", fosite.ErrServerError
			}
			return "", &dpopNonceError{nonce: nonce}
		}
		return "", fosite.ErrServerError
	}
	return proof.JKT, nil
}

func (s *Server) verifyDPoPResourceRequest(ctx context.Context, r *http.Request, request fosite.Requester, accessToken string) error {
	boundJKT := sessionDPoPJKT(request.GetSession())
	scheme, token, authorizationOK := authorizationToken(r)
	if boundJKT == "" {
		if !authorizationOK || !sameAuthorizationScheme(scheme, "Bearer") || token != accessToken {
			return fosite.ErrInvalidRequest
		}
		return nil
	}
	if !authorizationOK || !sameAuthorizationScheme(scheme, "DPoP") || token != accessToken || s.oidc == nil || s.dpop == nil {
		return fosite.ErrInvalidRequest
	}
	raw, present, valid := dpopHeader(r)
	if !present || !valid {
		return fosite.ErrInvalidRequest
	}
	now := time.Now().UTC()
	proof, err := dpop.Validate(raw, r, dpop.Options{Issuer: s.oidc.Issuer, Now: now, MaxAge: dpopProofMaxAge, FutureSkew: dpopProofFutureSkew, AccessToken: accessToken})
	if err != nil || !sameDPoPJKT(boundJKT, proof.JKT) {
		return fosite.ErrInvalidRequest
	}
	clientID := request.GetClient().GetID()
	if err := s.dpop.ConsumeNonce(ctx, proof.Nonce, clientID, proof.JKT, now); err != nil {
		if errors.Is(err, dpop.ErrInvalid) || errors.Is(err, dpop.ErrReplay) {
			nonce, issueErr := s.dpop.IssueNonce(ctx, clientID, proof.JKT, now)
			if issueErr != nil {
				return fosite.ErrServerError
			}
			return &dpopNonceError{nonce: nonce}
		}
		return fosite.ErrServerError
	}
	if err := s.dpop.MarkReplay(ctx, proof.JKT, proof.JTI, now, proof.IssuedAt.Add(dpopProofMaxAge)); err != nil {
		if errors.Is(err, dpop.ErrReplay) {
			nonce, issueErr := s.dpop.IssueNonce(ctx, clientID, proof.JKT, now)
			if issueErr != nil {
				return fosite.ErrServerError
			}
			return &dpopNonceError{nonce: nonce}
		}
		return fosite.ErrServerError
	}
	return nil
}

func authorizationToken(r *http.Request) (scheme, token string, ok bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", "", false
	}
	scheme, token, ok = strings.Cut(values[0], " ")
	return scheme, token, ok && token != "" && !strings.ContainsAny(token, " \t\r\n")
}

func sameAuthorizationScheme(actual, expected string) bool {
	return len(actual) == len(expected) && subtle.ConstantTimeCompare([]byte(strings.ToLower(actual)), []byte(strings.ToLower(expected))) == 1
}
