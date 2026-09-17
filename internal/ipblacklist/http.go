package ipblacklist

import (
	"net/http"
	"net/netip"
)

// Resolver extracts the canonical client IP from an HTTP request.
// Implementations must not re-derive trusted-proxy parsing.
type Resolver func(r *http.Request) (netip.Addr, error)

// Middleware returns an HTTP middleware that enforces IP blacklist decisions.
// Requests with a matched IP receive a generic 403 response. Resolver or
// store errors also produce 403 (fail closed). The response is identical
// in all rejection cases to avoid leaking information.
func Middleware(s *Store, resolve Resolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s == nil || resolve == nil {
				reject(w)
				return
			}
			addr, err := resolve(r)
			if err != nil {
				reject(w)
				return
			}
			result, err := s.Check(r.Context(), addr.String())
			if err != nil {
				reject(w)
				return
			}
			if result.Matched {
				reject(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func reject(w http.ResponseWriter) {
	http.Error(w, "Forbidden", http.StatusForbidden)
}
