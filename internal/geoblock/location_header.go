package geoblock

import (
	"net/http"
	"net/netip"

	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/security"
)

// RequestLocation returns a raw configured header location from a trusted
// immediate peer, or falls back to the database lookup for ip. Missing or
// empty headers and malformed or untrusted peers fall back; repeated headers
// use their first value, matching HeaderMap.get.
func RequestLocation(r *http.Request, header string, trusted []netip.Prefix, ip netip.Addr, lookup func(netip.Addr) (*string, error)) (*string, error) {
	if r != nil && header != "" {
		values := r.Header.Values(header)
		if len(values) > 0 && security.ValidHeaderText(values[0]) {
			peer, ok := loginpolicy.PeerIP(r.RemoteAddr)
			if ok {
				peerAddr, err := netip.ParseAddr(peer)
				if err == nil {
					for _, prefix := range trusted {
						if prefix.IsValid() && prefix.Contains(peerAddr) {
							location := values[0]
							return &location, nil
						}
					}
				}
			}
		}
	}
	if lookup == nil {
		return nil, nil
	}
	return lookup(ip)
}
