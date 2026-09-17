// Package geoblock implements country-based request admission.
package geoblock

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"

	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/oschwald/maxminddb-golang"
)

var (
	ErrInvalidCountry  = errors.New("invalid country code")
	ErrSpoofedHeader   = errors.New("country header is not trusted")
	ErrAmbiguousHeader = errors.New("country header is repeated or malformed")
)

type ListType string

const (
	Whitelist ListType = "whitelist"
	Blacklist ListType = "blacklist"
)

type Decision uint8

const (
	Unknown Decision = iota
	Allow
	Deny
)

// NormalizeCountry accepts exactly an ASCII ISO 3166-1 alpha-2 code.
func NormalizeCountry(value string) (string, error) {
	if len(value) != 2 || value[0] < 'A' || value[0] > 'Z' || value[1] < 'A' || value[1] > 'Z' {
		return "", ErrInvalidCountry
	}
	return value, nil
}

type Policy struct {
	Type         ListType
	Countries    []string
	BlockUnknown bool
}

func NewPolicy(kind ListType, countries []string, blockUnknown bool) (Policy, error) {
	if kind != Whitelist && kind != Blacklist {
		return Policy{}, errors.New("invalid country list type")
	}
	allowed := make(map[string]struct{}, len(countries))
	for _, country := range countries {
		country, err := NormalizeCountry(country)
		if err != nil {
			return Policy{}, err
		}
		allowed[country] = struct{}{}
	}
	list := make([]string, 0, len(allowed))
	for country := range allowed {
		list = append(list, country)
	}
	sort.Strings(list)
	return Policy{Type: kind, Countries: list, BlockUnknown: blockUnknown}, nil
}

func (p Policy) Decide(country string) Decision {
	if country == "" {
		if p.Type == Whitelist || p.BlockUnknown {
			return Deny
		}
		return Allow
	}
	country, err := NormalizeCountry(country)
	if err != nil {
		return Deny
	}
	listed := false
	for _, candidate := range p.Countries {
		if candidate == country {
			listed = true
			break
		}
	}
	if (p.Type == Whitelist) == listed {
		return Allow
	}
	return Deny
}

// CountryLookup is the narrow boundary used by both headers and databases.
type CountryLookup interface {
	Country(netip.Addr) (string, error)
}

type MaxMindReader struct{ reader *maxminddb.Reader }

type maxMindCountry struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

func OpenMaxMind(path string) (*MaxMindReader, error) {
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &MaxMindReader{reader: reader}, nil
}

func (r *MaxMindReader) Country(ip netip.Addr) (string, error) {
	if r == nil || r.reader == nil {
		return "", errors.New("nil MaxMind reader")
	}
	var record maxMindCountry
	if err := r.reader.Lookup(net.IP(ip.AsSlice()), &record); err != nil {
		return "", err
	}
	if record.Country.ISOCode == "" {
		return "", nil
	}
	return normalizeDatabaseCountry(record.Country.ISOCode)
}

func normalizeDatabaseCountry(value string) (string, error) {
	// Validate before strings.ToUpper: Unicode case folding can expand a
	// malformed value (for example, ß -> SS) into two accepted ASCII bytes.
	if len(value) != 2 || !asciiCountryLetter(value[0]) || !asciiCountryLetter(value[1]) {
		return "", ErrInvalidCountry
	}
	return NormalizeCountry(strings.ToUpper(value))
}

func asciiCountryLetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func (r *MaxMindReader) Close() error {
	if r == nil || r.reader == nil {
		return nil
	}
	return r.reader.Close()
}

// HeaderCountry resolves a configured country header only from a trusted
// immediate proxy. A present header from an untrusted peer is rejected.
func HeaderCountry(r *http.Request, header string, trusted []netip.Prefix) (string, error) {
	if r == nil {
		return "", ErrSpoofedHeader
	}
	if header == "" {
		return "", nil
	}
	values := r.Header.Values(header)
	if len(values) == 0 {
		return "", nil
	}
	peer, ok := loginpolicy.PeerIP(r.RemoteAddr)
	if !ok || peer == "" {
		return "", ErrSpoofedHeader
	}
	peerAddr, err := netip.ParseAddr(peer)
	if err != nil {
		return "", ErrSpoofedHeader
	}
	trustedPeer := false
	for _, prefix := range trusted {
		if prefix.IsValid() && prefix.Contains(peerAddr) {
			trustedPeer = true
			break
		}
	}
	if !trustedPeer {
		return "", ErrSpoofedHeader
	}
	if len(values) != 1 || strings.ContainsAny(values[0], " \t,\r\n") {
		return "", ErrAmbiguousHeader
	}
	return NormalizeCountry(values[0])
}

// Middleware applies policy and never exposes the lookup result to clients.
func Middleware(policy Policy, header string, trusted []netip.Prefix, lookup CountryLookup, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		country, err := HeaderCountry(r, header, trusted)
		if err != nil {
			deny(w)
			return
		}
		if country == "" && lookup != nil {
			ip, ok := loginpolicy.PeerIPFromRequest(r.RemoteAddr, r.Header, trusted)
			if !ok {
				deny(w)
				return
			}
			addr, parseErr := netip.ParseAddr(ip)
			if parseErr != nil {
				deny(w)
				return
			}
			country, err = lookup.Country(addr)
			if err != nil && policy.BlockUnknown {
				deny(w)
				return
			}
		}
		if policy.Decide(country) != Allow {
			deny(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func deny(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}
