// Package redirecturi contains the shared narrow RFC 8252 loopback policy.
package redirecturi

import (
	"net/url"
	"strconv"
	"strings"
)

type Policy struct{ AllowLoopback bool }

// Matches permits exact registered redirects for every client. Different
// loopback ports are permitted only for opt-in public dynamic clients.
func (p Policy) Matches(registered []string, requested string, publicDynamic bool) bool {
	if strings.Contains(requested, "#") {
		return false
	}
	for _, candidate := range registered {
		if strings.Contains(candidate, "#") {
			continue
		}
		if candidate == requested || p.AllowLoopback && publicDynamic && loopbackRedirectMatches(candidate, requested) {
			return true
		}
	}
	return false
}

// IsLoopbackTemplate accepts the DCR registration subset: canonical HTTP
// literal loopback URI, optional valid port, and no query or fragment.
func IsLoopbackTemplate(raw string) bool {
	parsed, ok := parseLoopbackRedirect(raw, false)
	return ok && parsed.query == "" && !parsed.forceQuery && (parsed.host != "localhost" || parsed.explicitPort)
}

// IsPortlessLoopbackTemplate reports whether raw is a valid loopback template
// whose port is intentionally left for the native client to choose.
func IsPortlessLoopbackTemplate(raw string) bool {
	parsed, ok := parseLoopbackRedirect(raw, false)
	return ok && parsed.host != "localhost" && !parsed.explicitPort && parsed.query == "" && !parsed.forceQuery
}

func loopbackRedirectMatches(registered, requested string) bool {
	left, ok := parseLoopbackRedirect(registered, false)
	if !ok {
		return false
	}
	right, ok := parseLoopbackRedirect(requested, true)
	return ok && left.host != "localhost" && left.host == right.host && left.path == right.path && left.query == right.query && left.forceQuery == right.forceQuery
}

type loopbackRedirect struct {
	host, path, query string
	forceQuery        bool
	explicitPort      bool
}

func parseLoopbackRedirect(raw string, requirePort bool) (loopbackRedirect, bool) {
	// url.Parse drops an empty fragment, but a raw fragment is never an
	// allowed loopback redirect even when it has no value.
	if strings.Contains(raw, "#") {
		return loopbackRedirect{}, false
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.Scheme != "http" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return loopbackRedirect{}, false
	}
	hostname := u.Hostname()
	if hostname != "localhost" && hostname != "127.0.0.1" && hostname != "::1" {
		return loopbackRedirect{}, false
	}
	port := u.Port()
	explicitPort := port != "" || strings.HasSuffix(u.Host, ":")
	if port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return loopbackRedirect{}, false
		}
	} else if requirePort {
		return loopbackRedirect{}, false
	}
	return loopbackRedirect{host: hostname, path: u.EscapedPath(), query: u.RawQuery, forceQuery: u.ForceQuery, explicitPort: explicitPort}, true
}
