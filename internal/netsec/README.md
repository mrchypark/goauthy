# Network Security (`internal/netsec`)

## Overview
Provides shared SSRF IP-filtering, DNS-rebinding-safe dialer, and hardened outbound HTTP client constructors used by outbound callers (`backchannel`, `cimd`, `notify`, `saas`, `scim`, and `upstreamprovider`).

## Interface
- `[ssrf.go:AllowedAddr]` — Reports whether a `netip.Addr` is safe for outbound server-initiated requests (always rejects invalid addresses, zoned IPv6 addresses, unspecified, multicast, link-local including `169.254.0.0/16`, and IANA special-use prefixes; unmaps IPv4-mapped IPv6 addresses before checking and gates private/loopback/CGNAT on `allowPrivate`, requiring global unicast).
- `[ssrf.go:SafeDialContext]` — Resolves hostnames via `LookupNetIP`, verifies every resolved address with `AllowedAddr`, and dials the pinned safe IP directly to prevent DNS rebinding.
- `[ssrf.go:NewSafeHTTPClient]` — Constructs an `*http.Client` with proxies, compression, and redirects disabled, TLS 1.2+ enforced, and `SafeDialContext` wired.
- `[ssrf.go:ErrUnsafeHost]` — Sentinel error returned when an outbound target resolves to a disallowed IP address.

## Verification
- Run: `go test ./internal/netsec`
