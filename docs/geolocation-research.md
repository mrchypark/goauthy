# Geolocation restriction research

## Rauthy v0.36.2 behavior

Rauthy documents `[geolocation]` with `country_header`, `country_list_type`,
`country_list`, and `block_unknown`. A country whitelist is default-deny; a
blacklist is default-allow. Unknown addresses are allowed by default, but
`block_unknown = true` blocks them. A configured country header is accepted
only in proxy mode from a trusted proxy, preventing spoofing. Rauthy can also
download and periodically use a MaxMind GeoLite2 Country database.

Sources: [Rauthy reference config](https://sebadob.github.io/rauthy/config/config.html),
[Rauthy v0.36.2 release/container documentation](https://sebadob.github.io/rauthy/getting_started/k8s.html),
[Rauthy repository](https://github.com/sebadob/rauthy/tree/v0.36.2).

## Go reader selection

`github.com/oschwald/maxminddb-golang` is a maintained public Go reader. Its
official API opens an MMDB path, performs IP lookups, and closes the reader;
the repository documents the MMDB metadata and supported binary format.
Sources: [reader API](https://github.com/oschwald/maxminddb-golang/blob/main/reader.go),
[module repository](https://github.com/oschwald/maxminddb-golang).

## Scope and gaps

`internal/geoblock` supplies strict ASCII ISO alpha-2 normalization, trusted
header handling through the existing `loginpolicy.PeerIPFromRequest`, a local
MaxMind adapter, fail-closed policy decisions, and generic `403` middleware
with `no-store` and `nosniff`. `GOAUTHY_GEOBLOCK_COUNTRY_HEADER` and
`GOAUTHY_GEOBLOCK_MAXMIND_DB` are alternative country sources (the trusted
header wins when both are present): a header-only
deployment must configure `GOAUTHY_TRUSTED_PROXIES`, while a database-only
deployment resolves the canonical client IP from the direct peer or trusted
proxy forwarding headers. Header repetition, malformed values, and untrusted
peers do not grant access; missing lookup data and lookup errors are denied
when the configured policy blocks unknown countries (as whitelists always do).
The local database setting also works with `GOAUTHY_GEOBLOCK_ENABLED=false`:
login notifications and revoke events can resolve locations without enabling
country admission rules. Revoke uses only the link's validated query IP and
the local database. Login locations accept the first configured header value when nonempty only from a trusted immediate peer; otherwise they use the canonical IP database lookup. Revoke events never use this header.

No network download, MaxMind credential handling, or update scheduler is
included: packages cannot safely choose deployment credentials, storage,
cadence, or atomic replacement policy, so that integration remains a future
deployment-owned layer.
