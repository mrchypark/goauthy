# Admission Kind overlay

The overlay enables the source-wired manual IP blacklist and trusts only the
local port-forward peer for deterministic `X-Forwarded-For` tests. A tiny,
legally redistributable MaxMind database is not shipped in this repository;
geoblock runtime coverage remains opt-in (`GOAUTHY_GEOBLOCK_ENABLED=true` with
`GOAUTHY_GEOBLOCK_MAXMIND_DB` pointing at an operator-supplied fixture).
