# Live profile-claims E2E

`TestProfileClaimsLive` is gated by `GOAUTHY_E2E_PROFILE_CLAIMS=1`. It uses the
existing deployed browser fixture to create and activate an ordinary user,
authorize `openid profile email address phone offline_access`, verify the signed
ID token and UserInfo profile projection, update profile fields through the
admin API, and verify refreshed tokens reflect current values. It also verifies
that an `openid`-only authorization does not include profile claims.

The test requires the normal E2E URL, secondary URL, browser admin credentials,
and client secret. It is intentionally not a startup or harness test and does
not claim coverage of an unconfigured tertiary endpoint.
