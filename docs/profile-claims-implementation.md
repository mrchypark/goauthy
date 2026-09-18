# Standard OIDC profile claims

GoAuthy now carries the standard profile projection through ID tokens and
UserInfo. `profile`, `email`, `address`, and `phone` are scope-gated; the
projection is resolved at each code/refresh issuance and UserInfo request, so
refreshes observe current profile data. Client-credentials grants do not call
the profile resolver. Custom claims reserve the standard names and cannot
overwrite them.

The source contract is Rauthy `dd61ac3c84d6b238108dc8438b53043b5177a662`,
`src/service/src/token_set.rs` (ID-token profile mapping) and
`src/service/src/oidc/userinfo.rs` (UserInfo mapping). The Go boundary is
`oauth.OIDCConfig.ResolveProfile`; the application wires it to the
credential-free `identity.Store.ProfileClaimsBySubject` projection and applies
the configured preferred-username email fallback.

Known boundaries: picture/webid are not yet exposed by the Go projection; no
phone verification mechanism exists, so a phone value
is emitted with `phone_number_verified: false`, matching Rauthy. Remaining
access-token profile parity is not completed by this batch.

`GOAUTHY_USER_VALUES_PREFERRED_USERNAME_EMAIL_FALLBACK` defaults to `true`;
only literal `true`/`false` are accepted. It affects both ID tokens and UserInfo
and is returned by `users/values_config`. Address formatting follows pinned
`src/jwt/src/claims.rs::AddressClaim::try_build`, including locality only when
ZIP exists. The pinned UserInfo source assigns email after attempting its
fallback; GoAuthy deliberately uses current profile email consistently with
ID tokens rather than reproducing that ordering bug.

Executed checks include `TestProfileClaimsCodeRefreshUserInfoAndScopeIsolation`,
the real Rhiza identity projection, configured policy/adapter tests, signed-token
round trips, and `TestProfileClaimsLive` on standalone and exact-three Kind.
The live test includes ordinary-user profile changes, signed ID-token refresh,
all-node UserInfo, OpenID-only withholding and profile-only email fallback.
