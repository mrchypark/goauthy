## 2026-09-17 Qualification ledger / federated creation correction / schema v102

### Current qualification ledger (verified 2026-09-17)

| # | Scope | Result | Evidence |
|---|-------|--------|----------|
| 1 | full go test first run | FAIL | OpenAPI8routes / loginpolicy eventref / schema normalization + 10min timeouts |
| 2 | loginpolicy fix | full PASS 188.907s; -race PASS 138.4s | Full + race qualified |
| 3 | upstreamprovider | full PASS 615.165s | Full package qualified |
| 4 | DCR | PASS 704.283s | -timeout 30m |
| 5 | go vet | exit 0 | /tmp/goauthy-final-vet-v2-20260917.log |
| 6 | realMinIO S3 account/signingkey recovery -race | PASS 42.202s | Log /tmp/goauthy-s3-recovery-20260916.log |
| 7 | storage v97-102/replay | PASS 22.189s | TestMigrationV98V102 + TestMigrationV98V102ReplayIdempotent |
| 8 | migration focused race | PASS 45.500s | Log /tmp/goauthy-migration-race-20260916.log, exit0 |
| 9 | creator/autolink 35 focused tests | PASS 105.211s | /tmp/goauthy-test-output.txt, exit0 |
| 10 | oauth | PASS 1016.179s | -count=1 -timeout=45m -p=3; supports original 10m timeout issue |
| 11 | rbac | PASS 771.519s | -count=1 -timeout=45m -p=3; supports original 10m timeout issue |
| 12 | saas | PASS 652.839s | -count=1 -timeout=45m -p=3; supports original 10m timeout issue |
| 13 | apidocs | PASS 3.484s | Carver exec-be16a5b1; OpenAPI corrected final OTP body code-only/initcookie/OAuthcompletion, publicpasskeystart profile schema; parent inspected mounted handler |
| 14 | storage | PASS 225.323s | -count=1 -timeout=45m -p=2; log /tmp/goauthy-storage-login-20260916.log |
| 15 | login | PASS 186.861s | -count=1 -timeout=45m -p=2; log /tmp/goauthy-storage-login-20260916.log |
| 16 | MFA focused race | login PASS 100.680s, upstreamprovider PASS 3.020s | -race -run TestCompleteUpstreamAuthentication\|TestCompleteExternalAuthenticationForceMFA\|TestLocalCallbackMFA; log /tmp/goauthy-upstream-mfa-race-20260916.log |
| 17 | creator/autolink race | PASS 273.746s exit0 | /tmp/goauthy-federation-create-race-20260916.log; worker tightened provider-link/recovery/principal-rollback assertions |
| 18 | upstream-fixture | PASS 0.499s | cmd/goauthy-upstream-fixture -v -count=1; parent verified log+env flag parsing; optional claims signed/per-auth frozen, whitelist bound 256, legacy absent unchanged; still NOT actual new Kind E2E |
| 19 | resolver focused | PASS 10.499s | go test -v -run TestResolveVerified -timeout 120s ./cmd/goauthy; 8 tests/table cases; real JWT/JWKS->raw claims, profile email/names/lastlogin, admin grant/revoke (existing role+peer), nil preserves manual admin, malformed path allowed, missing raw/email/evalerr reject, legacy static; both production closures wired |
| 20 | cmd resolver/OpenAPI/dynamic/coexist race | PASS 191.464s | /tmp/goauthy-resolver-race-20260916.log; combined race parent exit0 |
| 21 | MinIO noPVC schema98-102 recovery focused race | PASS 45.861s exit0 | /tmp/goauthy-s3-schema-recovery-20260917.log; nondefault v98-102 rows + accounts/keys/refresh full focused race; fixture cleanup confirmed |
| 22 | make test-e2e-session-policy | PASS | /tmp/goauthy-session-policy-20260916.log; actual make target |
| 23 | profile CAS + identity normal | PASS 752.955s + race 2149.417s | 17 focused normal + whole identity normal; whole identity race PASS supersedes earlier inconclusive focused profilerace |
| 24 | full ./... normal V2 | PASS | parent session31493; /tmp/goauthy-final-all-v2-20260917.log; superseded by V3 |
| 25 | full ./... normal V3 | PASS | /tmp/goauthy-final-all-v3-20260917.log; EXIT0 after E2E cleanup + mapping path fix |
| 26 | go vet V3 | PASS | /tmp/goauthy-final-vet-v3-20260917.log; EXIT0 |
| 27 | Kind V4 full E2E | PASS 11.946s | /tmp/goauthy-final-kind-v4-20260917.log; parent 84038 EXIT0; 3 app Pods 1 Kind node; GOAUTHY_UPSTREAM_MANAGED_E2E=1; first suite 11.725s + Pod0 UID changed/Ready + 60s login window wait + second suite 7/7 PASS 11.946s; actual onboarding/profile-update/local-password-autolink/ForceMFA positive+negative + 4 legacy lifecycles; tests create+cleanup fixtures each run |
| 28 | full ./... race V2 | PASS | parent 92004 EXIT0; /tmp/goauthy-final-race-v2-20260917.log; -race -p=3 -timeout=60m; valid native cache including updated storage & latest E2E |



### Federated creation correction

Historical Sep 12 entries below describe federated creation as "unwired" / "draft defects NOT qualified". Current source supersedes those claims: `internal/identity/federated_create.go` implements CAS provider-snapshot guard, auto_onboarding false-rejection, version-change rejection, disabled-provider rejection, duplicate email/key handling, admin claim mapping, email validation. `federated_create_test.go` has 15+ focused tests. `cmd/goauthy/federated_resolver.go` implements resolveVerified with profile update. Both `main.go` and `upstream.go` now wire the shared `FederatedIdentityResolver` into production. **Implemented and behavioral-verified: 8 focused resolver tests PASS (row 19).** The earlier FAIL 2.239 (session 6392) and "unwired" claims are superseded by the current source.

### Schema

Schema is now v102 (was v58 at parity.md baseline date). Migrations v98-v102: scim_client_config (v98), force_mfa column (v99), system_lockdown (v100), identity_email_otp + rate_limits (v101), event_log prev_hash/integrity_hash (v102). Upgrade path v97->v102 verified by real Migrate call.

### Gate status (2026-09-17)

| Gate | Status | Evidence |
|------|--------|----------|
| P0 security autolink guards + creator race | PASS | creator/autolink 35 focused PASS 105.211s; creator/autolink race PASS 273.746s exit0; resolver 8 focused tests PASS 10.499s; autolink CAS guard + provider-snapshot + auto_onboarding rejection tested |
| P0 full check compile cycle + normal/vet | PASS | full ./... V3 PASS /tmp/goauthy-final-all-v3-20260917.log; vet V3 PASS /tmp/goauthy-final-vet-v3-20260917.log; storage 169.120s, unchanged prod valid native cache |
| P1 upstream MFA | PASS | MFA focused race PASS 100.680s+3.020s login+upstreamprovider; log /tmp/goauthy-upstream-mfa-race-20260916.log |
| P1 admin mapping + profile | PASS | profile CAS+identity normal PASS 752.955s; resolver wired main.go+upstream.go; admin grant/revoke + nil preserves manual admin verified |
| P1 actual new E2E + schema | PASS | Kind V4 full E2E PASS 11.946s /tmp/goauthy-final-kind-v4-20260917.log; GOAUTHY_UPSTREAM_MANAGED_E2E=1; onboarding/profile-update/local-password-autolink/ForceMFA positive+negative + 4 legacy lifecycles; 3 app Pods 1 Kind node; schema v97→v102 upgrade+replay PASS 22.189s + race PASS 45.500s; MinIO S3 schema98-102 recovery PASS 45.861s |
| P2 full race Kind DR + ledger | PASS | full ./... race V2 EXIT0 parent 92004 /tmp/goauthy-final-race-v2-20260917.log (all packages); production race EXIT0 parent 45487 /tmp/goauthy-final-production-race-20260916.log; Kind V4 E2E PASS 11.946s; MinIO S3 schema98-102 recovery PASS 45.861s; session-policy PASS |

### Completion (2026-09-17)

**현재 검증된 사실 (2026-09-17):**

- Baseline f63a: 6 local audit gates PASS (full ./... V3, vet V3, Kind V4 E2E 11.946s)
- CI head51b normal/vet PASS; race CANCELLED when superseded
- Candidate f1443a3d pushed; CI run 35222763242 in progress
- Frozen f1443a3d branding 83.586s and storage 164.346s tests PASS
- Immutable image `ghcr.io/mrchypark/ternal@sha256:b618c4afd388ca3f175d7783835d3ce0fb964541c192141dcf5faa0433ecf29e` published; Grype 0.118.0 0 matches/0 ignored exit 0; live operational qualification pending
- Native GCS HA overlay render PASS; live operational qualification pending
- CNI deny test FAILED on IED/GKE `gke_ied-cluster`: HTTP remained reachable after removing the allow policy because NetworkPolicy enforcement is disabled. The corrected preflight blocks before creating resources; the test namespace is absent.
- Discoverable credentials pinned at `ResidentKeyDiscouraged` — not an established required gap
- Global hash-chain runtime absent; upstream requirement not established
- Fresh-browser passkey-only login: confirmed open
- Profile login revalidation: confirmed open

Broad Rauthy behavior-parity goal remains paused/outside this scope; event-hash runtime unimplemented (pre-existing, not claimed). Historical entries below are clearly dated and preserved as-is.

## 2026-09-12 Managed Kind #6 EXIT0 / lifecycle E2E PASS / canonical broad suites PASS

Parent Kind #6 session11067 exit0, log /tmp/goauthy-managed-kind-parent-0912h.log. 3 app Pods on 1 Kind host. Script env GOAUTHY_UPSTREAM_MANAGED_E2E=1 with all URL/credentials/CA set; all 4 lifecycle tests enabled: managedOIDC (create/link/crossreplicalogin/RPsignatureexternalAMR/unlink/passwordstillworks/delete), pendingcallbackafterunlinkreject, legacyOIDC, GitHub. e2e_upstream package PASS 4.644s before Pod0 replacement, PASS 6.311s after. Tests create and clean fixtures each run — NOT retained provider state, NOT entire chaos coverage, NOT auto onboarding.

Parent canonical qualified results supersede earlier stale-fixture fails (sessions 91250/18326): session 11540 go test ./cmd/goauthy -run 'TestDynamic|Test.*Coexist' -count=1 PASS 19.621s; session 46855 go test ./internal/upstreamprovider -run 'Test.*Callback|Test.*LocalStart|Test.*LinkFlow|TestRuntimeBinding|TestOAuthUserInfo|TestOIDCUserInfo' -count=1 PASS 0.921s.

aud strict8 parent 12282 PASS 0.303s, rejects null/mixed null. Creator baseline 6392 FAIL 2.239 err provider snapshot mismatch — native atomic guards added, duplicate declaration + auto_onboarding false-allowed guard + type normalization unresolved, predecessor closed verified defects, new Hypatia repair active, still unqualified/unwired. Numeric Rust probe 1e2→100.0, -0→-0.0, 1e20→1e+20 fix in progress. Profile hook transport new worker started — not qualified.

Not whole package; predates new VerifiedIdentity hook implementation. Entire upstream provider/full goal OPEN.
## 2026-09-12 Managed Kind #5 aud-parsing FAIL / parent scope chain PASS / broader cmd+callback FAIL

Managed Kind #5 log /tmp/goauthy-managed-kind-parent-0912g.log session85751 exit1 pkg3.641s lines238-245: 3 lifecycle tests FAIL at ID-token aud parsing — server emits string `aud`, test struct expects `[]string` ("json: cannot unmarshal string into Go struct field idTokenClaims.aud of type []string"). TestManagedProviderLifecycle, TestUpstreamLinkLoginAndUnlink, TestGitHubOAuthAppLinkLoginAndUnlink all FAIL same root cause. They reached RP token response with external AMR but verifier failed; NOT signature proven, NOT whole lifecycle proven. Fourth TestPendingCallbackAfterManagedUnlink has no failure line in the log — cannot assert standalonePASS without verbose proof. 3 Pods on 1 Kind host, setup PASS. This is the ID-token audience format boundary, not a complete upstream lifecycle failure.

Parent scope chain focused fresh PASS4.659s session46314: go test ./internal/upstreamprovider -run '^(TestRuntimeConfig.*Scope|TestGenerateAuthorizationURLScope)$' -count=1. Records RuntimeConfig scope handling and authorization URL scope generation. Source production plus-splitting fixed; realCreate→Runtime→URL test chain qualified narrow.

Broader canonical parent cmd dynamic+coexist session91250 FAIL19.956: 3 start 400 due stale fake test-session-token despite helper defined. Callback family session18326 FAIL.736: TestLoginCallbacksRejectLinkPurpose/local consumed=false stale fixture; new worker repairing. Earlier narrowPASS historical entries preserved separately — do not imply current broad suite PASS.

Creator/numericmapping still unqualified and unwired. Entire upstream provider/full goal OPEN.
## 2026-09-12 Upstream provider callback/userinfo boundary PASS / managed Kind #4 setup PASS + partial E2E

Upstream provider combined parent PASS6.043s session63804 (exit0): go test ./internal/upstreamprovider -run '^TestOAuthUserInfoExchange|^TestParseUserInfoSub|^TestOIDCUserInfoBoundary$|^TestProviderModeBoundary|^TestOAuthUserInfoCallback$' -count=1. Includes 3 restored callback cases (realJWKSVerifier/namespace, success, replay/version), strictJSON surrogate/duplicate/UTF8/token type, real TLS redirect tests, nonce zeroUserInfo trust boundary, and realRegistry mode immutability. Earlier qualified nonce session13342 .635s and mode session8780 5.878s; combined session63804 PASS6.043 retained as historical evidence.
OIDC profile preservation parent focused PASS1.042s session35767: typed 4 claims from signed JWT, absent-vs-false and bad-signature/malformed-verification; not callback/profile integration.

Schema94-97 migration parent PASS6.627s session36016 and cmd dispatcher+coexist combined PASS17.965s session33990 already documented; no new evidence.

Managed Kind #4 session35154 exit1 log /tmp/goauthy-managed-kind-parent-0912f.log lines 239-248: setup3Pods PASS. Canonical session digest fix resolved link start 403. Legacy OIDC explicitlink+externalloginreturned RP 303 code/state (server-correct contract, old test expected 302 wrong). Managed/GitHub fixture authorize 400. All 4 E2E tests FAIL (log lines 239-248): TestManagedProviderLifecycle 400, TestPendingCallbackAfterManagedUnlink 400, TestUpstreamLinkLoginAndUnlink 303 (correct location), TestGitHubOAuthAppLinkLoginAndUnlink 400. NOT whole E2E/token exchange/unlink proof. GitHub test wrong OIDC /authorize→/login/oauth/authorize corrected; callbackLocation expects 303 corrected. Parent e2e package 50352 PASS 0.471s (default tests SKIP NOT live). Managed root runtimeScope strings.Fields('openid+profile') wrong single scope; fix in progress, fixture ALLOW_MANAGED_CALLBACKS already set script132 (reject old missing env claim). Entire feature/full goal OPEN.

Canonical selected parent 85606 PASS 0.880s: ^TestLocalStartRejectsMismatchedRawSessionToken$|^TestLocalCallbackRejectsMismatchedRawSessionTokenWithoutConsume$|^TestOAuthUserInfoCallback$|^TestOIDCUserInfoBoundary$. Final4 RuntimePolicy parent 3467 PASS 2.842s: real6 policy fields/actual pointer mutation incl Scopes+PKCE. OIDC typed-profile parent 35767 PASS 1.042s: typed-profile verified claims (raw claims qualified by 6619). Final4 tests parent 6619 PASS 0.779s: ^TestVerifiedClaimPayload|^TestDecodeIDTokenClaimsCopiesInputBytes$|^TestRawClaimsAccessorReturnsIndependentCopy$. No actual profile/onboarding integration yet. New federated_create.go draft defects NOT qualified/NOT wired; repair active. JSONPath mapping 69799 FAIL 0.647: duplicate/numeric/object cases; repair active.

## 2026-09-12 Schema94-97 migration PASS / cmd dispatcher+coexist combined PASS

Schema94-97 migration parent PASS6.627s session36016: TestMigrationV9[4-7] covers fullpath94/95/96 current schemaVersion expectations, v97 crossmode bothdirection version-first transaction rollback plus same-mode SET typ allowed. Supersedes earlier combinedFAIL26.753 for this exact scope. 

Cmd combined dispatcher+coexist parent PASS17.965s session33990: TestDynamicDispatcher+TestCoexist+TestLegacyNilStaticReturnsNoRoutes strengthened pattern mount. Current focused evidence; historical session5889/26607 preserved separately. NOT full live managed login.


## 2026-09-12 Upstream provider race-focused PASS / parent combined callback/local/link/replay/time/ID PASS / cmd legacy config/start PASS

Focused race: go test -race ./internal/upstreamprovider -run '^TestRuntimeBinding|^TestLocalFlow|^TestLinkFlow|^TestReplayedStateRejected' -count=1 exit0 PASS2.059s session2189. Records race-only qualification for RuntimeBinding/LocalFlow/LinkFlow/ReplayedStateRejected; not full suite.
Parent combined go test ./internal/upstreamprovider -run '^TestRuntimeBinding|^TestCallbacksUseTimeAfterTokenExchange|^TestGitHubCallbacks|^TestLocalFlow|^TestLocalCallback|^TestLinkFlow|^TestCombinedCallback|^TestExchangerReceivesTrustedStoredContext|^TestReplayedStateRejected|^TestTamperedSameLengthStateRejected' -count=1 PASS1.346s session31691 (legacy http_test counterfixture restored beforehand). Records combined parent qualification for TestRuntimeBinding plus existing callback/local/link/replay/time/ID tests.

Cmd legacy upstream config/start focused fresh PASS0.899s session27559. Static+dynamic route coexist separately qualified by cmd TestCoexist/TestLegacyNilStaticReturnsNoRoutes PASS2.911s session71699; not covered by parent callback tests.

## 2026-09-12 Schema96 runtime_versions/replay PASS / token exchange+constructor+deep-copy PASS / static PKCE/basic/post flags PASS / transaction encrypted roundtrip PASS / upstream registry standalone PASS / runtime-version store resolved / Kind PASS (session97412)

schema96 TestMigrationV96 parent PASS 1.711s: creates and backfills runtime_versions table, replay Ready. Token explicit exchange+constructor+deep-copy parent focused PASS 0.643s. Static file optional PKCE/basic/post flags focused cmd PASS 0.754s. Transaction source/version encrypted roundtrip+legacy+long8192 whitespace parser rejection focused parent PASS 8.483s (no callback runtime integration yet). Real standalone `GOAUTHY_E2E_UPSTREAM_REGISTRY=1 sh scripts/e2e-open-registration-standalone.sh` parent exit0, log /tmp/goauthy-upstream-registry-integrated-parent.log: TestUpstreamRegistryLive before restart PASS 0.21s (package 0.939s), after restart PASS 0.19s (package 0.738s); CRUD/list/minimal/logo lifecycle. Tests clean own data so NOT retention proof. Prior session evidence preserved at log /tmp/goauthy-upstream-registry-standalone-parent.log (session21487exit0, 0.799s/.845s). Runtime-version store 8 fixture/versionmissing cases resolved; old 3 focused failures (delete permission/revoke setup/invalid apikey) now gone after parent combined foundation 35.343s. DB login dispatcher/callback binding and userinfo fallback still OPEN. New focused qualifications: ID+issuer/clientID identity namespace focused PASS0.712s (runtime version-only same identity, legacy key unchanged); provider Create/Update/Delete after version metadata PASS25.615s (log /tmp/goauthy-runtime-version-crud-parent.log); callback login/link/replay suite PASS0.638s; account dynamic+existing external boundary tests PASS4.156s. Namespace now source wired to OIDC/GitHub resolveSubject. Callback 3 paths current cfg source/version/issuer/clientid compare before exchange source wired But new 7 covers legacy+managed success status200/exchange1, version/source mismatch and local/link changedversion and issuer mismatch zeroexchange. Full E2E not claimed. Runtime version focused parent PASS 15.636s session15634 (TestRuntimeVersion/TestGetRuntime/TestUpdateAuthorizedMissingTarget). RuntimeConfig 11 tests PASS 14.529s session21830; cmd dynamic dispatcher+coexist current combined PASS17.965s session33990 (TestDynamicDispatcher+TestCoexist+TestLegacyNilStaticReturnsNoRoutes, strengthened pattern mount, NOT full live managed login). schema97 migration parent PASS6.627s session36016 (TestMigrationV9[4-7], fullpath94/95/96 schemaVersion, v97 crossmode bothdirection version-first rollback+same-mode SET typ allowed; supersedes earlier FAIL26.753; ). oauth_userinfo config foundation focused PASS0.657s, enum/map PASS0.652s. cmd TLS fixture package parent PASS0.332s, managed callback optin support

Kind current session97412 terminal exit0, log /tmp/goauthy-upstream-registry-kind-integrated-parent.log: registry pre TestUpstreamRegistryLive PASS 0.38s (pkg 0.931), post PASS 0.40s (pkg 0.968); Pod0 UID fbebb928→e0140bc8; DCR pre: TestDCRBackchannelLogoutAcrossPods 3.58s + TestDCRPasswordBackchannelURIUpdateRemovalAcrossPods 6.77s (pkg 11.165), post: 1.14s + 6.58s (pkg 8.307); CRUD fresh fixtures, cleanup verified via kind getclusters. Qualification: 3 app Pods on 1 Kind host; cleanup NOT retention; no DB provider login yet. Full goal OPEN.

## 2026-09-12 Provider CRUD routes integrated / writeHTTP race PASS / replacement-key fence PASS / PKCE URL repair PASS

Server shared unconditional routes now integrated: POST/providers list, GETminimal/delete_safe, POST/create PUT/DELETE{id}, logoGET/PUT/DELETEimg. 43 writeHTTP tests PASS56.546s. writeHTTP race terminal PASS362.426s (/tmp/goauthy-provider-write-http-race-parent.log), no data race. 15 registry+logo sharedmux parent tests PASS62.884s (/tmp/goauthy-provider-crud-routes-parent.log). mutation+read focused PASS45.745s. real replacement-key persisted encrypted-secret oldwriter fence PASS2.061s (realkeyring opens persistedblob, keyIDverified, nooldwrite/guards). PKCE URL repair parent15 matchingtests PASS0.901s: explicitfalse removes preexisting challenge/method, legacy/defaulttrue preserved. Token exchange protocol repair and DB/runtime E2E remain unqualified. Existing older rewrap/logo/minio/favicon evidence preserved with limitations.

## 2026-09-12 Upstream provider secret-rewrap/inspect PASS / ProviderLogoStore+HTTP PASS / deletion PASS / core rewrap race PASS

Focused upstream provider tests session18737 exit0 22.441s: TestInspect (auth-provider client secret inspect), TestRewrap (auth-provider client secret rewrap step), TestProviderSecretRewrapRequestID (provider-secret rewrap with RequestIDContentAware) all pass with real keyring auth-provider client secret envelopes. CAS test deterministically interposes a DB write and retries, demonstrating all-or-zero semantics; not an actual concurrent-worker test. Key-purpose enforcement (rewrap not signing) and tamper detection pass. RequestIDContentAware hash differs for changed old/new bytes but does not constitute an executed request-ID fence proof. Does not qualify HTTP provider handler, mutation, delete, or full provider lifecycle.

Focused branding ProviderLogoStore tests session60332 exit0 9.101s: TestProviderLogoStore passes with small and medium store sizes, own-SVG fallback for missing brand image, and revoked authenticated API key mutation denial. No cross-client or global fallback behavior observed. Does not qualify mutation or delete.

Focused branding ProviderLogoHandler tests session70254 exit0 13.977s: httptest with actual Rhiza covers PNG-to-20/128 WebP, SVG sanitizer, cache headers, unauthorized/revoked/wrong-group denial, malformed/oversize preserving prior, delete, and no fallback. Not main-mounted or live E2E. Does not qualify mutation or delete.

Focused upstream provider deletion tests session1577 exit0 12.544s: TestDeleteAuthorized nine tests pass atomically: provider/logo/link delete preserving users and other providers; revoked guard; constraint rollback; linked users; empty and missing provider; missing profile fallback; disabled listed. Store deletion qualified focused; HTTP delete route not yet implemented or mounted.

Additional constraint: oauth2_exchanger.go constructor and ExchangeCode require nonempty clientsecret AND pkceVerifier with static map configs. Provider runtime public-PKCE/confidential-nonPKCE and DB dynamic runtime remain incomplete.

New parent machine focused check session71118 exit0 5.874s: TestTokenExchangeMachineSubjectMapping, TestMachineExchangeRetainsCollidingUserAncestorGuard, TestMachineAccountMarkersFailClosed all pass. Records focused machine-subject mapping/colliding-user-ancestor/malformed-marker regression only; no fresh Kind/DR qualification.

New core rewrap race52160 PASS 103.230s (/tmp/goauthy-provider-rewrap-race-parent.log): TestInspect, TestRewrap, TestProviderSecretRewrapRequestID pass under race. Supersedes initial buildblocked race72356 for this focused race coverage. No actual concurrent-worker CAS stress; deterministic interposition remains exact qualification.

Previous cmd key lifecycle exec77074 PASS 8.709s (CAS/rekey/retirement real keyring) and API-key envelope exec91100 PASS 10.783s remain standing as broader upstream-provider/branding evidence; they are not superseded by these focused checks.

## 2026-09-12 Extended TestNoPVCThemeRecovery exact32WebP favicon+SVG/theme FS PASS / realMinIO 95-object PASS / Cmd key lifecycle PASS / API-key envelope PASS

Extended TestNoPVCThemeRecovery includes exact32WebP favicon plus SVG/theme. Parent FS exec99993 PASS 9.260s: filesystem-backed fresh-directory recovery of exact32WebP favicon plus SVG/theme without running migrations first.

Real local MinIO race log /tmp/goauthy-favicon-minio-recovery-mimo.log terminal PASS 16.081s (test 14.06s). Worker Gauss confirms exit0, 95 objects, owned bucket/container cleaned. Parent docker confirms container absent. This is local MinIO freshdir DR on one host; distinguished from one-host Kind Pod replacement (exec83518) and the earlier 106-object MinIO run (no-pvc-theme-recovery.log). The earlier real MinIO recovery validated 106 objects; this run validates 95 objects with exact32WebP favicon content included.

Cmd key lifecycle parent exec77074 PASS 8.709s focused: TestMasterKeyRewrapStep*, TestAuthProviderSecret*, TestMasterKeyRewrapWorkerInvokesAuthProvider*, TestSaaSProviderEnvelopeBlocksRetirement. Real keyring oldrefs/rekey/status tested; not all CAS boundaries (worker still replacing flawed fake core tests). Previous broad cmd/goauthy rewrap-fix run67.071s and focused rewrap-family regression2.125s remain historical.

API-key envelope focused exec91100 PASS 10.783s. Previous apikey-callers-b combined branding/masterkeyretirement/ipblacklist/claims/kv exit0 remain historical.

CRUD/HTTP/dynamic-runtime/provider-logos/full-UI still incomplete; full-goal not complete. Schema95 migration (exec22009 PASS 1.819s), storage run58408, Kind favicon retention (exec83518), and standalone favicon retention (exec89833) remain standing from the prior entry.

## 2026-09-12 Standalone favicon exact32WebP retention PASS / Kind cross-Pod favicon PASS / schema95 migration PASS / storage PASS standing

Kind exec83518 exited0 ("/tmp/goauthy-favicon-retained-kind-mimo.log"): three app Pods on one local Kind host. Pod0 UID replaced 289dd073-7274-4184-ae22-042e0a929faf -> 8bf5bf75-58c2-41e3-93c0-75163fc21d76. Before replacement: FaviconLive .64s, LogoLive .45s, PrepareFavicon .34s, PrepareLogo .35s. After replacement: FaviconLive .42s, LogoLive .41s, LogoPersistVerify .30s, FaviconPersistVerify .37s. DCR backchannel and password-backchannel-URI both pass. Exact retained favicon bytes verified across Pod replacement on one Kind host; not multi-host nor MinIO freshdir DR.

Standalone favicon retention proven across actual restart: FaviconPersistPrepare .12s Verify .12s and LogoPersistPrepare .12s Verify .12s all passed (exec89833 exit0, "/tmp/goauthy-favicon-retained-mimo.log"). Favicon exact32WebP is retained through a real stop/start cycle from the same data directory; this supersedes the earlier retained-logo-fixture-only claim.

TestMigrationV95CreatesFinalAuthProvidersShape passed1.819s (exec22009 exit0). Storage run58408 passed301.365s ("/tmp/goauthy-storage-current-full-fixed.log", exit0) predates schema95 and the current session changes; it is not the final current full-package qualification.

Previous Kind goauthy-favicon-ha35350 terminal exit1 ("/tmp/goauthy-favicon-kind.log") remains historical: build failed on internal/upstreamprovider/provider_registry.go undefined context (import now fixed). Focused schema95 migration and registry read/decode tests pass (parent exec7252 PASS 3.651s, realRhizaGet/List); SecretCleartext uses a fake keyring so that path is not real crypto qualification. CRUD/rewrap/runtime-provider integration and HTTP gaps remain open.

## 2026-09-12 Unified favicon standalone PASS / storage run58408 PASS

Storage run58408 passed301.365s (/tmp/goauthy-storage-current-full-fixed.log, exit0); predates schema95/current changes. Earlier broad-run noPVC logo mutation failure is not reproduced by this complete package run. It does not prove whole-repository completion.

Standalone81450 exited0 (/tmp/goauthy-favicon-live-fixed.log): favicon PNG/JPEG32px WebP, SVG sanitization, exact missing behavior, cache query, CSRF mutations without ETags and regular-logo preservation passed0.15s; logo live0.18s, retained-logo prepare0.29s and restart verify0.17s also passed. Retained favicon itself is not covered by the retained-logo fixture. Kind35350 is terminal exit1 (/tmp/goauthy-favicon-kind.log): build failed on provider_registry.go undefined context; import now fixed, no rerun yet. No cross-Pod favicon workflow evidence produced.

## 2026-09-12 Provider regexp startup fix verified / favicon live resumed

Parent replaced unsupported Go regexp White_Space property escapes with the exact supported Unicode whitespace code-point ranges. Provider DTO validation tests, including Unicode space acceptance, passed0.811s (/tmp/goauthy-provider-unicode-parent.log, session21823 exit0). Previous favicon live70099 failed during package initialization, before HTTP qualification. Current live81450 is running (/tmp/goauthy-favicon-live-fixed.log).

Favicon connected checks5724 passed branding85.447s, apidocs1.504s, cmd/goauthy4.095s (/tmp/goauthy-favicon-connected.log). Storage run58408 (predates schema95) remains the most recent full storage pass. Schema94/runtime favicon files are frozen; source-exact persisted upstream-provider schema95 is now delegated separately. Provider HTTP/runtime/encrypted-secret lifecycle remains incomplete.

## 2026-09-12 Favicon API connected / current checks restarted

Switched production client favicon GET/PUT/DELETE to ClientLogoHandler.Favicon and unified client_logos storage; removed legacy handler construction. Root /favicon.ico remains independent. Updated API catalog for exact lookup, updated cache query, normalized PNG/JPEG32px WebP, sanitized SVG and no ETag precondition. Handler/store integration tests5724 running (/tmp/goauthy-favicon-connected.log); no live favicon pass yet.

Provider DTO field/method collision was fixed as ResolveMetadataURL. Prior storage50633 stopped at compile; current full storage58408 restarted after the relevant fix (/tmp/goauthy-storage-current-full-fixed.log). Parent review requested Unicode whitespace fidelity for Rust regex versus Go regexp in provider DTO validation. Schema94 parent focused checks passed2.076s (/tmp/goauthy-favicon-migration-parent.log).

## 2026-09-12 Real MinIO theme/logo no-PVC recovery PASS

Real local MinIO qualification passed under race21.099s (/tmp/goauthy-no-pvc-theme-recovery.log, worker reported exit0). The opted-in test uses a fresh recovery directory after abrupt writer exit; exact client/provider SVG BLOBs, MIME/resolution/timestamps and typed theme/document JSON survived. Object listing records106 objects. Worker used a unique disposable bucket/container with generated credentials and confirmed owned-container cleanup. Initial endpoint URL-form attempt failed before writes; successful MinIO client endpoint was host:port.

Current filesystem reproduction56508 passed4.510s (/tmp/goauthy-theme-logo-dr-current.log). The earlier broad-run rejected mutation is not reproduced by this focused run; its cause remains unproven, and this is not a whole-storage-suite pass. Schema94 focused parent checks94987 are running (/tmp/goauthy-favicon-migration-parent.log); independent migration review delegated.

## 2026-09-12 Retained-logo Kind replacement PASS / broad run terminal FAIL

Kind run55844 exited0 (/tmp/goauthy-logo-persist-kind.log): retained SVG prepare0.69s, post-replacement live0.62s and exact retained SVG verification0.71s. Pod0 UID changed5ffea00f-ece9-423a-b964-137ead9f42ff to71a9c743-f37e-4240-b193-60113b79ff8f. Verification reads all three app Pods and deletes the owned fixture. One Kind host, not multi-host qualification.

Earlier whole-tree94119 is now terminal exit1 (/tmp/goauthy-all-tests-theme-integrated.log). It contains the already-fixed identity timestamp failure and an additional TestNoPVCThemeRecovery rejected recover-client_logos mutation. Current focused reproduction56508 is running (/tmp/goauthy-theme-logo-dr-current.log); no assumed stale-build explanation or whole-tree pass. Changes during this long run mean it is not a frozen final candidate. Favicon unification remains unfinished.

## 2026-09-12 Branding race PASS / legacy favicon cleanup PASS

Branding full race run2566 passed190.609s (/tmp/goauthy-logo-integrated-race.log); this precedes favicon runtime unification. Shared multipart decoding now supports favicon PNG/JPEG-to32px-WebP and SVG resolution; focused processing check passed1.637s (/tmp/goauthy-favicon-multipart.log).

Managed and DCR client deletion now removes legacy client_favicons in the same guarded transaction as unified logos and themes, preventing stale data surviving client deletion. Tests seed legacy and unified rows; denied/stale requests preserve both and authorized deletion clears both. Focused checks passed clients3.187s/DCR3.541s (/tmp/goauthy-legacy-favicon-delete.log).

Schema94 and favicon store/HTTP work remain in progress. The legacy table cannot represent new WebP/SVG writes; mixed-version favicon writers require draining/upgrading before switching traffic. Retaining the table does not establish mixed-version coherence. Static root /favicon.ico remains a separate supported asset.

## 2026-09-12 Logo retained restart and three-Pod HTTP PASS

Standalone retained-data run7543 passed live0.25s, prepare0.16s, verify0.16s (/tmp/goauthy-logo-persist-live.log, exit0). The exact uploaded SVG is read after a real stop/start from the same retained data directory. This is not no-PVC proof.

Kind run11414 passed cross-Pod logo HTTP before/after Pod0 UID replacement (2e16d1ca-5c2c-4d64-b29c-cc5095535a38 to541903c8-a8a0-433d-93a8-7efa419c0fd9; /tmp/goauthy-logo-kind.log, exit0). Fresh fixtures per phase. Retained-logo Kind run55844 is active separately (/tmp/goauthy-logo-persist-kind.log); no result claimed yet. Real MinIO theme/logo recovery is delegated using GOAUTHY_THEME_RECOVERY_S3; default opt-out recovery regression passed3.483s.

Pinned provider DTO/schema audit establishes missing persisted upstream admin CRUD, enabled runtime refresh, PKCE/auth-style settings, auto-onboarding/link and claim mapping. These remain unfinished; separate SaaS functionality cannot satisfy them. Source-exact provider DTO/validation work is delegated independently of favicon schema94 migration.

## 2026-09-12 Client logo standalone live PASS / Kind started

Standalone run65288 passed TestClientLogoLive in0.19s (/tmp/goauthy-logo-live-fixed.log, exit0): PNG upload produces decodable84px WebP, SVG replacement strips executable markup, public cache/CSP headers, unauthorized mutation rejection, delete fallback and global-logo preservation. Initial run24908 found GetFallback selected only small raster rows; it now selects small or SVG, with a local precedence regression passing2.939s. Independent sanitizer audit identified double-quote CSS URL filtering and empty-fragment divergence; both corrected, focused SVG tests passed0.837s. Style serialization issue was already fixed and tested.

Kind run11414 started (/tmp/goauthy-logo-kind.log, cluster goauthy-logo-ha) with the live logo test across three app Pods before and after replacement. These use fresh fixtures each time; retained-logo replacement verification is separately delegated and not claimed. Upstream auth-provider lifecycle audit confirms file-only runtime configuration and missing persisted admin CRUD, separate from SaaS providers; provider-logo table recovery is not provider feature completion.

## 2026-09-12 Client logo routes and API catalog connected

Mounted client-logo GET/PUT/DELETE and documented public image response, updated query, multipart upload and Clients.Update permissions. Focused API catalog/route checks passed apidocs1.317s and cmd/goauthy4.050s (/tmp/goauthy-logo-route-docs.log, session15010 exit0). This does not prove live endpoint behavior.

Added the standalone GOAUTHY_E2E_LOGO branch and synchronized feature/mapping ledgers. Live test is still under worker ownership: parent review requested CSRF headers for authenticated mutations, draining successful upload responses, and third-node coverage. HTTP worker is finishing test helpers; parent test attempt hit in-progress compile errors (/tmp/goauthy-logo-http-parent.log), not a passing HTTP qualification. Independent sanitizer review remains pending. SVG-hush license attribution was added by the sanitizer worker.

## 2026-09-12 Theme and logo fresh-directory recovery PASS

Extended TestNoPVCThemeRecovery with client and authentication-provider SVG logo BLOBs, content types, resolutions and timestamps. After abrupt writer exit, a separate fresh data directory recovers both tables byte-for-byte from the filesystem-backed object store without running migrations first. Race check passed23.477s (/tmp/goauthy-theme-logo-dr-race.log, session1693 exit0). This validates storage recovery, not provider HTTP lifecycle or real S3 logo recovery.

Branding integration run30776 passed83.927s before the latest review fixes. SVG style serialization now escapes filtered text and includes an output-reparse injection regression; logo replacement rejects mixed SVG/raster batches and favicon writes. Parent focused verification runs73211 and42689 are pending. Client logo HTTP implementation and live E2E remain delegated; independent sanitizer audit is pending.

## 2026-09-12 Identity full regression PASS / logo integration review

Complete identity regression after the monotonic login-location timestamp fix passed in335.190s (/tmp/goauthy-identity-after-monotonic.log, session38391 exit0). Original full-tree94119 is confirmed still live and remains an earlier candidate containing the pre-fix failure. No whole-tree pass claimed.

Started current branding integration check (/tmp/goauthy-logo-branding-integrated.log, session30776). Parent review identified two cases requiring verification before HTTP mounting: decoded SVG style text is serialized without XML escaping, and the asset batch validator permits SVG and raster representations together despite lookup assuming exclusive SVG replacement. Workers are addressing these with regressions. Five Luna workers now cover raster, SVG, storage, client HTTP, and independent sanitizer audit. Logo routes remain unmounted pending review.

## 2026-09-12 Pure-Go WebP dependency connected / raster checks isolated

Added github.com/HugoSmits86/nativewebp v1.3.0; its existing dependency requirement advances golang.org/x/image from0.18.0 to0.24.0. This supports CGO_ENABLED=0 WebP output. Raster review identified crop-before-scale versus pinned image.resize_to_fill scale-before-crop ordering; worker is aligning rounding/order and guarding intermediate memory expansion.

Initial branding package check hit incomplete concurrent SVG declarations (/tmp/goauthy-logo-raster-initial.log), so raster checks now run explicitly against its two source/test files (/tmp/goauthy-logo-raster-isolated.log). This is not full branding integration evidence. Identity after-fix and original broad suite remain active; no terminal result inferred from quiet redirected logs.

## 2026-09-12 Location ordering repeated race PASS / logo client cleanup PASS

The deterministic older-request timestamp and concurrent one-winner checks passed five repetitions under race in74.246s (/tmp/goauthy-location-monotonic-race.log). Both browser-ID and IP-only updates preserve monotonic last_seen and every login count. Started complete identity regression after the fix (/tmp/goauthy-identity-after-monotonic.log); original whole-tree94119 still contains the now-fixed earlier failure.

Extended existing managed/DCR deletion transactions to remove all client_logos resolutions, including favicon, only after authorized deletion. Existing real DB regressions now seed both small+favicon assets and verify denied/stale requests preserve them; race passed clients8.368s/DCR9.198s (/tmp/goauthy-logo-client-delete.log). LogoStore authorized replacement/fallback implementation is delegated separately; raster/SVG work continues. No logo endpoint or full logo parity claimed.

## 2026-09-12 Token-event Kind notification/replacement PASS / location ordering fix

Kind run89846 exited0 (/tmp/goauthy-token-events-kind.log). Machine, user and Device token event tests passed through three Pod forwards before/after replacement with SMTP notification checks enabled. Pre-replacement machine event IDs were verified after replacement before fresh issuance. DCR and login-location revoke checks also passed. One Kind host; no independent-host chaos claim.

Whole-tree94119 exposed TestRecordBrowserLoginLocationConcurrentOneWinner failing with a rejected SQL mutation. Inspection found last_seen>=first_seen constraint can fail when a request captures an earlier timestamp but executes after a later request. Both browser-ID and IP-only update paths now use MAX(existing last_seen, request time). Added deterministic backwards-timestamp regression and started repeated concurrent/race checks (/tmp/goauthy-location-monotonic-race.log). No fix verification pass claimed yet; this production change makes the ongoing broad run an earlier candidate.

## 2026-09-12 Client/provider logo port started

Inspected pinned src/api/src/clients.rs logo GET/PUT/DELETE and src/data/src/entity/logos.rs processing contract: global-client fallback, optional updated-query cache header, separate favicon preservation, SVG filtering and PNG/JPEG-to-lossless-WebP cropped variants. Added schema93 client_logos/auth_provider_logos resolution tables and idempotency/constraint regression (running /tmp/goauthy-logo-schema93.log). Runtime storage/HTTP/lifecycle wiring is not implemented yet.

Luna tasks cover bounded raster processing and exact svg_hush sanitization analysis/port. A pure-Go WebP encoder candidate was downloaded for source inspection, not yet added as a build dependency. The existing full-tree94119 run began before schema93 and remains an earlier candidate; it must not be called final logo integration evidence. Kind token-event run89846 continues independently using its captured image.

## 2026-09-12 All token-flow SMTP notifications PASS / Kind token qualification launched

Corrected info-threshold notification run60800 exited0 (/tmp/goauthy-token-events-notifications-info.log). Device, machine CC/exchange and user auth-code/password event tests all passed with actual recipient mailbox checks keyed by durable event IDs. General notification checks passed again after application restart, followed by machine-event persistence. This is standalone delivery/restart evidence, not cross-host delivery.

Reviewed and extended the existing Kind runner with opt-in token generation, machine event persistence checked before new post-replacement issuance, user/Device checks through three Pod forwards, and optional SMTP notification configuration at explicit info threshold. Shell syntax/port-scope checks passed. Started run89846 at59730, cluster goauthy-token-events-ha (/tmp/goauthy-token-events-kind.log), with token events, login-location SMTP fixture and notifications enabled. No Kind result claimed yet.

## 2026-09-12 Token notification threshold mismatch identified and corrected

Notification run75932 exited1 after token-event mail waits expired. Production configuration inspection showed TokenIssued defaults to info while the email notification threshold defaults to warning; the earlier warning Test events correctly delivered. Updated only the combined standalone token-notification fixture to explicitly set GOAUTHY_EVENT_NOTIFICATION_EMAIL_LEVEL=info. Production severity/threshold defaults remain unchanged. Started corrected live run at59710 (/tmp/goauthy-token-events-notifications-info.log); no token-mail delivery pass claimed yet.

## 2026-09-12 Device disabled-event PASS / notification qualification started

Disabled token batch43099 exited0 (/tmp/goauthy-device-token-events-disabled.log), including Device and user event absence plus machine persistence checks. Extended the existing event-notification waiter to cover user auth-code/password and Device event IDs as well as machine CC/exchange, without changing production notification handling. Started actual combined SMTP notification run75932 at59710 (/tmp/goauthy-token-events-notifications-live.log); no delivery result claimed yet.

Luna is wiring opt-in three-Pod token-event checks and pre-replacement event persistence into the existing Kind runner. Current whole-tree run94119 remains active; its log has progressed through command packages, account/admin and API docs.

## 2026-09-12 Chromium light/dark theme PASS / Device token event enabled PASS

Actual Chromium run47814 exited0 (/tmp/goauthy-theme-ui-light-dark.log): TestThemeLoginUI passed1.00s, proving unauthenticated OAuth login CSS loading, explicit light-mode computed colors, updated theme/cache URL, explicit dark-mode computed colors and no observed stylesheet CSP failures. CSS.supports and nonempty style assignment assertions prevent invalid-color inheritance from creating a false pass. The same standalone run also passed HTTP theme checks and retained-directory restart persistence. This qualifies the login surface in Chromium, not all admin/account/logo/theme-switch interfaces.

Enabled token batch4181 exited0 (/tmp/goauthy-device-token-events-live.log), including TestTokenIssuedDeviceEvents0.51s, machine/user events, and machine-event restart persistence0.14s. Dedicated Device user/client assertions verify pending/denied polls emit zero events and successful polling emits exactly one device_code event with expected metadata. Disabled Device run is active (/tmp/goauthy-device-token-events-disabled.log); cross-Pod token event/notification qualification remains incomplete.

## 2026-09-12 Pinned global CSS equality verified / full-tree candidate started

Compared embedded internal/branding/global.css directly with `git -C ../rauthy show v0.36.2:frontend/src/css/global.css` using cmp: byte-for-byte identical. Device TokenIssued opt-in test is now included in the standalone token batch; its dedicated fixture/assertion corrections are still in progress, so it has not been live-qualified.

Started current full-tree `go test -p 1 ./... -count=1 -timeout=30m` (/tmp/goauthy-all-tests-theme-integrated.log) after production theme/CSP/client-lifecycle integration. This does not enable gated live E2E; completion and failures will be recorded from the actual process result. Browser light/dark media-emulation tests are still being finalized separately.

## 2026-09-12 Chromium theme rendering reached / color-mode fixture correction

Actual Chromium run52407 reached rendered login styles, then failed computed-color comparison (/tmp/goauthy-theme-ui-corrected.log). Observed rgb(194,192,188) text / rgb(9,17,21) background correspond to the pinned dark theme, while the fixture expected custom light colors. The test did not control prefers-color-scheme. Worker is adding explicit light/dark media emulation and distinct theme values to qualify both modes. No production CSS was changed to bypass correct dark-mode behavior, and no visual success is claimed.

User token event enabled/disabled qualification is now reflected in the feature ledger; Device event qualification remains under development with dedicated user/client isolation and pre-issuance zero-event assertions.

## 2026-09-12 User TokenIssued enabled live PASS / login regression PASS

User-event run3845 exited0 (/tmp/goauthy-user-token-events-correct-contract.log): TestTokenIssuedUserEvents passed0.72s, machine event test and restart event persistence also passed. Verified user auth-code/password exact event payloads, refresh suppression, and no additional events from replayed code or invalid password. Corrected fixture status expectations to OAuth invalid_grant HTTP400 (including error body) and user deletion HTTP204. Disabled-event run2982 exited0, user event test0.67s and machine persistence0.10s (/tmp/goauthy-user-token-events-disabled.log); user/Device HA/notification closure remains incomplete.

Complete current login/cmd regression passed214.704s/133.995s (/tmp/goauthy-login-theme-full.log). First live Chromium theme run67002 failed at managed-client fixture creation HTTP400 before opening the browser; it is not visual evidence. Worker is aligning that request with the actual create contract. No production behavior changed to satisfy these fixture failures.

## 2026-09-12 Retained-theme Kind Pod replacement PASS / user-event fixture corrected

Kind run72073 exited0 (/tmp/goauthy-theme-persist-kind.log). TestThemePersistPrepare passed0.91s, goauthy-0 changed UID, and TestThemePersistVerify passed1.00s using the exact pre-replacement theme state; ordinary ThemeLive and DCR checks also passed afterward. The verification reads JSON and compressed CSS through all three explicit Pod forwards before cleaning the owned client. One Kind host, not independent-host DR.

User TokenIssued live47619 and diagnostic78613 failed because the bootstrap account has a recovery email binding but no identity_user_profiles email. Verified from main's recoveryService.BindEmail path and ProfileClaimsBySubject's separate profile query. The signed ID token verified successfully but omitted email; this was a test fixture assumption, not evidence of broken token signature/issuance. Updated the test to create/activate an owned ordinary user with a real profile via existing admin helpers and clean it afterward. Run83622 is active (/tmp/goauthy-user-token-events-real-user.log); no user-event success claimed yet.

## 2026-09-12 User TokenIssued qualification runner wired

Added TestTokenIssuedUserEvents to the existing standalone PROFILE_CLAIMS/TOKEN_EVENTS batch. Compile-only gated check passed0.787s (/tmp/goauthy-user-token-events-compile.log); this is not live evidence. Review corrected planned event expectations to distinguish before/after password issuance and to use profile email rather than login username. The worker is finishing these assertions before live execution.

Current full login/cmd regression run41241 is active (/tmp/goauthy-login-theme-full.log), after stylesheet/CSP integration. Kind retained-theme replacement run72073 remains active in image builds; it has not been restarted or declared failed based on log silence. No new HA or user-event result claimed.

## 2026-09-12 Theme retained-directory restart PASS / final page integration checks PASS

Standalone run99256 exited0 (/tmp/goauthy-theme-page-persist-live.log): TestThemeLive0.38s, TestThemePersistPrepare0.24s, then application stop/start and TestThemePersistVerify0.16s. Verification loads the theme created before restart and confirms JSON/CSS before cleanup; no theme recreation substitutes for persistence. Same retained data directory, not object-store recovery.

Final focused page/store/main checks passed login9.631s/branding32.985s/cmd0.988s (/tmp/goauthy-theme-page-integration-final.log); integrated vet exited0 (/tmp/goauthy-theme-page-vet.log). Started Kind run72073, cluster goauthy-theme-persist-ha at59730 (/tmp/goauthy-theme-persist-kind.log), now with explicit pre-replacement prepare and post-replacement verify. Automated Chromium computed-style qualification is being added; no visual outcome claimed yet.

## 2026-09-12 Login theme stylesheets mounted / restart persistence live launched

Main now sets the login ThemeURLResolver to ThemeStore.StylesheetURL and serves pinned global CSS at /auth/v1/theme/global.css, with matching OpenAPI entry. Login/FedCM/device page integration uses escaped stylesheet links and same-origin style CSP. Included the pinned Apache-2.0 license for copied CSS separately from the project's MIT license. An initial injection regression incorrectly rejected safely percent-encoded closing-tag text; worker corrected the test rather than weakening html/template behavior. Final focused integration checks are running in /tmp/goauthy-theme-page-integration-final.log.

Standalone theme runner now prepares a persisted theme, restarts the same application data directory, then verifies and cleans that preexisting theme. Live run99256 started at59710 (/tmp/goauthy-theme-page-persist-live.log). This will test retained-data-directory restart, not no-PVC recovery; the independent filesystem-object-store recovery test supplies the latter evidence. No restart result or visual browser qualification claimed yet.

## 2026-09-12 Theme Kind three-Pod HTTP qualification PASS

Run24431 exited0 (/tmp/goauthy-theme-kind-ha.log), cluster goauthy-theme-ha at port59730. TestThemeLive passed0.47s before and0.38s after goauthy-0 replacement, with DCR backchannel and URI update/removal tests also passing both phases. The test writes through primary, reads JSON and unauthenticated compressed CSS through three explicit Pod forwards, then deletes the override and verifies fallback across those forwards.

This is one Kind host with three app Pods. Each TestThemeLive invocation creates/cleans its own client/theme, so it does not prove a pre-replacement theme survived replacement; a dedicated prepare/verify persistence phase is under development. This image predates in-progress login-page/global CSS integration. Feature/package mapping updated accordingly. User auth-code/refresh/password TokenIssued qualification is being added separately; no result claimed yet.

## 2026-09-12 Final unauthenticated theme E2E PASS / Kind launched

Frozen final standalone test run18082 exited0: TestThemeLive passed0.21s, package0.761s (/tmp/goauthy-theme-live-final.log). This final run began after the worker froze its unauthenticated CSS clients and explicit gzip/br/none assertions. The earlier snapshot caveat is closed for standalone HTTP only.

Added effective-CSS versioned StylesheetURL generation with escaped client IDs. Its real store test passed1.784s (/tmp/goauthy-theme-css-url.log): a global fallback update changes the URL, deleting the override restores the default URL, and the version satisfies signed-int64 public path validation. Login/device/FedCM stylesheet link integration is under development; this does not yet prove visually themed pages.

Reviewed opt-in theme checks before/after replacement in existing DCR Kind runner; shell syntax and port-scope regression passed. Started actual one-host three-app-Pod Kind theme qualification at port59730, cluster goauthy-theme-ha (/tmp/goauthy-theme-kind-ha.log). No HA result claimed yet.

## 2026-09-12 Standalone theme HTTP live PASS

Actual disposable standalone run24231 exited0 (/tmp/goauthy-theme-live-standalone.log): TestThemeLive passed0.27s, package1.024s. It exercises real admin login, managed client creation, custom theme PUT/POST, CSS compression roundtrips, override deletion and built-in fallback with client cleanup. All configured node URLs point to this same standalone instance; this is not HA or restart-persistence evidence. The live test now also uses an unauthenticated CSS client and explicit encoding assertions; final assertion snapshot verification remains to be confirmed with the worker.

Pinned AcceptEncoding comparison found invalid header text must fall back to identity; reused shared header validation and handler regression passed5.889s (/tmp/goauthy-theme-header-parity.log). Additional actual-store bootstrap/dynamic/missing/disabled-managed client-kind tests passed6.008s (/tmp/goauthy-theme-client-kinds.log). Full theme frontend rendering and HA qualification remain incomplete.

## 2026-09-12 Theme atomic client fence and DCR cleanup race PASS

ThemeStore.PutAuthorized now checks nondeleted managed, static-bootstrap or dynamic client existence inside the API-key guarded SQL upsert transaction. It returns clients.ErrNotFound when authorization succeeds but no client remains. Deleted-managed-client/revoked-key race regressions passed13.845s (/tmp/goauthy-theme-client-fence.log), closing the previously documented preflight deletion window. The write/delete serialization is now protected by the same database transaction; extra client-kind coverage is underway.

DCR DeleteRegistration now removes client_themes in its existing registration-token guarded transaction. Parent race regression passed7.715s (/tmp/goauthy-theme-dcr-delete-race.log), proving wrong tokens preserve themes and valid deletion removes them. Integrated theme HTTP/store and main route tests passed branding8.238s/cmd0.983s (/tmp/goauthy-theme-http-integrated.log), including compressed response checks. Added opt-in standalone GOAUTHY_E2E_THEME runner with shell syntax check; live test authoring remains in progress, so no live result claimed.

## 2026-09-12 Theme route coverage and managed-client cleanup race PASS

Main theme client existence lookup now includes static bootstrap, disabled/nondeleted managed clients and dynamic registrations; lookup failures propagate instead of treating database errors as missing clients. Mounted route/OpenAPI coverage test passed0.990s (/tmp/goauthy-theme-route-integration.log), and integrated cmd/branding/clients vet passed (/tmp/goauthy-theme-integrated-vet.log). These are compile/contract checks, not live HTTP qualification.

Reviewed managed-client theme cleanup in the existing guarded deletion transaction. Parent race regression passed7.605s (/tmp/goauthy-theme-client-delete-race.log): denied/stale deletion preserves the theme; successful client deletion removes it. Dynamic registration deletion cleanup is now being implemented separately. Remaining theme gap: client existence preflight and theme upsert are not yet atomically fenced against concurrent client deletion; a transaction-level existence guard is still required before claiming complete lifecycle parity. HTTP worker is completing Brotli and exact pinned input acceptance checks.

## 2026-09-12 Current login package PASS / theme route integration underway

Current-source complete internal/login tests passed106.173s (/tmp/goauthy-login-current-full.log), clearing the historical mixed-source compilation failure from run31710 for that package. Theme OpenAPI/default-JSON/action-range and invalid typed email-theme checks passed apidocs1.609s/recovery0.792s (/tmp/goauthy-theme-contract-mail.log).

Main now constructs the theme handler using managed client lookup that includes disabled clients and mounts public CSS plus POST/PUT/DELETE configuration routes. Handler remains under active implementation/review; no runtime or route integration pass claimed yet. Review identified favicon-only client-ID restrictions, unrequested query/unknown-field rejection and missing Brotli encoding; these are being corrected against the pinned contract. Pinned theme FK deletes on client deletion; the corresponding local soft-delete transaction cleanup and regression are delegated.

## 2026-09-12 Theme filesystem object-store DR race PASS / API contract prepared

Reviewed Luna's fresh-directory theme recovery test: separate writer/recovery subprocesses, abrupt writer exit, existing object-store export configuration, recovered schema readiness, exact JSON row and typed Theme equality. Parent independently ran `go test -race ./internal/storage -run '^TestNoPVCThemeRecovery$' -count=1 -timeout=3m`: PASS13.329s (/tmp/goauthy-theme-dr-race.log). This covers filesystem-backed object storage, not a new S3 or multi-host run.

Added theme OpenAPI route/body/response contracts while HTTP implementation and mounting remain in progress. Catalog tests passed2.499s before the final action-field contract correction. Requested exact pinned action semantics: the source omits action range validation, so typed uint16 triples must remain accepted rather than imposing an extra range restriction; other HSL fields retain source bounds.

Whole-tree run31710 exited1. Its only failure was the previously observed mixed-source browser policy symbol compilation failure in internal/login; all other listed packages passed, with live E2E opt-ins not enabled by that command. Current login package full verification is running separately (/tmp/goauthy-login-current-full.log); no whole-tree success claimed.

## 2026-09-12 Login-location Kind replacement PASS / typed email theme and guarded mutations

Actual Kind run68161 exited0: DCR backchannel logout and URI update/removal passed before and after goauthy-0 replacement; TestLoginLocationRevokeLive passed0.98s/1.05s, including recipient SMTP link, session rejection and replay behavior. Evidence: /tmp/goauthy-login-location-kind-ha.log. This is one Kind host with three app Pods, not three independent hosts, and its build predates the latest email-theme integration.

Typed validated persisted global Theme now supplies login-warning email CSS. Real SMTP observer and mail focused checks passed cmd5.759s/recovery1.781s (/tmp/goauthy-login-mail-stored-theme.log). ThemeStore API-key mutations now use the existing atomic authorization guard with Clients.Update/Delete; real DB regression proves a previously authenticated revoked key cannot update or delete the stored theme, while browser-admin deletion succeeds. Focused store tests passed3.325s (/tmp/goauthy-theme-guard.log). HTTP mounting and theme DR remain in progress; no full theme feature completion claimed. Luna workers own HTTP implementation, typed CSS verification, mail invalid-theme regression, theme DR and HA evidence review in disjoint scopes.

## 2026-09-12 Theme store CRUD/fallback PASS / login-location Kind launched

Implemented ThemeStore on schema92 with linearizable reads, validated JSON writes, deletion, and separate admin built-in-default versus public global-theme-fallback behavior. Unknown stored versions restore default color fields while retaining client identity/border radius. Real Rhiza cross-store regression passed2.138s (/tmp/goauthy-theme-store.log): override visibility, rejected invalid CSS preserving old state, version fallback and deletion exposing the appropriate parent/default. Typed CSS worker remains responsible for detailed parity tests; HTTP/mailer runtime integration is not complete.

Reviewed corrected SMTP Kind opt-in, ran shell syntax and port-scope regression, and launched actual three-app login-location plus DCR qualification68161 (/tmp/goauthy-login-location-kind-ha.log), cluster goauthy-login-location-ha port59601. No HA result claimed yet. Original full-tree31710 has passed OAuth367.411s/OIDC39.081s/passkey47.754s but remains mixed-snapshot with historical login compiler failure.

## 2026-09-12 Theme port started / schema92 verified

Read pinned theme API/types/entity: public timestamped CSS with default/fallback semantics, authenticated JSON read/update/delete, validated theme fields, and email light-theme variables. Theme storage is a required missing feature, not a permanently excluded scope. Added schema92 client_themes JSON-document/version/timestamp persistence. Real Rhiza migration test passed1.079s (/tmp/goauthy-theme-schema92.log), proving repeat migration and malformed/non-object JSON rejection. Store, HTTP wiring, dynamic mail theme and DR/HA remain incomplete. Luna owns typed theme defaults/validation/CSS; parent owns schema/store integration.

Reviewed in-progress Kind SMTP extension and requested fixes for shared temporary patch path, SMTP image override, reset-key format and app egress policy before execution. No new Kind qualification run has started. Original full-tree31710 remains mixed-snapshot evidence, now predating schema92.

## 2026-09-12 Whole-tree compile PASS / HA revoke assertions

Current whole-tree compile-only60024 exited0 (/tmp/goauthy-current-tree-compile.log). This confirms the older full-run missing BrowserIDPolicy symbols were a mixed-source build issue, not a current unresolved compiler failure. No behavior tests were executed by this compile gate. Original full behavior31710 continues beyond notify and retains that historical failure.

Expanded actual-login revoke E2E to check old-session rejection on each distinct primary/secondary/tertiary URL, avoiding duplicate standalone probes. Extraction/test compilation passed0.718s (/tmp/goauthy-revoke-ha-test-compile.log); new cross-node assertions are not yet live-qualified. Assigned bounded Kind opt-in SMTP/registration fixture integration to existing DCR runner while preserving image-stream and port-scope fixes. Parent owns E2E test; worker owns runner plus isolated SMTP manifest. Actual HA and post-replacement results remain pending.

## 2026-09-12 Real login-to-email-to-revoke E2E PASS / S3 run started

Worker integration audit found runner/test names and opt-in variables mismatched. Parent aligned TestLoginLocationRevokeLive and GOAUTHY_E2E_LOGIN_LOCATION, then repaired a raw-regexp overescape that excluded literal s/r/n. Added a passing synthetic extraction regression0.692s. Actual standalone5848 exited0: real public activation, browser login, SMTP warning, public revoke, original-session rejection and generic replay refusal passed0.38s (/tmp/goauthy-login-location-live.log). This is actual-login integration, not the earlier direct observer test, and not HA.

S3 worker's ephemeral loopback connection failure was not reproduced with an isolated MinIO on fixed port59540: host readiness returned0. Created disposable login-revoke bucket using mc over the observed container IP (Dory rejects container-network mode because of injected host mappings). Actual S3 race45310 exited0 in15.662s (/tmp/goauthy-login-revoke-real-s3.log), proving the same fresh-directory encrypted-code/location recovery and redemption/replay checks with real MinIO. Removed owned goauthy-login-revoke-s3-check container after completion. This is not multi-host or physical-power-loss proof.

Full-tree31710 encountered login compilation against an earlier browser package snapshot (new policy symbols unavailable while files changed during the run). Current focused builds already passed those symbols; this full run is mixed-snapshot evidence and must not be called a final candidate. Leave it running to collect other package failures; rerun required gates after implementation stabilizes.

## 2026-09-12 Login-location subject prefix runtime PASS

Connected GOAUTHY_EMAIL_SUB_PREFIX to emitted login-location mail, defaulting only when unset to pinned rauthy_config.rs:407's Rauthy IAM. Explicit empty values are preserved and startup rejects line breaks. Actual observer/SMTP test confirms configured subject prefix; focused cmd tests passed6.285s (/tmp/goauthy-login-location-prefix-wiring.log). Integrated cmd/recovery vet20517 exited0.

Reviewed worker theme rendering fields but found no persistent theme store in current branding package (favicon only); no raw external CSS setting was invented. Theme runtime integration remains incomplete. Requested worker preserve exact unconditional prefix formatting rather than trimming/omitting, matching pinned email/login_location.rs. S3 opt-in was reviewed for FS environment isolation; actual worker S3 result requested rather than inferred.

## 2026-09-12 Browser-ID policy runtime wiring PASS

Reviewed Luna BrowserIDPolicy and connected per-instance configuration to login-page issuance, browser reads, and password-grant reads. Modes host/secure/danger-insecure and cookie-set-path are exposed through GOAUTHY_BROWSER_ID_COOKIE_MODE/GOAUTHY_BROWSER_ID_COOKIE_SET_PATH, with existing issuer-derived defaults. Focused policy/runtime tests passed browser0.582s/login3.281s/cmd7.155s (/tmp/goauthy-browser-id-policy-wiring.log), including configured reader/writer agreement and invalid configuration. Integrated vet49195 exited0.

Documented that /auth-scoped cookies do not reach /oidc routes and therefore use IP fallback there; broader upstream routes/session-cookie settings remain incomplete. Worker retains remaining primitive tests, while mail/S3/real-login E2E work continues in disjoint files. Full-tree31710 reached credential with no failure observed in its log; its earlier compiled packages predate this configuration.

## 2026-09-12 Synchronous login-location lookup failures

Login location callbacks now return synchronous lookup errors rather than silently replacing them with nil and continuing authentication. Main/password observer returns lookup failure before spawning notification work. Browser password flow returns generic500, and WebAuthn/MFA checks occur before replacement-session publication; response bodies do not expose lookup details. SMTP and persistence bookkeeping remain the upstream best-effort background stage. Focused integration passed login9.499s/cmd7.136s (/tmp/goauthy-location-error-propagation.log), integrated vet passed. A nil-store lookup-failure regression verifies no background path starts, plus actual password HTTP failure/no-success-response privacy coverage.

Five bounded Luna assignments cover browser-ID policy, login email theme/prefix, S3 recovery, actual login-to-SMTP E2E, and its standalone runner. Parent owns callback/runtime changes. Full-tree31710 remains live and has reached authcollection after cmd/apikey passes; this run's earlier compiled packages predate these callback edits, so final-candidate evidence must account for the delta.

## 2026-09-12 OAuth full suite PASS / live token-event restart evidence

Caller30597 terminated exit1 solely retaining the previously repaired cmd expectation failure; OAuth completed successfully391.074s. Cmd retry independently passed67.071s. Neither establishes the later full tree. New full-tree candidate test is running (/tmp/goauthy-all-tests-login-location-candidate.log), covering accumulated login-location changes and fixed fixtures.

Inspected standalone log /tmp/goauthy-token-events-current-standalone.log: AdminUIHTTP0.15s, ProfileClaimsLive1.39s, TokenIssuedEvents0.36s, and post-restart TokenIssuedEventsPersisted0.13s passed. Seven UI/event-notification cases were explicitly skipped; no HA or those-feature completion claim. Worker terminal/cleanup confirmation requested. Updated unknown-login feature ledger to reflect actual implemented lifecycle and reviewed focused/SMTP/no-PVC evidence while keeping cookie/error/theme/full integration gaps open.

## 2026-09-12 Login header validation integrated

Introduced shared security.ValidHeaderText for the pinned nonempty visible-ASCII/HTAB rule and reused it for location headers and browser/password-grant UA validation. This closes non-ASCII UA acceptance at existing password and WebAuthn/MFA checks without duplicating the rule. Focused integration passed security0.461s/geoblock0.654s/login11.620s/cmd2.024s (/tmp/goauthy-login-header-text-integration.log); scoped integrated vet exited0. These are focused tests, not four full package gates.

Assigned a bounded Luna qualification to the existing standalone profile-claims/token-events batch on port59510, including restart persistence, with /tmp/goauthy-token-events-current-standalone.log as requested output. No run result or live handle has been reported yet. This will be standalone evidence, not HA. Original full caller30597 remains the source for pending OAuth verification and retains its repaired cmd failure.

## 2026-09-12 Full command retry PASS / header string parity

Full cmd/goauthy retry8247 exited0 in67.071s (/tmp/goauthy-command-after-rewrap-fix.log) after the rewrap fixture correction. Original caller30597 retains its earlier cmd failure and continues OAuth; it must not be reported as a wholly passing run.

Pinned Cargo.lock includes http0.2.12, whose inspected local HeaderValue.to_str implementation permits visible ASCII and horizontal tabs only. RequestLocation now uses that exact character rule before accepting a trusted location header; non-ASCII/control values fall back to DB, tabs remain allowed. Full geoblock tests passed0.758s (/tmp/goauthy-location-header-ascii.log), including the new boundary cases. Existing cookieShape has no configurable mode/path; that parity gap remains open rather than introducing a competing configuration silently.

## 2026-09-12 Passkey UA boundary / rewrap regression fixture

Added missing-UA rejection for WebAuthn/MFA at the common browser-session transition when location observation is configured, before creating or publishing a session. The consumed-authentication handler maps the specific error to400. Real store regression checks no session rows/cookies and no notification; passed2.491s (/tmp/goauthy-passkey-location-ua.log), login vet passed. Existing external-provider transitions keep their separate contract.

Full caller30597 reported cmd failure in TestMasterKeyRewrapRunFamilyTimeoutAllowsLaterTickRecovery: expected10 family contexts but the newly added login-revoke family correctly makes12 across two ticks. Parent updated the test to exercise login-revoke explicitly and waits for its second invocation before canceling, instead of merely changing the count. Focused race71900 exited0 (/tmp/goauthy-rewrap-new-family-regression.log); full cmd package retry is running (/tmp/goauthy-command-after-rewrap-fix.log). Full caller process continues OAuth; do not claim all-green or restart it.

## 2026-09-12 Browser-ID issuance ordering parity

Pinned api/oidc.rs:269-270 issues rbid while rendering login HTML. Moved local cookie issuance to authorization/FedCM login page rendering; recordLoginLocation now uses only the request's existing ID and leaves missing IDs empty for IP-only novelty matching. It no longer invents a new ID during notification. Regression verifies page cookie issuance, no-ID first observation, and reuse of a subsequent browser cookie; combined password/MFA and browser-ID checks passed4.692s (/tmp/goauthy-location-first-browser-v2.log). Login vet passed.

Full caller30597 remains live; login package passed91.408s for its pre-cookie-ordering snapshot. Cmd/OAuth stages remain pending. Do not treat that old login snapshot as final coverage for this change. Remaining feature gaps include configurable cookie mode/path and complete passkey UA/geolocation error behavior.

## 2026-09-12 Password location before MFA / HTTP callback checks PASS

Moved browser password location notification to the shared successful authenticatePassword path, before MFA setup/completion. Missing UA is rejected when the observer is configured; wrong credentials never notify. Removed the duplicate password notification at session rotation while retaining other authentication methods there. Real handler regression verifies ordinary login emits once and correct-password/unenrolled-MFA emits before the 406 response. The first test expected503 incorrectly; inspection showed the fixture includes a passkey service and correctly returns406 for missing enrollment. Corrected focused check passed3.565s (/tmp/goauthy-location-pre-mfa-v2.log).

Reviewed real OAuth password observer HTTP test passed2.095s (/tmp/goauthy-password-observer-http-reviewed.log), covering authenticated subject, wrong password, non-password grant and callback-error response. Integrated login/cmd/oauth vet passed. Full login/cmd/oauth caller suites are running as30597 (/tmp/goauthy-login-location-final-callers.log); no full-candidate claim yet. Remaining gaps include cookie configuration/first-request semantics, passkey UA parity, geolocation error parity and broader feature qualification.

## 2026-09-12 DCR URI Kind qualification PASS / password location runtime

Kind23539 exited0 (/tmp/goauthy-dcr-uri-kind-port-scope.log). Actual TestDCRBackchannelLogoutAcrossPods and TestDCRPasswordBackchannelURIUpdateRemovalAcrossPods passed before Pod replacement (2.03s/7.00s) and after (1.30s/6.57s). This confirms the scoped port fix enables real tests; one Kind host with three app Pods is not three-host evidence. Qualification is for that build snapshot, before subsequent password-location edits.

Parent took OAuth server implementation ownership from worker to unblock integration; worker retains only real HTTP tests. Added successful password-grant post-issuance callback and main location observer wiring, with canonical peer context, required UA, existing optional browser cookie, and existing trusted-header/DB lookup and SMTP sender. No new cookie for password grant. Cmd metadata and SMTP observer tests passed4.276s (/tmp/goauthy-password-location-wiring.log); Integrated cmd/oauth/login/geoblock vet passed (/tmp/goauthy-password-location-vet.log); OAuth HTTP tests remain pending.

Pinned authorize.rs:110-114 additionally notifies after correct password even before MFA completion. Current common browser-session completion hook is later, so this ordering remains a concrete parity gap. Browser cookie creation/first-request matching and full UA boundary handling still need pinned-flow review. Overall login-location feature is not complete.

## 2026-09-12 Login-location IP-family parity / password grant hook started

Pinned LoginLocation stores Rust IpAddr.to_string. Parent found net.ParseIP.String collapsed IPv4-mapped IPv6 into native IPv4, changing IP-only novelty matching. RecordBrowserLoginLocation now uses netip.ParseAddr/String, preserves address family and rejects zones. All focused browser-location tests passed8.318s (/tmp/goauthy-location-ip-family.log), including equivalent IPv6 spelling, distinct native/mapped IPv4, and scoped-address rejection.

Pinned git grep confirms location checks in authorize, WebAuthn, and password grant. Password grant at src/service/src/oidc/grant_types/password.rs:134 performs the check after issuance. A bounded Luna worker owns OAuth server callback and real successful/failed password HTTP checks; main wiring and full UA contract still remain. Password BrowserId is extracted without automatically creating a cookie, so absent IDs must retain IP-only matching. Kind23539 remains live and has reached control-plane startup after builds.

## 2026-09-12 Kind port-scope root cause / trusted login location wiring

The 120-second port-forward retry67187 also exited2 before E2E. Parent traced wait_forward's assignment to global port: later offset expressions used the already-mutated value, making the sink probe target the wrong port. Changed the function body to a POSIX subshell in DCR backchannel, password-grant and forward-auth HA scripts. scripts/test-forward-wait-scope.py passes syntax/behavior checks and verifies that restoring the old global-scope function fails the same assertion. New Kind23539 runs /tmp/goauthy-dcr-uri-kind-port-scope.log. Prior timeout-only diagnosis was insufficient; no E2E success claimed.

Login observer now receives the request so main can resolve a configured location header only from a trusted immediate peer, otherwise use canonical IP database lookup. Revoke stays DB-only. Header configuration is retained without enabling country admission. Request-hook test passed0.805s; cmd configuration/SMTP observer cases passed4.280s and cmd/login vet passed. Initial combined check caught a worker test formatting issue; corrected combined v2 check passed (geoblock0.479s, cmd4.051s; /tmp/goauthy-location-header-integration-v2.log). Parent requested repeated-header first-value behavior to match pinned HeaderMap.get rather than introducing a parity difference.

## 2026-09-12 Login-revoke no-PVC race PASS / location-only configuration

Reviewed filesystem object-store recovery test passed with race instrumentation17.962s (/tmp/goauthy-login-revoke-no-pvc-reviewed-race.log): abrupt writer exit, fresh database directory, shared encrypted code preserved, schema91 browser locations restored, redemption deletes code/locations, replay rejected. Master-key fixture remains external and deliberately shared; this does not prove key backup, S3 or multi-host recovery.

Local MaxMind database now remains configured when country admission is disabled, so notifications/revoke locations do not require enabling a country filter. Focused TestGeoblockConfig tests passed (/tmp/goauthy-location-without-admission.log). User-deletion guarded cleanup was reviewed, including unauthorized deletion and injected late SQL failure rollback; parent race95907 passed14.136s (/tmp/goauthy-delete-location-reviewed-race.log). Kind67187 progressed from fixture builds to control-plane startup. Overall feature parity and broader gates remain incomplete.

## 2026-09-12 Reviewed geolocation wiring and terminal gate results

Parent revalidated handles: login-revoke core race56431 exited0 (71.063s); full login/browser/apidocs85766 exited0 (199.022s/10.128s/2.579s). Baseline whole-tree85247 exited1 with the three previously repaired command fixture failures; this is not a full passing candidate. Kind83471 exited2 after ready Pods, so DCR E2E remains unqualified; review shows fixture import and rollouts succeeded but port-forward readiness ended before test execution. After increasing the bounded startup wait from 5s to 120s (retaining process-liveness checks), parent launched a new qualification in /tmp/goauthy-dcr-uri-kind-forward-wait.log. The timeout diagnosis remains provisional until rerun evidence.

Shared configured MaxMind reader now supplies login record/event/MIME location and public revoke query-IP location. Login lookup is synchronous before detached notification work, so that work does not retain the reader. Parent compared pinned v0.36.2 Display and corrected present-empty city versus absent city semantics; full geoblock package passed0.639s. Integrated vet v2 caught an in-progress worker test unused import; after the test edit, integrated vet v3 exited0 for cmd/recovery/geoblock/login/identity/oidc. Parent HTTP query-IP lookup/fallback tests passed10.649s (/tmp/goauthy-login-revoke-location-http-reviewed.log). Real SMTP/location verification is pending. Header-only login geolocation, independent geo configuration/downloader, non-browser password coverage, UA behavior, and full DR/K8s/security qualification remain incomplete. New filesystem object-store no-PVC login-revoke recovery test was reviewed: abrupt writer exit, fresh data directory, preserved encrypted shared code and schema91 locations, redemption cleanup and replay rejection. Worker focused check passed; parent race76044 is running (/tmp/goauthy-login-revoke-no-pvc-reviewed-race.log). This is not S3 or multi-host proof. Five Luna workers cover SMTP integration, HTTP lookup, user-deletion cleanup, Kind failure diagnosis, and encrypted-code no-PVC recovery in disjoint files.

## 2026-09-12 Login-location caller suites / integrated vet started

Started full login/browser/apidocs caller suites85766 (`/tmp/goauthy-login-location-callers-full.log`) after common observer wiring and schema91. Started integrated identity/recovery/login/oidc/cmd vet (handle in tool output), `/tmp/goauthy-login-revoke-integrated-vet.log`. Neither is a completed gate yet. Kind83471 continues fixture-image build and baseline85247 remains live; no duplicate process started for either.

Geolocation lookup worker and real-SMTP observer integration worker continue. Remaining actual implementation includes sharing configured DB lookup with login/revoke paths, trusted-header semantics on login only, non-browser password flow coverage, production UA behavior, and full candidate DR/K8s/security validation.

## 2026-09-12 Login-location MIME complete / geolocation lookup gap

Heisenberg completed concrete SendLoginLocation MIME method and full recovery package tests (worker-reported pass); parent inspected sender reuse and bounded timeouts. Theme/prefix customizations remain gaps. Added bounded Luna worker for existing geoblock.MaxMindReader Location lookup only, reusing installed reader; no new updater/config/interface. Pinned ipgeo shows country-header lookup only after trusted proxy extraction for login, but revoke event uses DB-only lookup of query IP. These are distinct contracts and must not be conflated. Current handlers still pass nil location until wiring/verification.

Kind83471 remains live building bootstrap/fixture binaries (`/tmp/goauthy-dcr-uri-kind-mounted-stream.log`). Baseline85247 continues after recovery121.320s; no new failures beyond the independently repaired command fixtures observed.

## 2026-09-12 Login-revoke HTTP worker complete / OpenAPI added

Arendt completed locale-aware public HTML handler and realRhiza/keyring wrong-code/replay/malformed-IP/query-IP tests, reporting focused pass. Parent previously inspected the authoritative pinned handler directly; worker final linked line range is not authoritative. Geolocation still nil; no full feature completion claim.

Parent added always-present public revoke route to account OpenAPI, including required ip query, HTML200 response and shared/no-expiry/generic-error semantics. Focused catalog check99720 verifies route exists with password recovery disabled. Features ledger now says mounted, with end-to-end qualification pending, rather than stale unmounted. Kind83471 remains image-building; original full suite85247 progressed through recovery121.320s and retains repaired early command failures.

## 2026-09-12 Integrated compile PASS / mount-namespace Kind retry

Integrated compile-only91657 exited0 for cmd/goauthy,recovery,identity,oidc (1.001s,0.615s,0.747s,0.757s; `/tmp/goauthy-login-revoke-integrated-compile.log`). This is compilation, not new-feature behavioral validation. Reviewed LoginRevoke reference counts in status, safety and retirement, plus rewrap worker dispatch. Descartes reports OIDC full tests/vet pass and is now assigned only cmd/goauthy/login_location_test.go for real SMTP observer-to-HTTP-redemption integration; no mocked internal stores.

Launched corrected mount-namespace archive stream Kind qualification, `/tmp/goauthy-dcr-uri-kind-mounted-stream.log`; capture session from current tool output. This run evaluates DCR logout behavior on its build snapshot, not all subsequent login-revoke changes. Original whole-tree85247 continues with prior command failures already independently repaired.

## 2026-09-12 Login-location production observer wiring

Parent fixed raw-string backticks in core event SQL using SQLite char(96), after explicit handoff; no change to intended text. Login callback/cookie-retention test34739 now passed1.467s (`/tmp/goauthy-login-location-observer-retry.log`). Core worker retains remaining logic/tests ownership.

Added cmd loginLocationObserver and wired it to shared successful browser rotation. Bounded best-effort background work records browser-aware location, reads active profile/language, emits NewLoginLocation, obtains shared encrypted revoke code and sends existing SMTP MIME method with revoke/account links. Reuses recovery SMTP sender; separately configures sender when SMTP host is supplied without password recovery. It does not log codes or bearer URLs. Location geolocation is currently nil, production UA validation and non-browser password-grant coverage remain gaps. New browser location method is worker-owned/pending, so this intermediate wiring is not yet compiled/integration-tested. Must add real SMTP observer integration verification before claiming runtime completion.

## 2026-09-12 Login observer hook / revoke event bug found

Legacy IP-location tests on schema91 passed20.958s (93524, `/tmp/goauthy-location-legacy-schema91.log`); targeted migration2995 passed1.094s. Parent added optional login-location observer after the shared successful browser-session rotation, retaining/generated correlation cookie ID and passing subject/IP/UA. It is not yet wired to production observer service; no SMTP claim. Focused cookie-retention callback check11440 log `/tmp/goauthy-login-location-observer.log`.

Core review found RevokeLogin copied ForceLogout's output binding and replaced full UserLoginRevoke text with plain email. Peirce instructed to return committed full text from guarded statement and test exact persisted event. HTTP worker asked to retain typed-IP extractor distinction and implement pinned language selection; geolocation lookup remains missing. These reviews prevent claiming constructors alone prove persisted event/complete HTML parity.

## 2026-09-12 Schema91 browser-location migration implemented

Parent explicitly took migrate.go ownership from Peirce via interrupt/handoff, retained complete schema90 unchanged, and added91. The atomic rebuild preserves every existing subject/IP/first/last/count row, defaults legacy browser/UA to empty and location to NULL, and adds subject/IP/browser primary key plus browser lookup index. Current schemaVersion91. Aquinas notified that schema is available. Focused migration test2995 (`/tmp/goauthy-browser-location-migration.log`) checks old-row preservation, idempotent second invocation and a second browser sharing an IP. Result pending in this entry. It is a targeted migration fixture, not full DR qualification.

Core/key/HTTP/mail/location workers remain disjoint. No Kind run active; transport fix awaits compilable integrated candidate. Original full suite85247 remains baseline evidence, not this schema91 candidate.

## 2026-09-12 Browser-aware location storage assigned

Luna Aquinas (`01a09409-2aa4-7700-b124-8aba59061bdf`) owns only new identity/browser_login_location.go/tests, implementing browser-first matching with atomic new-location classification. Parent owns upcoming schema91 after Peirce releases migrate.go; preserve existing rows and add browser_id/user_agent/location with subject/IP/browser primary key. No automatic30day novelty reset is introduced because pinned upstream has none. Four other core/key/HTTP/mail workers continue, totaling five bounded workers.

Baseline whole-tree85247 now reports OAuth357.552s,OIDC32.913s,passkey55.357s passes; overall command remains live and retains the old repaired command failures. These compiled packages are not evidence for subsequent login-revoke/location changes. No Kind run currently active.

## 2026-09-12 Dory mount-namespace transfer cause verified

Luna reproduced the exact failure with a mounted /tmp: Docker cp writes a hidden underlying-rootfs path; successful copy is invisible inside the node. Streaming the saved archive through `docker exec -i ... cat > /tmp/...` produced matching 79,901,184-byte size and SHA-256 inside the mount namespace. Reviewed script fix and removed the now-unnecessary polling workaround; retain one node-side file check after synchronous stream completion. Disposable worker container removed. Full Kind retry waits for current core/HTTP implementation to compile; no live Kind run remains.

Current migrate.go already contains schema88 login locations and89 credential-stuffing, from preexisting work. Earlier entries naming new revoke schema88 were based on stale summary; core worker now explicitly instructed to preserve88/89 and use next unused90+. Existing schema87 feature evidence must not imply87 is the current highest schema. BrowserID focused test95136 previously exited0,0.843s.

## 2026-09-12 Browser correlation primitive / login-location SMTP worker

Luna Heisenberg (`01a09404-0985-72f1-82c3-bce4ee225c34`) is the fifth active bounded worker, owning only recovery/login_location_mail.go/tests and the new concrete SMTPSender method (no Sender interface churn). It must preserve IP/UA/location/revoke/account fields and no-expiry copy, with escaped MIME content and pinned multilingual source.

Parent inspected pinned browser_id.rs: upstream persistent32alphanumeric BrowserId cookie lasts5*365days, HttpOnly/SameSiteLax; browser identity takes precedence over IP in location matching. Added browser BrowserIDCookie/BrowserID primitives using existing issuer cookieShape and cryptographic sampling, explicitly correlation-only. Current existing host/loopback cookie modes are covered; upstream configurable __Secure/path modes remain a separate gap. Login-location storage and production hook are not wired, so no notification parity claim. Focused browser check95136 is pending in this entry.

## 2026-09-12 Login-revoke HTTP and transport workers

Added Luna Arendt (`01a09403-341b-7382-9e27-c172796e50e2`) owning only recovery/login_revoke_http.go/tests; parent mounted NewLoginRevokeHandler on GET /auth/v1/users/{subject}/revoke/{code} independently of password recovery enablement. Handler/core files are still being implemented, so this intermediate checkout may not compile; no new candidate build claimed. Pinned typed query extraction means malformed/missing ip can reject400 before the handler; outer200 HTML applies to valid-query handler success/code errors, correcting earlier overly broad prose.

Luna Anscombe (`01a09402-7ed9-70d3-9a1f-9376e510fee7`) owns only DCR script transport diagnosis/fix. All Kind runs are terminal/cleaned; 48598 failed node-side archive existence check before namespace creation. Worker compares default mktemp path and DOCKER_CONTEXT behavior against known-working explicit-context /tmp copy using its own disposable container, not full cluster retries. Core Peirce and key lifecycle Descartes continue on disjoint paths. Whole-suite85247 remains baseline-only and must not qualify these later changes.

## 2026-09-12 Login-revoke store and key lifecycle implementation started

Parent added domain-separated `oidc.LoginRevokeCodePurpose(subject,generation)` using the existing managed-envelope purpose pattern. Luna Peirce (`01a09401-384e-7000-a19d-077ae4a47777`) owns schema88 plus new identity/login_revoke store/tests: shared recoverable random48alphanumeric code, no invented expiry/binding, linearizable issuance, active-key write fence and atomic guarded revocation/cleanup/outbox/event. Luna Descartes (`01a09401-9da3-7063-bef4-274f64824fa6`) owns envelope reference scan/rewrap and command key-status/retirement integration. These paths are disjoint. HTTP/login-location/mail wiring remains parent responsibility and not implemented yet.

These production additions are later than ongoing security baseline suite85247 and Kind48598 builds; those results cannot qualify the new feature. Kind48598 reached image loading after successful build, still live. Core API agreed: FindOrCreateLoginRevokeCode(ctx,keyring,subject), RevokeLogin(ctx,keyring,subject,code,netip.Addr,*location). Scope remains full upstream flow plus required object-store/key-lifecycle safety; constructor/storage alone do not close the feature.

## 2026-09-12 Login-revoke event reviewed and tested

Parent reviewed `internal/eventlog/login_revoke.go` and its contract test against pinned v0.36.2 event.rs:822-841 (the worker's final linked line range was inaccurate). Warning/type/query-IP/null-data/exact text, nil-versus-empty location, stable operation ID and statement bindings agree. Fresh focused test74699 exited0,0.783s (`/tmp/goauthy-login-revoke-event-contract.log`). Runtime producer/route remains unimplemented; event constructor alone does not close the feature.

Protected shared-code storage can reuse existing Keyring.SealEnvelope/OpenEnvelope rather than invent new crypto. Any new purpose must also integrate key-status inventory and retirement/rewrap as managed-client envelopes do; this remains a required implementation dependency. Kind48598 remains live building fixtures, and full tests85247 continue with identity152.399s,ipblacklist6.589s,kv11.354s package passes after the original repaired command failures.

## 2026-09-12 Image copy verification before containerd import

Kind45827 exited2 before namespace creation: containerd could not find copied archive. BuildKit's earlier reference error was followed by successful image builds and cluster creation, so it was not the terminal blocker. Reproduced file copy twice in an isolated disposable kindest/node container: docker cp plus node test/ls succeeded. Direct archive API experiment returned HTTP500 even though the file appeared, so it is not adopted. Removed only that disposable transfer container.

Added a bounded node-side nonempty-file check after Docker copy and before containerd import. Transfer timing remains a hypothesis; the check now makes actual node state authoritative. Shell syntax passed. Retry48598 launched, `/tmp/goauthy-dcr-uri-kind-transfer-verified.log`; no deployment pass. Full tests85247 remain active with earlier known repaired command failures.

## 2026-09-12 BuildKit reference diagnostic / login-revoke contract refinement

Kind file-import qualification45827 remains live, but build output includes `failed to load ref ... not found` on bootstrap binary stage followed by further build progress. This is not yet a terminal failure; no duplicate build or cache purge started. Whole-tree85247 continues (DCR159.720s and device45.181s passed) with known repaired command fixture failures earlier in its log.

Login-revoke event constructor and focused tests assigned to Luna Copernicus (`01a093fb-a81d-76a0-9b2d-449d3b59f770`), owning only two new eventlog files. Parent pinned-source review confirmed Warning, query IP, null data, exact text and nil-only Unknown Location fallback. Constructor work does not mount the feature. Requested correction to contract document: digest-only storage cannot re-send the persistent shared code; protected recoverable code or equivalent domain-separated keyed derivation is needed before a storage design is accepted. No new expiry/address-binding semantics adopted.

## 2026-09-12 MinIO file export works / command suites PASS

Confirmed prior target cluster is gone and only its Docker image-save producer remained; terminated that exact owned orphan process. Import pipeline59878 exited137 after target cleanup/producer termination. Separate `docker image save --output /tmp/goauthy-minio-pinned-images.tar` completed exit0 (68718), producing a readable ~80MB OCI archive for the exact two pinned MinIO images. The evidence isolates a streaming transport problem; it does not establish a general Docker root cause.

DCR script now prepares the pinned fixture archive before cluster/application rollout, copies the file into the Kind node, and imports its native platform before applying workloads. Missing local tags use their exact pinned pull; no tag substitution or TLS bypass. Shell syntax passed. Started third qualification45827, `/tmp/goauthy-dcr-uri-kind-file-import.log`. No deployment pass yet.

Full repaired command suites35440 exited0: cmd/goauthy60.961s,cmd/goauthy-password0.285s (`/tmp/goauthy-policy-command-full-retry.log`). Original whole-tree run85247 continues through later packages with the already-repaired early fixture failures retained in its original output.

## 2026-09-12 Policy fixtures fixed / managed URI race strengthened

Reviewed Luna's test-only configured policy expectations: retain defaults and override only configured fields. Focused cmd/goauthy0.923s and cmd/goauthy-password0.385s pass (`/tmp/goauthy-policy-fixture-fixed.log`). Started both full command-package retries35440, `/tmp/goauthy-policy-command-full-retry.log`. Original all-tests85247 continues but its earlier failures are from the old fixtures.

Reviewed managed URI code/password race test and added an explicit assertion that the metadata update hook ran, preventing vacuous early rejection; removed possible bearer-token response dump. Both cases passed3.601s, session7919 exit0, `/tmp/goauthy-managed-uri-race-reviewed.log`. No production changes.

DCR Kind retry28001 reached deployment but MinIO images remained unavailable until rollout timeout. Native import59878 had remained live and was not restarted; cluster cleanup removes its target. No deployed E2E pass. Next action is to resolve local image export/import before starting application rollout, rather than allow the deployment timer to race image preparation. Pro consultation remains unavailable only; it does not block useful implementation work.

## 2026-09-12 Full-suite policy fixture failures / Kind progressing

Whole-tree tests85247 remain running but have three known failures: cmd/goauthy TestArgonPolicyFromEnv/configured and TestPasswordRulesFromEnv; cmd/goauthy-password TestPolicyFromArgs/configured. Actual defaults include hashing WaitTimeout100ms and password common/entropy settings omitted in fixture expectations. Assigned Luna Halley (`01a093f5-fbb9-77d2-b601-09060a12ef62`) test-only ownership to compare parser/default contracts before repair; no production relaxation authorized by this diagnosis.

Kind retry28001 passed API TLS normalization and reached application deployment. Exact pinned local MinIO images are importing natively via session59878; outcome pending. Unknown-login-revoke source analysis is complete (Pasteur): upstream shares a persistent 48-character code per user with no expiry, emits from query IP, and deletes code on success. A proposed new expiry/location-bound code changes that contract and is not automatically accepted as parity. Pro advisory attempt failed because `iab` is unavailable; no packet was sent and no alternative browser used. Continue local contract analysis and independent tests.

## 2026-09-12 Managed URI race coverage assigned

DCR Kind retry28001 and whole-tree tests85247 were re-polled and remain live. No new completed gate is claimed. Added bounded Luna worker Sagan (`01a093f4-f5b9-7230-aa35-e2442a561093`) owning only `internal/oauth/managed_logout_uri_race_test.go` to verify the existing managed id/generation/revision issuance fence against concurrent backchannel URI updates. This is distinct from the already-tested dynamic URI-at-commit path. Whole-tree tests were started before this new test, so their output must not be cited as its validation. No persistent search index was created when semantic lookup reported INDEX_MISSING; exact known guards were inspected instead.

## 2026-09-12 Whole-tree compile PASS / whole-tree tests started

Compile-only command2639 exited0: `go test -p 1 ./... -run '^$' -timeout=5m`, `/tmp/goauthy-final-compile-all.log`. This proves package/test compilation, not executed behavior. Reviewed `TestAuthenticateAcrossStoresRejectsKeyDeletedByPeer`: first Store authenticates, second Store sharing DB deletes, first rejects. Luna's focused command passed2.146s; no multi-node claim.

Started actual full `go test -p 1 ./... -count=1 -timeout=30m`, session85247, `/tmp/goauthy-all-tests-security-candidate.log`. Environment-dependent tests may skip; a pass will not replace explicit deployed/chaos gates. DCR Kind retry28001 remains live building the application, `/tmp/goauthy-dcr-uri-kind-retry.log`. Prior command63883 is terminal and must not be polled or treated as active. Unknown-login revoke contract analysis remains worker-owned by Pasteur.

## 2026-09-12 DCR Kind TLS address fix and retry

First DCR Kind63883 exited2 before application deployment: generated kubeconfig used `https://0.0.0.0:<port>`, but the API certificate covers 127.0.0.1 rather than 0.0.0.0. Cleanup removed the cluster; subsequent manual MinIO import therefore failed with missing container and changed no cluster. Copied existing sibling-script loopback address normalization into `scripts/e2e-dcr-backchannel-kind.sh`; TLS validation remains enabled. Shell syntax check passed. Retry28001 is running with the same isolated cluster/port, `/tmp/goauthy-dcr-uri-kind-retry.log`.

Whole-repository compile-only check2639 is also running, `/tmp/goauthy-final-compile-all.log`; `-run '^$'` intentionally executes no tests and is not behavioral evidence. DR and feature ledgers now distinguish retained password-token filesystem/S3 subprocess recovery from still-pending Kubernetes retained-token qualification.

## 2026-09-12 API-key downstream checks / DCR Kind launched

API-key caller suites exited0: claims19.738s,kv12.531s,ipblacklist6.349s (`/tmp/goauthy-apikey-callers-a.log`); branding7.664s,masterkeyretirement5.034s (`/tmp/goauthy-apikey-callers-b.log`). The former log separately records larger wall-clock command durations; these numbers are Go package test durations. Final auth cache vet41943 exited0 without diagnostics. Recovered TLS logout test `TestNoPVCBackchannelDeliveryRecovery` with race detection exited0,13.110s (`/tmp/goauthy-recovered-backchannel-race.log`); filesystem object-store subprocess recovery only, not S3 or multi-host evidence.

Reviewed E2E signed logout assertion against actual sink Host, so the DNS alias update is observable. Launched `DOCKER_CONTEXT=dory make e2e-kind-dcr-backchannel E2E_PORT=59401 KIND_CLUSTER=goauthy-dcr-uri-qualification`, session63883, `/tmp/goauthy-dcr-uri-kind.log`. Image build/deployment and before/after Pod replacement results remain pending. New cross-Store API-key deletion regression uses two Stores sharing the same DB; it is not itself a multi-node deployment test.

## 2026-09-12 API-key cache removed / authentication suites PASS

Removed per-process API-key authentication cache: cache hits bypassed linearizable digest and expiry checks after bootstrap replacement, expiry and cross-store mutation. Existing expiry/rotation and bootstrap replacement regressions passed3.463s; full API-key suite96199 exited0,38.765s (`/tmp/goauthy-apikey-cache-fixed-full.log`). Browser/RBAC cache-removal full suite75108 exited0: browser4.098s,RBAC231.771s (`/tmp/goauthy-browser-rbac-cache-fixed-full.log`). Additional cross-store API-key regression and downstream caller checks are worker-owned and pending. These package passes do not establish all-feature or deployed qualification.

DCR deployed E2E now uses the actual subject force-logout producer; review found that two DNS aliases reaching the same sink cannot prove which URI was used. Parent added actual HTTP Host to successful sink observations and assertions in the existing sink test; full sink race suite78847 exited0,1.396s. Luna is adding matching destination-host assertions to signed DCR logout observations before deployment. Recovered TLS delivery race verification is independently running; no new deployment/DR pass claimed.

## 2026-09-12 OAuth full retry PASS / browser-RBAC fix qualification

OAuth full retry90227 exited0,782.423s (`/tmp/goauthy-oauth-final-retry.log`), after the two fixture fixes. Subsequent browser/RBAC cache removal is a later production change, so that pass is not the final integrated security candidate. Luna removed both per-store caches; parent confirmed no cache references and retained linearizable principal/session paths. Worker reports three RBAC regression and four browser revocation/expiry passes. Started full browser/RBAC fixed-candidate suite75108 (`/tmp/goauthy-browser-rbac-cache-fixed-full.log`). Managed group-prefix HTTP create/update/null regression passed2.316s; API-key audit and corrected DCR deployed E2E remain pending.

## 2026-09-12 Identity caller suite completed / RBAC cache cause confirmed

Fixed identity/login/account/WebID command91067 exited0: identity481.936s, login228.189s, account165.980s, WebID4.704s (`/tmp/goauthy-identity-cache-removal-full.log`). Luna independently reproduced all three RBAC failures: per-store browser session cache survives revocation through a second store/direct identity mutation; principal cache bypasses changed role membership/bounds. Assigned removal of only browser session/principal caches with focused regressions. API-key cache gets a separate read-only cross-store revocation audit. These pending security fixes invalidate any whole-candidate completion claim; OAuth full retry90227 remains running.

## 2026-09-12 Identity/caller static checks PASS

`go vet ./internal/identity ./internal/rbac ./internal/login ./internal/account ./internal/webid` session34704 exited0 with no diagnostics (`/tmp/goauthy-identity-rbac-vet.log`). This does not clear the three RBAC behavioral failures; Luna root-cause diagnosis remains active. Fixed identity/login package passes remain valid for their compiled candidate, while account/WebID and OAuth full command completions are still pending. Managed-field HTTP contract audit and corrected dynamic E2E work continue independently.

## 2026-09-12 Managed schema87 Kind PASS

Main Kind session11426 exited0 (`/tmp/goauthy-schema87-kind.log`). `TestManagedClientsHTTPWorkflow` passed5.43s before and5.36s after the script's Pod replacement, including newly reviewed URI create/update/null-clear round trips across replicas. Dedicated pilot mode skipped UI, device and collection tests; it is not all-feature E2E or dynamic TLS delivery evidence. One Kind node hosted three replicas. Script cleanup removed the cluster/context. Registry failures were recovered by importing existing exact MinIO tags for arm64. Fixed-candidate login package also passed228.189s after identity481.936s in ongoing session91067; account/WebID completion still pending.

## 2026-09-12 Kind image transport recovery

Kind application deployment hit registry authorization failures for pinned MinIO/mc fixtures. Both exact tags were already present locally from real S3 tests. `kind load docker-image` failed because its all-platform import required unavailable non-native content. Exported the existing images and imported only linux/arm64 through node containerd; import11360 exited0. MinIO is now Running/Ready and GoAuthy pods advanced from image errors to initialization. No image tag substitution or release-gate bypass occurred. Cluster still has one Kind node and three GoAuthy replicas; this is not three-host HA evidence. Main run11426 remains live.

## 2026-09-12 Fixed identity full-suite PASS / Kind cluster creation

The fixed-candidate identity package passed481.936s in session91067 (`/tmp/goauthy-identity-cache-removal-full.log`); the same serialized command continues through login/account/webid, so the overall command is not complete. Kind11426 finished image builds and is creating the isolated goauthy-schema87-qualification cluster. OAuth retry90227 and original identity/rbac96463 remain live. Do not confuse the original identity failure log with the fixed-candidate package pass.

## 2026-09-12 DCR deployed test review correction

Luna's new dynamic password E2E compiles but currently uses /oidc/revoke as the supposed backchannel producer. Parent flagged that revoking an OAuth token does not establish subject logout delivery and requested tracing/replacing it with the actual producer before deployment. No DCR E2E pass is claimed from compilation. Managed Kind11426 and full validation processes continue. Warm-read expiry regression passed4.154s, covering time-only expiry after successful user/profile reads.

## 2026-09-12 Integrated suite boundary and retry

Session57587 is terminal exit1: OAuth537.098s failed on the two subsequently repaired fixture assertions; clients53.298s and apidocs2.465s passed. Started an OAuth-only full retry after those targeted checks passed, `/tmp/goauthy-oauth-final-retry.log`. Identity/login/account/webid fixed-candidate session91067 continues. Original identity/rbac96463 continues beyond its known identity failure. Kind11426 is building the application through local BuildKit; no deployment pass yet.

## 2026-09-12 OAuth fixture repairs and managed K8s launch

Full OAuth earlier failed537.098s on two tests. The successful-code storage fixture had an empty subject, violating the new nonempty user-client association invariant; supplied a subject only for that user code fixture. The expired-password test inspected Error() (OAuth code only) for a hint; now inspects Fosite HintField while retaining ErrAccessDenied assertion. First attempted field name Hint did not compile; corrected against installed Fosite source. Both focused tests passed10.630s (`/tmp/goauthy-oauth-fixtures-fixed.log`), no production relaxation. Reviewed managed E2E asserts URI create/update/null clear across nodes. Launched existing Kind open-registration managed workflow on isolated goauthy-schema87-qualification cluster, port59361, `/tmp/goauthy-schema87-kind.log`; deployment outcome pending.

## 2026-09-12 Account cache regression fixed

Full identity run failed two tests (254.475s): cached UserBySubject accepted a disabled user; cached AccountProfileBySubject returned a removed profile. Both failures reproduced standalone (1.661s). Current cache had 30s TTL, no mutation invalidation and bypassed expiry/linearizable reads; callers include login, account and WebID. Removed only these two caches and their construction from identity/store.go, restoring database reads. Existing regressions passed1.936s (`/tmp/goauthy-identity-read-fixed.log`). Started full identity/login/account/webid qualification on the fixed candidate (`/tmp/goauthy-identity-cache-removal-full.log`). Earlier running suites use earlier compiled candidates and cannot qualify this fix. No full pass claimed.

## 2026-09-12 Managed HTTP metadata gap repaired

K8s qualification audit found managed create/update JSON allowlists omitted backchannel_logout_uri despite store/OpenAPI support. Parent added the field to both allowlists and nullable sets. Real authenticated HTTP create, replacement update and null removal test passed4.508s (`/tmp/goauthy-managed-uri-http.log`). Previous store/TLS tests alone did not establish this API behavior. Running identity/rbac suite96463 compiled before this fix and cannot qualify it; focused HTTP test covers the change, final RBAC full check must use the final candidate. Managed deletion fix remains worker-owned. Two disjoint E2E workers now extend dynamic password delivery and managed metadata HTTP coverage; no deployed success claimed.

## 2026-09-12 Pending delivery recovery test review

Reviewed Luna's `TestNoPVCBackchannelDeliveryRecovery`: separate write/recover subprocesses, distinct DataDirs, shared filesystem object store, writer exits without Close, recovery asserts manually seeded pending outbox fields and URI association. Worker reports focused normal and race passes. This is persisted-row recovery evidence only: the fixture does not produce the event through a real logout or deliver it through the worker, and explicitly disables S3/GCS. It complements but does not replace lifecycle/TLS or real S3 tests. Full OAuth/clients/apidocs57587 and identity/rbac96463 remain live.

## 2026-09-12 Static verification PASS

`go vet ./internal/dcr ./internal/oauth ./internal/clients ./internal/apidocs` session53155 exited0 with no diagnostics (`/tmp/goauthy-schema87-vet.log`). Removed token-struct output from the new plain OAuth regression's failure path. Full OAuth/clients/apidocs session57587 remains running; empty output does not establish success. Four bounded Luna follow-ups remain active; no new deployed qualification result yet.

## 2026-09-12 DCR cleanup full-suite PASS

Integrated DCR suite session81535 exited0, 161.921s (`/tmp/goauthy-dcr-cleanup-full.log`), covering the current URI metadata/synchronization and authenticated deletion/anonymous cleanup candidate. OAuth/clients/apidocs full suite57587 remains running with no final result. Started `go vet` for dcr/oauth/clients/apidocs separately; pending. Existing whole-port and deployed DR gates remain open.

## 2026-09-12 Integrated package qualification launched

Started serialized full OAuth/clients/apidocs suites on the current schema87 candidate (`go test -p 1 ./internal/oauth ./internal/clients ./internal/apidocs -count=1 -timeout=20m`), session57587, `/tmp/goauthy-schema87-oauth-clients-apidocs.log`. DCR cleanup full suite session81535 remains live with no final output. No pass is inferred from an empty log. Luna code-flow URI regression reviewed: trigger changes metadata before association writes, verifies both subject and SID mappings for update and NULL removal without a later repair mutation. Remaining workers investigate deployed qualification gaps and deletion races. The complete port remains unfinished.

## 2026-09-12 Schema87 Linux interrupted-install PASS

`DOCKER_CONTEXT=dory make test-no-pvc-journal-linux` session23903 exited0. Local BuildKit built the test image, run read-only with no network, dropped capabilities and tmpfs. Five interrupted journal installation phases passed: prepared4.20s, sqlite-backed-up6.17s, graph-installed8.28s, sqlite-installed10.52s, committed12.34s (41.52s total). Trace-cut evidence checks passed. The shared recovered-password helper includes dynamic URI metadata/subject association plus retained refresh claims. Evidence: `/tmp/goauthy-schema87-journal-linux.log`. This is process SIGKILL/install recovery, not physical power loss or multi-host Kubernetes DR. Managed URI catalog check passed1.206s. Integrated DCR cleanup suite session81535 remains running, `/tmp/goauthy-dcr-cleanup-full.log`.

## 2026-09-12 S3 recovery PASS and corrected race oracle

Real MinIO S3 recovery with race detector completed successfully: 20.676s, session38844 exit0 (`/tmp/goauthy-schema87-s3.log`). It verifies fresh-directory recovery of URI metadata, password login association and retained refresh/ID claims; no multi-host/K8s claim. Parent found the first in-flight URI test performed another post-issuance Update, which could mask a stale association. Removed that update from in-flight modes and added in-flight NULL removal; original/update/remove plus both unmasked in-flight cases passed 7.082s (`/tmp/goauthy-uri-race-unmasked.log`). Earlier 2.063s result alone was insufficient race evidence and is superseded.

## 2026-09-12 DCR deletion integration review

Luna implemented guarded child-before-parent registration deletion, including subject/session associations and queued deliveries, with exact-one parent RETURNING precondition; anonymous cleanup now includes subject associations. Parent inspected transaction ordering and repeated registration-token authorization predicates. Worker reports deletion/wrong-token/stale-token/concurrent-delete-update checks passed; a forced final-parent failure rollback check requested before final qualification. This does not claim every historical authorization artifact is purged. Real S3 session38844 remains live; no recovery result yet.

## 2026-09-12 Schema87 object-store password state recovery

Extended the existing subprocess/fresh-DataDir no-PVC password helper to register a backchannel URI and verify both the DCR OAuth accessor and persisted subject/client association on writing and recovery. Existing refresh-token and signed ID-token checks remain. Filesystem object-store run passed 3.220s (`/tmp/goauthy-schema87-object-recovery.log`). Real disposable MinIO transport with race detector launched through the existing `scripts/e2e-no-pvc-s3.sh recovery`, session38844, `/tmp/goauthy-schema87-s3.log`; result pending. This does not establish multi-node host-loss or Kubernetes DR completion.

## 2026-09-12 Dynamic URI write-order regression

Association SQL now resolves dynamic backchannel metadata inside the token transaction, including NULL-as-empty removal; other client metadata retains its existing fallback. A deterministic AFTER access-token INSERT trigger changes the dynamic URI after the client snapshot and before association insertion. Real password login -> deletion -> TLS worker delivery uses the updated endpoint; focused test passed 2.063s (`/tmp/goauthy-uri-inflight.log`). Full original/updated/removed dynamic delivery checks passed 4.566s before the new trigger subcase. Plain OAuth with a supplied SID now records session associations; existing non-OIDC tests passed 9.146s and Luna's explicit revoke/outbox regression passed 2.024s. Reviewed late managed URI registration test confirms the existing empty association becomes the later logout destination. Reviewed clean-reopen storage test improved fixture/cleanup and passed 1.950s. Object-store recovery, deleted-client cleanup integration, code-flow URI race and final broad gates remain pending.

## 2026-09-12 Luna focused test review

Reviewed schema87 worker test: it builds a pre-column dynamic-client fixture, invokes migrateSchemaV87 twice, compares all existing column values plus the new NULL field, and checks a single version87 marker. This proves the isolated ALTER migration's preservation/idempotence, not a full production v86 snapshot upgrade or object-store DR. Dynamic password TLS tests cover original/updated/removed URI through actual login, user deletion, Worker.Step and signed issuer/audience/sub/no-SID claims. HTTP boundary tests cover invalid inputs and wrong-token immutability. Workers reported focused passes; broader integrated gates remain pending. Completed workers closed; next bounded Luna tasks cover late managed URI registration, recovery enhancement audit, and reopen persistence.

## 2026-09-12 URI-less OIDC session regression

OIDC code exchange now stores a session-client association even when no backchannel endpoint is registered, allowing later URI updates to reach the existing association. The regression uses the actual code exchange row (no manually seeded substitute), then confirms session revocation removes it without an outbox delivery. Focused check passed 1.896s; `go test ./internal/oauth -run '^TestOIDC' -count=1 -timeout=5m` passed 26.330s (`/tmp/goauthy-oidc-session-regression.log`). Plain OAuth SID association parity is still pending. Luna OpenAPI worker completed password grant enum/description and request/response backchannel checks; reported focused catalog pass, changes inspected by parent. Final integrated qualification remains outstanding.

## 2026-09-12 DCR full-suite result and parallel qualification

DCR suite session57179 exited successfully: 173.739s (`/tmp/goauthy-dcr-final-uri.log`). This covers the candidate compiled before the five Luna worker changes, not their eventual integrated result. Recovery compile-only check passed 0.910s after correcting missing storage/rhiza and unused imports in security_enhanced.go; no enhanced-reset behavioral qualification is claimed. Five bounded Luna workers own schema87 migration tests, dynamic TLS logout tests, read-only lifecycle/security review, DCR OpenAPI parity, and HTTP boundary tests. Parent retains integration/final verification. No full parity or DR completion claim.

## 2026-09-12 DCR URI contract and qualification

Pinned v0.36.2 `src/common/src/regex.rs` and dynamic client request confirm RE_URI metadata validation. DCR now accepts the same characters (including HTTP and query/fragment metadata), rejects explicit empty HTTP values, and leaves outbound network authorization to delivery. URI HTTP replacement/null/omission, persistence/rotation, and pattern checks passed 3.769s. Added matching nullable OpenAPI request/update property and schema checks. OpenAPI tests could not compile because unrelated `internal/recovery/security_enhanced.go` references undefined storage/rhiza; that file was not modified in this work. DCR full suite is running in session57179, log `/tmp/goauthy-dcr-final-uri.log`; no final full-suite pass claimed. Schema87 migration, dynamic delivery and final DR/security qualification remain incomplete.

# Rauthy v0.36.2 Parity Audit

**감사 일시:** 2026-09-12 (업데이트)  
**기준 버전:** Rauthy v0.36.2 (commit `dd61ac3c84d6b238108dc8438b53043b5177a662`)  
**데이터베이스:** Rhiza v0.12.3  
**GoAuthy 스키마:** v58 (account-expiry storage)  
**Go 패키지 수:** 47개 internal 패키지  
**Go 파일 수:** 904개

---

> **Historical snapshot (2026-09-12, unverified 2026-09-17):** The rows and counts in all feature tables below reflect the original baseline audit. Do not treat them as current completion metrics. Verified gate results are in the qualification ledger above.

## 1. Rauthy v0.36.2 전체 기능 목록

### 1.1 OIDC/OAuth 코어

| # | 기능 | Rauthy 상태 | GoAuthy 상태 |
|---|------|-------------|--------------|
| 1 | OIDC Discovery (RFC 8414) | ✅ | ✅ 완료 |
| 2 | JWKS (Ed25519 자동 로테이션) | ✅ | ✅ 완료 |
| 3 | Authorization Code + PKCE S256 | ✅ | ✅ 완료 |
| 4 | Refresh Token (회전/재사용 감지) | ✅ | ✅ 완료 |
| 5 | Client Credentials | ✅ | ✅ 완료 |
| 6 | ID Tokens (EdDSA) | ✅ | ✅ 완료 |
| 7 | UserInfo (GET/POST) | ✅ | ✅ 완료 |
| 8 | Token Introspection | ✅ | ✅ 완료 |
| 9 | Token Revocation | ✅ | ✅ 완료 |
| 10 | DPoP (RFC 9449) | ✅ | ✅ 완료 |
| 11 | Resource Indicators (RFC 8707) | ✅ | ✅ 완료 |
| 12 | Token Exchange (RFC 8693) | ✅ | 🔶 부분 (`may_act` 미구현) |
| 13 | Dynamic Client Registration (RFC 7591/7592) | ✅ | 🔶 부분 |
| 14 | CIMD (Ephemeral Clients) | ✅ | 🔶 부분 |
| 15 | Machine Subject Mapping | ✅ | ✅ 완료 |
| 16 | RFC 8252 Loopback Redirects | ✅ | ✅ 완료 |

### 1.2 인증/패스키

| # | 기능 | Rauthy 상태 | GoAuthy 상태 |
|---|------|-------------|--------------|
| 17 | WebAuthn/FIDO2 패스키 | ✅ | 🔶 부분 |
| 18 | 패스키 전용 계정 전환 (양방향) | ✅ | ✅ 완료 |
| 19 | MFA 수정 토큰 스텝업 | ✅ | ✅ 완료 |
| 20 | 강제 MFA (부트스트랩) | ✅ | 🔶 부분 |
| 21 | 패스키 등록 후 세션 MFA 업그레이드 | ✅ | 🔶 부분 |
| 22 | 패스키+비밀번호 쿠키 흐름 | ✅ | 🔶 부분 |
| 23 | 무비밀번호 계정 생명주기 | ✅ | ❌ 미구현 |
| 24 | Discoverable Credentials | ✅ | ❌ 미구현 |
| 25 | OTP via E-Mail | ✅ | ❌ 미구현 |

### 1.3 비밀번호/복구

| # | 기능 | Rauthy 상태 | GoAuthy 상태 |
|---|------|-------------|--------------|
| 26 | 비밀번호 인증/정책/만료 | ✅ | 🔶 부분 (그랜트 자격 진행 중) |
| 27 | Magic Links/비밀번호 재설정 | ✅ | 🔶 부분 |
| 28 | Argon2id 캘리브레이션 | ✅ | ✅ 완료 |
| 29 | 비밀번호 히스토리 | ✅ | 🔶 부분 |
| 30 | 자기 서비스 비밀번호 변경 | ✅ | 🔶 부분 |
| 31 | 이메일 OTP | ✅ | ❌ 미구현 |

### 1.4 사용자 관리

| # | 기능 | Rauthy 상태 | GoAuthy 상태 |
|---|------|-------------|--------------|
| 32 | 사용자 삭제 (관리자/셀프) | ✅ | ✅ 완료 |
| 33 | 역할/그룹/스코프 | ✅ | 🔶 부분 |
| 34 | 커스텀 속성/클레임 바인딩 | ✅ | 🔶 부분 |
| 35 | 위임 그룹 관리자 | ✅ | 🔶 부분 |
| 36 | 동적 사용자 역할/그룹 할당 | ✅ | 🔶 부분 |
| 37 | 사용자 대시보드/셀프 서비스 | ✅ | 🔶 부분 |
| 38 | Open Registration | ✅ | 🔶 부분 |
| 39 | 설정 가능한 사용자 프로필 필드 | ✅ | 🔶 부분 |
| 40 | 로그인 위치 이메일 알림 | ✅ | ❌ 미구현 |

### 1.5 클라이언트 관리

| # | 기능 | Rauthy 상태 | GoAuthy 상태 |
|---|------|-------------|--------------|
| 41 | 클라이언트 로그인 제한 (그룹 프리픽스) | ✅ | ✅ 완료 |
| 42 | 클라이언트 테마/로고/favicon | ✅ | 🔶 부분 |
| 43 | 클라이언트 크리덴셜 커스텀 클레임 | ✅ | 🔶 부분 |
| 44 | 관리 UI | ✅ | 🔶 부분 |
| 45 | Fine-grained API Keys | ✅ | 🔶 부분 |
| 46 | API Key JSON 부트스트랩 | ✅ | 🔶 부분 |

### 1.6 로그아웃

| # | 기능 | Rauthy 상태 | GoAuthy 상태 |
|---|------|-------------|--------------|
| 47 | RP-Initiated Logout | ✅ | ✅ 완료 |
| 48 | Back-channel Logout | ✅ | 🔶 부분 |
| 49 | 관리자 세션 관리/강제 로그아웃 | ✅ | 🔶 부분 |

### 1.7 Device Authorization

| # | 기능 | Rauthy 상태 | GoAuthy 상태 |
|---|------|-------------|--------------|
| 50 | Device Grant (RFC 8628) | ✅ | 🔶 부분 |

### 1.8 SCIM

| # | 기능 | Rauthy 상태 | GoAuthy 상태 |
|---|------|-------------|--------------|
| 51 | SCIM 사용자 동기화 | ✅ | 🔶 부분 |
| 52 | SCIM 그룹 동기화 | ✅ | 🔶 부분 |

### 1.9 보안

| # | 기능 | Rauthy 상태 | GoAuthy 상태 |
|---|------|-------------|--------------|
| 53 | IP 블랙리스트 (수동/자동) | ✅ | ✅ 완료 |
| 54 | 로그인/해싱 속도 제한 | ✅ | 🔶 부분 |
| 55 | 사용자명 열거 방지 | ✅ | 🔶 부분 |
| 56 | 크리덴셜 스터핑 감지 | ✅ | ❌ 미구현 |
| 57 | Geolocation 정책 | ✅ | ✅ 완료 |
| 58 | Forward Auth | ✅ | 🔶 부분 |
| 59 | 세션 관리/피어 IP 바인딩 | ✅ | 🔶 부분 |
| 60 | CSRF/callback 상태/nonce | ✅ | 🔶 부분 |
| 61 | 중요 DB 값 암호화/키 로테이션 | ✅ | 🔶 부분 |

### 1.10 데이터베이스/백업

| # | 기능 | Rauthy 상태 | GoAuthy 상태 |
|---|------|-------------|--------------|
| 62 | TLS 인증서 핫 리로드 | ✅ | ✅ 완료 |
| 63 | Namespaced KV Store | ✅ | ✅ 완료 |
| 64 | Three-peer HA | ✅ | ✅ 완료 |
| 65 | 백업/복구/빈 디스크 복구 | ✅ | ✅ 완료 |
| 66 | Rhiza 마이그레이션 | N/A | ✅ 완료 (v58) |

### 1.11 이벤트/알림

| # | 기능 | Rauthy 상태 | GoAuthy 상태 |
|---|------|-------------|--------------|
| 67 | 이벤트/감사/외부 스트림 | ✅ | 🔶 부분 |
| 68 | 이메일/Matrix/Slack 알림 | ✅ | 🔶 부분 |
| 69 | 설정 가능한 이메일 템플릿 | ✅ | 🔶 부분 |

### 1.12 기타

| # | 기능 | Rauthy 상태 | GoAuthy 상태 |
|---|------|-------------|--------------|
| 70 | Prometheus 메트릭/트레이스 | ✅ | 🔶 부분 |
| 71 | OpenAPI/Swagger | ✅ | 🔶 부분 |
| 72 | 하우스키핑/업데이트 확인 | ✅ | ❌ 미구현 |
| 73 | 설정/부트스트랩 검증 | ✅ | 🔶 부분 |
| 74 | Upstream Providers (OIDC/GitHub) | ✅ | 🔶 부분 |
| 75 | WebID/FedCM | ✅ | 🔶 부분 |
| 76 | Liveness/Readiness Probes | ✅ | ✅ 완료 |

### 1.13 제외 항목

| # | 기능 | 비고 |
|---|------|------|
| 77 | Hiqlite/Postgres 마이그레이션 | Rhiza 전용 제약으로 제외 |
| 78 | PAM/NSS Linux 통합 | 별도 전달물, GPL 경계 |
| 79 | Kubernetes 배포 강화 | Cilium 커널 호환성 문제 |

---

## 2. 구현 현황 요약

> **Historical snapshot (2026-09-12, unverified 2026-09-17):** The counts and percentages below reflect the original baseline audit and have not been re-verified against current production code. Some features counted as 미구현 or 부분 may have been implemented or advanced since. Do not treat these as current completion metrics. Verified gate results are in the qualification ledger above.

| 상태 | 수 | 비율 |
|------|-----|------|
| ✅ 완료 | 20 | 25% |
| 🔶 부분 구현 | 40 | 51% |
| ❌ 미구현 | 12 | 15% |
| 제외 | 3 | 4% |
| N/A | 1 | 1% |
| **합계** | **76** | **100%** |

---

## 3. 미완료 기능 상세 목록

### 3.1 ❌ 미구현 기능 (12개)

| # | 기능 | 우선순위 | 패키지 | 비고 |
|---|------|----------|--------|------|
| 1 | 무비밀번호 계정 생명주기 | P1 | `internal/passkey` | 계정 생성/등록/복구 없음 |
| 2 | Discoverable Credentials | P1 | `internal/passkey` | Rauthy v0.36.2 신기능 |
| 3 | OTP via E-Mail | P2 | `internal/recovery` | 이메일 OTP |
| 4 | 크리덴셜 스터핑 감지 | P1 | `internal/loginpolicy` | 분산 시도 감지 |
| 5 | 하우스키핑/업데이트 확인 | P2 | `cmd/goauthy` | 싱글톤 정리 |
| 6 | 로그인 위치 이메일 알림 | P2 | `internal/notify` | revocation 코드 |
| 7 | 이메일 OTP (로그인) | P2 | `internal/recovery` | 2FA |
| 8 | i18n 확장 | P3 | `internal/i18n` | en/ko만 구현 |
| 9 | 클라이언트 테마 전체 | P3 | `internal/branding` | 로고/색상 |
| 10 | 만료/위임 관리 UI | P3 | `internal/admin` | 관리자 화면 |
| 11 | CIMD 무시 정책 Kind E2E | P3 | `internal/cimd` | lenient-policy |
| 12 | FedCM 브라우저 E2E | P3 | `internal/fedcm` | 상호운용성 |

### 3.2 🔶 부분 구현 기능 (40개)

| # | 기능 | 완료된 부분 | 미완료 부분 |
|---|------|-------------|-------------|
| 1 | Token Exchange | 교차 클라이언트, 사용자 클레임 | `may_act`, 외부 JWT/SAML |
| 2 | DCR | 생성/수정/삭제, 소프트웨어 명세서 | 전체 HA/chaos 검증 |
| 3 | CIMD | 기본 resolver, ignore_unknown | TLS-fixture Kind E2E |
| 4 | WebAuthn/FIDO2 | 등록/로그인/전환 | 진정한 무비밀번호 계정 |
| 5 | 강제 MFA | 부트스트랩 정책 | 관리자 per-client 정책 |
| 6 | 패스키 등록 후 MFA | 엔진/라우트 | Kind E2E |
| 7 | 패스키+비밀번호 쿠키 | 새 쿠키 purpose | CookieKey 제거 |
| 8 | 비밀번호 인증/정책 | Argon2id, PoW, 리셋 | 생명주기 카운터, 로그인 상태 |
| 9 | Magic Links/재설정 | PoW, 리셋 | 전체 복구 패리티 |
| 10 | 비밀번호 히스토리 | v14 스키마 | 완전한 관리 |
| 11 | 자기 서비스 비밀번호 | CSRF 바운더리 | 완전한 UI |
| 12 | 역할/그룹/스코프 | CRUD, JWT 클레임 | 위임 관리, 동적 할당 |
| 13 | 커스텀 속성 | 스키마 v26/v28/v29 | 사용자 편집 가능 속성 |
| 14 | 위임 그룹 관리자 | 멤버십 PATCH | Kind E2E |
| 15 | 동적 역할/그룹 할당 | PATCH Op | 위임 Kind |
| 16 | 사용자 대시보드 | 프로필/자격 증명 | 세션/프로바이더 UI |
| 17 | Open Registration | PoW, 도메인 제한 | Captcha, 패스키 우선 |
| 18 | 프로필 필드 설정 | 9개 모드 | values_config UI |
| 19 | 클라이언트 테마 | favicon | 로고/색상/i18n |
| 20 | 클라이언트 커스텀 클레임 | 정적 클라이언트 | 동적/CIMD |
| 21 | 관리 UI | 사용자/역할/그룹 CRUD | 전체 화면, 위임 UI |
| 22 | API Keys | 생성/회전/만료 | 암호화 다이제스트 |
| 23 | API Key 부트스트랩 | Plain/Encrypted/Generate | TOML 시크릿 |
| 24 | Back-channel Logout | 단일 RP SID | 멀티 클라이언트 |
| 25 | 관리자 세션 관리 | 로컬 revocation | 전체 MFA 투영 |
| 26 | Device Grant | RFC 8628 구현 | Dynamic-client Kind |
| 27 | SCIM 사용자 | 동기화 | 암호화된 설정, chaos |
| 28 | SCIM 그룹 | 동기화 | PATCH-delta |
| 29 | 로그인 속도 제한 | 고정 윈도우, 지연 | 전체 DoS |
| 30 | 사용자명 열거 방지 | 상수 형태 정책 | 타이밍 분산 |
| 31 | Forward Auth | 베어러 검증, ID 헤더 | 프록시 모드/ACL |
| 32 | 세션 관리 | Init/Auth, 피어 IP | Kind E2E |
| 33 | CSRF/callback | PKCE, interaction | 전체 수명주기 |
| 34 | DB 암호화 | AES-GCM envelope | 자동 키 제거 |
| 35 | 이벤트/감사 | 생성/쿼리/SSE | 알림 전달, 영구 저장 |
| 36 | 이메일 알림 | go-mail | Matrix/Slack |
| 37 | 이메일 템플릿 | TOML 레이아웃 | 프리뷰/관리 UI |
| 38 | Prometheus | 메트릭 레지스트리 | OpenTelemetry |
| 39 | OpenAPI | 스펙/UI | 와이어 스키마 |
| 40 | Upstream Providers | OIDC/GitHub | Kind/chaos |
| 41 | WebID/FedCM | 기본 구현 | 브라우저 E2E |
| 42 | 설정 검증 | Rhiza 검증 | TOML 시크릿 |

---

## 4. 우선순위 제안

### P1 (즉시 필요 - 핵심 패리티)

1. **무비밀번호 계정 생명주기** (#1)
   - 계정 생성, 등록, 복구
   - 관리자 라이프사이클
   - Kind E2E

2. **Discoverable Credentials** (#2)
   - Rauthy v0.36.2 신기능
   - 패스키 저장소 관리

3. **크리덴셜 스터핑 감지** (#4)
   - 분산 시도 감지
   - 자동 IP 차단

### P2 (단기 - 기능 완성)

4. **Back-channel 멀티 클라이언트** (#24)
   - 레지스트리
   - chaos 검증

5. **강제 MFA per-client** (#5)
   - 관리자 관리 정책
   - API 구현

6. **SCIM 전체 패리티** (#27, #28)
   - chaos 검증
   - 중복 전달

7. **Admin UI 완전한 화면** (#21)
   - 클라이언트/프로바이더/설정
   - 위임 UI

8. **사용자 대시보드 완성** (#16)
   - 세션/프로바이더 UI
   - MFA 재인증

9. **이벤트 알림 완성** (#36)
   - Matrix/Slack 통합
   - 재시도/아웃박스

10. **Password 생명주기 카운터** (#8)
    - last_login, 실패 카운터

### P3 (중기 - 운영 강화)

11. **Prometheus/Traces** (#38)
    - OpenTelemetry 통합
    - 내보내기

12. **OpenAPI 완전성** (#39)
    - 와이어 스키마 패리티

13. **Upstream Providers 검증** (#40)
    - Kind/chaos 실행

14. **WebID/FedCM 브라우저 E2E** (#41)
    - 상호운용성 검증

### P4 (장기 - 확장)

15. **OTP via E-Mail** (#3)
16. **클라이언트 테마 전체** (#9)
17. **i18n 확장** (#8)
18. **하우스키핑/업데이트 확인** (#5)
19. **로그인 위치 이메일 알림** (#6)

---

## 5. 기술적 제약사항

1. **Docker inotify 제한**: `fs.inotify.max_user_instances=128`로 HA E2E 차단
2. **Cilium 호스팅 커널**: `protocol not supported` 오류
3. **Fosite v0.49 한계**: DCR, Device, DPoP 핸들러 없음
4. **Rhiza 전용**: Hiqlite/Postgres 마이그레이션 제외

---

## 6. 다음 단계

1. P1 기능 구현 시작 (무비밀번호 계정, 크리덴셜 스터핑)
2. Kind E2E 환경 inotify 제한 해결
3. SCIM 전체 패리티 검증
4. Admin UI 화면 완성

---

## 7. 이전 세션 기록

### 2026-09-12 DCR backchannel association synchronization

DCR 메타데이터 전체 suite가 127.522초에 통과. 연결 동기화 변경 후 회귀 테스트 추가. 업데이트는 메타데이터/토큰 회전과 두 가지 주제/세션 연결 URI 업데이트를 하나의 트랜잭션에서 커밋.

### 2026-09-12 새로운 패키지 추가

- **`internal/cache`**: 샤딩된 TTL-aware 동시성 안전 인메모리 캐시. 인증 서버 핫 패스 최적화.
- **`internal/security`**: HTTP 보안 헤더 미들웨어. OWASP 보안 헤더 모범 사례 준수.
- **`internal/credential`**: 비밀번호 및 크리덴셜 관리 패키지. 새로운 정책 검증 포함.

### 2026-09-12 비밀번호 정책 검증 강화

`internal/credential/policy.go` 추가: OWASP 권장 비밀번호 정책 구현.
- 최소/최대 길이 검증
- 대소문자, 숫자, 특수 문자 요구
- 반복 문자 제한
- 일반적인 비밀번호 차단

### 2026-09-11 schema86 crash/S3 failure metadata recovery — PASS

세션31392 종료. 실제 루프백 MinIO 복구 테스트가 17.105초에 통과.

### 2026-09-11 Password grant qualification (진행 중)

- [x] 관리 및 동적 클라이언트 비밀번호/리프레시 등록, 기본 스코프 선택, ID 토큰 비밀번호 출처 및 발견 기능.
- [x] 실제 Rhiza HTTP 테스트가 공개/기본/포스트 동적 클라이언트와 공개/기밀 관리 클라이언트를 커버.
- [x] 독립 실행형 관리 비밀번호 발행/리프레시가 서버 재시작 전후에 성공.
- [x] 3노드 관리 비밀번호 발행/교차 노드 리프레시가 UID 확인 Pod 교체 전후에 통과 (2.92초/3.62초).
- [ ] 교체/DR 전반에 걸친 지속된 비밀번호 토큰; schema86 배포 자격; 세션리스 사용자-클라이언트 로그인 상태.

### 2026-09-10 final mapped machine Kind — PASS

매핑된 Kind g 종료. 최종 후보는 공유 관리 기본값, 명시적 리소스 admission 및 추가 머신-액터 생존 assertion 포함.

---

*이 문서는 `docs/parity.md`와 `docs/features.md`를 기반으로 작성되었습니다.*
