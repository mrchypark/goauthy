# UI functional audit — 2026-09-26

This is an evidence ledger, not a claim that every button passed live testing. Local preview is a disposable standalone deployment at localhost:18120. Three-node HTTP test parameters pointed to this same endpoint; they do not establish HA behavior.

## Detailed control inventories

- [Account controls](ui-audit-account.md): profile, username, password, passkeys, attributes, connections, provider credentials, grants, devices, deletion.
- [Admin core](ui-audit-admin-core.md): dashboard, users, roles/groups, API keys.
- [Admin modules](ui-audit-admin-modules.md): clients, collections, providers, catalog, sessions, events, blacklist, templates.
- [Authentication scenarios](authentication-ui-scenarios.md) and [navigation/language](navigation-and-language.md): login, device flow, recovery, logout, consent and handoff boundaries.

## Actual browser evidence

| Area | Observed result | Limit |
|---|---|---|
| Group metadata | Created group, saved object metadata, reopened; edited and reopened again with persisted value. Malformed JSON rejected. | Localized error fix separately covered by Node tests; deletion not performed. |
| Collections | Created device-flow collection with one metadata field. Added/removed a second field. List showed revision 1. | Original stale post-save URL found and fixed; final URL verification recorded below. |
| Account connections | Created metadata-only connection, edited note, refreshed and reopened to verify stored value; cancelled edit. | No external credentials or consent grant created. |
| Service access | Opened and closed panel; unavailable creation correctly explained for device-flow collection. | Grant mutation not live-exercised. |
| Devices/collections refresh | Both refreshed successfully; empty device list displayed. | No real device revoke performed. |
| Templates | Password-reset Korean preview iframe rendered actual email; console had no errors. | Stale preview on type change found and fixed; final verification below. |
| Events | Loaded 19 events, selected critical and loaded 0 with matching empty state; auto-refresh checkbox checked/unchecked. | Five-second polling timing independently tested, not timed in live browser. |
| Sessions | Changed Auth to LoggedOut and applied Rows=1; returned LoggedOut records. | Server paging threshold can return all small result sets. Added explanation and numeric bounds; no global logout performed. |
| Clients | Device preset selected public/device+refresh; Web restored confidential/code+refresh; Cancel returned to list. | Creation/secret mutations not live-exercised. |
| Providers | Kind switch hid OAuth fields; Cancel returned to list. | External-provider setup/exchange unavailable; new API-key connector form covered by Node. |
| Blacklist | Disabled deployment explanation displayed. | Cannot claim successful block/unblock in this deployment. |
| Registration | Required name and optional-details disclosure rendered; optional fields expanded. | No live new account completion. |
| Password recovery | Submitted synthetic nonexistent email; proof-of-work and request succeeded, form hid and Korean anti-enumeration notice appeared. | Does not prove email delivery or password change. |

## Fixes integrated

- Collection and catalog writes now navigate to the list URL instead of leaving the form URL behind.
- Template type changes clear stale previews; preview sizing uses the CSP-compatible stylesheet.
- Metadata parse errors are localized; valid scalar/array JSON remains supported by the backend contract.
- Added native session page-size validation and explained server paging behavior.
- Provider connector labels/errors and collection method labels use Korean translations.
- Reduced form/control/panel spacing; unversioned theme CSS revalidates to avoid stale styling.
- Corrected old standalone admin smoke expectations to verify the dashboard redirect and current navigation.
- Corrected API-key HTTP E2E to rotate/delete using browser-admin session+CSRF; explicitly asserts API keys cannot perform those operations. No security gate was relaxed.

## Executed checks

- 21 Node UI suites passed, including reset-stage mismatch, CSRF/payload binding, success, rejected write, server failure, lost response and duplicate-submit prevention.
- Go tests passed: branding, recovery, login, logout, device, i18n, account, admin, cmd/goauthy. Worker verified rbac, authcollection, ipblacklist, saas, eventlog.
- Standalone admin HTTP smoke passed: sign-in, root redirect, dashboard navigation, rejected unauthorized/cross-site requests, sign-out and stale-cookie rejection.
- Live HTTP tests passed: admin UI routes, user create lifecycle and user update; corrected API-key lifecycle passed on fresh standalone state.

## Remaining live qualification

Hardware passkeys/MFA, real external OAuth/API-key providers, destructive deletion, security-sensitive grants, disabled blacklist configuration, and multi-node HA are not qualified by these runs. Browser credential creation/change requires user handoff; irreversible deletion or new access requires action-time confirmation under the computer-use tool policy. Unit/HTTP coverage for these cases is explicitly separate from live browser evidence.

## Final rebuilt preview verification

- Collection creation navigated to `/auth/v1/admin/collections`; the saved `UI audit final` row appeared with revision 1. Reload retained the list route.
- Selecting password-reset/ko produced the expected preview URL; changing type to password-new removed the old iframe (count 0).
- Mobile administrator menu opened and its Sessions link navigated successfully. The Korean paging explanation rendered.
- All 14 administrator destinations were loaded at measured CSS widths 1422, 911 and 433; no document-level horizontal overflow was observed. Tablet/mobile runs waited for loading notices to disappear. This is layout evidence, not every conditional form/mutation state.
- Account fields measured 36px high with 6px/10px padding, buttons 36px; language selector 32px with 4px/8px padding. Account width checks showed no overflow at desktop/tablet/mobile sizes. Pointer-coarse 44px touch rules exist but were not hardware-tested.
- Current final tab console error list was empty. Viewport override was reset, and the account tab remains open.
- Evidence artifacts: `/tmp/goauthy-ui-audit-final-account.png`, `/tmp/goauthy-ui-audit-layout.json`. These are local temporary files, not committed fixtures.

## Feature-by-feature qualification follow-up

The Korean entry point is [기능과 사용 흐름](ui-user-guide.md), with separate account, administrator, and integration guides. All procedures are documentation, not implicit execution claims.

Independent Pro review: [UI qualification boundaries](https://chatgpt.com/g/g-p-69ecdc42175c819186cf485b225c0e46/c/6ab7d80b-0264-83e8-a4af-a71401a9482a). Its acceptance matrix separates role/ownership, state transitions, uncertain writes, external activation, revocation effects, and responsive error states. Advice was checked against local contracts; for example event severity is a minimum threshold (`level>=?`), so All/info includes higher severities.

### Additional actual browser observations

- Attribute `audit_department`: created with JSON default `"engineering"`, reopened, changed to `"design"`, reopened with that value. User-editable remained false.
- Scope `audit_profile`: saved with one ID-token claim (`audit_department`), reopened and verified; not assigned to a client.
- Role `audit-unassigned`: created without assigning membership; reopened and confirmed scalar JSON `false`. Malformed JSON rejected with Korean error, then Cancel returned to the list.
- API-key form: no-rights submission rejected and Cancel returned to empty list; no key created.
- Provider API-key form: malformed connector JSON rejected and Cancel returned to empty list; no provider created.
- Sessions: zero rows rejected by native validation; global logout without acknowledgment showed an error without ending the session.
- Account language: unsaved username triggered confirmation; Continue editing retained input and Korean; Change language discarded input and loaded English. Switched back to Korean.
- Logout: cancel returned to signed-in account; confirming logout reached login.
- Existing member fixture `admin-updated@goauthy.e2e`: actual password sign-in reached `/account`; no admin return link; Home returned to account. Direct `/auth/v1/admin` showed access guidance, and Home returned to account without a login loop.
- Member fixture was produced by the existing pure HTTP `TestAdminUserUpdateAcrossPods`, which passed against the disposable local instance. Same URL for all nodes is standalone evidence only. Log: `/tmp/goauthy-member-fixture-http.log`.

### Follow-up fixes

- Session filter explanation moved below the controls; provider/registration field spacing reduced. Live mobile testing with populated session data exposed one-character wrapping: shared table cells now retain a 12ch minimum width inside the existing horizontally scrollable container.
- API-key permission labels localized while wire enums remain unchanged. Explicit browser-admin requirement and plaintext-secret storage wording added.
- Catalog save/delete share a pending guard, preserve disabled control state on failure, and prevent Cancel during a pending request. JSON-default errors localized.
- Shared admin mutation fetch rejection or failed successful-response body read reports unknown outcome and never retries automatically; actual no-content responses remain supported. A deterministic mocked regression covers the message and request count; it is not live packet-loss evidence.

### Explicitly unqualified cases

| Case | Missing evidence / prerequisite | What completion requires |
|---|---|---|
| New passwords, passwordless conversion, hardware passkeys | Browser credential entry and authenticator require user handoff | User performs credential/authenticator step; inspect final account state and subsequent sign-in |
| Real OAuth or external API-key connector | Test provider account, callback, allowed scopes/operations, credential entry | Complete upstream flow and invoke intended operation; check state and failure recovery |
| New grants or expanded memberships/scopes | Action-time confirmation for security-sensitive access | Review exact subject/consumer, permissions and duration; after action prove actual allowed/denied use |
| Permanent deletes / credential revocation in browser | Confirmation of exact target and effect | Execute chosen action and verify protected use fails; distinguish local from upstream revocation |
| IP blacklist active enforcement | Preview feature disabled | Isolated enabled deployment with safe test range and expiry; verify enforcement/unblock |
| Lost response after server commit | Mocked boundary only | Controlled disposable-server response loss and delayed completion; inspect persisted record without blind retry |
| Ownership isolation between two real users | Handler/HTTP tests, no full two-user browser sequence | Two approved existing member fixtures; direct owned/unowned routes and denied mutations |
| Mail delivery beyond local sink | Local SMTP fixture is not an external inbox | Verify actual test inbox, link expiry/reuse and final password setup by user |
| Multi-node HA | Current endpoint is one standalone instance | Independent nodes and actual failover; outside this UI preview qualification |

Temporary audit records are disposable preview data and are removed by the preview script on restart. No production or remote Git changes were made in this qualification pass.

- Invalid device code was submitted in the real browser: the localized unusable-code message appeared and Exit to account was available. This exposed the old unbounded page layout; the verification page now reuses the shared authentication shell and error styling.
- Full Go check initially failed one stale account-login continuation expectation (`/account` instead of role-routing `/`). Updated that assertion; the entire login package then passed (`/tmp/goauthy-qualification-login-rerun.log`). Other listed packages passed. Final admin/device packages passed after response handling and device markup updates (`/tmp/goauthy-qualification-final-modules.log`).
- All 21 Node suites passed; the changed admin regression and locale checks passed again after response-body handling. Catalog pending behavior includes duplicate submit, pending delete, cancel blocking, recovery and preserved disabled state.
- API-key pure HTTP lifecycle passed again on the rebuilt preview (`/tmp/goauthy-qualification-api-key-http.log`). Browser mutations remain a separate unqualified layer.

### Final responsive/error-state check (2026-09-27 KST)

- Final catalog error form measured CSS widths 433 / 911 / 1422 without document overflow. Korean invalid JSON message appeared; correcting it allowed save and list navigation.
- Final API-key form at 433px showed Korean group/right labels and retained no-rights validation. Mobile menu opened and navigated to it.
- Populated sessions table at 433px: document width 433, scroll region 401, table width about 609, cell widths at least 95px. The table scrolls inside its region instead of collapsing to single-character columns.
- Device verification initially still loaded the account stylesheet despite auth markup. Both entry and completion renderers now load the shared global auth stylesheet; regression checks its exact issuer-bound URL.
- Candidate base is `ea830e24` plus the uncommitted worktree changes. Preview flags: `GOAUTHY_UI_PREVIEW=1`, `GOAUTHY_E2E_ACCOUNT_PASSKEY_UI=1`, `GOAUTHY_E2E_PROFILE_CLAIMS=1`, standalone port 18120. This is not a release or remote deployment.

- Final device error shell visually verified on desktop and 433px mobile (panel 385px, no document overflow); code entry, localized error, and Exit to account remained available. The final return link uses shared authentication spacing. Screenshot: `/tmp/goauthy-final-device-verification.png`. Device package and targeted final spacing check passed.
- Viewport overrides were cleared; the rebuilt preview remains running on port 18120.

## 클라이언트 로그인 테마 편집기 (2026-09-27)

- 클라이언트별 light/dark 7색·버튼 글자색·모서리 편집, 격리된 실시간 미리보기, 저장·재조회·공통 테마 상속 복원을 추가했다.
- 실제 로컬 브라우저에서 두 모드 저장과 새로고침 유지, 미저장 변경 되돌리기, 복원 취소/확인, 실제 OAuth 로그인 CSS의 저장된 action/radius 반영을 확인했다.
- CSS viewport 433 / 911 / 1422px에서 문서 가로 넘침 없음, 모바일/태블릿 세로 배치와 데스크톱 두 열 배치를 확인했다.
- 부트스트랩 클라이언트의 상세 편집은 지원되지 않으므로 복귀 링크를 클라이언트 목록으로 수정하고 실제 이동을 확인했다.
- Node 22개 UI 검사 스위트와 관련 Go 검사가 통과했다. 마지막 복귀 링크 변경 후 theme/admin Node 회귀 검사 및 Go admin 검사를 다시 통과했다.
- 로고·문구·임의 HTML 편집은 범위 밖이다. 미리보기는 인증을 실행하지 않는다.

## 로그인 로고·문구·레이아웃 확장 (2026-09-27)

- Theme JSON의 선택적 login 필드로 한·영 제목/안내/버튼 문구와 정렬/카드 너비를 저장한다. 기존 데이터는 그대로 읽는다.
- 로고는 기존 multipart 업로드/삭제 API를 재사용한다. 관리 UI의 자체 이미지 CSP 허용과 sandbox 미리보기 이미지 상태 동기화를 보완했다.
- 브라우저: SVG 업로드 성공 및 미리보기 표시, 삭제 확인 취소/실행, 한·영 문구 저장과 저장된 설정 재조회, 실제 OAuth 페이지 로고/문구/480px 카드 너비 확인. 실제 로그인 언어 전환 시 사용자 이름 입력이 유지됨을 확인했다.
- 최종 편집기의 CSS viewport 433px/911px에서 가로 넘침이 없고, 데스크톱은 두 열로 표시됨을 확인했다.
- 전체 관련 Node UI 검사, Go login/branding/admin/cmd 검사 통과. 마지막 CSP 수정 후 admin 검사 재통과.
- 자유 HTML, 가입·복구 화면별 문구, 영구 초안/게시 버전 이력은 이번 확장에 포함하지 않는다.
