# 실제 소비 프로젝트 연동

2026-09-06 사용자 요청: backoffice·compos의 계정 인증, conductor의 사용자 소유
SaaS 연결 인증, ternal의 계정 인증과 OAuth Device Flow를 GoAuthy로 실제 사용한다.
이 문서는 연동 완료 선언이 아니라 코드 근거·담당 작업·수용 검사의 추적표다.
Rauthy 전체 기능 목표와 standalone/HA 목표는 유지하며 새 HA 검증은 사용자 요청대로 뒤로 미룬다.

2026-09-07 사용자 추가: Beesuh도 실제 소비자로 포함한다.

## 최신 수용 상태 (2026-09-07 후속)

2026-09-08 후속: GoAuthy OAuth BFF handoff API/기본 브라우저 화면 구현과
실제 HTTPS standalone 재시작 전후 승인이 통과했다. 공개 provider/account/scopes/
version 검토와 버전 고정 동의, access-token 전달/owner refresh/철회를 검증했다.
이는 실제 Backoffice BFF의 callback/state 소비 검증이 아니다.
후속 schema82는 별도 `allow_refresh` 동의와 consumer refresh API를 추가했다.
실제 HTTPS/Chromium consumer refresh/새 token 전달/철회는 재시작 전후 PASS했다.
전달 자체의 자동 refresh나 background scheduler는 없으며 소비자가 명시적으로
요청해야 한다. 소비자 OAuth adapter와 실제 BFF 통합은 여전히 남는다.

추가 후속: 실행 consumer의 현재 version/state 복구를 위한
`GET /auth/v1/connection-grants/{grant_id}/credential-status`를 구현했다.
자기 confidential human use token과 현재 OAuth delivery 동의를 요구하며
상태 6개 필드만 반환한다. 실제 HTTPS Chromium에서 refresh 전후 조회/철회
차단과 외부 호출 0을 standalone 재시작 전후 확인했다. 앱 재시작/복구 wiring
완료는 아니며 BFF의 read-token으로 다른 consumer를 조회할 수 없다.

최신 담당 피드백: Compos/Backoffice/Conductor/Beesuh 모두 이미 검증한 계정 또는
API-key 기본 경로에서 새 GoAuthy API 부재를 확인하지 않았다. 남은 소비자 wiring을
GoAuthy API 미구현과 구분한다. GoAuthy의 다음 공통 구현은 OAuth 전용 BFF
handoff(provider/account/scopes 검토)와 장기 실행을 위한 승인된 refresh 흐름이다.
현재 delivery 자체는 refresh하지 않는다. 목적별 token/resource, callback/return
URI와 introspection 제한은 [소비자 토큰 계약](consumer-token-resources.md)을 따른다.
Backoffice 실제 로그인→승인→실행 E2E는 여전히 0건이다.

아래 초기 조사와 역사적 SKIP 기록보다 이 요약 및 STATUS.md의 후속 결과를
우선한다. 부분 pilot 성공은 운영 연결 완료가 아니다.

보안 후속: 기존 amd64 후보의 High 의존성 취약점을
[의존성만 수정한 별도 후보](ternal-security-candidate-20260907.md)에서 해결했다.
root는 새 이미지 scan JSON과 인증/메일 회귀 검사를 확인했다. Ternal 담당은
별도 GCS prefix의 old→candidate→emptyDir replay, token introspection/JWKS
연속성 검증 후 기존 설정/비밀/storage를 유지한 image-only 교체와 Ready를
보고했다. 실제 Chrome RP 로그인·관리자 session·logout도 통과했다고 보고했다.
이는 담당의 운영 검증 보고이며 GoAuthy root가 직접 IED를 변경한 것은 아니다.
기존 schema 버전을 추정하거나 일반적인 downgrade 호환을 보장하지 않는다.

| 소비자 | 완료한 실제 검증 | 아직 열린 수용 검사 |
| --- | --- | --- |
| Ternal standalone | 실제 API/CLI Device 로그인·그룹·logout, GoAuthy 재시작 전후. 담당 보고: 보안 후보 amd64/GCS cold replay 및 실제 RP 웹 로그인·logout | 같은 Ternal 세션 재시작 유지·SSH/relay 전체 흐름 |
| Compos | 계정/session/logout, OAuth Bearer 및 audience/scope/revoked·업무 membership | EXPIRED fixture, 운영 설정·계정 연결·갱신 |
| Conductor | 실제 API-key adapter와 로컬 TLS 제공자, 동의 철회 후 호출 차단 | 사용자 인증부터 execution/queue, 실제 SaaS·OAuth adapter |
| Beesuh | identity와 두 API-key 연결 선택·Runtime·철회 | EXPIRED fixture, 실제 공개 로그인부터 실행, OAuth/Codex |
| Backoffice | GoAuthy 측 제공자/연결/동의/credential-use API | BFF callback state 및 token-source 분리, PB 인증 대체와 실제 브라우저 통합 |

일반 GoAuthy native browser 로그인은 CSP 수정 후 code→PKCE token exchange→
JWKS/nonce/subject→UserInfo→revoke/401까지 standalone 재시작 전후 통과했다.
이는 실제 소비자 RP의 웹 세션 테스트와 구분한다. Ternal 후보는
[소스·이미지 identity](ternal-candidate-20260907.md)가 확정됐지만 arm64 Dory의
amd64 실행 probe가 앱 시작 전 exec format error로 끝나 amd64 runner가 필요하다.
후보 게시·IED 배포·host session 복구는 이 검증에서 수행하지 않았다.
이 문단은 최초 로컬 후보 검사 이력이다. 이후 보안 후보의 담당 측 amd64
실행·배포·웹 RP 검증 보고는 위 최신 요약을 따른다. host session 복구는
여전히 확인되지 않았다.

만료 검사에서는 토큰 내용을 임의 수정하거나 revoked token을 expired로
이름만 바꾼 결과를 인정하지 않는다. 실제 소비자의 EXPIRED가 검증되기 전에는
GoAuthy 내부 fixed-clock HTTP 검사로 해당 SKIP을 완료 처리하지 않는다.

담당 소스 재확인: Compos `internal/server/oauth2.go`와 Beesuh
`httpapi/goauthy_e2e_test.go`는 introspection 응답의 exp를 실제 현재 시각과
비교하며 clock 주입 지점은 없다. 기존 합성 HTTP 검사는 과거 exp 응답으로
401을 검증하지만 실제 GoAuthy가 발급한 만료 토큰 E2E는 아니다. Live 계약은
각각 `COMPOS_E2E_OAUTH2_EXPIRED_TOKEN_FILE`,
`BEESUH_E2E_GOAUTHY_EXPIRED_TOKEN_FILE`의 0600 일반 파일을 받는다.
이 확인 과정에서 소비자 코드·설정·자격증명은 변경하지 않았다.

### 2026-09-07 HTTPS standalone 증거와 Backoffice 대기 계약

후속 관리 Bearer gate는 `GOAUTHY_E2E_PROVIDER_BEARER=1 GOAUTHY_E2E_TLS=1
GOAUTHY_STANDALONE_OPEN_REG_PORT=17960 sh scripts/e2e-open-registration-standalone.sh`.
`/tmp/goauthy-provider-bearer-live-20260907.log` 종료 0, 재시작 전후 각 1.11초 PASS.
GoAuthy cookie 없이 실제 PKCE access token으로 제공자 CRUD, wrong audience/scope,
nonadmin, revoked token, cookie 혼합 거절을 검증했다. 담당에게
`GOAUTHY_PROVIDERS_RESOURCE`, read/write scope catalog·DCR audience 등록,
Backoffice BFF의 서버측 access-token 사용 계약을 전달했다. 실제 Backoffice 앱은
아직 별도 연결 검증이 필요하며 사용자 연결/동의/credential-use는 다음 구현 범위다.

제공자 CRUD 후속 gate: `GOAUTHY_E2E_PROVIDER_REGISTRATION=1 GOAUTHY_E2E_TLS=1
GOAUTHY_STANDALONE_OPEN_REG_PORT=17950 sh scripts/e2e-open-registration-standalone.sh`.
`/tmp/goauthy-provider-registration-both-kinds-final-20260907.log` 종료 0:
OAuth2/API-key 제공자 CRUD는 재시작 전 0.16초, 후 0.18초 PASS.
이는 GoAuthy browser-admin 경로의 검증이다. 외부 OIDC Bearer 관리·연결 callback·
consumer 동의/credential-use가 남았음을 Backoffice 담당에게 함께 전달했다.

`GOAUTHY_E2E_DEVICE_OIDC=1 GOAUTHY_E2E_TLS=1 GOAUTHY_STANDALONE_OPEN_REG_PORT=17940 sh scripts/e2e-open-registration-standalone.sh`
는 `/tmp/goauthy-open-registration-tls-17940.zmLtTT`에서 정상 종료했다.
`TestDeviceOIDCLive`는 재시작 전 1.89초, 후 1.93초 PASS다. 임시 CA와
localhost/127.0.0.1 SAN 인증서를 사용하고 시스템 trust store는 변경하지 않는다.
이는 실제 Backoffice 브라우저 연동이나 새 HA 검증 완료를 의미하지 않는다.

Backoffice 담당의 등록 후보 callback은 `https://127.0.0.1:5175/auth/oidc/callback`이다.
계약은 `OIDC_CLIENT_SECRET_FILE`(0600), `OIDC_ISSUER`, `OIDC_CLIENT_ID`,
`OIDC_TOKEN_AUTH_METHOD=client_secret_post`, `OIDC_REDIRECT_URI`,
`BACKOFFICE_OIDC_PILOT=true`, `DEV_HTTPS=true`, `DEV_HTTPS_KEY_FILE`,
`DEV_HTTPS_CERT_FILE`, `NODE_EXTRA_CA_CERTS`다. 인증서 준비와 실제 IdP pilot은
미완료이며 현재 5175 HTTP UI 확인을 HTTPS 연동 성공으로 처리하지 않는다.
담당 요청에 따라 별도 issuer/credential은 만들지 않았다. GoAuthy의 제공자 등록·
연결·동의·자격증명 사용 API 구현은 이 pilot을 기다리지 않고 진행한다.

**사용자 정정(Backoffice 담당 작업에서 전달): GoAuthy가 PB 인증을 대체한다.**
Backoffice 직접 OIDC 로그인과 Compos GoAuthy token 검증으로 전환한다.
아래 초기 PB 중개 제안은 폐기되었으며 실행 계획으로 사용하지 않는다.
기존 PB ID 데이터 참조는 검증된 명시적 이전 매핑으로 보존하고 이메일 자동 병합은 금지한다.
PB 업무 데이터 저장소 이전·폐기는 이 인증 대체의 승인 범위에 포함되지 않는다.

## 현재 코드와 연동 경계

| 소비자 | 확인한 현재 동작 | 추가로 필요한 계약 | 상태 |
| --- | --- | --- | --- |
| backoffice | `src/lib/infra/auth/oauth.js`: PocketBase users OAuth, Google 고정 callback, 도메인 검증 | 직접 OIDC·서버 세션, locals.user/PB token 의존 분리, legacy ID 명시적 매핑 | 사용자 정정 반영, 직접 인증 구현 경계 재분석 |
| compos | `porting-go/internal/server/auth.go:verifyRauthy`: Basic introspection 후 UserInfo, audience/scope/verified email 검사, 자체 workspace session 교환 | 실제 issuer/resource/scope 설정, 기존 principal hash 보존, 세션 폐기 정책 | 분석 수신, opt-in live harness 구현 요청 |
| conductor | `internal/connections/oauth.go`: 자체 OAuth PKCE·암호화 토큰 저장; `cmd/conductor/main.go`: 공통 service token 및 workspace/provider resolver | 사용자↔workspace/connection 권한, 명시 동의·작업별 위임·bound-call 공개 API | 초기 분석 수신, 첫 작업 계약 선정 중 |
| ternal | `internal/auth/oidc.go`: coreos OIDC 검증·nonce/state·DeviceAuth/PollDevice, openid/groups | 로그인 S256 PKCE, groups/issuer/client auth 실제 호환, 장치 승인과 계정 연결 E2E | PKCE 호환 수정 요청 |
| beesuh | `NewAuthenticated`+`RequireIdentity/Authorize/ResolveCredential`, owner/workspace Connection; CLI는 operator bearer | 전용 audience/scope 검증 host, principal 매핑, 실행 위임·Conductor 프로토콜 | 분석 수신, Conductor 담당과 계약 수정 협업 요청 |

소비자 경로는 각각 `<consumer-repo>/{backoffice,compos,conductor}`와
`<consumer-repo>/ternal`이다. Ternal 담당 작업의 checkout은
`<consumer-repo>/ternal` (사용자 지정 checkout)이며 checkout과 버전 차이가
있다는 보고를 받았다. 임의 복사나 사용자 checkout 갱신은 하지 않는다.

## 담당 로컬 작업

사용자가 기존 작업과 직접 소통하도록 요청했다. 새 작업은 만들지 않았다.

- backoffice: [internal coordination reference omitted]
- compos: [internal coordination reference omitted]
- conductor: [internal coordination reference omitted]
- ternal: [internal coordination reference omitted]
- GoAuthy 통합·검증: [internal coordination reference omitted]
- beesuh: [internal coordination reference omitted]

각 담당은 자기 checkout의 분석·합의된 구현·검증 결과만 공유한다. 원래 프로젝트의
다른 변경을 덮어쓰지 않고 commit/push/production 배포는 이 초기 연동에서 하지 않는다.
비밀값은 작업 메시지·문서·로그로 전달하지 않는다.

## 확인한 장애와 구현 순서

- [x] 네 프로젝트 코드와 로컬 담당 작업 식별, 분석 요청 전달 및 활성 상태 확인.
- [x] Ternal PKCE 장애 확인: GoAuthy `internal/oauth/server.go`의 `EnforcePKCE=true`,
  `EnablePKCEPlainChallengeMethod=false`와 Ternal의 verifier 없는 로그인 흐름 불일치.
- [x] 최신 Ternal worktree의 signed state에 verifier 결합 및 S256/code exchange 전달.
  담당의 auth 일반/race/전체 테스트 통과 보고와 부모의 두 파일 diff 대조 완료.
  사용자 지정 오래된 checkout으로 복사·commit·배포하지 않았으며 실제 GoAuthy E2E는 남아 있다.
  GoAuthy의 PKCE 보안 요구를 낮추지 않는다.
- [ ] backoffice 직접 GoAuthy OIDC 로그인·서버 세션 및 legacy ID 매핑, 실제 브라우저 검증.
- [x] compos 실제 GoAuthy 토큰 introspection/UserInfo→workspace session positive E2E.
  `rauthy`라는 내부 이름만 변경하면 principal ID가 달라질 수 있으므로 이름 변경부터 하지 않는다.
- [x] compos wrong audience/scope/revoked 실제 token fixture 음성 검사.
- [ ] compos expired 실제 token fixture 검사(고정 sleep 기반 만료 테스트로 대체하지 않음).
- [ ] conductor 첫 read-only SaaS operation의 입력·출력·권한 계약 확정.
- [ ] GoAuthy 컬렉션 허용 목록·명시적 대상 동의·공개 bound-call·사용자 위임 구현.
- [ ] 지속적인 로컬 실행 환경, 각 소비자 client 등록과 비밀 없는 설정 예제.
- [ ] 각 담당 실제 사용 피드백 수신→재현→회귀 테스트→수정→다시 사용.

Conductor의 요청 `actor`, `subject_ref`, `workspace_id`는 권한 증명이 아니다.
client_credentials 또는 기존 정적 service token만으로 사용자의 SaaS credential 사용을
허용하지 않는다. 현재 GoAuthy token exchange의 same-client/single-audience 범위를
cross-client 위임 지원으로 해석하지 않는다. raw key export는 연동 경로가 아니다.

## 실사용 완료 증거

각 프로젝트별로 실제 GoAuthy standalone을 사용하는 성공 흐름과 잘못된
audience/scope/다른 사용자·workspace, 만료·철회·GoAuthy 장애 시 거절을 확인한다.
로그인에는 callback/state/nonce/PKCE, Device에는 pending/slow_down/승인/거절/만료와
일회성 소비를 포함한다. SaaS는 Rhiza 암호문→검증 TLS 공급자→Conductor 제한된 결과까지
검증하고 미동의·잘못된 대상 전송 0건 및 진행 중 폐기/회전 후 결과 거절을 확인한다.
현재 개별 엔진 테스트 통과는 이 소비자 E2E의 대체 증거가 아니다.

## 담당 분석에서 추가 확인한 필요사항

Backoffice는 현재 PB 사용자 token을 Compos의 `/api/v1/auth/pocketbase`로 넘긴다.
사용자 정정에 따라 이 의존은 GoAuthy 직접 인증으로 교체할 대상이다.
초기 PB custom-provider/hook pilot 및 provider별 callback 구현 요청은 취소했다.
PB 서버 경로·권한 비동기 질문은 이 폐기된 pilot의 선행 조건이므로 더는 차단점이 아니다.
다만 PB 업무 데이터 접근의 인증·사용자 참조를 보존할 계약은 직접 인증 구현 시 확인한다.

Compos principal은 issuer까지 포함해 생성되므로 issuer 변경도 계정 이전이다.
production migration 없이 별도 테스트 workspace로 검증한다. Compos 자체 session은
외부 token의 만료 시각을 상한으로 삼지만 외부 철회가 즉시 전파되지는 않는다.
Backoffice PB session도 GoAuthy session과 별개다. 전역 logout/비활성 전파는 별도
수용 조건이며 현재 각 앱 logout을 전역 logout으로 표시하지 않는다.

Compos 담당과 합의한 첫 pilot: host-local 별도 standalone DB, issuer 후보
`http://localhost:17889`, resource `https://compos.local.test`, 동일 confidential
발급·introspection client, `openid email profile`, 필수 scope `openid`.
주소는 아직 실행·배포된 endpoint가 아니며 전용 업무 권한은 Compos membership이
판단한다. token/client secret은 비공개 FILE 경로로 전달하고 argv/로그/문서에 넣지 않는다.

## 2026-09-07 첫 actual Compos 연동 결과

`GOAUTHY_E2E_COMPOS=1 GOAUTHY_E2E_COMPOS_PROJECT_DIR='<consumer-repo>/compos/porting-go' GOAUTHY_STANDALONE_OPEN_REG_PORT=17889 sh scripts/e2e-open-registration-standalone.sh`

- GoAuthy standalone Rhiza에서 실제 사용자 로그인/S256 authorization code 발급,
  `https://compos.local.test` audience와 UserInfo verified email 확인.
- 기존 검증된 사용자 생성 helper를 재사용하여 필수 profile 필드 누락으로 발생한
  최초 fixture activation 400을 수정했다. 서버 validation은 완화하지 않았다.
- Compos 별도 실제 Rhiza DB에서 두 로그인 동일 principal/person, membership 중복 없음,
  session 조회, 비회원 workspace 403, 첫 session logout 후 401 및 두 번째 session
  독립 유지·자체 logout 통과. 두 번째 logout 뒤 추가 GET 401은 최초 live 검사에 없었다.
  담당 피드백으로 이 증거 범위를 정정했고 추가 assertion과 재검증을 요청했다.
- 로그 `/tmp/goauthy-compos-live-20260907.log`, outer 종료 0.
  `TestConsumerTokenFixture` package 1.388초, `TestGoAuthyLiveE2E` 0.88초.
- WRONG_AUD/WRONG_SCOPE/EXPIRED/REVOKED 네 subtest는 fixture 미제공으로 명시적 SKIP.
  전체 음성 matrix 또는 장기 실사용 완료로 계산하지 않는다.
- 테스트 서버·DB·0700/0600 비밀 파일은 종료 시 폐기했다. localhost:17889는 상시 서비스가 아니다.

Ternal 추가 확인: 현재 GoAuthy `internal/oauth/device_grant.go`는 openid/groups를
명시적으로 거절한다. 따라서 Ternal Device의 ID token/groups 계약과 호환되지 않는다.
GoAuthy Device OIDC 기능을 구현해야 하며 Ternal의 필수 ID token/RBAC 검사를 제거해
우회하지 않는다.

## 2026-09-07 실제 음성 검사 확장

같은 실행 명령으로 `/tmp/goauthy-compos-negative-20260907.log` 종료 0 확인.
실제 사용자 authorization-code 발급 경로를 재사용해 다른 audience의 활성 토큰,
openid 없는 활성 토큰, 실제 `/oidc/revoke` 후 inactive인 토큰을 생성한다.
서버 토큰을 조작하거나 단순 임의 문자열을 폐기 토큰으로 대신하지 않는다.

- GoAuthy fixture 발급·검증 2.46초, Compos live 1.49초.
- WRONG_AUD / WRONG_SCOPE / REVOKED에서 Compos 401 확인.
- 두 번째 session logout 이후 GET 401 추가 단언도 이번 actual live에서 통과.
- EXPIRED만 명시적 SKIP. 기존 네 가지 SKIP 기록은 첫 실행의 역사이며 이번 실행에
  소급 적용하지 않는다. 전체 expiry/HA/production 전환은 여전히 미완료다.

## Generic Compos OAuth2 신규 pilot 진행 상태

기존 `/auth/rauthy` live PASS와 다른 `TestOAuth2LiveE2E`용으로 독립 DCR RP와
introspection caller, `compos.api` scope 및 resource-bound token fixture를 추가했다.
`GOAUTHY_E2E_COMPOS_OAUTH2=1` runner의 최초 두 실행은 실패했다.
첫 실제 실행은 custom scope catalog 누락으로 client lookup이 거절됐고,
scope 등록을 추가한 다음에는 attribute 없는 scope가 400으로 거절됐다.
`/tmp/goauthy-compos-oauth2-live-20260907.log` 및
`/tmp/goauthy-compos-oauth2-live-final-20260907.log`는 모두 실패 증거다.
권한 전용 scope를 수정한 뒤에도 DCR RP audience가 비어 있어 authorization이 거절됐다.
`/tmp/goauthy-compos-oauth2-permission-scope-20260907.log` 역시 실패 증거다.
기존 Compos session pilot PASS에 이 새 모드 결과를 합산하지 않는다.

2026-09-07 새 direct OAuth2 actual PASS:

- GoAuthy permission-only scope와 authenticated DCR `audience` 등록을 사용했다.
  RP와 introspection caller는 서로 다른 새 client이며 기존 bootstrap 토큰을 재사용하지 않는다.
- `/tmp/goauthy-compos-oauth2-audience-20260907.log`, runner 종료 0.
  GoAuthy token fixture 1.25초 / Compos `TestOAuth2LiveE2E` 0.71초(package 1.499초).
- 실제 Basic cross-client introspection + resource-bound token의 UserInfo sub/verified email 검증.
  consumer에서는 `openid compos.api`와 exact resource를 확인한다.
- identity 등록은 membership/session을 만들지 않음. membership 없는403 → 명시 fixture grant200 →
  cross-workspace403 → membership 삭제403, logout405, Compos own session0 단언 통과.
- WRONG_AUD / WRONG_SCOPE / REVOKED401 통과. EXPIRED만 명시 SKIP이며 sleep 기반 fixture를 추가하지 않았다.
- 임시 issuer/DB/credential 파일은 소비자 검사 후 runner가 정리했다. 상시 서비스나
  Backoffice 브라우저 통합, audience별 introspection ACL, 새 HA 증거가 아니다.

재현은 GoAuthy dirty worktree와 Compos의 현재 dirty source가 모두 필요하다:

```sh
GOAUTHY_E2E_COMPOS_OAUTH2=1 \
GOAUTHY_E2E_COMPOS_PROJECT_DIR='<consumer-repo>/compos/porting-go' \
GOAUTHY_STANDALONE_OPEN_REG_PORT=17920 \
sh scripts/e2e-open-registration-standalone.sh
```

## Beesuh 분석에서 확인한 추가 계약

2026-09-07 actual standard identity pilot 완료(공통 fixture 최종 후보):

- `/tmp/goauthy-beesuh-identity-live-final-20260907.log`, runner 종료 0.
  GoAuthy 전용 DCR RP+별도 caller fixture 1.25초, Beesuh live 0.71초(package 1.307초).
- `https://beesuh.local.test` audience와 `openid` 필수 scope, 실제 introspection/UserInfo,
  compact 0600 `memberships.json`의 `(issuer, sub, workspace-a)` 명시 매핑을 사용한다.
- 로컬 model chat 두 번과 안정된 identity, 비회원 workspace403,
  WRONG_AUD/WRONG_SCOPE/REVOKED401, 거절 후 추가 model 호출 없음 단언 통과.
- EXPIRED만 명시 SKIP. provider/Codex 실제 계정, production auth wiring, 새 HA 증거가 아니다.
  테스트 issuer/DB/credential 파일은 consumer 검사 후 정리됐다.
- 공통 fixture의 필수 scope를 Beesuh(openid)와 Compos(compos.api)별로 분리했다.
  최종 Compos 회귀도 0.78초, runner 종료 0:
  `/tmp/goauthy-compos-oauth2-shared-fixture-final-20260907.log`.
  앞선 `/tmp/goauthy-compos-oauth2-shared-fixture-20260907.log`는 fixture 오류의 실패 기록이다.

```sh
GOAUTHY_E2E_BEESUH=1 \
GOAUTHY_E2E_BEESUH_PROJECT_DIR='<consumer-repo>/beesuh' \
GOAUTHY_STANDALONE_OPEN_REG_PORT=17920 \
sh scripts/e2e-open-registration-standalone.sh
```

Beesuh/Compos 모드를 한 fixture에서 동시에 선택하면 provisioning 전에 거절한다.
소비자 source와 GoAuthy source 모두 현재 dirty worktree가 필요하며 commit만으로 재현되지 않는다.

2026-09-07 사용자 교정: 외부 인증 연결·복수 프로파일·credential lifecycle과 허가된
사용은 GoAuthy의 선택 확장이 공통으로 소유한다. AI/SaaS별 테이블·API로 나누지 않는다.
소비자는 실행/connector 요청 의미와 업무 권한을 소유하며 공개 adapter로 독립 테스트한다.
HTTP provider 인증 주입이 첫 공통 요구이며, 전달 방식과 Codex CLI adapter는 미확정이다.
아래 초기 분석은 실제 live 검증 완료를 의미하지 않는다.

담당 분석과 `auth_integration_test.go`, `scoped_conductor_test.go`를 대조했다.
Beesuh에는 인증된 HTTP client 주입과 owner/workspace별 connection 경계가 있지만
현재 CLI는 operator bearer이고 실제 OIDC authenticator/bootstrap은 미구현이다.
Compos principal은 issuer/sub로 파생되는 별도 값이므로 Beesuh raw UserID와 같다고
가정하지 않는다. 모델 입력 actor/subject_ref 및 X-Beesuh scope 헤더는 위임 증명이 아니다.

Beesuh의 `/v1/runs/{id}`와 Conductor의 `/v1/executions` 및 event envelope 요구가
다르다는 담당 보고를 받아 두 작업을 직접 연결했다. 각 repo의 프로토콜/클라이언트
검사를 수정할 권한만 전달했으며, 정적 service bearer로 사용자 권한을 대신하는 경로는
만들지 않는다. 첫 GoAuthy 소비 pilot의 후보 resource는 `https://beesuh.local.test`;
client/scope/명시 membership/FILE 계약과 테스트 host는 아직 확정·구현해야 한다.
