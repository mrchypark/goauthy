# Conductor / SaaS 자격 증명 전달 검증 — 2026-09-27

## 범위와 판정

현재 GoAuthy 작업 트리와 Conductor `0e7bf03` + 기존 미커밋 delivery/OAuth adapter를 검사했다. Conductor HEAD는 fetched origin/main과 같지만 adapter 파일은 아직 untracked이므로 출시 기능으로 간주하지 않는다. 기존 변경은 보존했다.

GoAuthy의 사용자 세션 → SaaS 연결 → 사용자 동의 → 소비자 토큰 전달 → 갱신 → 철회 흐름은 로컬 검증을 통과했다. 실제 외부 SaaS 로그인 화면이나 Conductor 공개 execution 경로 전체의 통과를 뜻하지 않는다.

## 세션과 전달 대상

- 사용자 브라우저 세션은 GoAuthy에서 연결 관리·동의에 사용한다.
- 소비자는 별도의 confidential 사용자 OAuth 토큰과 connections resource/scope로 승인된 자격 증명을 받는다.
- 전달 대상은 API key 또는 OAuth access token이다. 임의 SaaS의 브라우저 로그인 쿠키를 가져와 실행하는 기능은 확인되지 않았다. Auth collection은 `oauth2`, `api_key`, `device_flow`만 지원한다.
- owner cookie, provider refresh token, client secret을 소비자가 공유하는 구조가 아니다. 소비자 갱신은 별도 `allow_refresh` 동의가 필요하다.
- 이미 전달한 자격 증명을 원격으로 회수하는 것은 보장하지 않는다. 철회 후 추가 전달·어댑터 호출 차단을 검사한다.

## 이번 실행 증거

### SaaS OAuth 실제 HTTPS 흐름

현재 소스로 빌드한 `goauthy-ternal-device-e2e:readiness-20260927` 이미지를 재사용하고 Ternal 프로필을 껐다. 네트워크 없는 Linux 컨테이너에서 합성 TLS OAuth 제공자로 실행했다.

1. `REGISTERED_OAUTH2=1`, `OAUTH2_ACTIVE_RESTART=1`, `CONSUMER_REFRESH=1`: `TestConnectionOAuth2RegisteredSuccess` **PASS 1.47s**, runner 종료 0.
2. 위 설정에 `OAUTH2_HANDOFF_UI=1`, `OAUTH2_CONNECTION_UI=1`, `OAUTH2_CALLBACK_UI=1` 추가: 실제 Chromium 연결·callback·동의 화면을 포함해 **PASS 7.74s**, runner 종료 0.

모든 설정 접두사는 `GOAUTHY_E2E_`이다. 같은 owner session, consumer token, connection, grant를 유지하고 GoAuthy를 두 번 재시작했다. 버전별 동일 access token 유지, 소비자 갱신 후 버전 증가, 오래된 버전 거부, 동의 철회 후 전달 거부를 확인했다. 제공자는 합성이며 실제 외부 SaaS 계정으로 로그인하지 않았다.

로그:
- `/tmp/goauthy-saas-readiness.log`
- `/tmp/goauthy-saas-handoff-readiness.log`

### 만료·재사용·권한 경계

```sh
go test -mod=readonly -count=1 -timeout=5m ./internal/saas -run '^(TestUseHandoff.*|TestUseGrantRefresh.*|TestRefreshCredentialChecksExpiryAndCurrentAuthority|TestOAuth2RevokePreventsRefreshResurrection)$'
```

**PASS 3.736s**. Handoff 만료·replay·동시 승인·client/authority 경계, refresh 동의·만료·철회·동시 실행, 철회된 credential의 복구 방지 검사다. 실제 서비스에서 토큰이 만료될 때까지 기다린 E2E와는 구분한다. 로그: `/tmp/goauthy-saas-boundaries-readiness.log`.

### Conductor 코드와 집중 검사

Luna 검토에서 `go test ./internal/connectors ./internal/connections` 두 패키지가 통과했다. 기본 실행의 opt-in live fixture는 skip이므로 아래 별도 live bridge 결과와 구분한다.

부모가 확인한 차단 요인:
- `cmd/conductor/main.go`의 `connectorCredentialsResolver`는 Conductor 내부 connection store를 조회한다.
- `NewAPIKeyDelivery`와 `NewOAuthDelivery`는 현재 production caller가 없고 테스트에서만 호출한다.
- 따라서 공개 로그인 → 동의 callback 소비 → 사용자/workspace 권한 확인 → queue/execution → SaaS 호출을 하나로 연결한 통합은 아직 완료되지 않았다.

### Conductor 실제 API-key bridge

GoAuthy HTTPS standalone에 `USE_GRANTS=1`, `CREDENTIAL_DELIVERY=1`, `RAW_AUTHORIZATION=1`, `CONDUCTOR_DELIVERY_PROJECT_DIR=/absolute/path/to/conductor` 프로필을 사용했다(접두사 `GOAUTHY_E2E_`). 기존 UI preview와 분리된 18240–18242 포트 및 전용 lock으로 실행했다.

`TestConnectionUseGrantLive` **재시작 전 13.09s / 후 10.35s PASS**, runner 종료 0. 각 실행에서 실제 Conductor `TestAPIKeyDeliveryGoAuthyFixture`가 다음 두 조건을 통과했다:
- 승인된 API key를 GoAuthy에서 조회하고 Conductor 어댑터로 로컬 TLS 제공자에 두 번 호출.
- 동의 철회 후 전달 거부, 결과 없음, 제공자 호출 0.

공급자 주소는 테스트 transport로 로컬 TLS에 매핑되며 실제 Gowid에 호출하지 않았다. Conductor OAuth delivery adapter와 공개 execution/queue는 이 bridge 범위에 포함되지 않는다. 상위 `test/e2e` 패키지의 `no tests to run`과 달리 `test/e2e/browser`의 선택된 검사 및 그 자식 Conductor 검사는 실제 실행됐다. 로그: `/tmp/goauthy-conductor-readiness.log`.

## 남은 수용 조건

1. Conductor execution 경로에 승인 binding과 사용자 토큰 source를 연결한다. caller가 제공한 사용자/workspace ID만 권한 증명으로 사용하면 안 된다.
2. 실제 Conductor OAuth adapter까지 포함한 token 전달·refresh·generation 변경·철회 E2E를 추가한다.
3. 실제 외부 SaaS 테스트 계정으로 login/consent/callback와 허용된 읽기 작업을 검증한다.
4. 임의 SaaS 브라우저 세션/쿠키 전달이 요구사항이면 OAuth/API-key 전달과 별도의 기능 범위를 정해야 한다.
