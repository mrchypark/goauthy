# Upstream OIDC back-channel logout

상태: **배포 검증 미완료**. 토큰 검증, 로그인 시 공유 세션 연결, HTTP 수신과
원자적 철회/outbox 연결을 구현했다. Kubernetes 배포 E2E 증거는 아직 없다.

## 근거와 패키지 선택

[OIDC Back-Channel Logout errata 1](https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation)의
서명·issuer/audience·시간·events·nonce 검증을 적용한다. JWT 서명/JWKS는 이미 사용 중인
`go-jose/v4`와 기존 `JWKSVerifier`를 재사용한다. JSON과 시간 검사는 Go 표준
`encoding/json`, `time`을 쓴다. 별도 의존성이나 암호 구현을 추가하지 않는다.
기존 ID-token 전용 검증은 nonce를 요구하고 logout events/JTI를 해석하지 않으므로
logout claim 정책은 별도로 구현해야 한다. 공유 세션 철회는 표준에서도 RP별
동작으로 남겨 둔 부분이며, GoAuthy의 Rhiza transaction/outbox에 통합해야 한다.

[고정 Rauthy 검증 코드](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/service/src/oidc/bcl_logout_token.rs)와
[로그아웃 처리](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/service/src/oidc/logout.rs)를
비교했다. Rauthy와 같이 logout event 값은 빈 객체만 허용한다(표준의 빈 객체
권고보다 엄격). audience는 표준에 따라 문자열/배열 모두 받는다. 미래 iat는
허용하지 않으며, 호출자가 양수 maxAge를 지정해야 한다. 만료 정각은 거절한다.
이 함수는 JTI를 반환할 뿐 소비하지 않으므로 replay 방어가 완성된 것은 아니다.
현재는 signed compact JWS만 지원하며 encrypted logout token은 지원하지 않는다.

## 구현과 남은 연결

- [x] 기존 설정 issuer의 JWKS만 사용한 서명 검증 재사용; 토큰 제공 URL로 fetch하지 않음.
- [x] 16 KiB 입력 제한, exact issuer, audience membership, 필수 iat/exp/JTI,
  sid 또는 sub, nonce 존재 자체 거절, logout event 검증.
- [x] upstream ID-token `sid`를 decoded claims에 보존.
- [x] 로그인 완료와 함께 upstream issuer/client/sub/sid와 새 local session 연결을
  schema83의 `browser_upstream_session_bindings`에 세션 생성과 같은 Rhiza transaction으로 기록. upstream sid를 local session ID로 사용하지 않는다.
- [x] issuer/client 범위의 sid-only/sub-only 선택; 둘 다 있으면 교집합만 선택.
  sid 조회 실패를 사용자 전체 철회로 확대하는 fallback을 사용하지 않는다.
- [x] schema84 JTI receipt, local browser/OAuth 철회, downstream outbox를 한 transaction으로 묶고
  before-ack 불확실성을 성공 응답으로 바꾸지 않음. 재시도는 idempotent하게 처리.
- [x] `POST /upstream/{providerID}/backchannel-logout`: 24 KiB form body, 16 KiB token, no-store 응답. 검증/저장 실패 400, 내구성 확인 성공 200. 미존재 세션도 receipt를 기록하고 200.
- [ ] 실제 upstream 서명 토큰으로 standalone/3-peer E2E: 다른 issuer/사용자/세션 보존,
  sid/sub 불일치, replay, 재시작, quorum/object-store 장애 및 downstream 수신.

검증: `go test ./internal/upstreamprovider -run 'TestVerifyLogoutToken|TestDecodeIDToken|TestJWKSVerifier' -race -count=1 -timeout=3m`
2.422초 PASS. 검증기는 실제 RSA 서명과 HTTP JWKS 서버를 사용한다. 이는 배포된
로그아웃 경로의 E2E가 아니다. `go vet ./internal/upstreamprovider` PASS.

전체 `internal/upstreamprovider` 패키지 26.775초 PASS:
`/tmp/goauthy-incoming-logout-provider-20260908.log`.

후속 보안 검사: 다른 RSA 키로 같은 kid를 사용한 토큰, unsigned/malformed/과대
입력, 비어 있는 audience, 잘못된 maxAge, 만료 정각, maxAge+1ns,
nil verifier/context와 취소된 context를 검증했다. maxAge 정각은 수용한다.
`TestLogoutTokenRejectsUnauthenticatedAndBoundaryInputs`와 기존 검증/JWKS 테스트의
집중 race 2.676초 PASS. 배포 E2E는 여전히 미완료다.

로그인 연결 지점 조사: `LocalCallbackHandler`는 초기 세션 digest를 검증하지만
`login.completeConsumedAuthentication` → `rotateBrowserSession`은 새 세션을
생성하고 초기 세션을 철회한다. 따라서 초기 세션에 upstream mapping을 쓰면
실제 인증 세션을 철회할 수 없다. 구현은 새 세션 생성과 upstream mapping을
같은 Rhiza transaction에 묶고, durable 확인 전에 cookie/authorization code를
내보내지 않는다. `SubjectResult`만 확장하거나 callback에서 별도 write를
수행하는 것으로 이 요구를 충족하지 않는다.


## 세션 연결 통합

`resolveSubject`는 검증한 OIDC claims만 `OIDCSession`으로 전달한다. GitHub는 nil이다.
서버 adapter가 `CompleteUpstreamAuthentication`에 전달하며, 브라우저 저장소의
`CreateUpstreamSession`이 활성 사용자 조건부 세션 insert와 연결 insert를 함께
실행한다. 기존 비 OIDC 로그인은 별도 mapping을 생성하지 않는다. SID 없는 OP도
issuer/client/sub 연결을 남겨 이후 subject-only 로그아웃을 지원할 수 있다.

Rhiza에서 SQLite FK가 강제되지 않으므로 만료 세션 삭제와 관리자의 개별 세션·사용자
삭제 transaction에 명시적인 연결 삭제를 포함한다. 세션 철회만 한 경우 연결은
만료 정리까지 유지된다. 수신 경로의 outbox 생성은 아직 철회되지 않은 세션만
대상으로 삼고, 토큰 정리는 같은 선택 집합에 적용한다. schema84 JTI 소비를
추가했으며 실제 HA 동시 로그인/로그아웃·quorum 장애 검증은 남아 있다.

현재 callback 집중 race 1.969초, provider 전체 33.583초 및 서버 upstream 설정
테스트 1.675초 PASS. 관련 패키지 vet PASS. 실제 배포된 upstream 로그인→로그아웃
E2E와 schema83 혼합 버전 배포/복원은 미검증이다.

최종 저장/로그인/삭제 검증:

- browser 전체 race 6.223초, 최종 upstream 세션 집중 race 2.901초 PASS.
  실제 filesystem before-ack 장애에서 `ErrCommitUnknown`과 빈 토큰/ID를 확인하고,
  복구 후 세션과 연결 행이 각각 하나임을 확인했다. SQL 실패는 양쪽 insert를 롤백한다.
- schema83 집중 migration 1.859초 PASS: 새 테이블·인덱스와 재실행 시 행 보존.
  별도 전체 storage 실행은 관찰 도구의 출력 핸들이 유실되어 결과 미확인이다.
  이 실행을 전체 PASS 근거로 사용하지 않는다.
- login 전체 107.845초 PASS: `/tmp/goauthy-upstream-binding-login.log`.
- RBAC 삭제 집중 race 36.194초, identity 삭제 집중 race 7.384초 PASS:
  `/tmp/goauthy-upstream-binding-rbac-race.log`, `/tmp/goauthy-upstream-binding-identity-race.log`.
  대상만 삭제하고 권한 거부·늦은 SQL 실패 시 연결도 보존한다.
- 변경한 패키지 vet와 CGO=0 서버 build PASS. 산출물 `/tmp/goauthy-upstream-binding`.

기존 v82 배포 기록을 v83 검증으로 바꾸지 않는다. 신규 로그아웃 수신 기능의 완료
체크는 실제 세션 철회/fan-out과 standalone·Kubernetes E2E가 통과한 뒤에만 가능하다.


## 수신·철회 연결 (schema84)

라우트에 등록된 provider의 issuer/client/JWKS를 사용한다. 공개 토큰의 issuer나
kid만으로 임의 JWKS URL을 선택하지 않는다. form의 logout_token은 정확히 하나여야
하며 query-only token은 받지 않는다. 브라우저 쿠키나 CSRF는 이 서비스 간 증명에
사용하지 않는다. OpenAPI에도 form 요청과 서명 토큰 증명 계약을 추가했다.

기존 단일-SID `SessionRevocationStatements`를 읽기 목록에 반복 적용하면 조회와
철회 사이에 새 세션을 놓칠 수 있다. 따라서 같은 기존 테이블/outbox 정책을 사용하는
집합 SQL을 직접 작성했다. 외부 패키지는 GoAuthy의 Rhiza 스키마와 원자적 경계를 알 수
없으므로 이 부분은 앱 구현이 필요하다. 새 암호·OAuth 라이브러리는 추가하지 않았다.

issuer/client/sub/sid 조건은 트랜잭션 안에서 평가하며 sid와 sub가 모두 있으면
교집합만 선택한다. receipt `(issuer,client_id,jti)`는 raw 토큰 대신 SHA-256 digest,
검증한 식별자와 최초 operation ID를 보존한다. 동일 JTI의 다른 토큰은 실패한다.
동일 토큰 재전송은 새 acknowledged mutation을 거치지만 최초 operation만 철회를
수행하여 이후 새 로그인 세션을 다시 철회하지 않는다. `ErrCommitUnknown`을 로컬
receipt 조회만으로 성공 처리하지 않는다.

replay 보존 기한은 `min(exp, iat+maxAge+1ms)`다. 현재 HTTP maxAge는 2분이며,
1ms는 포함되는 maxAge 정각과 DB millisecond 시간 단위 사이의 조기 삭제를 막는다.
서명된 exp가 매우 멀어도 기록을 그때까지 남기지 않는다. receipt 만료 정리는 다음
로그아웃 mutation에서 수행되므로 트래픽이 없으면 만료 행은 다음 요청까지 남는다.

철회는 browser session·authorization interaction·authorization code/PKCE·SID가
연결된 refresh/access token과 downstream session-client 행을 처리한다. 브라우저 SID가
없는 device grant 또는 다른 사용자의 세션까지 확대하지 않는다. 새 로그인은 각
transaction 순서에 따라 처리되며, 같은 token 재전송은 이미 처리한 범위를 확대하지 않는다.


schema84 최종 검증 기록:

- Store·migration 집중 OAuth 4.981초/storage 2.681초, Store race 18.757초 PASS:
  `/tmp/goauthy-upstream-logout-store-final-20260908.log`,
  `/tmp/goauthy-upstream-logout-store-final-race-20260908.log`.
- 최종 검증기·HTTP 경계 race 2.361초 PASS:
  `/tmp/goauthy-upstream-logout-final-validation.log`.
- 실제 upstream 서명 JWT HTTP 수신부터 Rhiza 철회와 downstream Worker.Step/RP
  수신 JWT의 Ed25519 서명·issuer·audience·SID·events·JTI 검증까지 통과했다.
  정상 2.342초/race 10.631초 PASS:
  `/tmp/goauthy-upstream-logout-http-integration.log`,
  `/tmp/goauthy-upstream-logout-http-integration-race.log`.
  로컬 RP endpoint의 private/HTTP 예외는 테스트에만 명시적으로 허용했다.
- OpenAPI 전체 2.250초, cmd upstream/OpenAPI 0.945초 PASS:
  `/tmp/goauthy-upstream-logout-apidocs.log`, `/tmp/goauthy-upstream-logout-command.log`.
  최종 관련 패키지 vet PASS.

이 HTTP 통합 검사는 실제 네트워크와 DB/worker를 사용하지만 서버 프로세스 배포나
3-peer Kubernetes E2E를 대체하지 않는다. HA replay·quorum·rolling-upgrade,
백업복원과 전체 기능 parity 체크는 열린 상태다.

최종 provider 전체 31.987초 PASS (`/tmp/goauthy-upstream-logout-provider-final.log`),
CGO=0 build PASS (`/tmp/goauthy-upstream-logout`). Kind 사전 검사 재확인은
여유 공간 7,388,856 KiB < 12,582,912 KiB로 실패했다. 조건을 낮추지 않았다.


재시작 회귀: `TestUpstreamLogoutReceiptSurvivesRestart`가 동일 Rhiza DataDir을
정상 Close/Open한 뒤 readiness와 철회/receipt 보존을 검사한다. 재시작 후 새로
만든 동일 upstream 세션 연결은 이전 토큰 replay로 철회되지 않고 outbox도 하나다.
같은 JTI의 다른 토큰과 만료 정각 replay는 거절한다. 집중 race 7.238초와 OAuth
vet PASS (`/tmp/goauthy-upstream-logout-restart-race.log`). 이 증거는 정상 재시작이며
프로세스 강제 종료·HA failover·복원 테스트를 대체하지 않는다.


동시 replay/JTI 충돌 회귀: 별도 Store 8개가 동일 JTI의 서로 다른 두 검증 결과를
동시에 제출한다. receipt의 실제 승자만 성공하고, 패자의 세션은 유지되며,
receipt/outbox가 각각 한 행임을 검증했다. 특정 스케줄 순서에 의존하지 않는다.
`TestUpstreamLogoutConcurrentReplayAndConflictingJTI` 집중 race 7.123초 및 OAuth
vet PASS (`/tmp/goauthy-upstream-logout-concurrency-race.log`). 단일 Rhiza 인스턴스의
동시 호출 검증이며 여러 K8s peer의 failover 검증으로 해석하지 않는다.

후속 schema84 storage 전체 재검증은 93.889초 PASS:
`/tmp/goauthy-schema84-storage-full.log`. 이전 출력 유실 실행과 구분되는 새 검증이다.
