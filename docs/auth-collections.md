# 사용자 연결을 관리하는 인증 컬렉션

2026-09-06에 시작한 요구사항/구현 기록이다. 이 문서에는 당시 중간 상태를 설명하는
역사적 절이 남아 있다. **현재 제품 상태는 [capabilities.md](capabilities.md)와
[external-credential-consumer-contract.md](external-credential-consumer-contract.md)를
우선한다.**
사용자 확인: **관리자가 컬렉션 구조·인증 방식을 정의하고, 사용자는 자신의
외부 SaaS 연결과 agent 등록을 생성·관리한다.** Rhiza 및 standalone/exact-three
HA 요구사항은 유지한다. Rauthy 동등성 목록과는 별도의 제품 확장이다.

## 목표와 구분

[PocketBase collections](https://pocketbase.io/docs/collections/)의 관리자 정의,
필드 구성, 레코드 관계라는 사용 방식을 참고한다. PocketBase DB를 도입하거나
기존 사용자 인증 저장소를 컬렉션마다 복제한다는 결정은 아니다.

| 개념 | 관리자/사용자 역할 | 예시 |
|---|---|---|
| 컬렉션 정의 | 관리자: 이름, 일반 필드, 지원 인증 방식, connector와 허용 scope, 사용 가능 정책 | `github_accounts`, `workspace_connections`, `personal_agents` |
| 사용자 연결 | 사용자: 자신의 외부 계정 연결·상태 확인·연결 해제 | 같은 사용자의 개인/업무 GitHub 계정을 별개 연결로 관리 |
| 인증정보 | 서비스 전용: 암호화 보관·갱신·회전·폐기; 일반 레코드 응답에는 미포함 | SaaS access/refresh token, API key |
| agent 등록 | 사용자 소유의 별도 principal과 인증 수단 | Device Flow로 승인한 로컬 agent |
| 사용 위임 | 사용자: 특정 agent가 특정 연결에서 수행할 작업·기간 승인 | agent A가 업무 계정의 허용된 읽기 작업만 수행 |

인증 수단, 소유권, 위임은 서로 다르다. Agent가 로그인했다고 사용자 소유
모든 연결을 사용할 수 없으며, OAuth client 등록만으로 agent principal이나
사용자 위임이 생기지 않는다. 외부 로그인 identity link 또한 SaaS API 사용
동의나 장기 토큰 저장 권한이 아니다.

## 구현 순서

1. 관리자 정의 + 사용자 소유 레코드: 제한된 일반 필드 타입과 버전/CAS,
   생성·조회·비활성화 API 및 UI. owner는 요청 JSON이 아니라 인증 세션에서
   정하고 관리자 정의 필드로 덮어쓸 수 없다. 시스템 필드와 일반 필드를 분리한다.
2. 설정 기반 표준 OAuth2/OIDC 연결과 첫 SaaS 프리셋: 명시적 연결 동의,
   PKCE/state/세션 바인딩, credential 암호화, 상태·해제, 실제 인증된 읽기
   작업까지 구현한다. 프로토콜 처리와 공급자별 예외를 분리하되 플러그인
   런타임이나 임의 코드 실행 엔진은 만들지 않는다.
3. Agent 등록 + 좁은 위임: 기존 Device Flow를 인증 수단으로 연결하되 별도
   agent ID를 보존하고 connection/action/scope/expiry 단위 grant를 둔다.
4. standalone에서 위 흐름을 end-to-end로 검증하고 API-key connector와
   추가 OAuth 프리셋을 확장한다. 사용자 요청에 따라 신규 HA 검증은 나중에
   모아서 수행한다. 기존 HA 통과 기록은 신규 기능 검증으로 간주하지 않는다.

초기 메타데이터는 고정된 SQL 테이블의 검증된 JSON으로 저장한다.
사용자 정의 SQL, 실행 가능한 권한 표현식, 임의 webhook/목적지
프록시, 자동 권한 확대는 포함하지 않는다. 인증 URL/허용 목적지는 일반
사용자 레코드 필드로 재정의할 수 없어야 한다.

## 설정 기반 연결: PocketBase · TrailBase · Rauthy 참고

2026-09-06 조사. 아래는 구현 방향이며 SaaS 연결 완료를 뜻하지 않는다.

| 프로젝트 | 확인한 기능 | GoAuthy에 적용할 부분 |
|---|---|---|
| [PocketBase 인증](https://pocketbase.io/docs/authentication/) / [공급자 설정](https://pocketbase.io/jsvm/interfaces/core.OAuth2ProviderConfig.html) | auth collection별 OAuth2 설정, client ID/secret, auth/token/userinfo URL, PKCE override | 관리자 설정과 사용자 연결 레코드를 구분하는 관리 UX, 공급자 프리셋 |
| [TrailBase Record APIs](https://trailbase.io/documentation/apis_record/) | 관리 UI/설정 파일로 TABLE/VIEW의 CRUD API 정의, 작업별 ACL와 레코드 접근 규칙, JSON schema | 컬렉션 정의로 CRUD 계약 생성, 인증된 owner에 따른 접근 제한. 임의 SQL 규칙 엔진은 도입하지 않음 |
| [TrailBase OAuth 설정 소스](https://github.com/trailbaseio/trailbase/blob/f24291b894bb6c6696608e5f4c2f68666fe97686/crates/core/proto/config.proto#L55) | 이름으로 구성하는 공급자 설정, generic OIDC의 endpoint와 scope 설정 | 표준 연결을 설정 데이터로 추가. 이 조사만으로 discovery나 임의 공급자 호환성을 보장하지 않음 |
| [Rauthy v0.36.2 upstream provider](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/auth_providers.rs) | OIDC discovery, endpoint/client-auth/PKCE/claim 설정, 암호화된 client secret, 외부 로그인 후 로컬 identity 연결 | 기존 upstream 로그인 경계와 검증을 재사용하되 장기 SaaS credential 저장과 분리 |

TrailBase의 [인증 흐름](https://trailbase.io/documentation/auth/)은 외부 로그인 후
TrailBase 자체 API용 토큰을 발급하는 구조다. Rauthy v0.36.2 역시 upstream
access token을 userinfo 조회에 일시 사용하며 일반 SaaS refresh-token 저장소나
대리 호출 서비스가 아니다. 따라서 로그인 지원을 장기 SaaS 연결 지원으로
체크하지 않는다.

GoAuthy의 설정 경계:

- 관리자 공급자 정의: 표준 방식, issuer 또는 명시적 endpoint, client 인증,
  허용 scope, 검증된 사용자 식별자 매핑. 비밀값은 일반 설정 응답에서 제외.
- 컬렉션 정의: 허용 공급자와 일반 필드, 연결 및 사용 정책을 참조한다.
- 사용자 연결: 현재 사용자에게 바인딩한 외부 계정, 동의, 암호화 credential,
  갱신·철회 상태. URL/client secret/owner를 일반 필드로 덮어쓸 수 없다.
- 대리 호출: 공급자 설정과 별도로 허용된 목적지·작업·입출력 계약을 둔다.
  OAuth2는 SaaS API 경로·권한 의미를 표준화하지 않으므로 공급자별 최소
  어댑터가 필요할 수 있다. 임의 URL 프록시나 원본 토큰 반출은 제공하지 않는다.

기존 `golang.org/x/oauth2`와 upstream 교환 코드를 먼저 활용한다. 공급자
프리셋은 설정 기본값이며 별도 OAuth 엔진이 아니다. 직접 작성해야 하는
소유권·동의·credential lifecycle·작업 위임의 이유와 패키지 매핑은 아래
표 및 독립 검토 계약을 따른다. 외부 HTTP 경계만 대체한 결정론적 테스트와
standalone E2E를 구분하고, 실제 SaaS 계정 검증 전에는 실서비스 연동 완료로
표시하지 않는다.

## 재사용 / 직접 구현 이유

| 기능 | 재사용 근거 | 새로 필요한 제품 로직 |
|---|---|---|
| OAuth 연결 | `golang.org/x/oauth2`, `internal/upstreamprovider/oauth2_exchanger.go`, 기존 state/PKCE/TLS 경계 | 기존 exchange는 로그인 완료를 위한 것으로 장기 SaaS credential 관리와 다르다. 명시적 consent·소유권·갱신 lifecycle 필요 |
| 비밀정보 암호화 | 기존 `oidc.Keyring` envelope/rewrap/retirement, `internal/kv/envelope.go` 패턴 | owner/collection/connection/credential generation을 바인딩하는 용도 분리와 신규 secret family reference 검사 |
| 권한/감사 | 기존 session, RBAC, API-key 검증, event store | 일반 레코드 CRUD와 credential 사용 권한을 구분하는 commit-time guard 및 agent 위임 |
| Agent 인증 | 기존 Fosite/Device Flow, 만료/철회 경계 | 사용자 소유 agent 등록, 별도 actor ID와 명시적 connection별 위임 |
| 메타데이터 | stdlib `encoding/json`, 기존 strict body/size/type 검사 | 지원 field 타입·예약 필드·schema version 정책. 새 validator 패키지는 필요가 확인된 뒤 비교 |
| 관리 화면 | 기존 admin/account 세션·CSRF·asset wiring, native DOM/form/textarea, `JSON.parse`/`JSON.stringify`/`BigInt` | 정의 편집과 사용자 소유 draft CRUD를 기존 화면에 추가. 새 UI framework·JSON parser 패키지는 사용하지 않음 |
| API-key 대리 읽기 | stdlib `net/http`, `net/url`, `encoding/json`, `mime`, `strconv`, `crypto/sha256`, `slices` 및 기존 restricted HTTPS client | API Key 인증은 작업 URL·결과 의미·소유자 동의를 표준화하지 않는다. 검증된 설정 digest에 키를 결합하고, 지정된 scalar 필드만 반환하는 제품 로직이 필요하다. 별도 프록시/템플릿 엔진은 추가하지 않음 |

`internal/kv`는 namespace 접근 권한이므로 per-user connection 권한으로
그대로 쓸 수 없다. 암호화 코드는 재사용하되 namespace key를 가진 모든
클라이언트에 SaaS credential을 노출하는 API를 만들지 않는다.
`internal/upstreamprovider/rhiza_store.go`의 일회성 거래는 소비 후 종료되는
state/PKCE 저장소다. 이 테이블을 장기 credential 저장소로 재해석하지 않는다.

## 필수 보안·HA 조건

### OAuth2 프로토콜 계층 구현 상태 (2026-09-06 당시 기록)

이 절은 최초 프로토콜 계층을 구현했을 당시의 기록이다. 이후 provider 저장/API,
사용자 callback, encrypted credential, reconnect, use grant와 credential delivery가
추가되었다. 현재 계약은
[external-credential-consumer-contract.md](external-credential-consumer-contract.md)를
따른다.

`internal/saas/oauth2.go`는 관리자 공급자 설정을 받을 표준 교환 계층이다.
authorization/token URL, callback, client ID, scopes와 명시적 client 인증
방식(Basic 또는 POST)을 받는다. secret은 설정과 별도 인자로 전달한다.
설정 API/저장소/화면에 연결된 상태는 아니다.

- [x] 기존 [golang.org/x/oauth2 v0.36.0](https://pkg.go.dev/golang.org/x/oauth2@v0.36.0)
  재사용: S256 PKCE, authorization-code 교환, 명시적 1회 refresh.
  OAuth 인증 방식 자동 탐색을 금지해 code/refresh의 재호출을 피한다.
- [x] scope 입력 검증과 복사, HTTPS endpoint, redirect 거절, timeout,
  공급자 오류 본문 비노출. scope 없는 토큰 응답에 임의 scope를 추가하지 않는다.
- [x] GitHub 프리셋은 공통 교환 코드를 사용하며 별도 OAuth 엔진이 아니다.
  `/user` 조회와 `/applications/{clientID}/token` 철회만 고정 어댑터로 제공한다.
  JSON은 `encoding/json`, Basic 인증은 `http.Request.SetBasicAuth`를 사용한다.
- [x] 로컬 TLS 공급자 경계를 이용한 Basic/POST·PKCE·교환·갱신·오류·취소,
  GitHub 고정 작업의 테스트 및 `go test -race ./internal/saas -count=1` 통과.
  `go vet ./internal/saas` 통과. 실제 외부 SaaS 계정 E2E 증거는 아니다.
- [x] `internal/saas/http.go`: 기존 CIMD의 special-use 주소 정책을 바탕으로
  DNS 결과 전체 검증, 선택 IP 고정, 원래 Host/SNI 인증서 검증, proxy 및
  redirect 거절, 응답 header/time 제한. 표준 `net/http`, `net/netip`,
  `crypto/tls`를 사용한다. 테스트는 resolver/dial 외부 경계만 대체하며
  실제 인증서 검증과 고정된 dial 주소를 확인했다. 사설망 공급자는 기본 거절한다.
- [x] 관리자 provider 저장/API, 일회성 state/세션/연결 callback 바인딩,
  encrypted OAuth/API-key credential 저장, reconnect/local revoke, owner use grant와
  제한된 credential delivery가 production route에 연결되어 있다.
- [ ] consumer-facing automatic refresh coordinator, provider-side remote revoke,
  provider revision migration, stable consumer SDK/reference adapter와 실제 외부 SaaS
  계정에 대한 제품 qualification은 남아 있다.

위 transport의 주소 분류와 관리자/컬렉션별 provider binding, 등록된 API-key
operation/use-grant 인가 계층은 현재 연결되어 있다. Keep-alive는 per-request IP 검증 구현에서
소켓 pool을 남기지 않도록 비활성화했다. 서비스 수준 성능 증거가 있을 때
정책을 보존하는 연결 pool을 검토하며 현재 proxy/임의 URL 호출 API는 없다.

[현재 GitHub OAuth 앱 문서](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)는
`offline_access`를 통한 만료 토큰 opt-in과 refresh를 설명한다. 프리셋은
`read:user offline_access`를 요청하지만 모든 서버가 refresh token을 반환한다고
가정하지 않는다. 반환된 토큰의 보관·rotation 결과 commit은 후속 저장 계층의
책임이며, 이 프로토콜 계층을 일반 HTTP proxy나 자동 refresh client로 공개하지 않는다.

직접 구현한 부분은 설정 검증·오류 경계와 GitHub 고정 작업/숫자 identity
응답 검증이다. `x/oauth2`는 SaaS API의 의미나 Rhiza 소유권·동의를 제공하지
않으므로 해당 제품 로직은 별도 구현이 필요하다. OIDC discovery/ID token
검증을 이 클래스가 제공한다고 주장하지 않는다.

### 운영자 공급자 설정과 관리자 목록

`GOAUTHY_SAAS_PROVIDERS_FILE`은 upstream 로그인 설정과 별개의 JSON 파일이다.
미설정이면 빈 공급자 목록이며, 설정 시 시작 단계에서 전체 파일을 검증한다.
최대 64 KiB/32개 공급자, 고유 ID, 알 수 없는 필드/후행 JSON 거절,
기존 제한된 client-secret 파일 로더를 재사용한다. 설정 파일 변경은 재시작이
필요하다. 관리 HTTP API에서 이 파일을 수정하거나 임의 secret 경로를 받지 않는다.

```json
{"providers":[{"id":"github","kind":"github","client_id":"configured-client-id","client_secret_file":"/run/secrets/github-client-secret","callback_uri":"https://auth.example.com/saas/github/callback"}]}
```

GitHub는 고정 endpoint와 `read:user offline_access` preset을 사용하며 generic
OAuth2 필드를 함께 지정하면 거절한다. `kind: oauth2`는 `auth_endpoint`,
`token_endpoint`, `scopes`, 명시적 `auth_style: header|params`가 추가로 필요하다.
표준 엔진은 기존 `golang.org/x/oauth2`를 사용한다. OIDC discovery는 이 설정
로더의 구현 범위가 아니다. 이 파일 기반 provider 외에도 DB-backed provider와
실제 `/auth/v1/saas/callback/{provider_id}` callback handler가 현재 구현되어 있다.

`GET /auth/v1/saas/providers`는 file/DB provider metadata를 합쳐 조회한다. 현재
full administrator browser session과 별도 resource/scope를 가진 관리자 human
Bearer 경로가 있으며, secret은 반환하지 않는다. DB provider에는 revision-guarded
create/update/delete가 존재한다. 정확한 현재 필드와 권한은
[external-credential-consumer-contract.md](external-credential-consumer-contract.md)의
provider 등록 계약을 따른다.

schema v68부터 컬렉션의 `provider_ids` 배열로 허용 공급자를 지정한다.
관리자 HTTP 요청은 현재 설정된 공급자만 허용하고, 저장소는 중복 없는
최대 32개의 canonical ID를 검증한다. schema v77부터 API-key는 빈 목록(legacy)
또는 등록된 API-key 제공자 하나를 허용하며 device_flow는 빈 목록만 허용한다.
관리 편집 화면은 한 줄에 한 ID를 표시·저장하며 제거 전 확인을 요청한다.
PUT은 전체 교체이므로 `provider_ids` 생략 또는 `[]`는 허용 목록을 비운다.
기존 schema67 컬렉션은 빈 목록으로 이행하여 암묵적으로 공급자를 허용하지 않는다.

credential 저장/사용/갱신은 현재 허용 목록을 SQL에서 확인한다. 공급자 제거는
Rhiza의 동일 변경에 포함된 DB trigger로 해당 토큰을 revoked로 만들고 claim을
비운다. 다시 허용해도 이전 토큰을 복구하지 않는다. 이 규칙은 일반 metadata
연결 레코드를 삭제하지 않으며, 외부 공급자의 원격 철회가 완료되었다는 뜻도 아니다.
표준 OAuth 패키지는 제품별 컬렉션 정책과 Rhiza 원자적 폐기를 제공하지 않아
이 작은 SQL trigger와 소유권 guard를 직접 구현했다. 추가 의존성은 없다.

standalone 설정 로딩/관리자 목록/익명 거절/동일 DB 재시작 후 재조회:
`/tmp/goauthy-saas-catalog-e2e-final-20260906.log` 종료 0.
첫 `/tmp/goauthy-saas-catalog-e2e-20260906.log`는 HTTP localhost callback
fixture가 loopback-IP 정책에 맞지 않아 시작 실패했다. fixture를 127.0.0.1로
고쳤으며 정책을 완화하지 않았다. 외부 GitHub 호출은 없는 목록 E2E다.

### 인증정보 저장·갱신 구현

schema69의 `saas_authorization_requests`는 로그인용 upstream transaction과
분리된 SaaS 동의 기록이다. 원문 state/verifier/session token 대신 canonical
SHA-256 digest와 사용자·연결·공급자 설정 digest·generation·만료를 기록한다.
`authorization_proof.go`는 설치된 `x/oauth2.GenerateVerifier`를 사용하며,
원문 proof의 JSON/debug 출력은 노출하지 않는다. 브라우저에 proof를 전달·보관하는
HTTP 경계는 아직 구현하지 않았으므로 cookie 방식의 안전성을 검증했다고 주장하지 않는다.

`CreateAuthorization`은 현재 owner/컬렉션 공급자 허용 및 caller 권한과 빈 credential
상태를 확인한다. `ConsumeAuthorization`은 최대 10분 TTL, 네 digest, 현재 권한과
정확한 연결 필드를 CAS로 검사하고 한 번만 소비한다. 성공한 소비는 외부 OAuth
호출의 선행 조건이며, 실패/불확실한 소비 응답만으로 외부 코드를 재전송하면 안 된다.

공급자 제거는 이미 소비한 요청도 invalidated로 만든다. `CompleteAuthorization`은
같은 소비 기록이 여전히 유효한 경우에만 기존 envelope writer fence를 통해
credential을 설치한다. 소비→공급자 제거→재추가→지연 응답 순서도 거절한다.
이 메서드를 호출하기 전에 adapter가 외부 identity와 실제 scope를 검증해야 한다.
현재는 최초 연결 설치 경로이며, 기존 credential을 대체하는 재연결/원격 철회 조정은
아직 별도 작업이다. 만료 기록 정리와 HTTP 동의 화면도 남아 있다.

직접 구현 이유: `x/oauth2`는 OAuth wire protocol/PKCE를 제공하지만, Rhiza의
일회성 소비·제품별 소유권·컬렉션 정책과 외부 응답 저장의 원자성을 제공하지 않는다.
기존 로그인 transaction을 SaaS 승인으로 재해석하지 않고 작은 별도 SQL 상태를 둔다.
기존 Pro 검토의 세션-bound 일회성 state 계약을 재확인했으나, 이번 브라우저 proof
보관 방식에 대한 추가 Pro 요청/답변은 완료하지 않았다.

`TestAuthorization*` 실제 Rhiza 집중 race 검사와 schema69 migration 검사가 통과했다.
잘못된 session/verifier/provider digest는 정상 요청을 소비하지 않고, 8개 동시 소비 중
하나만 성공한다. HTTP callback/실제 SaaS/HA E2E 증거로 계산하지 않는다.

`internal/saas/credential.go`에 package-private 인증정보 envelope 처리를
추가했다. 기존 `oidc.Keyring.SealEnvelope/OpenEnvelope`를 사용하며 새로운
암호 알고리즘·키 파일 형식·암호화 패키지는 도입하지 않는다. 소유자, 컬렉션,
연결, 공급자, 재연결 generation, token version의 구조화된 값을 purpose에
바인딩한다. 표시용 metadata revision은 포함하지 않는다.

`TestCredentialEnvelopeBindsIdentityAndTokenVersion`과
`TestCredentialEnvelopeReusesMasterKeyRotation`은 문맥 변경/변조 거절,
토큰 값의 debug 출력 비노출, 기존 master-key rewrap 후 이전 키 없이
복호화를 검증한다. schema v67의 `saas_connection_credentials`와
`credential_store.go`에 내부 영속 저장을 추가했다. `master_key_status.go`,
`master_key_retirement.go`, `key_rewrap.go`의 참조 검사·writer fence·rewrap에도
연결했다. 폐기·고아 레코드의 비밀정보도 이전 키 참조에서 제외하지 않는다.
일반 레코드 JSON과 인증정보 payload는 분리한다. 수동 API Key API는 이 저장소에
연결했지만 OAuth callback과 실제 SaaS 호출은 아직 연결하지 않았다.

### 수동 API Key 등록 (2026-09-06)

외부 SaaS에 전달해야 하는 API Key는 해시가 아닌 기존 AES-GCM envelope로
암호화한다. 새로운 암호화 패키지 없이 기존 keyring, 문맥 바인딩, 키 교체를
재사용한다. 이 서비스에 제시되는 자체 인증 키의 검증과는 별개 용도다.

`/auth/v1/account/connections/{collection_id}/{connection_id}/api-key`:

- GET: `registered`, `version`만 반환. 원문 조회 기능은 없다.
- PUT: `api_key`, `version` 필수. 최초 등록은 0, 교체는 현재 version으로 CAS.
  등록 제공자 컬렉션은 추가로 `connector_digest`가 필수다. 먼저 owner 전용
  `GET .../api-key/connector`에서 목적지·주입 규칙과 digest를 확인한다.
- DELETE: 현재 `version`으로 로컬 사용을 폐기. 외부 공급자의 키 자체를
  무효화하지는 않는다. 폐기된 연결은 재활성화하지 않으며 새 연결이 필요하다.

소유자 브라우저 세션 및 변경 요청 CSRF를 검사하고 Bearer 혼합은 거절한다.
일반 metadata 필드에 키를 넣지 않는다. schema70은 공급자 제거 trigger를
OAuth2에 한정하여 `provider_ids: []`인 API-key 컬렉션 편집 시 키를 보존한다.
schema77은 등록 API-key 제공자 제거에도 폐기를 적용하되 legacy 빈 목록의
일반 편집 보존은 유지한다. 새 connector/digest 입력은 공개 API에 연결되어 있으며,
관리자 컬렉션 화면에서 등록 제공자 ID를 지정할 수 있으며, 계정 UI는 digest에 포함된
설정을 보여주고 명시적인 확인 후 키를 등록·회전한다. 이 확인은 consumer 사용 승인이
아니다. 실제 Chromium의 등록 제공자 키 관리 E2E는 status.md에 기록한다.
사용동의 및 검증 범위는 [사용동의 계약](connection-use-grants.md)을 참고한다.

`TestAPIKeyEncryptedStorageCanDecryptAndRewrap`은 실제 저장 암호문 복호화,
새 master key로 재암호화한 뒤 새 키만으로 복호화 및 다른 owner 문맥 거절을
검증한다. `TestConnectionAPIKeyPilot`은 standalone 서버 재시작 전후 등록,
컬렉션 편집 보존, 교체, stale version 거절, 폐기, 부활 거절을 검증했다.
계정 화면에서 API-key 컬렉션의 연결을 생성한 뒤 `Manage API key`로 상태 조회,
등록·교체·로컬 폐기를 수행한다. 기존 vanilla JS/DOM과 CSRF 요청 함수를
재사용했으며 별도 UI 의존성을 추가하지 않았다. 비밀 입력은 metadata와 분리되고
제출 실패·취소·화면 이동에도 비운다. 상태/버전은 서버 응답으로만 갱신한다.

- [x] Node 회귀: 등록/교체/충돌/폐기, CSRF, 입력 삭제, 폐기 후 재등록 거절,
  Promise barrier를 통한 이전 화면의 늦은 상태 응답 무시.
- [x] `TestConnectionAPIKeyPilot/browser`: 실제 Chromium 등록/교체,
  외부 요청의 동시 교체 후 충돌 및 입력 삭제, 재조회 후 폐기.
  standalone 및 재시작 후 최종 로그:
  `/tmp/goauthy-saas-api-key-ui-e2e-final-20260906.log` (종료 0).
- [ ] 실제 SaaS 요청의 키 삽입, 원격 철회, 재연결과 해당 UI의 HA 검증.

### API-key 대상 동의 및 내부 호출 엔진 (2026-09-06)

`APIKeyConnector`는 운영자가 신뢰하는 설정을 검증하고 불변 복사한다.
ID/인증 header 및 prefix/작업별 고정 HTTPS URL/GET method/응답 필드 타입을
정렬한 JSON의 SHA256 digest로 묶는다. URL·method·응답 계약을 바꾸면 digest도
변경된다. 의미를 변경하는 엔진 업데이트는 digest 형식 버전도 변경해야 한다.

`Info()`는 같은 컴파일된 connector에서 ID/digest/인증 header·prefix와 정렬된
작업의 URL/GET/응답 필드 타입을 반환한다. map과 slice는 분리되어 표시 계층의
수정이 실행 계약을 바꾸지 않는다. 이 정보 자체가 현재 호출 허가를 의미하지 않는다.
`loadSaaSAPIKeyConnectors`는 `{ "connectors": [...] }` 파일을 최대 64KiB/32개로
읽고, `id/header/prefix/operations` 및 작업의 `id/url/response_fields`만 받는다.
stdlib JSON 파서와 기존 connector 검증을 사용하며 오류에 설정 내용을 넣지 않는다.
현재 내부 로더만 구현되어 환경변수 설정이나 공개 API로 활성화되지는 않는다.

`PutBoundAPIKey`는 호출자가 명시한 동의 digest가 해당 connector와 일치할 때만
기존 CAS·writer fence로 API key와 `connector_digest`를 같은 AES-GCM payload에
저장한다. 신규 테이블/암호화 패키지는 없다. 기존 `PutAPIKey`는 계속 보관 전용이며
이미 대상이 지정된 key에 대한 구형 회전 요청은 거절한다. 동의가 없는 기존 키를
자동 승격하지 않는다. 이 동작은 [Pro 검토](https://chatgpt.com/g/g-p-69ecdc42175c819186cf485b225c0e46-codex-request/c/6a9d762c-db44-83e8-b990-9efa07afedc0)를
실제 CAS/암호화 코드와 대조해 보완했다. 별도 connector ID는 digest의 입력에 이미
포함되며, 기존 봉투 안의 인증된 digest 유무로 bound/보관 전용을 구별한다.

`CallAPIKey`는 현재 권한·generation·ready version을 읽고 동의 digest를 대조한 뒤
기존 restricted TLS client로 정확한 작업 URL에 애플리케이션 호출 1회를 수행한다. 원본 응답/헤더는
반환하지 않는다. JSON object의 지정된 string/int64/boolean 필드만 재인코딩하며,
중복 키·trailing JSON·잘못된 타입·64KiB 초과 body·4096byte 초과 문자열을 거절한다.
문자열의 직접적인 키 반사는 거절하지만, 악의적인 공급자의 인코딩된 정보 유출까지
방지하는 DLP는 아니다. 공급자와 응답 계약은 운영자가 검토해야 한다.

반환 직전에 권한/동일 credential version을 재확인한다. 폐기·회전·권한 철회가
관측되면 결과를 버린다. DB 검사와 외부 전송은 원자적이지 않으며, 검사 후 시작된
요청은 철회와 경합할 수 있다. 이미 전송된 요청을 취소·소급 차단한다고 주장하지
않는다. 마지막 반환 검사와 응답 쓰기 사이에도 경합이 남는다. 애플리케이션 재시도는
없지만 물리적인 exactly-once 전송을 보장하지 않는다. GET도 실제 읽기 작업인지
공급자 계약 확인이 필요하다.

- [x] `TestCallAPIKeyEncryptedStoreToTLSProvider`: 실제 Rhiza 암호문 복호화→인증서
  검증 TLS 전송→응답 투영. 미동의/다른 설정/사전 폐기는 전송 0회, 진행 중
  폐기/회전/권한 철회는 전송 1회 후 결과 미반환. 고정 sleep 없이 서버 handler로
  변경 순서를 결정한다.
- [x] 대상 binding 포함/미포함 모두 master-key rewrap 후 새 키만으로 복호화.
- [x] 운영 설정 파일 로더와 동의용 메타데이터, 파일 계약 일치·변경 격리 단위 검사.
- [ ] 설정 로더의 main 연결·컬렉션 허용 목록·사용자 대상 동의 화면·공개 호출 HTTP route.
- [ ] 권위 있는 활성 connector digest와 인가 재활성화를 구별하는 버전 검사.
  단순 현재 활성 boolean만으로 중간 철회→재허용을 감지했다고 주장하지 않는다.
- [ ] OpenCode chat POST/중첩 응답 등 공급자별 작업 계약, agent 위임과 HA/chaos.

이는 내부 엔진 검증이며 사용자용 SaaS 호출 E2E 완료가 아니다. 기존 API-key
등록 HTTP/UI는 아직 목적지 미지정 보관 전용 경로를 호출한다.

저장소는 ready → refreshing → ready(version 증가), refreshing → uncertain,
local revoked 상태를 지원한다. 현재 owner/collection/generation과 활성 사용자,
호출자가 제공하는 서버 내부 SQL 권한 조건을 검사한다. provider 설정·동의·agent
위임의 검사는 후속 coordinator에서 연결해야 한다. 불확실한 외부 refresh를
자동 재시도하거나, 모호한 DB commit 결과를 성공으로 추정하지 않는다.

실제 Rhiza 회귀는 이전 키만 참조하는 ready/revoked/refreshing 행 재암호화,
새 키만으로 토큰 복호화, 상태·claim 보존, 손상 배치의 무변경을 검증한다.
main 통합 회귀는 손상된 고아 credential의 키 폐기 거절과 batch cursor의
성공 시 진행/실패 시 보존을 검사한다. 실제 외부 SaaS·HA E2E 증거는 아니다.

`refresh.go`는 내부 provider adapter 함수를 durable claim/commit과 연결한다.
외부 작업은 한 번만 호출하고, commit 성공 후에만 새 token-version binding을
반환한다. 외부 오류·취소·commit 불확실성은 비밀정보 없는 고정 오류로 반환하며,
요청 취소와 분리된 5초 제한 context로 uncertain 상태를 기록한다. 기록 실패 시에도
기존 refreshing claim은 자동 재사용하지 않는다. 이를 사용자 재연결 API나
프로세스 재시작 후 복구 작업까지 구현한 것으로 계산하지 않는다.

`TestRefreshCredential*`는 실제 Rhiza와 외부 adapter 경계만 대체한 테스트다.
경쟁 claim, 외부 호출 도중 local revoke/권한 철회, 응답 오류, 취소 후 상태 기록,
재시도 시 외부 호출 0회, 고정 시계의 refresh 만료 경계를 검사한다.

- 사용자/컬렉션/연결/agent/grant의 현재 활성 상태와 generation을 모든
  credential 사용·갱신 commit에서 재확인. 메타데이터 조회 허용 ≠ 비밀 사용 허용.
- 갱신은 Rhiza CAS로 한 worker가 claim. 외부 OAuth 호출은 DB transaction
  밖에서 수행하고, 결과 저장은 같은 claim/generation일 때만 허용한다.
- provider가 refresh token을 회전한 직후 process가 죽으면 결과는 불확실하다.
  무조건 이전 refresh token을 재시도하거나 exactly-once라고 주장하지 않는다.
  provider 계약에 따라 재연결 필요 상태 또는 안전한 복구 정책을 정한다.
- 철회는 로컬 사용 권한을 먼저 원자적으로 끊는다. 외부 provider 철회는
  별도 상태/재시도로 추적하며, 이미 시작된 원격 작업의 취소를 보장하지 않는다.
- 일반 브라우저/record API는 secret write-only/masked metadata만 제공한다.
  향후 token brokerage가 필요하면 audience, caller, scope, expiry와 provider의
  실제 downscope 능력을 먼저 확인한다. 단기 bearer를 발급했다는 이유만으로
  이미 외부에 나간 토큰을 즉시 회수할 수 있다고 주장하지 않는다.
- 최소 slice에서는 connector의 고정된 작업을 서비스가 실행하는 방식을
  검토한다. 임의 URL 프록시는 SSRF/credential 유출 위험 때문에 별도 설계 대상이다.
- 컬렉션 보안 설정 변경으로 기존 동의를 자동 확대하지 않는다. 비호환 변경은
  재동의/새 generation 또는 명시적 migration을 요구한다.

## 완료 체크리스트

- [x] 관리자 정의 / 사용자 연결 생성이라는 권한 모델 확인.
- [x] 기존 KV 및 upstream login link와 새 기능의 경계·패키지 재사용 후보 조사.
- [x] 컬렉션/draft 레코드 schema v64·migration·권한 API·OpenAPI.
- [x] 사용자 hard-delete 시 자신의 draft 연결만 동일 트랜잭션에서 정리.
- [x] strict JSON, 예약 필드/정수 범위, 소유권/권한·revision 거절, tombstone 재사용 거절.
- [x] 가짜 시계의 owner 만료 경계와 interposed 연결 생성 후 schema 변경 거절.
- [x] standalone 실제 HTTP/SMTP/login CRUD 및 프로세스 재시작 후 재실행.
  `/tmp/goauthy-collections-standalone-20260906.log` 종료 0, 0.39/0.36초.
- [x] Dory exact-three 교차 Pod CRUD 및 Pod 교체 후 재실행.
  `/tmp/goauthy-collections-ha-20260906.log` 종료 0, 0.79/1.04초.
- [x] 집중 회귀/race/vet 통과. `/tmp/goauthy-collections-focused-20260906.log`,
  `/tmp/goauthy-collections-race-20260906.log`, `/tmp/goauthy-collections-vet-20260906.log`.
- [x] 관리자 정의/사용자 소유 draft 관리 UI, CSRF/If-Match, 비활성·충돌 입력 보존.
- [x] Chromium standalone/재시작 후 실제 CRUD, int64 최대값·false·미입력 enum,
  문자열 줄바꿈과 선택지 공백/줄바꿈 보존, 1280/375 viewport overflow 검사.
  `/tmp/goauthy-collections-ui-final-standalone-20260906.log` 종료 0,
  API 0.51/0.38초, UI 3.61/3.10초.
- [x] 신규 Node UI 회귀 및 기존 dashboard/admin/catalog/session Node 검사.
  최종 집중 Go `/tmp/goauthy-collections-ui-final-go-20260906.log`와
  `/tmp/goauthy-collections-ui-final-vet-20260906.log` 종료 0.
- [x] 최종 UI 후보 Dory exact-three 교차 Pod API/UI 및 동일 draft Pod 교체.
  `/tmp/goauthy-collections-ui-final-ha-20260906.log` 종료 0,
  API 1.04/0.88초, UI 4.00/3.55초, 동일 ID/revision/metadata chaos 5.06초.
  교체 후 3 Pod Ready/새 UID와 UI 재실행, 소유 cluster/container 정리 확인.
- [ ] 한 SaaS의 연결→암호화 저장→실제 작업→갱신→연결 해제.
- [ ] Agent 등록→사용자 승인→특정 연결 사용→위임 철회.
- [ ] 다른 사용자/agent/컬렉션 접근 거절, 일반 JSON·로그 secret 비노출.
- [ ] schema 변경·권한 철회와 동시 commit, key rotation/retirement 회귀 검사.
- [ ] 가짜 시계·barrier 기반 만료/경쟁/장애 결정론적 테스트.
- [ ] standalone 및 exact-three 교차 Pod E2E, refresh 중 Pod 손실·쿼럼 손실.

첫 UI HA 로그 `/tmp/goauthy-collections-ui-ha-20260906.log`는 실패 기록이다.
Pod 교체 후 테스트 사용자 cleanup이 삭제된 primary forward를 사용해 EOF가
발생했다. 다른 cleanup과 동일하게 survivor `apiBase`를 사용하도록 수정했고
최종 HA gate가 그 cleanup까지 통과했다. 실패 실행을 통과로 세지 않는다.
이번 최종 실행의 Device/managed-client opt-in 테스트는 skip이며 이전 증거와
구분한다. 실제 SaaS credential을 다루는 기능이나 모든 Rauthy 기능의 검증은 아니다.

## 독립 설계 검토 반영

[Pro 독립 검토](https://chatgpt.com/g/g-p-69ecdc42175c819186cf485b225c0e46-codex-request/c/6a9d3d03-0420-83ee-9771-201b36f0ac18)의
최종 답변을 확인했다. 소스 리뷰나 runtime 인증을 받은 것은 아니다.
현 코드의 로그인용 exchange/일회성 state와 장기 credential 관리가 별개라는
경계에 부합하며, 다음 계약을 후속 구현의 검증 조건으로 채택한다.

- 표시 metadata revision, 보안 설정 버전, `authorization_epoch`,
  `token_version`을 혼동하지 않는다. 외부 계정 교체/재연결은 기존 위임을
  무효화하지만 정상 토큰 갱신만으로 위임을 무효화하지 않는다.
- 위임은 agent/연결뿐 아니라 provider가 확인한 외부 리소스 ID와 허용 작업에
  결합한다. 공급자 OAuth scope 문자열만으로 내부 위임을 대체하지 않는다.
- refresh lease 만료는 외부 재호출 허가가 아니다. 결과 불명 상태에서 자동
  재시도하지 않으며, `x/oauth2`의 자동 TokenSource가 Rhiza 조정을 우회하지
  않게 한다. 새 토큰은 저장 commit 확인 후에만 사용한다.
- 로컬 철회 commit 이후 인가된 호출을 거절한다. 이전에 시작된 원격 효과의
  취소를 약속하지 않는다. 지연된 provider 철회 작업은 정확한 이전 credential
  세대에 묶어 재연결된 새 계정에 적용되지 않게 한다.
- 원본 토큰 반출과 임의 HTTP 프록시는 첫 구현에 포함하지 않는다. 필요한
  경우 한 connector의 고정 HTTPS 읽기 작업으로 위임을 검증한다.

## 메타데이터 계층: authcollection

schema v64의 `auth_collection_definitions`, `auth_collection_connections`와
`internal/authcollection`을 추가했다. 인증 방식은 현재 의도 표시값이며
`oauth2`, `api_key`, `device_flow` 선택 자체가 credential을 저장하는 것은 아니다.
이 패키지는 계속 **비밀이 없는 metadata/ownership 계층**이다. 실제 API key와
OAuth credential lifecycle은 별도 `internal/saas` 저장/HTTP 계층이 담당한다.
따라서 authcollection row의 `state=draft`를 SaaS credential의 연결 상태로
해석하면 안 된다.

| 경로 | 권한과 동작 |
|---|---|
| `/auth/v1/auth-collections` | 관리자 브라우저 세션: GET 목록, POST 정의 |
| `/auth/v1/auth-collections/{collection_id}` | 관리자: GET, PUT, DELETE |
| `/auth/v1/account/auth-collections` | 사용자 세션: GET 정의 목록(비활성 포함) |
| `/auth/v1/account/connections/{collection_id}` | 현재 사용자: GET 자신의 목록, POST draft |
| `/auth/v1/account/connections/{collection_id}/{connection_id}` | 소유자: GET, PUT, DELETE |

쓰기에는 CSRF, PUT/DELETE에는 따옴표로 감싼 `If-Match` revision이 필요하다.
연결 POST/PUT 입력은 `definition_revision`과 `metadata`뿐이다. owner는
현재 세션에서 결정한다. API key나 OAuth bearer로 브라우저 권한을 대체하지 않는다.
지원 필드는 string/boolean/integer/enum, 최대 32개이며 정수는 int64 범위다.
본문 전체는 기존 strict JSON 8 KiB 제한을 따른다. 목록은 최대 1,000개를
초과하면 오류이며 아직 pagination은 없다. 활성 연결 레코드가 있는 정의의
인증 방식/필드 변경과 삭제는 충돌로 거절한다. 삭제된 정의 ID는 재사용하지 않는다.

관리자는 `/auth/v1/admin/collections`에서 정의를 만들고 수정·삭제하며,
사용자는 `/account`의 **My connections**에서 자신의 metadata row를 관리한다.
OAuth/API-key credential 상태와 연결/해제는 별도 SaaS API/UI가 이 row에 결합한다.
비활성 정의는 생성/수정을 막고 기존 레코드 조회/삭제는 허용한다. 충돌 응답은
입력값을 보존하고 재조회 안내를 표시하며 자동 덮어쓰기하지 않는다.
선택지는 JSON 문자열 배열로 편집하여 공백과 줄바꿈을 보존한다.
문자열은 textarea, 정수는 검증된 int64 문자열, 선택 boolean은 미입력/true/false로
구분한다. 새 선택 문자열의 빈 입력은 생략하지만, 기존 값이 빈 문자열이면
그 값을 유지한다. 선택 필드를 명시적으로 제거하는 별도 UI는 아직 없다.

큰 정수 읽기는 [ECMAScript JSON reviver source context](https://tc39.es/ecma262/multipage/structured-data.html#sec-internalizejsonproperty)와
`BigInt`를 사용한다. 해당 native 기능이 없는 브라우저에서 안전 범위 밖 정수를
읽으면 오류를 표시하고 읽기를 중단한다. IEEE-754로 반올림한 값을 저장하지 않는다.
임의 범용 JSON parser를 새로 구현할 필요가 없었다.

실행 gate(위 체크리스트에 통과 증거 기록):

```sh
GOAUTHY_E2E_AUTH_COLLECTIONS=1 GOAUTHY_E2E_AUTH_COLLECTIONS_UI=1 \
  GOAUTHY_STANDALONE_OPEN_REG_PORT=26590 \
  sh scripts/e2e-open-registration-standalone.sh
GOAUTHY_E2E_AUTH_COLLECTIONS=1 GOAUTHY_E2E_AUTH_COLLECTIONS_UI=1 \
  make e2e-kind E2E_PROFILE=open-registration \
  KIND_CLUSTER=goauthy-auth-collections E2E_PORT=26690
```

API gate는 실제 HTTP/SMTP/login을 사용하고, UI flag는 실제 Chromium에서
관리자 정의와 사용자 연결 CRUD·비활성·stale revision을 검사한다.
`GOAUTHY_E2E_AUTH_COLLECTIONS_SCREENSHOT_DIR`를 지정하면 1280/375 CSS-pixel
viewport의 populated form을 캡처하고 가로 overflow도 검사한다. 실제 휴대폰
검증은 아니다. 고정 sleep 대신 DOM 상태·HTTP 결과·Pod Ready/UID를 기다린다.
exact-three runner는 별도 API chaos 실행에서 생성한 **동일 connection ID와
revision/metadata**를 보존한 채 goauthy-0을 교체하고 살아 있는 Pod에서
조회·수정·삭제한다. 그 뒤 primary forward를 다시 열고 UI/API를 재실행한다.
단일 Kind host에서 수행하는 Pod 교체이며 물리 host 장애나 쿼럼 상실을 이
authcollection CRUD gate가 검증한 것으로 계산하지 않는다. Credential refresh와
delivery는 별도 SaaS/use-grant 검증 범위를 따른다.
