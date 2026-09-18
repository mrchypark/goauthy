# 사용자 관리: 계약과 구현 잔여 항목

기준: Rauthy v0.36.2, Rhiza v0.12.0, GoAuthy schema 61.
전체 사용자 CRUD는 **미완료**다. 기존 삭제·멤버십·비밀번호 API가 있다는 이유로
사용자 생성/상세 조회/전체 프로필 수정을 완료 처리하지 않는다.

## 사용자 메타데이터 (schema 56)

schema 56은 공개 사용자 CRUD가 아니라 `identity_users`의 생성·최근 로그인
메타데이터를 보존하기 위한 저장소 bookkeeping이다. 목록 API는 이를 Unix 초로
변환해 반환한다. 상세 조회 라우트도 연결됐지만 아래 저장 모델의 공백이 남아 있고,
관리자 생성·수정 API는 아래 범위로 연결했으며 전체 정책/상세 모델은 미완료다.

- `created_at_unix_ms`는 새 bootstrap/open-registration 계정에서 주입된 실제 시각을
  저장한다. 과거 행은 `0` sentinel이며, 누락된 legacy 생성 시각을 현재 시각으로
  꾸미지 않는다. 중복 bootstrap, re-bootstrap, 비밀번호 변경은 생성 시각을 보존한다.
- `last_login_at_unix_ms`는 legacy 행에서 `NULL`일 수 있다. 인증된 세션이 실제로
  영속화한 `created_at` 시각을 사용해 갱신하며, 벽시계 현재 시각이나 요청 생성
  시각을 새로 만들어 넣지 않는다. 갱신은 단조성을 보장한다.
- 이 기록은 로그인 credential generation guard가 아니며, metadata만으로 토큰·세션을
  폐기한다고 주장하지 않는다.

결정론적 확인 체크리스트:

- [x] schema 56 migration이 두 컬럼과 marker를 함께 요구하고 legacy 행을 `0`/`NULL`로
  보존한다 (`internal/storage/identity_metadata_test.go`, migration tests).
- [x] bootstrap/open-registration, duplicate/re-bootstrap, password update의 생성
  시각 보존과 저장된 인증 세션 생성 시각 기반 last-login 갱신은
  `internal/identity/user_metadata_test.go`에서 고정 시각으로 검사한다.
- [x] 로그인 handler에서 익명 초기화·잘못된 인증이 시각을 기록하지 않으며, 성공 시
  고정된 DB 세션 생성 시각을 기록한다. 저장 실패 시 새 세션 폐기·기존 세션 유지·
  쿠키 미발행을 실제 Rhiza trigger로 검사한다 (`internal/login/user_metadata_test.go`).
- [x] schema 56의 실제 Chrome standalone 패스키 관리 회귀 검증.
- [x] schema 56의 정확히 3-peer HA 관리 회귀 검증. 새 이미지로 모든 노드 기동과
  등록/조회/권한 거절/삭제를 확인했다. 이번 gate에는 pod 교체·quorum 상실이 없다.
- [x] 공개 목록의 생성/로그인 시각·nullable 필드·빈 배열의 단위/HTTP/OpenAPI 검사.
- [ ] 전체 사용자 CRUD E2E는 나머지 API 구현 후 검증한다.

## 사용자 언어 (schema 57)

- [x] `identity_users.language`는 `de/en/fr/ko/nb/nl/ru/uk/zhhans`만 허용한다.
  마이그레이션은 컬럼·marker를 한 트랜잭션으로 추가하고 부분 상태는 거절한다.
  legacy/bootstrap의 알 수 없는 언어는 `NULL`로 남긴다.
- [x] 공개 가입은 비민감 `locale` 쿠키를 우선하고, 없으면 제한된
  `Accept-Language` q/order resolver를 사용한다. 신규 계정 기본값은 `en`이다.
  중복 가입은 새 요청의 언어로 기존 계정을 변경하지 않는다.
- [x] 최초 비밀번호·재설정·중복 등록 메일에 저장된 언어를 전달한다.
  API `zhhans`는 기존 템플릿 키 `zh_hans`에 매핑한다. 전체 override catalogue를
  SMTP에 전달하며, legacy의 빈 언어만 배포의 `GOAUTHY_EMAIL_TEMPLATE_LANG`을 따른다.
- [x] 상세 조회는 저장된 언어를 반환하며 legacy `NULL`만 `en`으로 표시한다.
  실제 DTO/OpenAPI는 같은 9개 값을 허용하고 별칭·빈 값·null은 거절한다.
- [x] 9개 값·legacy·중복·재개방·동시 마이그레이션·메일 선택의 결정론적 검사.
- [x] standalone 실제 가입→SMTP→비밀번호 설정→로그인→언어 상세 조회,
  반대 언어로 재가입해도 기존 한국어 알림 유지.
- [x] 정확히 3-peer HA의 모든 노드 상세 조회·메일 선택 및 발급 노드 교체 후
  비밀번호 설정 exactly-once·저장 언어 알림 보존. 임시 클러스터 정리 확인.
- [ ] 언어 workflow의 quorum 상실·네트워크 분할/복구 검증.
- [ ] self/admin 언어 변경 API, 전체 계정·관리 UI 번역과 시간대별 메일 시각.

원본의 [locale 선택](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/language.rs),
[중복 등록 메일](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/email/email_registered_already.rs)을
대조했다. Go resolver는 기존 1024-byte/16-range 상한과 strict qvalue 검사를 재사용하며,
헤더의 지역 태그를 기본 언어로 축약한다. 원본 alias 목록과 완전히 동일한 언어 협상
라이브러리 구현이라고 주장하지 않는다. UI의 기존 en/ko 범위는 확대하지 않았고,
기본 메일 일부에는 영어 placeholder가 있으므로 9개 언어 완역 완료가 아니다.

재현: `make e2e-standalone-open-registration` (필요하면
`GOAUTHY_STANDALONE_OPEN_REG_PORT` 설정), `make e2e-kind-open-registration`.
K8s와 standalone은 기존 공유 포트 lock을 사용하거나 별도 직렬 실행한다.
실행 결과와 범위는 [상태 보고서](status.md)에 기록한다.

## 원본 계약과 현재 상태

| 기능 | Rauthy 계약 | GoAuthy 상태 |
|---|---|---|
| 사용자 목록 | `GET /auth/v1/users`, 관리자·위임 그룹 관리자·Users/read API key, 임계값에 따라 200/206 및 개수/페이지 헤더 | [x] 라우트·저장소·페이지네이션·OpenAPI·결정론적 검사; live 상태는 아래 구분 |
| 사용자 생성 | `POST /auth/v1/users`, Users/create 또는 그룹 관리자, 이메일·언어·역할·선택 그룹/이름/만료/시간대, 200 상세 응답 | [ ] 생성·설정 메일·활성화·SCIM 생성 wake는 연결; 전체 이벤트·관리 UI·모든 live 권한/장애 경계는 아래 미완료 |
| 사용자 상세 | `GET /auth/v1/users/{id}`, self 또는 인가된 관리자/키의 상세 응답 | [ ] 라우트·저장 언어·대상 권한 검사는 구현; 실패 이력/만료/연동 원문 등 전체 모델은 미완료 |
| 관리자 수정 | `PUT /auth/v1/users/{id}`, Users/update 또는 그룹 관리자, 프로필·권한·활성·만료·비밀번호 | [ ] 전체 parity; HTTP/권한/원자적 수정/응답/양쪽 SMTP/SCIM wake 연결, scoped standalone·HA·재시작 PASS. required-profile/전체 상세 모델·UI·원격 SCIM·광범위 chaos는 미완료 |
| 멤버십 수정 | `PATCH /auth/v1/users/{id}` | [x] 기존 좁은 역할/그룹 경로; 전체 CRUD의 대체물이 아님 |
| self 수정 | `PUT /auth/v1/users/{id}/self`, 이메일 변경은 202 확인 흐름 | [ ] 비밀번호 변경만 구현, 일반 프로필/이메일 확인 확장 필요 |
| 삭제 | 관리자/API key 및 별도 opt-in self 삭제 | [x] 기존 원자적 삭제·최종 관리자 보호·SCIM tombstone 경로 |

목록의 200과 206은 모두 `UserResponseSimple[]`이다. 원본 API annotation의
전체 `UserResponse` 표기 대신 실제 `find_all_simple`/`find_paginated` 반환을 따른다.
간단 응답은 id/email/이름/생성 시각/마지막 로그인/사진 ID만 포함한다.
위임 관리자의 목록 허용과 개별 대상의 상세·수정 허용은 별개다.
[API 구현](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/users.rs),
[실제 목록·생성 저장소](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/users.rs).

### 관리자 생성 구현과 남은 경계

- [x] `GOAUTHY_PASSWORD_RECOVERY_ENABLED=true`의 기존 SMTP/설정 링크 서비스가
  있을 때 `POST /auth/v1/users`와 OpenAPI를 노출한다. 공개 가입 허용 여부와는
  독립적이다. `GOAUTHY_PASSWORD_NEW_EXPIRY`를 재사용하며 새 dependency는 없다.
- [x] 필수 `email/language/roles`와 선택 이름·`preferred_username/groups/user_expires/tz`.
  이메일은 소문자로 저장하고, 빈 roles 배열은 유효하다. 선택 null은 미설정이다.
  Unix seconds→milliseconds는 overflow를 검사하고 UTC/Etc/UTC는 저장하지 않는다.
  IANA timezone은 표준 `time.LoadLocation` 및 scratch용 `time/tzdata`로 검증한다.
- [x] 직접 관리자·Users/create API key·위임 그룹 관리자 경로. 브라우저는 정확한
  세션/peer/CSRF, 키는 digest/현재 grant를 검사하고 같은 생성 배치에서 인가를 고정한다.
  위임 생성은 빈 roles와 최소 한 개의 실제 관리 그룹을 요구하며 모든 요청 그룹이
  관리 범위여야 한다. 생성 결과를 받는 데 별도의 Users/read 키 권한은 필요 없다.
- [x] identity/profile/email/auth-mode/revision/password_new 및 역할/그룹을 같은 Rhiza
  쓰기로 생성한다. 원본 sanitize처럼 없는 역할/그룹 이름은 걸러낸다. 인가 실패는
  403, 인가된 중복 충돌은 406이며 새 bearer가 응답에 포함되지 않는다. 존재 확인을
  인가 전에 하지 않는다. 공개 가입도 선호 사용자명 중복 조건을 공유한다.
- [x] 저장된 언어로 커밋 후 최초 설정 메일을 보내고, 기존 cookie/CSRF-bound
  password-new 경로로 한 번만 비밀번호 설정·이메일 확인을 수행한다. SMTP 실패는
  기존 OnError 경로에 전달하며 이미 커밋한 생성을 되돌리거나 HTTP 실패로 바꾸지 않는다.
- [x] 미사용 password-new 계정 정리는 관리자 생성도 포함한다. 역할/그룹 관계를
  함께 제거하고 패스키 등록이 끝난 계정은 보존한다. 기존 64건/tick 상한과 시간 주입을
  사용한다. worker는 공개 가입이 꺼져도 recovery 서비스가 있으면 실행한다.
- [x] 같은 선호 사용자명 동시 생성의 단일 승자, 공개/관리자 경로 중복, SQL 실패
  rollback, 사전 인가 후 역할/세션/계정 만료/키/grant 철회와 무메일 검사.
- [x] 최종 standalone 및 새 이미지 exact-three HA에서 관리자 생성→SMTP→
  비밀번호 설정→재사용 거절→로그인과 전체 노드 상세/중복 확인 PASS.
  전체 Go suite·관련 race 2회·vet도 PASS. 실행 근거는 [상태 보고](status.md)에 기록했다.
  같은 HA 프로필의 기존 공개 가입 pod 교체 회귀는 관리자 생성 자체의 chaos가 아니다.
- [x] 관리자 생성·공개 가입 커밋 직후 기존 SCIM worker wake 연결. 알림은
  capacity-one 채널로 병합하고 SMTP 실패와 분리한다. 대기 비밀번호 계정은
  canonical email/subject 및 `active=false`로 투영한다. 원격 전송은 기존
  outbox/claim fence/retry를 사용하며 HTTP 생성은 전송 완료를 기다리지 않는다.
  startup/정기 scan이 종료로 유실된 알림을 복구한다. 고정 시각·barrier·동시 wake
  회귀와 standalone 무재시작 생성/중복 E2E PASS; HA 결과는 상태 문서에 기록한다.
- [x] 만료된 미사용 password-new 계정의 기존 원격 orphan 결함 수정: 같은
  ordered 64건 후보의 삭제 전에 hard-delete tombstone과 제공자별 DeleteRemote
  의무를 원자적으로 저장한다. 제공자가 없으면 불필요한 tombstone을 만들지 않는다.
  같은 시각의 다음 배치도 처리하도록 cleanup mutation ID는 새 nonce를 포함한다.
- [x] 생성 UI에 preferred_username/user_expires/tz와 서버가 지원하는 9개
  언어를 연결했다. 실제 Chromium 생성·수정·삭제에서 새 필드와 프랑스어의
  저장·보존을 검증했다(4.85s, standalone batch exit 0).
  근거: `/tmp/goauthy-admin-create-ui-language-live-20260910.log`.
  exact-three Kind Chromium에서도 통과했다(10.64s, 전체 gate exit 0):
  `/tmp/goauthy-create-ui-kind-20260910.log`.
- [x] create-only API 키의 생성 성공, 상세 조회 403, 키 폐기 후 생성 401을
  standalone 전체 lifecycle/restart 배치에서 확인했다(생성 0.34s, exit 0).
  `/tmp/goauthy-create-only-key-live-final-20260910.log`; 같은 endpoint를 사용하므로
  교차 Pod 권한은 후속 Kind 전체 gate에서도 통과했다(아래 근거).
- [x] 위임 그룹 관리자의 exact/wildcard 복합 그룹 생성, 비관리 그룹·전역 역할·
  빈 그룹 거부, 기존 세션에서 wildcard 권한 제거 후 exact 권한만 유지하는
  경계를 standalone 전체 lifecycle/restart 배치에서 확인했다(exit 0).
  `/tmp/goauthy-delegated-create-retry-aware-20260910.log`.
  같은 실행에서 실제 429의 Retry-After를 기다린 비밀번호 재설정도 통과했다.
- [x] preferred username 이메일 fallback 기본값/비활성화 설정과 명시적 이름
  우선순위는 구현돼 있다. 집중 단위 검사 PASS(0.936s); 기본 fallback의
  profile-only ID token은 기존 standalone TestProfileClaimsLive PASS(1.42s),
  `/tmp/goauthy-admin-create-ui-language-live-20260910.log`.
- [x] 위임/API-key 생성의 교차 Pod E2E: exact-three Kind 생성 lifecycle
  4.62s 및 전체 gate exit 0. 이벤트 stream·교체 후 지속성 검사도 통과했다.
  `/tmp/goauthy-delegated-create-kind-20260910.log`.
- [ ] 전체 원본 `new_user/new_rauthy_admin` 이벤트·알림,
  메일 durable retry/outbox 및 재전송 관리 API.
- [x] fallback=false 실제 배포에서 최초·refresh·profile-only ID token과 UserInfo의
  preferred_username 미노출을 확인했다(TestProfileClaimsLive 1.66s, batch exit 0).
  근거: `/tmp/goauthy-profile-no-email-fallback-20260910.log`. 이는 standalone 증거다.
  같은 강화된 검사의 fallback=true 실행도 통과했다(1.64s, batch exit 0):
  `/tmp/goauthy-profile-email-fallback-enabled-20260910.log`.
- [ ] preferred-username 로그인 재검증 정책, fallback 비활성화 HA, 전체 생성 관리 UI,
  생성 자체의 pod 교체/quorum chaos.

원본 대조: [POST handler](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/users.rs#L130),
[request DTO](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api_types/src/users.rs#L54),
[creation](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/entity/users.rs#L229),
[role sanitize](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/entity/roles.rs#L219),
[magic-link cleanup](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/schedulers/src/magic_links.rs).
검증된 tag 해시는 `dd61ac3c...`이며 이전 문서의 `dd61ac3b...`는 오타였다.
GoAuthy는 기존 ASCII email·역할/그룹 grammar 및 8 KiB/64개 상한을 재사용한다.
이름은 원본 문자 범위를 사용하되 제어문자는 거절한다. 위임자의 존재하지 않는
그룹만으로 scope 없는 사용자를 만들 수 없게 제한한다. 기존 정리는 1시간 간격/
정각부터이며 원본 magic-link 정리의 6시간/300초 여유와 동일하다고 주장하지 않는다.
SMTP 본문에서 사용자 timezone으로 시각을 표시하는 기능도 별도 잔여 항목이다.
생성 wake는 기존 O(users*providers) 전체 scan과 pass당 최대 64개 due job을
재사용한다. 따라서 backlog/제공자 오류에서 즉시 전달 SLA나 exactly-once를
보장하지 않는다. 비밀번호 활성화·멤버십 변경·삭제까지 모든 변경의 즉시 wake,
생성 직후 프로세스 종료와 제공자 장애의 전용 live/chaos 검증은 별도 잔여다.

### 생성 이벤트의 원본 계약과 미구현 범위

고정 Rauthy [POST handler](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/users.rs#L145)는
생성 뒤 `NewUserRegistered`, 결과가 관리자이면 `NewRauthyAdmin`을 추가 전송하고
SCIM 작업은 비동기로 시작한다. [이벤트 생성자](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/events/event.rs#L782)는
email을 text, 요청 IP를 ip, data를 null로 사용한다. 저장·알림 level, 이벤트 조회와
SSE는 현재 GoAuthy의 pseudonymous API-key/master-key audit와 다른 계약이다.

- [x] lifecycle event DTO/type와 관리자 여부에 따른 두 번째 이벤트: schema 59,
  같은 생성 배치에서 저장. 검증·개인정보 보존 경계는 [events](events.md).
- [ ] persistence/notification threshold 및 email/Matrix/Slack 전달.
- [x] Events:read/API key 또는 현재 browser admin 권한의 POST 시간/level/type 조회.
- [ ] SSE stream.

기존 audit CHECK에 사용자 문자열만 추가하거나 기존 GET audit 응답을 원본
event API 완료로 표시하지 않는다. IP/email 보존 정책과 event DTO, 저장/조회는
[events](events.md)에 명시했다. stream과 알림 retry는 아직 구현·검증해야 한다.

### 목록 구현과 의도적인 차이

- `GOAUTHY_SSP_THRESHOLD`는 `1..65535`, 기본 `1000`이다. 원본
  [설정](https://github.com/sebadob/rauthy/blob/v0.36.2/config.toml)의 기본값과 같다.
  사용자 수가 임계값 미만이면 `200` 전체 배열, 이상이면 `206`이다. 유효 페이지
  크기는 `max(page_size 또는 20, 임계값)`이다. `page_size`는 `1..65535`, `offset`은
  `0..65535`, `backwards`는 bool이다. `session_state`는 원본 enum을 검증하되 무시한다.
- 권한과 전체 개수, 페이지 결과는 같은 선형화 SQL 읽기에 포함된다. 정확한 브라우저
  세션과 현재 활성 직접/위임 역할, 또는 정확한 API-key digest와 Users/read grant를
  재검사한다. 권한이 철회되면 목록뿐 아니라 개수도 반환하지 않는다.
- cursor는 서명된 권한이 아닌 위치다. 원본의 10자리 시각+ID 문자열은 legacy `0`과
  GoAuthy의 다양한 subject를 표현하기 어려워 `u1.` + 표준 base64url의 밀리초/ID
  cursor를 사용한다. 정렬은 `(created_at_unix_ms, subject)`로 고정해 동시 생성 계정의
  중복·누락을 방지한다. 역방향 조회는 결과를 오름차순으로 반환하고 첫 행을 다음
  cursor로 사용한다. 원본처럼 비어 있지 않은 페이지에는 cursor를 반환한다.
  빈 마지막 페이지도 `206`과 전체 개수/페이지 헤더를 보존한다.
- 이메일은 profile, recovery email 순으로 읽는다. 알려진 이메일이 없는 기존
  username 계정은 `email=""`, 사진 기능이 없는 현재 모델은 `picture_id=null`이다.
  이메일·사진을 추정하지 않는다. 민감한 credential/권한/사용자 속성은 목록에 없다.
- 알 수 없는/중복 query, 비정상 숫자·bool·cursor와 cross-site 요청은 거절한다.
  Authorization이 있으면 유효한 브라우저 쿠키로 우회하지 않는다.

검증: `internal/rbac/user_list*_test.go`는 고정 값/명시적 커밋 순서로 일반·페이지·
역방향·같은 시각 경계·빈 마지막 페이지·legacy/null을 검사하고, preflight 이후
역할/활성/세션/API key/grant 철회를 커밋한 뒤 조회가 거절됨을 확인한다.
`internal/apidocs/user_list_test.go`는 실제 공개 DTO JSON을 명세와 대조한다.
Chrome standalone과 정확히 3-peer HA는 임계값 200/1에서 모두 PASS했다.
HA 임시 클러스터의 종료·정리도 확인했다. 최종 일반 Go 테스트·scoped race·vet·
실제 DTO/OpenAPI 검사도 PASS했으며 실행 근거는 [상태 보고서](status.md)에 있다.
두 모드의 재현은 기존 admin-passkey gate에 `GOAUTHY_E2E_USER_LIST_THRESHOLD=200`
또는 `1`을 지정한다. 이번 gate는 한 사용자 경계·인증·모든 노드 일관성·키 철회이고,
다중 사용자 생성·위임 관리자 live·pod 교체·quorum 상실은 별도 미검증이다.

### 상세 조회 구현과 남은 저장 모델

`get_user_by_id`는 일반 사용자의 본인 조회와 관리자/Users-read 키의 조회를
구분한다. 위임 그룹 관리자는 본인은 조회할 수 있지만 다른 대상에는 별도의
`validate_group_admin_can_view`가 적용된다. 목록 허용을 상세 허용으로 재사용하지
않는다. 원본 handler 주석은 비관리 일반 대상의 `428`과 관리자 대상의 `403`을
구분한다. 실제 helper와 대조해 self/direct-admin 우선, 관리자 대상 보호,
exact/suffix-wildcard 그룹 매칭 및 `403`/`428`을 구현했다.
[원본 상세 handler](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/users.rs).

상세 `UserResponse`는 목록과 달리 선택 필드에 `skip_serializing_if`가 있다.
이름·그룹·선택 시각·연동/사진 ID가 없으면 `null`이 아닌 **키 생략**이다.
필수 `user_values` 객체의 선택 필드도 생략하므로 값이 없으면 `{}`가 된다.
`roles`는 빈 배열을 유지한다. 상세 타입을 목록의 nullable DTO나 임의의 JSON
속성 맵으로 대체하지 않는다. 언어 변경·만료·실패 로그인 상태와 계정 종류의 저장/계산
근거를 확인한 뒤 실제 응답·OpenAPI·권한 변경 장벽 검사에 같은 DTO를 사용한다.
[응답 타입](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api_types/src/users.rs),
[실제 변환](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/users.rs).
현재 `GET /auth/v1/users/{subject}`는 session/API-key 인가, 대상 역할/그룹과
공개 projection을 한 선형화 SQL 읽기에 담는다. preflight 이후 세션/활성/역할/
scope/대상 그룹/대상 관리자 승격/키 grant 변경은 명시적 커밋 장벽 테스트로 검사한다.
원본 PHC·credential JSON·내부 키 해시는 공개하지 않는다. `user_values`는 알려진
DTO 필드만 내보내고 preferred username은 별도 profile 컬럼을 사용한다.

- 비밀번호 만료는 기존 `ValidDays` 정책과 실제 password-changed 시각에서 계산한다.
  인증 경로와 공유하는 UTC `AddDate` 계산 및 strict `now.After` 경계는 유지한다.
  만료 정책 비활성/legacy 시각 0/비밀번호 없는 계정에는 만료 필드를 생략한다.
- 계정 종류는 사용 가능한 password, 등록 credential, 외부 링크 상태에서 계산한다.
  MFA credential이 있는 password 계정은 `password`이며, 외부 링크가 있으면
  해당 `federated_*` 값이다. 인증 mode/외부 링크/공개 ID는 서로 바꿔 쓰지 않는다.
- schema 57의 저장 언어를 반환하고 legacy만 `language="en"` fallback을 사용한다.
  schema 58은 저장된 계정 만료를 초 단위로 반환한다. 언어 변경 API,
  전체 계정 만료 lifecycle과 실패 로그인 이력의 기록/집행은 **미완료**다.
  없는 이력은 0으로 꾸미지 않고 선택 필드를 생략한다.
- 기존 외부 링크는 원본 federation UID가 아닌 해시만 저장한다. 해시를 UID로
  오인해 반환하지 않는다. 링크가 하나일 때만 provider ID를 반환하며, 여러 링크의
  주 제공자는 임의로 선택하지 않는다. 원본 UID/주 제공자 모델과 사진 기능도 남았다.

현재 상세 범위의 검증:

- [x] focused HTTP/DTO/OpenAPI 및 결정론적 대상 권한·계정 종류 검사.
- [x] 전체 일반 Go 테스트, 관련 race 및 vet.
- [x] Chrome standalone/정확히 3-peer HA의 bootstrap 관리자 browser/API-key
  응답 일치와 키 철회 거절. 임시 클러스터 정리 확인.
- [ ] 위임·다중 사용자 lifecycle의 live E2E와 네트워크 분할/복구.
- [ ] 위에 명시한 누락 저장 모델의 실제 기록/집행 및 공개 필드 연결.

실행 근거는 [상태 보고서](status.md)에서 구분한다. 이 라우트가 있다는
이유로 전체 상세 모델이나 사용자 CRUD를 완료 처리하지 않는다.

관리자 생성은 즉석 임시 비밀번호 계정이 아니라 `New` 상태와 최초 비밀번호 설정
링크/메일을 만든다. `BootstrapUser`는 멱등 부트스트랩 전용이므로 그대로 노출하지
않는다. 전체 응답에는 언어, 생성/로그인/실패 시각, 만료, 계정 종류, user_values
등이 필요하다. 현재 없는 과거 시각을 현재 시각으로 꾸며 반환해서는 안 된다.
[요청·응답 타입](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api_types/src/users.rs).

관리자 수정에서 이메일 변경은 즉시 저장되고 기존 세션 무효화와 양쪽 주소 알림이
이어진다. self 변경은 기존 이메일을 유지하고 확인 링크를 보낸다. 이 링크의 원본
수명은 `MagicLink::create(..., 60, ...)`의 **60분**이다. 인자 단위는
`lifetime_minutes`이며 60초로 구현하지 않는다. 관리자 비밀번호 지정은 새 verifier를
설정하는 경로이고 최초 계정 생성의 설정 링크와 다르다.
[수정 구현](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/users.rs),
[링크의 수명 단위](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/magic_links.rs).

### 관리자 PUT 입력·권한 기반 (2026-09-06, route 미연결)

이 단락은 기반 구현 당시의 기록이다. 이후 HTTP 연결 및 검증 범위는 아래
관리자 수정 HTTP 연결과 [최신 status](status.md)를 따른다.

- [x] `UserUpdateRequest`와 `UserValuesRequest`, 엄격한 JSON decoder.
  필수 `email`, `roles`, `enabled`, `email_verified`는 누락/null을 거절하되
  명시적인 false/빈 역할 배열은 허용한다. 선택 언어/비밀번호/이름/그룹/만료/
  profile 값의 null과 생략을 표현한다. 비밀번호는 DTO의 256 rune 상한만
  검사하며 실제 비밀번호 정책·이력 검사는 아래 저장 경로의 미완료 항목이다.
  초→밀리초 overflow, 중복/미지 필드(중첩 포함), 잘못된 타입/UTF-8,
  과대 body, 추가 JSON 문서, 중복 Content-Type과 query를 거절한다.
- [x] `userUpdateAuthority`는 현재 DB의 역할/그룹으로 PUT 권한을 평가한다.
  직접 관리자는 대상 사용자 존재만 필요하다. 위임 관리자는 이미 관리하는
  일반 사용자 또는 본인을 수정할 수 있고, 역할 집합은 그대로여야 하며
  범위 밖 그룹의 추가와 제거 모두 거절한다. 마지막 관리 그룹을 제거하는
  요청 자체는 허용하지만 그 이후 PUT은 거절한다. 본인 수정도 역할 변경은
  허용하지 않는다. 대상이 disabled여도 관리/재활성화를 막지 않는다.
  이 predicate는 **브라우저 세션/MFA 검사를 대체하지 않는다**. 통합 시 현재
  세션 guard와 결합하고, API key는 별도의 현재 `Users:update` guard를 쓴다.
- [x] 실제 Rhiza schema에서 권한 행렬, 정확/접두/전체 wildcard,
  `_` 리터럴, 알려지지 않은 요청 이름, 빈 역할, disabled 대상 검사.
  권한 사전조회 이후 역할 회수/관리자 비활성화/대상 승격/관리 그룹 이탈/
  역할·범위 밖 그룹 변경을 순서대로 끼워 넣어 같은 SQL batch의 장벽에서
  후속 쓰기 두 개가 모두 거절됨을 검사한다. 시간 sleep이나 경쟁 확률에
  의존하지 않는다. 이는 준비된 predicate의 저장소 검사이며 PUT E2E가 아니다.
- [ ] HTTP `PUT /auth/v1/users/{id}`, 현재 browser+CSRF/MFA 또는 API-key
  권한과 위 predicate의 연결, 전체 원자적 수정/상세 응답/OpenAPI.
- [ ] 관리자 비밀번호 정책/이력/해시 및 generation CAS, passkey-only→password
  관리 정책, 최종 관리자 보호, old/new email 소유권과 로그인/복구 매핑.
- [ ] 양쪽 이메일 알림, 세션 무효화, disabled 상태의 refresh 무효화,
  password-reset/email-change/new-admin 이벤트 및 SCIM 수정 wake/투영.
- [ ] configurable required user-values 정책, 전체 관리자 UI,
  standalone·exact-three HA 수정/만료/재활성화 E2E와 장애 검증.

원본의 누락/변경 의미도 그대로 연결해야 한다. `language`가 없으면 보존하되
이름·그룹·`user_expires`는 PUT의 교체 의미를 따른다. `user_values`가 없으면
일반 profile 값을 지우지만 별도 endpoint의 `preferred_username`은 보존한다.
주어진 역할/그룹에서 실제 존재하는 이름만 저장하는 sanitize는 **위임 권한
검사 후** 수행한다. 먼저 unknown 이름을 없애면 범위 밖 변경 요청을 숨기게 된다.

근거는 고정 SHA의 [DTO 및 profile 값](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api_types/src/users.rs#L158),
[PUT admission](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/api/src/users.rs#L1940),
[위임 변경 정책](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/entity/principal.rs#L363),
[수정 부수 효과](https://github.com/sebadob/rauthy/blob/dd61ac3c84d6b238108dc8438b53043b5177a662/src/data/src/entity/users.rs#L1223)다.
기존 좁은 PATCH는 이 전체 PUT을 대체하지 않으며 이번 단계에서 동작을 바꾸지 않았다.

## 패키지 매핑과 직접 구현 경계

### 사용자명 생성 정책 (2026-09-06)

- [x] `identity.PreferredUsernamePolicy`가 공개 가입과 관리자 생성의 형식을
  공유한다. 원본 기본 regex는 `^[a-z][a-z0-9_-]{1,61}$`: 소문자로 시작하는
  **2~62자**, 이후 소문자·숫자·underscore·dash를 허용한다. 기존 대문자/dot
  허용 및 공개 가입에서 로그인 식별자 검증기를 대신 쓰던 차이를 제거했다.
  로그인 ID/이메일 검증기와 이미 저장된 사용자명은 변경하지 않는다.
- [x] 공개 가입의 모드는 기본 `optional`, 선택적으로 `required`/`hidden`이다.
  `hidden`도 제출 값의 형식/금지 목록을 검사한다. 기본 금지 목록은
  `admin`, `administrator`, `root`. 금지 이름은 일반적인 406 응답이며 입력을
  응답·로그에 반사하지 않는다. 형식/필수 검사는 400이고 모두 PoW 소비 전에
  수행한다. `preferred_username`의 생략/null과 명시적 빈 문자열을 구분한다.
- [x] 관리자 POST는 원본처럼 required/blacklist를 면제한다. 따라서 형식이
  맞는 예약 이름을 관리자에게 허용하지만, 중복·권한·regex 검사는 그대로다.
  이 이름 자체가 역할/권한을 부여하지는 않는다. 기존 일반 프로필 PUT은
  사용자명 수정 API가 아니며 계속 별도 관리 값을 보존한다.
- [x] 시작 시 다음 env를 해석하고 동일한 불변 정책을 HTTP 및 Rhiza 저장
  명령에 전달한다. 커스텀 regex가 저장 단계의 이전 고정 검사에 다시 막히지 않는다.

  | 설정 | 의미 |
  |---|---|
  | `GOAUTHY_USER_VALUES_PREFERRED_USERNAME` | `required`, `optional`, `hidden`; 빈 값은 optional |
  | `GOAUTHY_USER_VALUES_PREFERRED_USERNAME_REGEX` | Go 표준 `regexp` 식; 빈 값은 원본 기본 regex |
  | `GOAUTHY_USER_VALUES_PREFERRED_USERNAME_BLACKLIST` | JSON 문자열 배열; 미설정은 원본 목록, `[]`는 해제, `null`은 설정 오류 |
  | `GOAUTHY_USER_VALUES_PREFERRED_USERNAME_IMMUTABLE` | 기본 `true`; 정확한 `true`/`false`만 허용. 기존 이름의 일반 변경 금지 여부 |

  비교는 **입력만 소문자로 바꿔 원문 목록과 비교**한다. 원본처럼 목록을
  자동 정규화하지 않으므로 운영자가 금지 목록을 소문자로 작성해야 한다.
  목록은 복사하고 regex는 한 번 컴파일한다. 잘못된 설정은 DB를 열기 전에
  거절하며 설정값을 오류에 넣지 않는다. regex 4096 bytes, 목록 256개,
  항목/입력 128 bytes 및 유효 UTF-8 한계를 둔다(기존 DB 한계 보존).
- Go RE2와 Rust regex의 임의 패턴 전체 문법이 동일하다고 주장하지 않는다.
  Rust 전용 문법은 Go 형식으로 명시적으로 변환해야 하며 지원하지 않는 식을
  조용히 무시하거나 다른 정규식 엔진으로 fallback하지 않는다. 원본 기본식과
  테스트의 사용자 지정 ASCII 식은 직접 대조했다. 빈 문자열을 매칭하는
  커스텀 식으로 제출한 빈 이름은 기존 저장 계층에서 absent/null로 정규화된다.
  이 기존 저장 의미와 128-byte 제한은 임의 원본 커스텀 설정까지의 완전한 동등성이 아니다.
- [ ] `values_config`, HTML pattern/hint,
  email-fallback/token/UserInfo, 로그인 재검증/UI, 혼합 정책 rolling/장애 검증.
  생성 정책 연결을 사용자명 전체 lifecycle 완료로 세지 않는다.
  [현재 테스트 증거](status.md)는 기본/사용자 지정 정책과 배포 모드를 구분한다.

### 사용자명 변경 API (2026-09-06)

- [x] `PUT /auth/v1/users/{subject}/self/preferred_username`는 JSON의 선택 필드
  `preferred_username: string|null`, `force_overwrite: bool|null`을 받는다.
  성공은 본문 없는 200이다. 알 수 없는/중복 필드, 잘못된 타입, query,
  비-JSON, 8 KiB 초과 입력을 거절한다. 별도 서비스나 dependency는 추가하지 않았다.
- [x] 현재 사용자 자신의 인증 세션, `Users:update` API 키, 전체 관리자 또는
  관리 범위에 속한 위임 관리자를 허용한다. 브라우저는 CSRF/교차 사이트
  검사를 통과해야 한다. 명시된 잘못된 API 키를 쿠키 권한으로 대체하지 않는다.
- [x] 위임 관리자는 관리자 역할을 가진 대상이나 관리 그룹 밖의 대상을
  수정할 수 없다. 타인의 기존 사용자명은 mutable 설정에서도 덮어쓸 수
  없으며, 아직 이름이 없는 대상만 초기화한다. 자기 자신에게는 self 규칙이 적용된다.
- [x] immutable 기본값은 true이며 같은 이름 재제출도 400이다. 오직 전체
  관리자와 `Users:update` 키만 `force_overwrite:true`로 우회할 수 있다.
  관리자 POST 생성과 달리 **변경 API는 강제 변경도 required/blacklist를
  면제하지 않는다**. 이름 형식·required·immutable 거절은 400, 예약·중복은 406이다.
- [x] Rhiza 한 트랜잭션의 권한 판정과 조건부 upsert에서 현재 세션/키,
  역할/그룹, 대상의 기존 이름, 중복을 검사한다. 기존 생성 경로도 같은
  트랜잭션 내 중복 검사를 사용한다. 새 unique index/schema는 추가하지 않았다.
  이메일·다른 프로필·세션·SMTP·SCIM/event 상태를 변경하지 않는다.
- 명시적 빈 문자열은 먼저 regex 검사를 받는다. optional/hidden에서 허용된
  null/생략은 이름을 지우며, profile 자체가 없으면 안전한 no-op이다.
  GoAuthy의 legacy 계정에 profile/recovery 이메일이 모두 없는데 이름을
  설정하면 409를 반환한다. 가짜 이메일을 생성하지 않으며 실제 이메일을
  연결한 뒤 다시 설정할 수 있다. 원본의 이메일 보유 사용자와 구분하는 호환 경계다.
- 검증: [상태 보고서](status.md)의 해당 변경 API 증거를 따른다. 사용자명
  claims/email-fallback, 로그인 재검증, 설정 조회 및 UI까지 완료되었다는 의미는 아니다.

### 일반 프로필 필수 항목 정책 (2026-09-06)

- [x] `identity.UserValuesPolicy`를 공개 가입과 관리자 PUT에서 공유한다.
  `given_name` 기본값은 `required`, 나머지 일반 필드는 `optional`이다.
  이름은 missing/null/empty가 필수 검사에서 거절된다. `hidden`은 저장 금지가
  아니므로 제출된 값의 기존 형식·길이 검증은 계속 수행한다.
- [x] 관리자 POST 생성은 원본의 명시적 예외에 따라 필수 항목 검사를 면제한다.
  입력 형식·권한·이메일 등의 기존 검증까지 면제하지는 않는다.
- [x] 다음 환경변수에 정확히 `required`, `optional`, `hidden`을 설정한다:
  `GOAUTHY_USER_VALUES_GIVEN_NAME`, `GOAUTHY_USER_VALUES_FAMILY_NAME`,
  `GOAUTHY_USER_VALUES_BIRTHDATE`, `GOAUTHY_USER_VALUES_STREET`,
  `GOAUTHY_USER_VALUES_ZIP`, `GOAUTHY_USER_VALUES_CITY`,
  `GOAUTHY_USER_VALUES_COUNTRY`, `GOAUTHY_USER_VALUES_PHONE`,
  `GOAUTHY_USER_VALUES_TZ`. 빈 값/미설정은 원본 기본값이다. 잘못된 mode는
  시작 시 DB를 열기 전에 거절하며 실제 설정 문자열은 로그에 넣지 않는다.
  모든 HA 노드에 동일한 설정을 배포해야 한다. 원본의 일반 필드 설정은
  `[user_values]` TOML이며 위 env는 GoAuthy의 기존 배포 방식에 맞춘 매핑이다.
- 원본 v0.36.2는 **전체 `user_values` 객체가 생략/null이면 내부 필수 검사를
  건너뛴다**. `{}` 또는 개별 missing/null/empty에는 내부 required 검사가
  적용된다. 이 구분을 보존했으며, 기존 저장 값으로 누락 입력을 채우지 않는다.
  따라서 이 정책을 데이터베이스의 NOT NULL 보장으로 해석하면 안 된다.
- 공개 가입의 필수 검사는 PoW 소비·quota·DB 변경·SMTP 전에 수행한다.
  거절된 입력을 고친 뒤 같은 미사용 PoW로 재시도할 수 있다. PUT 거절 시
  프로필·이벤트·post-commit hook은 변경되지 않는다.
- [ ] `GET /users/values_config`, preferred-username의 configurable
  required/immutable/blacklist/pattern/email-fallback 전체 정책, 로그인 중
  재검증 및 프로필 보완 UI. 이번 구현은 이 기능들을 완료한 것이 아니다.
- [x] 일반 9개 필드를 모두 required/optional/hidden으로 설정하는 세 동질
  정책의 standalone 재시작 및 exact-three HA Pod 교체 E2E. 필수 모드는 필드별 missing/null/empty
  거절, 선택/숨김은 실제 저장 후 삭제, 전 모드는 형식 거절과 같은 PoW
  재시도/SMTP 부수 효과를 검사한다. 최종 결과와 정확한 범위는
  [status](status.md)의 일반 프로필 정책별 실배포 E2E 항목을 따른다.
- [ ] 임의 혼합 정책의 deployed E2E 및 서로 다른 정책이 공존하는 HA
  rolling rollout/정책 변경 중 장애 검증. 세 동질 정책을 전체 조합으로 세지 않는다.
- [x] 기본 required 이름의 공개 가입/관리자 PUT 거절과 정상 입력, 같은 PoW
  재시도, 관리자 생성 면제는 standalone/3-peer E2E를 통과했다. 일반 테스트의
  idle 설정은 90분이며 10초 실제 시간 만료는 명시적 전용 검사에만 적용한다.

### 관리자 수정 HTTP 연결 (2026-09-06)

- [x] public PUT, strict DTO/CSRF/API-key precedence, 현재 직접/위임 역할과
  target/field scope. Users:update만 있는 key도 자신의 변경 결과를 받는다.
- [x] GET/PUT이 `identity.UserResponseJSONSQL`/decoder를 공유한다. PUT은
  mutation batch 마지막 SELECT를 receipt로 받아 응답한다. 자기 session
  폐기·마지막 관리 그룹 제거·commit 이후 별도 편집이 응답을 바꾸지 않는다.
- [x] SMTP 설정 시 양쪽 주소에 변경 완료 안내를 보낸다. 기존 go-mail TLS,
  text/html template와 pinned 9언어 copy를 재사용한다. `email_change_confirm`
  override의 `text`/`footer`는 원본 msg/msg_from_admin에 해당한다. 관리자
  변경에는 확인 링크가 없고 실패한 메일이 DB 변경을 rollback하지 않는다.
- [x] commit 후 기존 SCIM wake. startup/주기적 재조회가 신호 유실을 보완한다.
- [x] standalone/3-peer 공개 첫 비밀번호 지정·이메일·프로필·미래 만료 설정/
  만료 제거·비활성화/재활성화·로그인·양쪽 SMTP·event 조회와 재시작 보존.
- [ ] required-profile 전체 설정/API/로그인 검증, 미지원 상세 필드, UI, remote SCIM 전체 필드,
  API-key/위임/MFA live matrix, 열린 SSE의 해당 emitter 검증, 실제 시간 만료
  scheduler 및 수정 중 quorum/partition 장애 검증. 메일 durable retry 없음.

### 원자적 관리자 수정 엔진 (2026-09-06)

`identity.UpdateUserWithGuard`가 아래 저장 동작을 한 Rhiza batch로 수행한다.
읽은 credential/profile/recovery/role revision snapshot과 현재 권한을 첫
`ExpectedReturnedRows=1` 장벽에서 검사한다. 이메일 충돌과 최종 관리자
보호도 변경 전에 같은 batch에서 검사하며 실패는 전체 rollback이다.
반환값은 **커밋된 알림용 subject/old email/new email/language**이며,
관리자 API의 전체 `UserResponse`를 대신하지 않는다.

- [x] 이메일/profile/복구 주소·이름·언어·활성 상태·nullable 만료·일반
  user_values 변경. 생략 언어는 유지하고 일반 profile/만료/그룹은 교체 또는
  제거하며 preferred username·등록 시각·로그인 이력은 보존한다.
- [x] 존재하는 role/group만 저장하고 실제 멤버십 변화에만 revision을 올린다.
  기존 역할·그룹의 SQL 변경 패턴을 재사용한다. 브라우저 위임 권한 검사는
  여전히 sanitize 전 입력을 사용해야 한다.
- [x] 기존 비밀번호 정책/현재·과거 verifier 재사용 검사/해시를
  `preparePassword`로 공유한다. 관리자 설정은 현재 비밀번호나 self MFA
  proof를 요구하는 메서드에 우회 접속하지 않고 관리자 명령의 권한 장벽을
  사용한다. password generation, 최근 N개 이력, pending/password-new 종료와
  passkey-only→password 전환을 같은 batch로 저장하며 등록된 passkey는 보존한다.
- [x] email 변경의 browser session 폐기, disabled 저장 시 로컬 code/PKCE/
  access/refresh/device 및 진행 중 MFA/연동 상태 폐기. disabled→enabled도
  처리하며 기존에 폐기된 session/refresh는 다시 활성화하지 않는다.
  원본의 이 경로는 back-channel을 직접 호출하지 않으므로 별도 전송을 만들지
  않으며 알려진 사용자/client 기록도 지우지 않는다.
- [x] password-reset/email-change/new-admin 이벤트를 실제 변경과 같은
  트랜잭션에 추가한다. 마지막 승격 이벤트가 실패하는 경우 앞선 비밀번호,
  이메일, 권한, 세션, 앞선 이벤트까지 rollback한다. 동일 상태 저장은
  email-change/new-admin 이벤트를 중복 추가하지 않는다.
- [x] 이메일 변경/비밀번호 지정/비활성화 시 미사용 복구 증표를 제거한다.
  공개 복구 서비스는 새 `IssuePasswordResetForEmail`로 발송 예정 주소를
  발급 트랜잭션에 묶는다. 이메일 변경 전에 조회했던 주소로 **변경 후 새
  토큰을 발급하는** 경쟁을 막으며, 거절된 stale 요청은 현재 유효한 링크를
  지우지 않고 메일도 보내지 않는다.
- [x] 권한은 정적인 SQL 인자 묶음이 아니라 재생성 함수로 전달한다. 비밀번호
  해시 전의 사전 조회와 해시 후 커밋 준비에서 각각 현재 세션/API-key 시간
  인자를 만든다. 오래된 시각을 SQL에서 다시 쓰는 것만으로는 만료를 재검증한
  것이 아니므로, 호출자는 `SessionAuthorizationGuard`/API-key guard를 함수
  안에서 호출해야 한다. 정적 `1=1`은 내부 테스트용일 뿐 HTTP 인가가 아니다.
- [x] HTTP/OpenAPI/기존 공개 상세 응답과 current browser/CSRF/Users:update
  key 연결, 양쪽 SMTP 및 SCIM wake. 상세 모델의 기존 공백과 전체 원격 투영은
  위 미완료 목록을 따른다. 오류 409는 충돌/최종 관리자/동시 권한 변경의
  공통 결과이며 원본 오류별 세분화와 동일하다고 주장하지 않는다.

GoAuthy 적용 차이: 명시적으로 설정한 legacy/bootstrap 로그인 이름은 이메일
변경으로 덮어쓰지 않는다. 기존 로그인 이름이 이메일과 같을 때만 함께 바꾸고
profile/복구 주소는 항상 새 이메일로 바꾼다. 명시적인 disabled 저장은 재활성화
시 이전 OAuth/MFA 작업이 살아나지 않도록 원본의 session/refresh보다 넓게
로컬 발급 중 상태를 폐기한다. 마지막 활성 직접 관리자의 역할 제거/비활성화/
즉시 만료를 거절하고 동시 두 관리자 비활성화도 한 명을 남긴다. 미래 만료
예약은 허용하며, 실제 만료 scheduler의 정책은 변경하지 않았다.

검증 명령·실제 실행과 남은 범위는 [status](status.md)의 최신 기록을 따른다.

### 계정 만료 기반 — schema 58

`identity_users.user_expires_at_unix_ms`는 nullable 비음수 INTEGER다. 기존 행은
`NULL`(무제한)로 보존하며 `0`은 무제한이 아니다. 상세의 `user_expires`는 정수
초로 내림 변환하고 NULL은 생략한다. 읽기가 영구 `disabled` 값을 바꾸지 않는다.

요청 시 정책은 `now >= deadline`부터 거절하는 배타적 상한이다. 원본
[사용자 검사](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/users.rs)는
초 단위 `>`이고 [스케줄러](https://github.com/sebadob/rauthy/blob/v0.36.2/src/schedulers/src/users.rs#L45-L86)는
정각부터 비활성화한다. GoAuthy는 기존 세션의 배타적 경계와 통일하므로 원본
요청 검사보다 만료 초 구간에서 더 엄격하다. 비밀번호 수명 정책과는 별개다.

- [x] 원자적 migration/marker, legacy NULL, 제약·부분 상태·재실행 검사.
- [x] 현재 사용자 조회·프로필·비밀번호 인증/검증과 reset/new 링크의 계정 만료 거절.
  비밀번호 검증 후 주체를 재확인하고 변경/토큰 소비는 쓰기 조건도 검사한다.
- [x] 세션 생성은 같은 SQL에서 실제 활성 사용자와 만료를 검사하고 수명을 제한한다.
  조회/인가 증표와 interaction 소비는 변경된 현재 사용자 상태를 다시 검사한다.
  초기 익명 세션은 별도이며, 없는 사용자를 무제한 사용자로 취급하지 않는다.
- [x] 기존 code/refresh 주체 가드에 계정 만료 추가. Device는 저장된 정확한 claim의
  소유자를 사용해 access/request/refresh 및 consumed marker를 모두 가드한다.
- [x] 고정 시각의 NULL/직전/정각/직후, 세션 기한 단축, device 거절 시 토큰 없음과
  claim 미소비, reset/new 거절 시 비밀번호·토큰·메일 검증 상태 보존 검사.
- [x] 사용자 생성 DTO의 만료 설정을 실제 관리자 명령에 연결.
- [ ] 사용자 수정 DTO의 만료 설정·전체 재활성화 관리 명령.
- [x] schema 61 사용자/client 기록을 만료 및 공통 hard-delete 트랜잭션에
  연결했다. SID 없는 subject-only back-channel 전송, 동일 client 중복 통합,
  다른 사용자 기록 보존, 최종 쓰기 실패 rollback 및 동시 만료 worker 회귀를
  고정 시계로 검증했다. 사용자 삭제의 실제 RP 전달과 재시작 검증은
  [status](status.md)에 별도 기록하며, 만료 public E2E의 대체 근거로 쓰지 않는다.
- [x] Token endpoint에서 현재 사용자(및 exchange actor)의 기한으로 access/refresh를
  제한하고 ID token도 같은 상한을 적용한다. Fosite의 code 재조회 후에도 상한을
  다시 적용하며 저장된 access 만료와 서명된 `exp`를 검사한다. Machine grant는
  사용자 행에 의존하지 않는다. JWT 초 정밀도 때문에 상한은 초 단위 내림이며,
  남은 유효한 초가 없으면 발급을 거절한다.
- [x] 같은 복제 쓰기에 NULL 포함 기한 snapshot 일치·활성 사용자·최종 제출 시각을
  조건으로 둔다. 아직 미래인 기한의 단축과 NULL→유한 변경도 거절한다.
  Device claim/grant와 exchange source/actor도 동일한 제출 시각을 쓴다.
  성공 응답 직전 계정 상태를 재조회하고 `expires_in`을 남은 수명으로 갱신한다.
- [x] 인가 코드/PKCE의 저장 수명과 serialized session에 계정 상한을 적용한다.
  기존 Fosite 수명이 더 짧으면 보존한다. 인가 완료도 정확한 NULL/유한 기한
  snapshot을 같은 복제 쓰기로 검사하며 성공 응답 직전에 다시 확인한다.
- [x] 현재 구현된 OAuth 온라인 소비 경로인 access/refresh introspection,
  UserInfo, ForwardAuth 및 exchange source/actor 검증에 공통 계정 검사를 연결한다.
  기한 변경 후 아직 토큰 자체는 유효하고 worker도 실행되지 않은 상태를 검사한다.
  owner와 `act.sub`가 모두 활성이고 계정 기한 전이어야 하며 machine grant는 별도다.
- [ ] 전체 만료 lifecycle 및 물리적 커밋/응답 지연의 live 장애 검증.
- [x] 시작 즉시 및 주기적 만료 계정 비활성화, 세션/인가 코드/access/refresh/device
  폐기와 durable back-channel enqueue를 동일 Rhiza 쓰기로 처리한다. 보존된
  비밀번호·passkey·프로필·역할은 삭제하지 않으며 다시 활성화해도 기존 세션/토큰은
  복원되지 않는다. 고정 시각·후보 조회 뒤 기한 연장/NULL 변경·동시 worker 검사 포함.
- [x] opt-in 보존 기간 삭제는 기존 guarded deletion/SCIM tombstone을 재사용한다.
  보존 중 비활성 계정도 기존 SCIM 정기 동기화가 `Active=false`로 전달한다.
- [ ] PAM 키 폐기, 전체 재활성화 관리 API 및 원본 전체 lifecycle parity.
- [ ] 만료 자체의 전체 HTTP E2E를 standalone·3-peer·노드 교체·quorum 상실로 검증.

사용자 만료 상한을 외부로 설정하는 API는 위 미완료 경계를 무시한 채 노출하지 않는다.
캡처한 시각을 복제 SQL의 인자로 쓰므로 결정적 재생은 가능하지만, 물리적인 커밋이나
네트워크 전달이 그 시각에 끝났다는 보장은 아니다. 발급 후 기한 단축은 외부 RP의
오프라인 검증 토큰을 즉시 바꿀 수 없으며 온라인 검증/유효기간 한계를 별도 명시해야 한다.

기존 `time`, Rhiza SQL `CHECK`/`MIN`/`COALESCE`/`EXISTS`, identity/browser/OAuth
저장소를 재사용한다. Fosite는 토큰 프로토콜을 제공하지만 이 프로젝트의 사용자 행과
복제 claim/세션/권한 스냅샷을 소유하지 않는다. 따라서 직접 작성한 부분은 동일 배치의
정책 조건과 응답 projection이며, 별도 인증·암호·스케줄링 프레임워크는 추가하지 않았다.

추가 패키지 조사: 설치된 Fosite `v0.49.0`의
[code response flow](https://github.com/ory/fosite/blob/v0.49.0/handler/oauth2/flow_authorize_code_token.go)와
[token helper](https://github.com/ory/fosite/blob/v0.49.0/handler/oauth2/helper.go)를 확인했다.
세션 만료를 서명·저장·`expires_in` 생성에 재사용할 수 있으므로 별도 토큰 구현이나
새 의존성은 불필요하다. 사용자/actor의 Rhiza 상태와 동일 배치 snapshot 조건은
Fosite가 소유하지 않는 애플리케이션 정책이므로 `account_expiry.go`에서 연결한다.
일반 HTTP 검사에는 실제 Fosite·Rhiza·서명 검증을 사용하고, 경계/경쟁 검사는
고정 시각 또는 명시적인 상태 변경으로 구동한다. 만료 전용 live Kubernetes E2E는
아직 체크하지 않는다.

온라인 소비 검사는 현재 Rhiza 사용자 상태를 같은 linearizable query로 확인한다.
경계는 밀리초 `now >= deadline`이며, 최종 응답 전까지 적용한다. ForwardAuth는
프로필 조회 중 기한이 바뀌어도 401과 함께 준비한 identity header를 지운다.
다중/nested actor chain은 아직 지원하지 않으며 단일 `act.sub` 형식만 허용한다.
계정 조회 실패는 fail-closed이고, 읽기 자체는 계정이나 토큰을 삭제하지 않는다.

저장소의 raw access/refresh 조회는 일부러 그대로 둔다. 설치된 Fosite의
[명시적 폐기](https://github.com/ory/fosite/blob/v0.49.0/handler/oauth2/revocation.go)는
같은 getter로 토큰을 찾고, [refresh 처리](https://github.com/ory/fosite/blob/v0.49.0/handler/oauth2/flow_refresh.go)는
`ErrInactiveToken`을 재사용으로 해석한다. 조회 단계에서 계정 만료로 행을 숨기면
명시적 폐기가 무동작으로 끝나거나 만료를 재사용으로 잘못 분류할 수 있다.
따라서 공통 정책 helper를 소비 경계에서 호출하고 기존 폐기/재사용 절차를 유지한다.
만료 후 명시적으로 폐기한 토큰은 기한을 다시 NULL로 바꿔도 살아나지 않는 HTTP
회귀 테스트가 있다. 이를 새로운 token crypto나 storage framework로 대체하지 않는다.

[Fosite 인가 코드 발급](https://github.com/ory/fosite/blob/v0.49.0/handler/oauth2/flow_authorize_code_auth.go)은
자체 시계로 기본 수명을 설정한 다음 sanitized session을 저장소에 넘긴다.
두 저장 callback에서 계정 상한을 적용하므로 PKCE의 별도 clone도 우회하지 않는다.
HTTP 경로 검증과 별도로 고정 시각의 실제 Rhiza 저장 matrix가 NULL/더 짧은 기본
수명/더 짧은 계정 수명 및 JSON/SQL 동일값을 검사한다. 계정 snapshot 경쟁도
고정 hook과 유효한 이웃 요청으로 검증하며 sleep으로 기한 도달을 기다리지 않는다.

#### 만료 worker 운영 계약

`GOAUTHY_USER_EXPIRY_INTERVAL_MINUTES`는 기본 60분, 허용 범위 1–525600분이다.
`GOAUTHY_USER_EXPIRY_DELETE_AFTER_MINUTES`는 미설정 시 삭제하지 않으며, 설정하면
같은 양수 범위를 허용한다. `0`은 비활성화 설정이 아니라 설정 오류다. 기한에
도달하면 비활성화하고, 만료 이후 경과 시간이 삭제 보존 기간을 **초과**해야 삭제한다.
초기 관리자도 만료 예외가 아니다. 기본 설정에서는 계정을 자동 삭제하지 않는다.

원본 [users scheduler](https://github.com/sebadob/rauthy/blob/v0.36.2/src/schedulers/src/users.rs)와
[설정](https://github.com/sebadob/rauthy/blob/v0.36.2/config.toml)의 기본 간격과 삭제
opt-in 계약을 따른다. GoAuthy는 별도 leader lease 대신 모든 HA 멤버가 실행하되
정확한 subject/활성 상태/기한 조건을 모든 SQL에 적용하여 한 작업만 성공시킨다.
이미 비활성화된 계정은 반복 폐기하지 않고 삭제 단계만 검사한다. 이는 원본의
반복 조회와 다른 명시적 구현 방식이다. 세션은 행 삭제 대신 revoked 상태를 보존한다.

한 tick은 비활성화 최대 128건, 삭제 최대 128건이다. 큰 backlog는 다음 tick으로
이월되며 후보 조회는 아직 전용 index 없이 스캔한다. 요청 시 만료 거절과 토큰 수명
상한은 worker 대기 시간과 별개다. SCIM은 기존 5분 주기와 backlog/재시도에 따라
수렴하며 만료 쓰기와 원격 HTTP 완료를 하나의 트랜잭션으로 보장하지 않는다.
발신 back-channel도 기존 outbox 재시도 경로를 사용한다. PAM은 아직 구현하지 않았다.

패키지 선택: `context`, `time.NewTicker`, 기존 Rhiza atomic batch와 삭제/outbox
구현을 재사용한다. 원본의 작업은 cron 표현식이나 별도 분산 스케줄러를 요구하지
않는다. 사용자 스키마와 권한·세션 폐기 순서는 일반 스케줄링 패키지가 소유하지
않으므로 이 정책만 직접 작성한다. 새 dependency나 schema migration은 없다.

### 전체 사용자 관리 매핑

| 책임 | 우선 재사용 | 직접 작성이 필요한 부분 |
|---|---|---|
| HTTP/JSON/검증 | `net/http`, `encoding/json`, 기존 strict JSON·email 검증 | Rauthy 필수/선택/null/빈 값 계약과 권한별 필드 정책 |
| 계정/프로필 | `internal/identity`, 기존 Rhiza 테이블 | 누락 메타데이터 migration, 모든 생성/로그인 경로의 기록, 목록/상세 projection |
| 권한 | `internal/rbac`, `internal/apikey`, `browser.SessionAuthorizationGuard` | 전체 명령에 대한 위임 대상/그룹 정책, 동일 트랜잭션의 세션·키·역할 재검사 |
| 비밀번호/설정 링크 | 기존 `internal/credential`, `identity`, `recovery` | 관리자 명령과 reset/인증 세대/정책 연결 |
| 메일·SCIM·감사 | 기존 go-mail, `internal/scim`, `internal/audit` | 변경과 함께 기록되는 durable 작업 및 재시도/재조정 의미 |
| API 명세 | 기존 kin-openapi와 실제 응답 DTO | 실제 라우트 연결 후 정책별 request/response 검사 |

Go 표준 라이브러리와 이미 설치된 패키지는 HTTP·암호·메일·SQL 기초 기능을 제공한다.
하지만 Rauthy의 계정/위임 정책과 GoAuthy의 Rhiza·인증 세대·SCIM 상태를 한 번에
변경하는 공개 패키지는 위 조사에서 확인되지 않았다. 새 CRUD 프레임워크를 추가하지
않고 기존 저장소의 원자적 명령과 표준 JSON 타입을 연결한다. 이는 새로운 암호 구현을
정당화하는 결정이 아니다.

## 원자적 변경의 구현 조건

독립 Pro 검토는 공개된 요구사항만으로 진행했다. 아래는 그 조언을 실제 로컬 코드와
대조한 구현 조건이며, 기존 코드 전체에 결함이 있다는 판정이 아니다.

- 변경 전의 권위 있는 상태에서 **전체 명령**을 인가한다. 자기 역할/세션 변경 이후
  후속 문장마다 변경 전 관리자 역할을 다시 요구하면 정상 자기 변경이 부분 실패한다.
- 기존 API-key mutation guard는 한 Rhiza 배치 안에서 만들고 제거하는 증표다.
  `RunMutation(nil, ...)`은 브라우저 관리자의 권한을 직접 검증하지 않는다.
  새 브라우저 CRUD는 정확한 세션 가드와 활성 사용자/직접 또는 위임 권한을
  같은 배치에서 조합해야 하며, nil principal을 일반 관리자 승인으로 쓰지 않는다.
- 필수 대상의 0행 변경과 SQL 오류를 구별한다. `storage.Execute`는 Rhiza의 거절
  receipt를 오류로 반환하지만, 0행 SQL을 자동으로 도메인 실패로 만들지는 않는다.
  권한 증표만으로 대상 버전 충돌·최종 관리자·필수 outbox 기록까지 보장되지 않는다.
- 위임 그룹 변경은 비관리 그룹을 보존하고 보호 대상/역할 부여 정책을 재검사한다.
  최종 활성 직접 관리자 보호는 변경 후 상태로 검사한다. 향후 만료의 anti-lockout
  정책은 원본과 명시적으로 대조하며 임의의 동등성을 주장하지 않는다.
- 비밀번호/활성 변경과 인증 상태 전이를 같은 배치로 처리한다. 발급 중이던 로그인도
  검증 당시 세대를 재확인해야 한다. 외부 RP가 서명만 검사하는 토큰까지 즉시 폐기된다고
  주장하지 않는다.
- 외부 호출은 커밋 이후다. 메일은 수신 측 중복 제거 없이 exactly-once를 보장할 수
  없다. Rhiza의 같은 request ID 재시도와 별도 HTTP 요청의 멱등 정책도 구별한다.

## 결정론적 완료 조건

- [x] 실제 Rhiza 저장소에서 API-key 인가 증표의 사전 철회, 같은 명령의 자기 철회,
  후속 변경, 다음 요청 거절, SQL 오류 전체 롤백 검사:
  `internal/apikey/mutation_atomicity_test.go`.
- [ ] 새 사용자 생성/조회/수정의 전체 DTO·필수/선택 값과 페이지 경계.
- [ ] 브라우저 세션·API key 권한·위임 범위를 preflight 이후 변경한 뒤 재개하는 장벽 테스트.
- [ ] 마지막 관리자 동시 변경과 관리/비관리 그룹의 동시 변경.
- [ ] 이전 인증 검증 이후 비밀번호/활성 변경을 커밋하고 발급을 재개하는 테스트.
- [ ] 메일/SCIM/감사 실패 및 응답 유실/동일 명령 재시도의 원자성.
- [ ] 같은 시나리오의 standalone·정확히 3-peer E2E, pod 교체와 quorum 상실.

시간 경계는 주입된 고정 시각으로 이동하고 실행 순서는 채널/장벽/커밋 응답으로
확정한다. readiness polling과 테스트 timeout은 실행 상한이지 정확성 판정이 아니다.

## 패스키 API의 별도 호환성 보정

- [x] 목록은 `name`, `registered`, `last_used`, 선택 `user_verified`를 반환한다.
  시각은 Unix 초 정수이며 빈 목록은 `[]`다. 내부 모델의 `time.Time`을 그대로
  JSON으로 노출하지 않는다. stdlib 변환만 추가하고 WebAuthn 구현은 재사용했다.
- [x] 실제 handler 고정 시각 검사, 실제 `account.PasskeyResponse` 기반 OpenAPI,
  malformed 응답을 거절하는 E2E assertion 회귀 검사.
- [x] 실제 Chrome standalone 및 정확히 3-peer 관리 E2E: 등록/모든 노드 목록,
  읽기 전용 API key 삭제 거절, self MFA 삭제/모든 노드 빈 목록. 재현 명령은
  [패스키 문서](passkey-bootstrap.md), 현재 실행 근거는 [상태 보고서](status.md)에 있다.
- [ ] MFA token 응답의 원본 `ip`, 로그인 시작 `exp` 및 로그인 완료 응답의 원본
  계약을 추가 대조/보정해야 한다. 목록 수정만으로 전체 패스키 wire parity를 선언하지 않는다.


### 로그인 중 프로필 재검증: pinned 원본 경계 (미구현)

v0.36.2 `src/service/src/user_values_validator.rs::does_user_need_update`는
내장 `rauthy` client를 면제하고, 설정이 활성화되면 현재 사용자 값 전체를
기존 validator로 검사한다. `src/service/src/oidc/authorize.rs`는
인증 코드와 인증 세션을 만든 뒤 수정 필요 여부를 MFA·ToS 경로에도 전달한다.
`src/api/src/lib.rs::map_auth_step`는 수정이 필요할 때 Location 없는 HTTP 205를
반환하고, 정상 경로에서만 Location을 전달한다. 따라서 잘못된 비밀번호로
취급하거나 모든 로그인을 403으로 막는 구현은 이 기능의 동등성을 충족하지 않는다.

현재 Go 경계는 `internal/login/handler.go::completeConsumedAuthentication`의
세션 회전 후 `CompleteAuthorizationWithSession` 호출이다. 구현 시에는
기존 세션의 SSO, password/passkey/upstream, 프로필 수정 UI, 안전한 인증 재개,
정책 변경 및 HA 경계를 함께 검증해야 한다. 이 대조는 구현 완료 증거가 아니다.
