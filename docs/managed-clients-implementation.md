# Managed static clients: partial core

2026-09-06, Rhiza v0.12.0 / schema v65. Bootstrap 설정이나 DCR 등록을
대체하지 않는 명시적 관리자 registry다. 전체 Rauthy client parity가 아니다.

## 구현

- [x] `/auth/v1/clients` GET/POST 및 `/{id}` GET/PUT/DELETE.
- [x] `/{id}/secret` POST 읽기 / PUT 회전. 일반 응답에는 secret이 없고
  별도 Secrets.Read/Update 권한, no-store, 브라우저 CSRF가 필요하다.
- [x] required/unknown/duplicate/null JSON, body 상한, redirect와 scope/grant
  allowlist 검증. update/delete/rotation은 strong If-Match revision을 받는다.
- [x] browser session과 API-key authority를 Rhiza 쓰기 조건에 포함한다.
- [x] Bootstrap ID를 내구적으로 예약하고 managed/DCR ID 충돌을 DB trigger로
  막는다. 삭제는 tombstone으로 남겨 같은 ID가 다른 클라이언트로 재사용되지 않는다.
- [x] secret bcrypt hash와 keyring 암호문을 함께 저장하고 master-key rewrap,
  status/retirement 참조 집계에 포함한다. AAD는 ID와 generation digest에 바인딩한다.
- [x] OAuth client resolution, code/PKCE/access/refresh commit 조건 및
  요청 내 인증 snapshot 보존. metadata 변경은 기존 code/refresh를 보존하고,
  disable 또는 public/confidential 전환은 generation을 바꾼다.
- [x] standalone 실제 HTTP CRUD, confidential client-credentials, disable/
  re-enable, secret rotation, stale update/delete 거절, ID 재사용 금지 통과.
- [x] exact-three HA 교차 Pod HTTP 및 goauthy-0 UID 교체·3 Pod Ready 후
  재실행 통과: 2.57/1.98초, `/tmp/goauthy-device-pilot-ha-final-20260906.log`.

지원되는 흐름은 authorization_code, refresh_token, confidential
client_credentials 및 managed Device Grant다. 지원 scope는
openid/email/profile/groups/offline_access/goauthy.read다. Device 경로의
openid/groups/custom user claims 제한은 그대로다. 상세 field 계약은 생성된
OpenAPI의 managed-client 경로를 따른다. 지원하지 않는 Rauthy 입력은 무시하지
않고 strict decoder에서 거절한다.

## 초기 사용 경로 연결 (schema v65)

- [x] 관리자 `/auth/v1/admin/clients` 목록·생성·편집·비활성화·삭제 및
  명시적 secret 읽기/숨기기/회전. public Web + PKCE와 Device 혼합 정책도 보존한다.
- [x] 생성 시 선택적인 scopes/default_scopes/enabled_flows를 원자적으로 저장한다.
  생략한 각 항목은 기존 기본값을 유지한다. authorization_code에는 callback이
  필요하고, 나머지 흐름에서는 빈 배열이 가능하다. 제공된 callback은 항상 검증한다.
- [x] Device 생성 시 인증된 ID/revision/generation과 현재 정책을 같은 쓰기에서
  비교한다. grant에는 generation을 보존해 비활성화·인증 유형 변경으로 폐기한다.
  일반 metadata revision 변경은 이미 발급한 grant를 폐기하지 않는다.
- [x] 회전 응답의 secret 재조회는 회전 결과 revision에 묶는다. 경쟁 회전 뒤
  더 최신 secret을 이전 ETag와 섞어 반환하지 않고 충돌로 거절한다.
- [x] 실제 Chromium UI → public Device 승인 → access/refresh → 비활성화와
  confidential secret 회전을 standalone 및 동일 DB 재시작 후 검증했다.
  `/tmp/goauthy-managed-device-ui-standalone-retry-20260906.log`, 종료 0.
  관리 HTTP 1.96/1.73초, 관리 UI 8.17/4.93초. 기존 public/confidential Device도 통과했다.
- [ ] 이 후보의 exact-three UI 및 동일 managed pending grant Pod 교체 최종 검증.

기존 Fosite의 client 인증/토큰 처리를 재사용하고 새 패키지는 추가하지 않았다.
프로젝트별 managed registry와 Rhiza 트랜잭션의 정책 snapshot/generation 연결은
일반 OAuth 패키지가 알 수 없는 저장소·권한 계약이므로 기존 adapter에 구현했다.
관리 UI는 기존 API/CSRF helper와 표준 DOM/form을 사용한다.
첫 standalone 실행은 retained callback을 잘못 거절하는 정책 회귀와 navigation 중
브라우저 polling 오류로 실패했다. 해당 실패 로그를 통과 증거로 세지 않는다.

## 남은 것

- 전체 Rauthy policy fields, algorithms/lifetimes,
  forced MFA, resources/claims/theme/SCIM/back-channel.
- secret grace period 및 전체 rotation parity.
- secret rotation과 token authentication이 경합하는 실제 HTTP/HA 증거,
  rewrap 경합, mixed-version upgrade.
- 사용자 소유 컬렉션의 scoped bearer API 및 기기별 목록/개별 철회는 별도 후속 작업이다.

단위 수준의 실제 DB/HTTP 검증은 `internal/clients/store_test.go`,
`internal/rbac/clients_http_test.go`, `internal/oauth/managed_client_http_test.go`,
`internal/oauth/managed_clients_test.go` 및 oidc envelope 검사가 담당한다.
새 live E2E는 `test/e2e/managed_clients_test.go`다. skip된 검사는 통과가 아니다.
