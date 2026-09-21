# Global JSON KV

Rauthy v0.36.2의 전역 KV 기능을 Rhiza v0.10.0 SQL schema v55로 구현한다.
별도의 저장 엔진이나 암호화 패키지를 추가하지 않는다. 제품 전체 완료 여부와
실행별 검증 상태는 [진행 현황](status.md)과 [기능표](features.md)를 따른다.

## 접근 경계

초기 `default` 네임스페이스는 비공개다. 관리 API는 기존 관리자 브라우저 세션을
요구하고, 변경 요청은 `X-CSRF-Token`을 검사한다. OAuth 토큰과 일반 API-Key로
관리 권한을 대신할 수 없다. 초기 관리자의 passkey는 선택 사항이다.

KV 접근키는 `Bearer {id}${secret}` 형태이며 정확히 한 네임스페이스에 속한다.
서버가 키에서 네임스페이스를 결정한다. 비활성화·삭제·회전된 키는 다시 사용할 수
없으며, 데이터 변경 시 동일 키의 유효성을 Rhiza 트랜잭션 안에서 다시 검사한다.
관리자는 접근키를 생성·조회·수정·회전·삭제할 수 있다. 접근키의 비밀 값은 DB에
암호화되어 저장되며, 관리자 조회 응답에 포함되므로 응답을 로그로 남기면 안 된다.

`public=true`는 정확한 키를 아는 경우의 단건 읽기만 공개한다. 목록·전체 값·쓰기
권한을 공개하지 않는다. 공개 정책과 값은 하나의 선형화 가능한 읽기로 확인한다.

## API

모든 경로의 접두사는 `/auth/v1/kv`이다.

| 경로 | 메서드 | 권한 |
|---|---|---|
| `/ns` | GET, POST | 브라우저 관리자 |
| `/ns/{ns}` | PUT, DELETE | 브라우저 관리자 |
| `/ns/{ns}/access` | GET, POST | 브라우저 관리자; 생성은 201 |
| `/ns/{ns}/access/{id}` | PUT, DELETE | 브라우저 관리자 |
| `/ns/{ns}/access/{id}/secret` | POST | 브라우저 관리자 |
| `/ns/{ns}/values` | GET, POST, PUT | 브라우저 관리자 |
| `/ns/{ns}/values/{key}` | DELETE | 브라우저 관리자 |
| `/pub/{ns}/{key}` | GET | 공개 네임스페이스 단건 읽기 |
| `/keys` | GET, PUT | 네임스페이스 접근키 |
| `/keys/{key}` | GET, DELETE | 네임스페이스 접근키 |
| `/values` | GET | 네임스페이스 접근키 |
| `/test` | GET | 네임스페이스 접근키 |

네임스페이스 요청은 `{"name":"example","public":false}`, 접근키 요청은
`{"enabled":true,"name":"service"}`, 값 요청은
`{"key":"settings","encrypted":true,"value":{"enabled":true}}` 형태다.
접근키 이름과 `public`은 생략할 수 있다. JSON의 null·boolean·number·string·array·object를
지원한다. 네임스페이스·키·표시 이름은 upstream 문자 규칙과 2–64자 제한을 적용한다.
슬래시를 포함한 이름은 URL의 한 경로 요소로 인코딩한다.

목록 요청은 `limit`·`search`·`cursor`만 허용한다. 기본·최대 목록 크기는 1,000개,
검색어는 64바이트, JSON 요청 본문은 64KiB 이하이다. 검색은 키·값 목록에만 적용되고
네임스페이스·접근키 목록에는 영향을 주지 않는다. 검색은 리터럴 부분 문자열
비교다. 초과 크기·알 수 없는 필드·잘못된 JSON·중복/알 수 없는 쿼리를 거부한다.

네임스페이스·접근키·키·값 목록은 keyset 페이지다. 목록은 항상 200으로 답하고, 다음
페이지가 있으면 `X-Continuation-Token`을 반환한다. 그 값을 다음 요청의 `cursor`로
보내면 마지막 행 바로 뒤에서 이어 읽는다. 토큰은 목록 종류와 위치를 담으므로 다른
목록에 재사용하면 거부된다. 값 목록 페이지는 응답 크기 예산(8MiB)으로도 잘리므로
`limit`보다 적게 돌아올 수 있다.

## 암호화와 장애 일관성

기존 `oidc.Keyring`의 AES-GCM envelope를 재사용한다. 접근키 비밀 값은 접근키 ID,
암호화된 값은 변경 불가능한 네임스페이스 식별자와 키 이름에 묶인다. 이름 변경은
암호화를 깨뜨리지 않고, 다른 행으로 복사한 암호문은 인증에 실패한다.
네임스페이스 삭제는 값과 접근키를 DB 외래키로 함께 삭제한다.

모든 변경은 무작위 요청 ID와 기존 Rhiza 커밋 확인·키 폐기 fence를 사용한다.
암호화된 KV 값과 비활성 접근키까지 키 참조 점검에 포함한다. 기존 정기 작업은
제한된 배치와 정확한 암호문 비교 후 갱신으로 envelope를 새 키로 재암호화한다.
알 수 없는 키나 훼손된 envelope는 키 폐기 판정을 막는다.

## Upstream과 의도적 차이

Rauthy v0.36.2 KV에는 TTL·CAS API가 없다. GoAuthy도 이를 새 기능으로 추가하지
않는다. 공개 scalar를 HTML로 보내는 upstream 방식 대신 항상 JSON과 `nosniff`로
응답해 같은 출처의 스크립트 실행을 방지한다. 모든 값 쓰기에 동일한 검증을 적용하고
요청·목록 크기를 제한한다. [고정 API](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/kv.rs),
[타입](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api_types/src/kv.rs),
[저장 모델](https://github.com/sebadob/rauthy/blob/v0.36.2/src/data/src/entity/kv.rs).

## 실행 가능한 검증

- `go test -count=1 ./internal/kv ./internal/storage ./cmd/goauthy`
- `make e2e-standalone-kv`: 깨끗한 단일 노드와 동일 DB의 프로세스 재시작
- `make e2e-kind-kv`: 정확히 3노드, 노드 간 API 일관성 및 pod 교체

E2E는 시간 경과를 성공 조건으로 쓰지 않는다. 요청 결과, 저장 값, 접근키 상태,
Ready와 변경된 pod UID를 검사한다. 준비 대기는 상한 있는 폴링이다.
