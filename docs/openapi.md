# OpenAPI / Swagger UI

## 노출 정책

- `GOAUTHY_SWAGGER_UI_ENABLE=false`가 기본값이다. 비활성 상태에서는 UI, 명세,
  JS/CSS 모두 제공하지 않는다.
- 활성화 후에도 `GOAUTHY_SWAGGER_UI_PUBLIC=false`가 기본이다. 기존 브라우저
  관리자 검사로 활성 세션과 `rauthy_admin`을 확인하며 Init 세션, API-Key,
  OAuth Bearer, cross-site 요청은 대체 인증으로 사용하지 않는다.
- `GOAUTHY_SWAGGER_UI_PUBLIC=true`는 명시적인 공개 설정이다. 이 값만으로
  문서를 활성화하지는 않는다. API 자체의 인증 정책도 바꾸지 않는다.
- UI: `<issuer>/auth/v1/docs/`, JSON: `<issuer>/auth/v1/docs/openapi.json`.
  issuer의 경로 prefix는 기존 애플리케이션 미들웨어가 처리한다.
- 모든 UI/명세/asset 응답은 `no-store`·`nosniff`·프레임 차단을 적용한다.
  CDN, Petstore, 외부 validator, 원격 URL/query 설정은 사용하지 않는다.
  Swagger의 요청 실행 버튼은 비활성이다. 쿠키 기반 CSRF 동작을 UI에서 우회하지 않는다.

## 구현·패키지 매핑

| 기능 | 구현 |
| --- | --- |
| HTTP 라우팅·설정·응답·정적 파일 | 표준 `net/http`, `strconv`, `encoding/json`, `io/fs` |
| OpenAPI 3.0.3 모델·참조 해석·검증 | `github.com/getkin/kin-openapi v0.149.0` |
| 공개 Go JSON 타입의 스키마 생성 | 같은 패키지의 `openapi3gen` (`apikey`, `kv`, registration, FedCM, 기존 `go-webauthn` options/credential wire types) |
| 바이너리에 내장된 Swagger UI | `github.com/swaggo/files/v2 v2.0.2` (MIT) |
| 관리자 권한 | 기존 `browserAdministrator`, Rhiza 세션·사용자·역할 저장소 재사용 |
| 브라우저 검증 | 기존 `chromedp` 및 HTTP E2E 도우미 재사용 |

Go 표준 라이브러리에는 OpenAPI 검증기나 Swagger UI 배포물이 없다. 이미 사용하는
Fosite는 OAuth 프로토콜을 제공하지만 관리·계정 API 문서를 생성하지 않는다.
따라서 검증기와 UI는 공개 패키지를 사용하고, **현재 핸들러의 요청·응답·권한과
운영 feature switch를 연결하는 명세만 직접 작성**했다. `http-swagger`의 별도
전역 Swag 등록/Swagger 2 생성 계층은 추가하지 않았다. 참고:
[kin-openapi](https://github.com/getkin/kin-openapi/releases/tag/v0.149.0),
[embedded UI](https://github.com/swaggo/files/blob/v2.0.2/files.go),
[Rauthy 노출 정책](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/swagger_ui.rs),
[Rauthy 명세 등록](https://github.com/sebadob/rauthy/blob/v0.36.2/src/api/src/openapi.rs).

## 계약의 범위와 검증

문서는 Rauthy에 있지만 아직 포팅하지 않은 기능을 지원한다고 광고하지 않는다.
DCR·passkey·recovery·registration·blacklist·WebID·FedCM·upstream의 선택적 경로는
실제 서버 설정과 연결한다. 표준 loader는 로컬 참조만 해석하고 startup 시 명세를
검증한다. 같은 설정의 명세는 같은 바이트열로 생성한다.

`TestOpenAPIRouteCoverage`는 production 라우트의 operation 누락을 검사한다.
root-only health/별도 metrics listener/문서 asset은 issuer API와 분리한다.
**라우트 커버리지는 모든 세부 schema/분기 계약의 완전성을 증명하지 않는다.**
FedCM의 실제 HTTP 응답, 키 폐기 barrier의 실제 JSON 변환, WebAuthn options의
공개 타입 직렬화를 명세와 대조하는 결정론적 회귀 검사를 추가했다. 로그인 경로가
공유될 때 일반 OAuth 폼과 `fedcm=1`의 CSRF 포함 폼을 구분하고, FedCM 전용 세션
쿠키를 일반 브라우저 쿠키와 구별한다. 키 폐기 작업의 prepare/epoch-only 요청도
분리한다. 다만 외부 provider 및 관리 API의 모든 세부 응답과 정책별 오류/제약의
엄밀한 wire-schema 대조는 별도 남은 작업이다. 이에 따라
기능표 전체 OpenAPI 항목은 아직 완료로 체크하지 않는다.

검증 명령:

```sh
go test ./internal/apidocs ./cmd/goauthy -run 'TestDocument|TestSwagger|TestOpenAPI|TestDocs|Test.*Catalog'
make e2e-standalone-openapi
make e2e-kind-openapi
```

실제 브라우저 E2E는 DOM의 operation 렌더링 완료를 기다리고 원격 HTTP 요청이
없는지 검사한다. 내장 CSS의 `data:image` 아이콘은 외부 네트워크가 아니다.
standalone은 비활성→private→동일 DB 재시작→public을, HA는 private→pod 교체→
public rollout→disabled rollout을 검사한다. 저장한 동일 세션을 사용하고,
별도 쿠키 jar의 폐기 전 토큰으로 로그아웃 후 거절을 확인한다. 시간 대기는
성공 판정이 아니라 readiness/DOM 조건을 확인하는 제한된 polling에만 사용한다.
