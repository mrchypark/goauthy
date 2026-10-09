# GoAuthy API·UI 전체 인벤토리

기준일: 2026-09-26. 기준: `feature/authentication-ui-scenarios`, HEAD `ea830e24` + 현재 미커밋 UI/브랜드 변경. **릴리즈된 main만의 목록이 아니라 현재 로컬 구현의 목록**이다.

실제 `cmd/goauthy` 라우터, KV/UI 하위 라우터, OpenAPI 카탈로그를 대조했다. 선택 기능까지 합친 코드 수준의 목록이며, 모든 경로가 현재 localhost 배포에서 활성화되었다는 뜻은 아니다. 이번 점검은 코드 기반 인벤토리이며 모든 변경 API를 실제 실행하지 않았다.

- `{subject}`, `{id}` 등은 경로 변수다. `/auth/v1`는 경로 일부이며, issuer에 하위 경로가 있으면 그 앞에 배포 prefix가 붙는다. `/livez`, `/readyz`는 health 우회 경로이며 `/metrics`는 별도 리스너다.
- GET/POST/PUT/PATCH/DELETE를 각각 표시했다. 일반 Go GET 등록의 HEAD 대응은 개별 핸들러가 거부할 수 있어 일괄 보장하지 않는다. Swagger의 명시적 HEAD만 별도 기재했다.
- 아래 인증 열은 문서의 인증 방식 요약이다. 관리자 역할, 위임 범위, API 키 세부 권한, OAuth audience·scope·proof, CSRF 등 추가 검증은 실제 핸들러가 수행한다. 브라우저 세션이 있다는 것만으로 관리자 권한이 생기지 않는다.
- ¹ `공개/프로토콜별 검증`은 무조건 익명 호출 가능하다는 뜻이 아니다. OAuth 클라이언트 인증, 일회성 interaction·복구 코드·PoW, Origin, FedCM 헤더 등 각 프로토콜 조건이 적용된다.
- 가입·복구, API 응답, HTML 화면, 정적 자산을 혼동하지 않도록 모두 표시했다. 아래 UI 상세 목록에는 별도 URL 없는 패널과 상태 화면도 포함한다.

## API·HTML·정적 자산 경로

## 01. 서비스·운영·발견



| 경로 | 메서드 | 설명 | 인증 방식(메서드별) | 활성 조건 |
|---|---|---|---|---|
| `/` | GET | 서비스 식별 문자열 GoAuthy 반환. 홈페이지 UI는 아님 | GET: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/.well-known/oauth-authorization-server` | GET | OAuth 서버 메타데이터 | GET: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/.well-known/openid-configuration` | GET | OIDC 제공자 메타데이터 | GET: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/livez` | GET | 프로세스 생존 확인. 정상 204 | GET: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/metrics` | GET | 별도 선택적 metrics 리스너의 관측 지표. 설정된 인증 토큰 정책 적용 | GET: 공개/프로토콜별 검증¹ | metrics 활성; 서비스 URL과 리스너가 다를 수 있음 |
| `/readyz` | GET | DB와 런타임 준비 상태 확인 | GET: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |

## 02. OAuth·OIDC·기기 인증

클라이언트가 GoAuthy를 인증 서버로 사용할 때의 표준 프로토콜이다. `/oidc/authorize`는 적절한 client_id·redirect_uri 등 요청 문맥이 필요하다.

| 경로 | 메서드 | 설명 | 인증 방식(메서드별) | 활성 조건 |
|---|---|---|---|---|
| `/oidc/authorize` | GET | OAuth/OIDC 인가 요청. 로그인·MFA·프로필 보완 또는 리다이렉트 | GET: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/oidc/device` | POST | 기기 인증 grant 생성 | POST: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/oidc/device/login` | GET, POST | 기기 승인 전 로그인 화면(GET), 로그인(POST). 로그인 자체로 승인하지 않음 | GET: 공개/프로토콜별 검증¹<br>POST: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/oidc/device/verify` | GET, POST | 기기 코드 입력·요청 검토(GET), 승인·거부(POST) | GET: 공개/프로토콜별 검증¹<br>POST: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/oidc/forward_auth` | GET | 리버스 프록시의 Bearer 접근 검증 | GET: OAuth Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/oidc/introspect` | POST | 토큰 유효성·메타데이터 확인 | POST: clientBasic 또는 공개 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/oidc/jwks.json` | GET | 서명 검증용 공개키 집합 | GET: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/oidc/logout` | GET, POST | OIDC 로그아웃 확인(GET), 확인 제출(POST) | GET: 공개/프로토콜별 검증¹<br>POST: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/oidc/register` | POST | 동적 OAuth 클라이언트 등록(DCR) | POST: registrationAdminBearer | DCR 활성 |
| `/oidc/register/{id}` | GET, PUT, DELETE | 동적 등록 클라이언트 조회(GET), 교체(PUT), 삭제(DELETE) | GET: registrationBearer<br>PUT: registrationBearer<br>DELETE: registrationBearer | DCR 활성 |
| `/oidc/revoke` | POST | 토큰 회수 | POST: clientBasic 또는 공개 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/oidc/token` | POST | 인가 코드·refresh·client credentials·기기 grant·token exchange 등 토큰 발급 | POST: clientBasic 또는 공개 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/oidc/userinfo` | GET, POST | Bearer 토큰에 대응하는 사용자 클레임 | GET: OAuth Bearer<br>POST: OAuth Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |

## 03. 로그인·가입·복구·사용자

로그인·가입·계정 생명주기를 처리한다. 관리자 사용자 관리와 본인 전용 경로는 권한이 다르다. 공개 패스키 가입은 경로가 있어도 완성된 가입 여정으로 계산하면 안 된다.

| 경로 | 메서드 | 설명 | 인증 방식(메서드별) | 활성 조건 |
|---|---|---|---|---|
| `/auth/login` | GET, POST | OAuth 로그인 폼 제출. FedCM 설정에 따라 GET 로그인 화면도 추가됨 | GET: 공개/프로토콜별 검증¹<br>POST: 공개/프로토콜별 검증¹ | POST 기본; GET은 FedCM landing으로 선택 시 |
| `/auth/profile` | GET, POST | 필수 프로필 보완 화면(GET)과 저장(POST) | GET: 브라우저 세션<br>POST: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/pow` | POST | 가입·복구용 작업 증명(PoW) challenge 발급 | POST: 공개/프로토콜별 검증¹ | 복구 서비스 구성 |
| `/auth/v1/register/passkey/finish` | POST, OPTIONS | 공개 패스키 가입 완료 계약 및 CORS. 현재 가입 시작이 차단되어 정상 여정 불가 | POST: 공개/프로토콜별 검증¹<br>OPTIONS: 공개/프로토콜별 검증¹ | 복구+공개 가입+패스키 가입+패스키; 시작 현재 거부 |
| `/auth/v1/register/passkey/start` | POST, OPTIONS | 공개 패스키 가입 시작 계약 및 CORS. 현재 구현은 가입 예약 전에 안전하게 거부 | POST: 공개/프로토콜별 검증¹<br>OPTIONS: 공개/프로토콜별 검증¹ | 복구+공개 가입+패스키 가입+패스키; 시작 현재 거부 |
| `/auth/v1/users` | GET, POST | 사용자 목록(GET), 관리자 사용자 생성(POST) | GET: 브라우저 세션 또는 권한 API 키<br>POST: 브라우저 세션 + CSRF 또는 권한 API 키 | GET 상시; POST 복구 서비스 필요 |
| `/auth/v1/users/otp/verify` | POST | 로그인 OTP 검증 | POST: 공개/프로토콜별 검증¹ | OTP 핸들러 구성 |
| `/auth/v1/users/password_reset` | GET | 비밀번호 복구 요청 HTML | GET: 공개/프로토콜별 검증¹ | 복구 서비스 구성 |
| `/auth/v1/users/recovery.js` | GET | 복구·가입 화면 공통 스크립트 | GET: 공개/프로토콜별 검증¹ | 복구 서비스 구성 |
| `/auth/v1/users/register` | GET, POST, OPTIONS | 가입 화면(GET), 가입 요청(POST), CORS 사전 확인(OPTIONS) | GET: 공개/프로토콜별 검증¹<br>POST: 공개/프로토콜별 검증¹<br>OPTIONS: 공개/프로토콜별 검증¹ | 복구+공개 가입 활성 |
| `/auth/v1/users/request_reset` | POST | 비밀번호 재설정 이메일 요청 | POST: 공개/프로토콜별 검증¹ | 복구 서비스 구성 |
| `/auth/v1/users/values_config` | GET | 프로필 필드의 필수 여부·표시 설정. 공개 가입 시 공개 | GET: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/users/webauthn_finish` | POST | 로그인 패스키 검증 완료 | POST: 공개/프로토콜별 검증¹ | 패스키 서비스 활성 |
| `/auth/v1/users/webauthn_start` | POST | 로그인 패스키 challenge 시작 | POST: 공개/프로토콜별 검증¹ | 패스키 서비스 활성 |
| `/auth/v1/users/{subject}` | GET, PUT, PATCH, DELETE | 사용자 상세(GET), 전체 수정(PUT), 역할·그룹만 수정(PATCH), 삭제(DELETE) | GET: 브라우저 세션 또는 권한 API 키<br>PUT: 브라우저 세션 + CSRF 또는 권한 API 키<br>PATCH: 브라우저 세션 + CSRF 또는 권한 API 키<br>DELETE: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/users/{subject}/attr` | GET, PUT | 사용자 속성 값 조회(GET), 저장(PUT). 본인은 편집 허용 속성만 가능 | GET: 브라우저 세션 또는 권한 API 키<br>PUT: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/users/{subject}/attr/editable` | GET | 본인의 편집 가능한 속성 조회. 관리자 대리 조회 불가 | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/users/{subject}/convert_password` | POST | 관리자 비밀번호 계정 전환 | POST: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/users/{subject}/mfa_token` | POST | 계정 보안 변경용 MFA 토큰 발급 | POST: 브라우저 세션 + CSRF | 패스키 서비스 활성 |
| `/auth/v1/users/{subject}/reset` | PUT | 비밀번호 재설정 완료 | PUT: 공개/프로토콜별 검증¹ | 복구 서비스 구성 |
| `/auth/v1/users/{subject}/reset/{token}` | GET | 재설정 링크 HTML 또는 명시적 JSON bootstrap. HTML GET은 토큰을 소비하지 않음 | GET: 공개/프로토콜별 검증¹ | 복구 서비스 구성 |
| `/auth/v1/users/{subject}/revoke/{code}` | GET | 이메일 코드로 의심 로그인 회수. 단순 조회로 취급하면 안 됨 | GET: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/users/{subject}/self` | PUT | 본인 비밀번호 변경 | PUT: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/users/{subject}/self/convert_passkey` | POST | 본인 계정을 패스키 전용으로 전환 | POST: 브라우저 세션 + CSRF | 패스키 서비스 활성 |
| `/auth/v1/users/{subject}/self/delete` | GET, DELETE | 본인 탈퇴 준비 정보(GET), 탈퇴 실행(DELETE). HTML 페이지 아님 | GET: 브라우저 세션<br>DELETE: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/users/{subject}/self/preferred_username` | PUT | 선호 사용자 이름 설정. 불변성·강제 덮어쓰기 권한 규칙 적용 | PUT: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/users/{subject}/webauthn` | GET | 등록 패스키 목록 | GET: 브라우저 세션 또는 권한 API 키 | 패스키 서비스 활성 |
| `/auth/v1/users/{subject}/webauthn/admin_register` | POST | 관리자 패스키 등록 시작 작업 | POST: 브라우저 세션 + CSRF | 상시 마운트; 정책·패스키 구성 검증 |
| `/auth/v1/users/{subject}/webauthn/auth/finish` | POST | 계정 변경용 패스키 MFA 검증 완료 | POST: 브라우저 세션 + CSRF | 패스키 서비스 활성 |
| `/auth/v1/users/{subject}/webauthn/auth/start` | POST | 계정 변경용 패스키 MFA challenge 시작 | POST: 브라우저 세션 + CSRF | 패스키 서비스 활성 |
| `/auth/v1/users/{subject}/webauthn/delete/{name}` | DELETE | 패스키 삭제 | DELETE: 브라우저 세션 + CSRF | 패스키 서비스 활성 |
| `/auth/v1/users/{subject}/webauthn/register/finish` | POST | 패스키 등록 완료 | POST: 브라우저 세션 + CSRF | 패스키 서비스 활성 |
| `/auth/v1/users/{subject}/webauthn/register/start` | POST | 패스키 등록 시작 | POST: 브라우저 세션 + CSRF | 패스키 서비스 활성 |
| `/auth/{subject}/profile` | GET | WebID 프로필. 일반 계정 설정 화면 아님 | GET: 공개/프로토콜별 검증¹ | WebID 활성 |

## 04. 본인 계정·연결·기기

브라우저에서 로그인한 본인의 데이터를 다루는 영역이다. `/account` 안의 여러 패널이 이 API들을 사용한다.

| 경로 | 메서드 | 설명 | 인증 방식(메서드별) | 활성 조건 |
|---|---|---|---|---|
| `/account` | GET | 본인 계정 대시보드 HTML | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/account/login` | GET, POST | 독립 로그인 후 `/`에서 권한별 화면 이동 | 세션·CSRF·MFA 정책 적용 | 임의 복귀 URL을 받지 않음 |
| `/account/locale.js` | GET | 계정 화면 영어·한국어 문구 | 브라우저 세션 | UI 언어와 이메일 언어는 별도 |
| `/account/account.css` | GET | 계정 화면 스타일 | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/account/app.js` | GET | 계정 기본 화면 동작 | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/account/connection-grants.js` | GET | 연결 사용 권한 관리 스크립트 | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/account/connection-handoffs/{handoff_id}` | GET, POST | 외부 앱의 연결 요청 검토 화면(GET), 명시적 처리(POST) | GET: 공개/프로토콜별 검증¹<br>POST: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/account/connection-login` | GET, POST | 연결 요청을 검토하기 전 로그인 화면(GET), 로그인 처리(POST) | GET: 공개/프로토콜별 검증¹<br>POST: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/account/connections.js` | GET | 연결 관리 스크립트 | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/account/data` | GET | 본인 프로필과 CSRF 토큰 JSON. Authorization 헤더는 거부 | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/account/devices.js` | GET | 기기 관리 스크립트 | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/account/password` | GET | 비밀번호 정책과 CSRF 토큰 JSON. 독립 HTML 화면 아님 | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/account/auth-collections` | GET | 본인 연결 생성에 사용할 인증 컬렉션 목록 | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/account/connection-handoffs/{handoff_id}` | GET, POST | 본인 연결 요청 검토 데이터(GET), 승인 등 처리(POST) | GET: 브라우저 세션<br>POST: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/account/connections/{collection_id}` | GET, POST | 본인 연결 목록(GET), 연결 초안 생성(POST) | GET: 브라우저 세션<br>POST: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/account/connections/{collection_id}/{connection_id}` | GET, PUT, DELETE | 본인 연결 조회(GET), 교체 수정(PUT), 삭제(DELETE) | GET: 브라우저 세션<br>PUT: 브라우저 세션 + CSRF<br>DELETE: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/account/connections/{collection_id}/{connection_id}/api-key` | GET, PUT, DELETE | 연결 API 키 상태 조회(GET), 저장(PUT), 제거(DELETE) | GET: 브라우저 세션<br>PUT: 브라우저 세션 + CSRF<br>DELETE: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/account/connections/{collection_id}/{connection_id}/api-key/connector` | GET | 연결 API 키 커넥터 검토 정보 | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/account/connections/{collection_id}/{connection_id}/grants` | GET, POST | 연결 사용 권한 목록(GET), 권한 생성(POST) | GET: 브라우저 세션<br>POST: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/account/connections/{collection_id}/{connection_id}/grants/{grant_id}` | DELETE | 연결 사용 권한 회수 | DELETE: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/account/connections/{collection_id}/{connection_id}/oauth2` | GET, POST, DELETE | 외부 OAuth 연결 시작(POST), 상태(GET), 해제(DELETE) | GET: 브라우저 세션<br>POST: 브라우저 세션 + CSRF<br>DELETE: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/account/connections/{collection_id}/{connection_id}/oauth2/reconnect` | POST | 외부 OAuth 다시 연결 | POST: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/account/connections/{collection_id}/{connection_id}/oauth2/refresh` | POST | 외부 OAuth 자격 증명 갱신 | POST: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/account/devices` | GET | 본인 승인 기기 목록 | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/account/devices/{id}` | DELETE | 본인 기기 권한 회수 | DELETE: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |

## 05. 관리자 UI 보조 경로

실제 관리 화면 경로는 뒤의 UI 표에 별도로 전부 나열했다. 이 표의 csrf·email-templates는 콘솔 보조 API다.

| 경로 | 메서드 | 설명 | 인증 방식(메서드별) | 활성 조건 |
|---|---|---|---|---|
| `/auth/v1/admin` | GET | 인증된 관리자를 콘솔 대시보드로 303 이동 | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/admin/admin.css` | GET | 관리 콘솔 CSS | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/admin/app.js` | GET | 관리 콘솔 모듈을 합쳐 제공하는 JavaScript | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/admin/csrf` | GET | 관리 UI에서 사용할 세션 귀속 CSRF 토큰 | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/admin/email-templates` | GET | 이메일 템플릿 종류와 지원 언어 목록 JSON | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/admin/email-templates/preview` | GET | type·lang 쿼리로 이메일 샘플 HTML 미리보기 | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |

## 06. 역할·그룹·클레임



| 경로 | 메서드 | 설명 | 인증 방식(메서드별) | 활성 조건 |
|---|---|---|---|---|
| `/auth/v1/groups` | GET, POST | 그룹 목록(GET), 생성(POST) | GET: 브라우저 세션 또는 권한 API 키<br>POST: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/groups/{id}` | PUT, DELETE | 그룹 수정(PUT), 삭제(DELETE) | PUT: 브라우저 세션 + CSRF 또는 권한 API 키<br>DELETE: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/roles` | GET, POST | 역할 목록(GET), 생성(POST) | GET: 브라우저 세션 또는 권한 API 키<br>POST: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/roles/{id}` | PUT, DELETE | 역할 수정(PUT), 삭제(DELETE) | PUT: 브라우저 세션 + CSRF 또는 권한 API 키<br>DELETE: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/scopes` | GET, POST | 클레임 scope 정의 목록(GET), 생성(POST) | GET: 브라우저 세션 또는 권한 API 키<br>POST: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/scopes/{id}` | PUT, DELETE | 클레임 scope 정의 수정(PUT), 삭제(DELETE) | PUT: 브라우저 세션 + CSRF 또는 권한 API 키<br>DELETE: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/users/attr` | GET, POST | 사용자 속성 정의 목록(GET), 생성(POST) | GET: 브라우저 세션 또는 권한 API 키<br>POST: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/users/attr/{name}` | PUT, DELETE | 사용자 속성 정의 수정(PUT), 삭제(DELETE) | PUT: 브라우저 세션 + CSRF 또는 권한 API 키<br>DELETE: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |

## 07. OAuth 클라이언트 관리



| 경로 | 메서드 | 설명 | 인증 방식(메서드별) | 활성 조건 |
|---|---|---|---|---|
| `/auth/v1/clients` | GET, POST | 관리형 OAuth 클라이언트 목록(GET), 생성(POST) | GET: 브라우저 세션 또는 권한 API 키<br>POST: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/clients/{id}` | GET, PUT, DELETE | 관리형 클라이언트 조회(GET), 설정 교체(PUT), 삭제(DELETE) | GET: 브라우저 세션 또는 권한 API 키<br>PUT: 브라우저 세션 + CSRF 또는 권한 API 키<br>DELETE: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/clients/{id}/claims` | GET, PUT | 부트스트랩 클라이언트의 client_credentials 클레임 조회·수정 | GET: 브라우저 세션 또는 권한 API 키<br>PUT: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/clients/{id}/favicon` | GET, PUT, DELETE | 클라이언트 파비콘 조회(GET), 업로드(PUT), 삭제(DELETE) | GET: 공개/프로토콜별 검증¹<br>PUT: 브라우저 세션 + CSRF 또는 권한 API 키<br>DELETE: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/clients/{id}/login-restriction` | GET, PUT | 부트스트랩 클라이언트 로그인 제한 조회·수정 | GET: 브라우저 세션 또는 권한 API 키<br>PUT: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/clients/{id}/logo` | GET, PUT, DELETE | 클라이언트 로고 조회(GET), 업로드(PUT), 삭제(DELETE) | GET: 공개/프로토콜별 검증¹<br>PUT: 브라우저 세션 + CSRF 또는 권한 API 키<br>DELETE: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/clients/{id}/scopes` | GET, PUT | 부트스트랩 클라이언트 scope 조회·수정 | GET: 브라우저 세션 또는 권한 API 키<br>PUT: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/clients/{id}/secret` | POST, PUT | 관리형 클라이언트 비밀 조회(POST), 비밀 교체(PUT) | POST: 브라우저 세션 + CSRF 또는 권한 API 키<br>PUT: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |

## 08. 외부 로그인 제공자

GoAuthy에 로그인하기 위한 외부 IdP 설정이다. 09번의 외부 SaaS 자격 증명 연결과 목적이 다르다.

| 경로 | 메서드 | 설명 | 인증 방식(메서드별) | 활성 조건 |
|---|---|---|---|---|
| `/auth/v1/providers` | POST | 외부 로그인 제공자 전체 목록 조회. 관리자용 응답에는 client_secret 포함 | POST: 브라우저 세션 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/providers/create` | POST | 외부 로그인 제공자 생성 | POST: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/providers/minimal` | GET | 로그인 선택용 활성 제공자의 id·name·updated 공개 목록 | GET: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/providers/{id}` | PUT, DELETE | 외부 로그인 제공자 설정 수정(PUT), 삭제(DELETE) | PUT: 브라우저 세션 + CSRF 또는 권한 API 키<br>DELETE: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/providers/{id}/delete_safe` | GET | 외부 제공자 삭제 전 연결 사용자 확인. 연결 사용자가 있으면 406 | GET: 브라우저 세션 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/providers/{id}/img` | GET, PUT, DELETE | 제공자 로고 공개 조회(GET), 권한 검증 후 업로드(PUT)·삭제(DELETE) | GET: 공개/프로토콜별 검증¹<br>PUT: 공개/프로토콜별 검증¹<br>DELETE: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/providers/{providerID}/link` | POST, DELETE | 본인 계정에 외부 로그인 제공자 연결(POST), 해제(DELETE) | POST: 브라우저 세션 + CSRF<br>DELETE: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/upstream/{providerID}/backchannel-logout` | POST | 외부 로그인 제공자의 서명된 로그아웃 통지 수신 | POST: 공개/프로토콜별 검증¹ | 동적 경로 등록; 해당 provider 구성 필요 |
| `/upstream/{providerID}/callback` | GET | 외부 로그인 제공자 인증 콜백 | GET: 공개/프로토콜별 검증¹ | 동적 경로 등록; 해당 provider 구성 필요 |
| `/upstream/{providerID}/start` | GET | 외부 로그인 제공자 인증 시작 | GET: 공개/프로토콜별 검증¹ | 동적 경로 등록; 해당 provider 구성 필요 |

## 09. 인증 컬렉션·SaaS·연결 위임

외부 서비스 연결을 보관하고 앱에 사용 권한을 부여한다. `/account/...` 브라우저 전용 API, `/connections/...` 사용자 Bearer API, `/connection-grants/...` 실행 API를 구분해야 한다.

| 경로 | 메서드 | 설명 | 인증 방식(메서드별) | 활성 조건 |
|---|---|---|---|---|
| `/auth/v1/auth-collections` | GET, POST | 인증 컬렉션 정의 목록(GET), 생성(POST) | GET: 브라우저 세션<br>POST: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/auth-collections/{collection_id}` | GET, PUT, DELETE | 인증 컬렉션 정의 조회(GET), 교체(PUT), 삭제(DELETE) | GET: 브라우저 세션<br>PUT: 브라우저 세션 + CSRF<br>DELETE: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/connection-collections` | GET | 사용자 Bearer 토큰으로 접근 가능한 연결 컬렉션 목록 | GET: OAuth Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/connection-grants/{grant_id}/credential` | POST | 권한에 따라 외부 서비스 자격 증명 전달 | POST: OAuth Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/connection-grants/{grant_id}/credential-status` | GET | 위임된 자격 증명 상태 | GET: OAuth Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/connection-grants/{grant_id}/invoke` | POST | 연결 권한을 사용해 허용된 외부 요청 수행 | POST: OAuth Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/connection-grants/{grant_id}/refresh` | POST | 위임된 외부 자격 증명 갱신 | POST: OAuth Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/connection-handoffs` | POST | 브라우저에서 사용자가 검토할 연결 요청 생성 | POST: OAuth Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/connections/{collection_id}` | GET, POST | 사용자 Bearer 토큰 기반 연결 목록(GET), 생성(POST) | GET: OAuth Bearer<br>POST: OAuth Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/connections/{collection_id}/{connection_id}` | GET, PUT, DELETE | 사용자 Bearer 토큰 기반 연결 조회·수정·삭제 | GET: OAuth Bearer<br>PUT: OAuth Bearer<br>DELETE: OAuth Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/connections/{collection_id}/{connection_id}/grants/{grant_id}` | GET | 연결 사용 권한 상태 조회 | GET: OAuth Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/saas/callback/{provider_id}` | GET | 외부 SaaS OAuth 콜백 처리 | GET: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/saas/providers` | GET, POST | 외부 SaaS 연결 제공자 목록(GET), 생성(POST) | GET: 브라우저 세션 또는 OAuth Bearer<br>POST: 브라우저 세션 + CSRF 또는 OAuth Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/saas/providers/{provider_id}` | GET, PUT, DELETE | 외부 SaaS 연결 제공자 조회·수정·삭제 | GET: 브라우저 세션 또는 OAuth Bearer<br>PUT: 브라우저 세션 + CSRF 또는 OAuth Bearer<br>DELETE: 브라우저 세션 + CSRF 또는 OAuth Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |

## 10. API 키·세션·감사·보안 운영



| 경로 | 메서드 | 설명 | 인증 방식(메서드별) | 활성 조건 |
|---|---|---|---|---|
| `/auth/v1/api_keys` | GET, POST | 관리 API 키 목록(GET), 일회성 비밀을 반환하는 생성(POST) | GET: 브라우저 세션<br>POST: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/api_keys/{name}` | PUT, DELETE | 관리 API 키 수정(PUT), 삭제(DELETE) | PUT: 브라우저 세션 + CSRF<br>DELETE: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/api_keys/{name}/secret` | PUT | 관리 API 키 비밀 교체 | PUT: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/api_keys/{name}/test` | GET | 지정된 API 키 검증 | GET: 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/blacklist` | GET, POST | IP 차단 목록(GET), 항목 추가(POST) | GET: 브라우저 세션 또는 권한 API 키<br>POST: 브라우저 세션 + CSRF 또는 권한 API 키 | IP blacklist 활성 |
| `/auth/v1/blacklist/{ip}` | GET, PUT, DELETE | IP 차단 항목 조회(GET), 수정(PUT), 삭제(DELETE) | GET: 브라우저 세션 또는 권한 API 키<br>PUT: 브라우저 세션 + CSRF 또는 권한 API 키<br>DELETE: 브라우저 세션 + CSRF 또는 권한 API 키 | IP blacklist 활성 |
| `/auth/v1/events` | GET, POST | API 키 전용 감사 이벤트 조회(GET), 라이프사이클 이벤트 조건 검색(POST) | GET: 권한 API 키<br>POST: 브라우저 세션 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/events/stream` | GET | 라이프사이클 이벤트 SSE 스트림 | GET: 브라우저 세션 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/events/test` | POST | 영속 테스트 이벤트 생성 | POST: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/lockdown` | GET, POST, DELETE | 로그인 잠금 상태 조회(GET), 활성화(POST), 해제(DELETE). 브라우저 관리자 전용; 변경에는 CSRF | GET: 브라우저 세션<br>POST: 브라우저 세션<br>DELETE: 브라우저 세션 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/master_key_retirement` | GET | 마스터 키 폐기 진행 상태 조회 | GET: 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/master_key_retirement/{action}` | POST | 마스터 키 폐기 prepare·fence·ready·abort 실행 | POST: 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/sessions` | GET, DELETE | 브라우저 세션 목록(GET), 전체 기존 세션 로그아웃(DELETE) | GET: 브라우저 세션 또는 권한 API 키<br>DELETE: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/sessions/id/{session_id}` | DELETE | 세션 하나 삭제. 식별자는 쿠키 원문이 아닌 저장된 digest | DELETE: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/sessions/{subject}` | DELETE | 지정 사용자 전체 세션 강제 로그아웃 | DELETE: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |

## 11. KV 저장소

관리자 네임스페이스 관리, KV 전용 자격 증명 접근, 공개 네임스페이스 조회의 세 가지 권한 경계가 있다.

| 경로 | 메서드 | 설명 | 인증 방식(메서드별) | 활성 조건 |
|---|---|---|---|---|
| `/auth/v1/kv/keys` | GET, PUT | KV 접근 자격 증명으로 키 목록(GET), 값 저장(PUT) | GET: KV 전용 Bearer<br>PUT: KV 전용 Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/kv/keys/{key}` | GET, DELETE | KV 값 조회(GET), 삭제(DELETE) | GET: KV 전용 Bearer<br>DELETE: KV 전용 Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/kv/ns` | GET, POST | 관리자 KV 네임스페이스 목록(GET), 생성(POST) | GET: 브라우저 세션<br>POST: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/kv/ns/{ns}` | PUT, DELETE | KV 네임스페이스 수정(PUT), 삭제(DELETE) | PUT: 브라우저 세션 + CSRF<br>DELETE: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/kv/ns/{ns}/access` | GET, POST | 네임스페이스 접근 자격 증명 목록(GET), 생성(POST) | GET: 브라우저 세션<br>POST: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/kv/ns/{ns}/access/{id}` | PUT, DELETE | 네임스페이스 접근 자격 증명 수정(PUT), 삭제(DELETE) | PUT: 브라우저 세션 + CSRF<br>DELETE: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/kv/ns/{ns}/access/{id}/secret` | POST | KV 접근 비밀 교체 | POST: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/kv/ns/{ns}/values` | GET, POST, PUT | 관리자 값 목록(GET), 생성(POST), 수정(PUT) | GET: 브라우저 세션<br>POST: 브라우저 세션 + CSRF<br>PUT: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/kv/ns/{ns}/values/{key}` | DELETE | 관리자 KV 값 삭제 | DELETE: 브라우저 세션 + CSRF | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/kv/pub/{ns}/{key}` | GET | 공개 네임스페이스의 값 조회 | GET: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/kv/test` | GET | KV 접근 자격 증명 검증 | GET: KV 전용 Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/kv/values` | GET | KV 접근 자격 증명으로 값 목록 조회 | GET: KV 전용 Bearer | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |

## 12. FedCM

브라우저 FedCM 프로토콜이다. 전용 헤더와 쿠키 조건을 사용하며 일반 계정 세션만으로 대체되지 않는다. landing은 `/auth/v1/account` 또는 `/auth/login` 중 설정한 하나다.

| 경로 | 메서드 | 설명 | 인증 방식(메서드별) | 활성 조건 |
|---|---|---|---|---|
| `/.well-known/web-identity` | GET | FedCM 제공자 발견용 manifest | GET: 공개/프로토콜별 검증¹ | FedCM 활성; landing은 설정된 경로 하나 |
| `/auth/v1/account` | GET, POST | FedCM 설정에서 선택 가능한 로그인/계정 landing HTML | GET: 공개/프로토콜별 검증¹<br>POST: 공개/프로토콜별 검증¹ | FedCM 활성; landing은 설정된 경로 하나 |
| `/auth/v1/fed_cm/accounts` | GET | FedCM 계정 목록. 전용 세션 필요 | GET: FedCM 전용 세션 | FedCM 활성; landing은 설정된 경로 하나 |
| `/auth/v1/fed_cm/client_meta` | GET | FedCM 클라이언트 메타데이터 | GET: 공개/프로토콜별 검증¹ | FedCM 활성; landing은 설정된 경로 하나 |
| `/auth/v1/fed_cm/config` | GET | FedCM 제공자 설정 | GET: 공개/프로토콜별 검증¹ | FedCM 활성; landing은 설정된 경로 하나 |
| `/auth/v1/fed_cm/status` | GET | FedCM 로그인 상태 | GET: FedCM 전용 세션 | FedCM 활성; landing은 설정된 경로 하나 |
| `/auth/v1/fed_cm/token` | POST | FedCM ID assertion 발급 | POST: FedCM 전용 세션 | FedCM 활성; landing은 설정된 경로 하나 |

## 13. API 문서

Swagger UI는 기본 비활성이다. 활성화해도 기본은 관리자 전용이고 Try it out 실행은 꺼져 있다.

| 경로 | 메서드 | 설명 | 인증 방식(메서드별) | 활성 조건 |
|---|---|---|---|---|
| `/auth/v1/docs` | GET, HEAD | 문서 루트에서 슬래시 경로로 리다이렉트 | GET: 공개/프로토콜별 검증¹<br>HEAD: 공개/프로토콜별 검증¹ | Swagger 활성; 기본 비공개(관리자), 공개 설정 가능 |
| `/auth/v1/docs/` | GET, HEAD | 탐색 전용 Swagger UI | GET: 공개/프로토콜별 검증¹<br>HEAD: 공개/프로토콜별 검증¹ | Swagger 활성; 기본 비공개(관리자), 공개 설정 가능 |
| `/auth/v1/docs/favicon-16x16.png` | GET, HEAD | Swagger UI 정적 자산 | GET: 공개/프로토콜별 검증¹<br>HEAD: 공개/프로토콜별 검증¹ | Swagger 활성; 기본 비공개(관리자), 공개 설정 가능 |
| `/auth/v1/docs/favicon-32x32.png` | GET, HEAD | Swagger UI 정적 자산 | GET: 공개/프로토콜별 검증¹<br>HEAD: 공개/프로토콜별 검증¹ | Swagger 활성; 기본 비공개(관리자), 공개 설정 가능 |
| `/auth/v1/docs/index.css` | GET, HEAD | Swagger UI 정적 자산 | GET: 공개/프로토콜별 검증¹<br>HEAD: 공개/프로토콜별 검증¹ | Swagger 활성; 기본 비공개(관리자), 공개 설정 가능 |
| `/auth/v1/docs/index.html` | GET, HEAD | Swagger UI HTML | GET: 공개/프로토콜별 검증¹<br>HEAD: 공개/프로토콜별 검증¹ | Swagger 활성; 기본 비공개(관리자), 공개 설정 가능 |
| `/auth/v1/docs/openapi.json` | GET, HEAD | 현재 배포 기능 설정을 반영하는 OpenAPI JSON | GET: 공개/프로토콜별 검증¹<br>HEAD: 공개/프로토콜별 검증¹ | Swagger 활성; 기본 비공개(관리자), 공개 설정 가능 |
| `/auth/v1/docs/swagger-initializer.js` | GET, HEAD | Swagger UI 정적 자산 | GET: 공개/프로토콜별 검증¹<br>HEAD: 공개/프로토콜별 검증¹ | Swagger 활성; 기본 비공개(관리자), 공개 설정 가능 |
| `/auth/v1/docs/swagger-ui-bundle.js` | GET, HEAD | Swagger UI 정적 자산 | GET: 공개/프로토콜별 검증¹<br>HEAD: 공개/프로토콜별 검증¹ | Swagger 활성; 기본 비공개(관리자), 공개 설정 가능 |
| `/auth/v1/docs/swagger-ui-standalone-preset.js` | GET, HEAD | Swagger UI 정적 자산 | GET: 공개/프로토콜별 검증¹<br>HEAD: 공개/프로토콜별 검증¹ | Swagger 활성; 기본 비공개(관리자), 공개 설정 가능 |
| `/auth/v1/docs/swagger-ui.css` | GET, HEAD | Swagger UI 정적 자산 | GET: 공개/프로토콜별 검증¹<br>HEAD: 공개/프로토콜별 검증¹ | Swagger 활성; 기본 비공개(관리자), 공개 설정 가능 |

## 14. 테마·브랜드 자산



| 경로 | 메서드 | 설명 | 인증 방식(메서드별) | 활성 조건 |
|---|---|---|---|---|
| `/auth/v1/branding/{name}` | GET | 번들 브랜드 CSS·폰트·Gateway SVG 등 허용된 자산 | GET: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/theme/global.css` | GET | 공유 인증 화면 CSS | GET: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/theme/{client_id}` | POST, PUT, DELETE | 테마 설정 조회(POST), 교체(PUT), 삭제(DELETE) | POST: 브라우저 세션 또는 권한 API 키<br>PUT: 브라우저 세션 + CSRF 또는 권한 API 키<br>DELETE: 브라우저 세션 + CSRF 또는 권한 API 키 | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/auth/v1/theme/{client_id}/{timestamp}` | GET | 공개 클라이언트 테마 CSS | GET: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |
| `/favicon.ico` | GET | 서비스 파비콘 | GET: 공개/프로토콜별 검증¹ | 등록됨; 권한·정책·대상 상태에 따라 거부 가능 |

## 라우터 해석상 보충

- Go 라우터의 `PUT /auth/v1/users/{first}/{second}`는 임의 사용자 API가 아니다. `{first}=attr`일 때 속성 정의 수정, `{second}=attr`일 때 사용자 속성 값 저장으로 분기하므로 위 표에 두 의미 경로로 풀어 썼다.
- issuer에 경로가 있으면 RFC 8414 발견 URL `/.well-known/oauth-authorization-server{issuerPath}`도 조건부 등록된다.
- `/auth/v1/master_key_retirement/{action}`의 유효 action은 `prepare`, `fence`, `ready`, `abort`다.
- `/auth/v1/admin/`의 미지 경로는 서버가 SPA HTML을 반환할 수 있지만, 인식된 업무 화면이 생기는 것은 아니다.
- `/auth/v1/branding/{name}`는 허용 목록에 있는 번들 자산만 반환한다. 임의 파일 조회 API가 아니다.
- 문서의 FedCM landing은 허용된 두 대안의 합집합으로 표현했다. 한 배포에 두 landing이 동시에 활성화된다는 뜻이 아니다.

## UI 화면 전체 목록

### 관리자 콘솔

이 표의 경로는 브라우저 관리자 세션이 필요하다. 위임 관리자에게 보이는 데이터·허용 작업은 서버 권한에 따라 달라진다. API 키나 OAuth Bearer만으로 관리 HTML에 로그인할 수는 없다.

| 전체 경로 | 화면·기능 |
|---|---|
| `/auth/v1/admin` | 인증 후 대시보드로 303 이동 |
| `/auth/v1/admin/` | SPA 공통 셸과 영역 선택 안내 |
| `/auth/v1/admin/dashboard` | 현재 계정 표시와 Identity·Applications·Operations 관리 메뉴. 계정 편집은 /account로 연결 |
| `/auth/v1/admin/users` | 사용자 목록·페이지 이동 |
| `/auth/v1/admin/users/new` | 사용자 생성·활성화 이메일 요청 |
| `/auth/v1/admin/users/{subject}` | 사용자 상세 편집. 프로필·역할·그룹·계정 상태·삭제 |
| `/auth/v1/admin/clients` | 관리형 OAuth 클라이언트 목록 |
| `/auth/v1/admin/clients/new` | 관리형 클라이언트 생성 |
| `/auth/v1/admin/clients/{id}` | 클라이언트 상세 |
| `/auth/v1/admin/clients/{id}/edit` | 클라이언트 설정 편집 |
| `/auth/v1/admin/clients/{id}/theme` | 로그인 테마 편집: 로고 업로드·삭제, 한·영 문구, 레이아웃, 라이트/다크 색상, 미리보기·저장·복원 |
| `/auth/v1/admin/roles` | 역할 목록 |
| `/auth/v1/admin/roles/new` | 역할 생성 |
| `/auth/v1/admin/roles/{id}` | 역할 편집·삭제 |
| `/auth/v1/admin/groups` | 그룹 목록 |
| `/auth/v1/admin/groups/new` | 그룹 생성 |
| `/auth/v1/admin/groups/{id}` | 그룹 편집·삭제 |
| `/auth/v1/admin/api-keys` | 관리 API 키 목록·권한·만료 관리. 생성/편집/일회성 비밀 표시/교체/삭제는 같은 URL의 패널 |
| `/auth/v1/admin/scopes` | 클레임 scope 목록 |
| `/auth/v1/admin/scopes/new` | scope 생성 |
| `/auth/v1/admin/scopes/{name}` | scope 이름으로 선택하여 설정 편집·삭제 |
| `/auth/v1/admin/attributes` | 사용자 속성 정의 목록 |
| `/auth/v1/admin/attributes/new` | 속성 정의 생성 |
| `/auth/v1/admin/attributes/{name}` | 속성 정의·기본값·사용자 편집 허용 여부 수정·삭제 |
| `/auth/v1/admin/collections` | 인증 컬렉션 목록 |
| `/auth/v1/admin/collections/new` | 인증 컬렉션 생성 |
| `/auth/v1/admin/collections/{id}` | 인증 컬렉션 상세 |
| `/auth/v1/admin/collections/{id}/edit` | 인증 컬렉션 정의 편집 |
| `/auth/v1/admin/providers` | **SaaS 연결 제공자** 목록. `/auth/v1/saas/providers` API 사용 |
| `/auth/v1/admin/providers/new` | SaaS 연결 제공자 생성 |
| `/auth/v1/admin/providers/{id}` | SaaS 제공자 편집 폼 |
| `/auth/v1/admin/providers/{id}/edit` | SaaS 제공자 편집 폼 |
| `/auth/v1/admin/sessions` | 세션 목록·회수 작업 |
| `/auth/v1/admin/events` | 이벤트 검색·스트림·테스트 관련 관리 |
| `/auth/v1/admin/blacklist` | IP 차단 목록 관리 |
| `/auth/v1/admin/templates` | 이메일 템플릿 종류·언어 선택과 샘플 미리보기 |
| `/auth/v1/admin/email-templates/preview?type={type}&lang={lang}` | iframe에 표시하는 이메일 HTML. 템플릿 편집/저장 화면은 아님 |

근거: `internal/admin/ui.go`, `admin.js`, `catalog.js`, `dashboard.js`, `clients.js`, `collections.js`, `providers.js`, `templates.js`.

### 로그인·가입·복구·승인 화면

| 경로 또는 진입 조건 | 화면·상태 | 접근 조건 |
|---|---|---|
| `/oidc/authorize?...` | 비밀번호 로그인, 패스키 선택, 외부 IdP 선택 | 유효한 OAuth 인가 요청. 이미 인증됐다면 화면 없이 다음 단계로 진행 가능 |
| `POST /auth/login` 뒤 OTP 요구 | 6자리 OTP 입력·실패 상태 | 해당 인증 interaction과 OTP/MFA 정책. 독립 GET 화면 없음 |
| 패스키 시작·완료 API를 사용하는 로그인/계정 화면 | 패스키 대기·취소·오류·성공 UI와 브라우저/OS 인증기 창 | 패스키 활성 및 지원 브라우저. OS 창은 GoAuthy가 렌더하는 웹 페이지가 아님 |
| `/auth/profile` | 필수 프로필 보완 폼·검증 오류 | 기존 인증 흐름 및 필수 필드 정책 |
| `/oidc/device/login[?user_code={code}]` | 기기 코드 검토 전 로그인 | 기기 인증 로그인 흐름. 로그인만으로 권한 승인 안 됨 |
| `/oidc/device/verify[?user_code={code}]` | 코드 입력, 요청 scope 검토, 승인/거부, 처리 결과 | 미로그인 시 device/login으로 이동 |
| `/oidc/logout` | 로그아웃 확인 및 결과/허용된 리다이렉트 | OIDC logout 요청 문맥에 따른 검증 |
| `/auth/v1/users/password_reset` | 이메일 입력, 복구 요청 접수 안내, 재시도 제한/오류 | 복구 서비스 활성 |
| `/auth/v1/users/register` | 가입 폼, 정책에 따른 추가 필드, 이메일 안내·실패 상태 | 복구+공개 가입 활성. CAPTCHA 설정 시 위젯 미구현으로 제출 차단 |
| `/auth/v1/users/{subject}/reset/{token}` | 링크 확인, 명시적 계속, 새 비밀번호 설정, 성공/만료/오류 | 복구 서비스 활성. `Accept: text/html`은 화면만 렌더; 명시적 JSON bootstrap에서 검증 |
| `/auth/v1/users/{subject}/revoke/{code}` | 의심 로그인 회수 결과 | 이메일에서 발급된 유효 코드 |
| `/account/connection-login?handoff_id={id}` | 연결 요청 검토 전 로그인 | 연결 요청 문맥 |
| `/account/connection-handoffs/{handoff_id}` | 연결 요청 검토, 승인/거부, 완료/오류 | 로그인한 소유자와 유효 요청; 변경은 CSRF POST |
| `/auth/v1/saas/callback/{provider_id}` | SaaS OAuth 연결 완료/실패 안내, 계정 화면 복귀 | 앞서 시작된 외부 OAuth 연결 문맥 |
| FedCM 설정의 `/auth/v1/account` 또는 `/auth/login` | FedCM 로그인 폼, 로그인 완료 안내 | FedCM 활성. 현재 강제 MFA 부트스트랩과 동시 구성 불가 |
| `/auth/v1/docs/` 또는 `/auth/v1/docs/index.html` | Swagger API 문서 탐색 | Swagger 활성; 공개 설정이 아니면 관리자 |

근거: `internal/login/handler.go`, `profile_continuation.go`, `device.go`, `internal/device/http.go`, `internal/logout`, `internal/recovery/pages.go`, `http.go`, `login_revoke_http.go`, `internal/rbac/connection_handoff_page.go`, `account_connection_oauth2_page.go`, `internal/apidocs/http.go`.

### 본인 계정 화면의 모든 영역

공통 URL은 `/account`다. 대부분 별도 페이지가 아니라 같은 문서의 섹션·폼이다. 로그인 세션, 계정 상태, 기능 설정에 따라 섹션이 숨겨질 수 있다.

| 영역 | 위치/형태 | 하는 일 |
|---|---|---|
| 프로필 개요 | `#profile` | 본인 계정 기본 정보 |
| 선호 사용자 이름 | username 폼 | 사용자 이름 설정·정책 오류 표시 |
| 비밀번호 변경 | `#password-section` | 현재/새 비밀번호 입력·변경 |
| 개인 속성 | `#attributes-section` | 본인 편집이 허용된 사용자 속성 |
| 패스키 | `#passkeys-section` | 목록·등록·삭제·지원 여부 안내 |
| 패스키 전용 전환 | `#passwordless-section` | 비밀번호 로그인을 끄는 전환 |
| 비밀번호 로그인 복원 | `#password-restore-section` | 정책에 따라 새 비밀번호 설정으로 복원 |
| 연결 관리 | `#connections-section` | 컬렉션 선택·연결 초안 생성·편집·삭제 |
| 연결 API 키 | 연결 목록에서 여는 패널 | 외부 서비스 API 키 보관·삭제·상태 |
| 연결 OAuth | 연결별 동작 | 외부 SaaS 연결·재연결·해제·갱신 |
| 연결 사용 권한 | 연결별 권한 관리 패널 | 소비 앱에 허용한 연결 사용 권한 조회·생성·회수 |
| 승인 기기 | `#devices-section` | 기기 인증 목록·회수. 기기명·위치·최근 사용 상세는 현재 제공되지 않음 |
| 계정 삭제 | `#self-delete-section` | 이메일 확인을 통한 본인 탈퇴 |
| 로그아웃 | 상단 링크 → `/oidc/logout` | 로그아웃 확인 흐름 시작 |

근거: `internal/account/dashboard.html`, `dashboard.js`, `connections.js`, `connection_grants.js`, `devices.js`.

## 화면으로 착각하기 쉬운 경로

| 경로 | 실제 응답 |
|---|---|
| `/` | 영어·한국어 공개 홈. 계정 로그인, 기기 코드 입력, 활성화된 복구·가입 화면으로 이동 |
| `/account/data` | 프로필·CSRF JSON |
| `/account/password` | 비밀번호 정책·CSRF JSON |
| `/auth/v1/users/{subject}/self/delete` GET | 탈퇴 준비 API, 별도 HTML 아님 |
| `/auth/{subject}/profile` | WebID 프로필 문서, 계정 편집 UI 아님 |
| `/auth/v1/roles`, `/groups`, `/scopes`, `/users` | 각각 `/auth/v1` 기준 JSON API. 관리자 UI는 `/auth/v1/admin/...` |
| `/upstream/{providerID}/start`, `/callback` | 외부 IdP 이동·인증 콜백. 별도 제공자 관리 화면 아님 |
| `/auth/v1/fed_cm/*` | FedCM 프로토콜 JSON/상태 응답 |

## 이번 목록에서 확인한 부족한 부분

1. **관리자 진입 동선을 수정했다.** `/auth/v1/admin`은 이제 인증 후 `/auth/v1/admin/dashboard`로 이동한다. 첫 화면은 실제 `/account/data`에서 계정 표시를 읽고 관리 메뉴를 제공한다.
2. **OpenAPI와 실제 라우터가 완전히 일치하지 않는다.** 외부 로그인 provider registry 6개 작업, provider logo 3개 작업, lockdown 3개 작업이 생성된 계약에서 빠져 있다. 콘솔 보조 API·운영 경로 등도 별도로 보완했다. 위 표는 이러한 누락을 포함한다.
3. **외부 로그인 IdP와 SaaS provider가 UI에서 구분되지 않는다.** 현재 `admin/providers`는 SaaS API를 호출한다. `/auth/v1/providers` 로그인 IdP 레지스트리용 전용 UI는 현재 관리자 라우터에서 확인되지 않는다.
4. **KV, 마스터 키 폐기, lockdown, 전체 시스템 설정용 전용 관리 화면이 없다.** 해당 API가 있어도 UI 메뉴가 있는 것은 아니다. PAM은 권한 이름이 코드에 있으나 이 런타임의 PAM API·화면 마운트는 확인되지 않는다.
5. **공개 패스키 우선 가입은 미완성이다.** 시작 API는 유효 요청도 503으로 안전하게 거부하며 계정을 예약하지 않는다. 로그인·기존 계정 패스키 등록과 구분해야 한다.
6. **CAPTCHA 가입 UI가 미완성이다.** CAPTCHA가 설정되면 위젯 없이 제출을 막는다.
7. **계정·관리 UI의 언어와 오류 경험이 완전히 통일되지 않았다.** 인증 화면의 한국어와 달리 관리자·계정 템플릿에 영어가 다수 남아 있다. 권한 오류 등이 항상 디자인된 전용 화면으로 이어지지는 않는다.
8. **화면 존재와 시나리오 검증 완료는 다르다.** 이 문서는 라우팅/템플릿/스크립트를 정적으로 대조한 결과다. 모든 조합·권한·모바일·배포 prefix에서 동작을 실검증했다는 의미가 아니다.

## 주요 근거 파일

- `cmd/goauthy/main.go`: 서비스의 주 라우팅·조건부 기능·health·metrics
- `cmd/goauthy/provider_registry_routes.go`, `provider_logo_routes.go`, `upstream.go`, `fedcm.go`, `openapi.go`: 보조 마운트
- `internal/apidocs/catalog_*.go`: API 계약·요약·권한 정보
- `internal/kv/http.go`: KV 20개 메서드/경로 조합
- `internal/admin/ui.go`, `admin.js`, `catalog.js`: 관리자 보조 API·정적 자산·SPA 화면 분기
- `internal/account/dashboard.html`, `dashboard.go`: 계정 섹션과 HTML/JSON 구분
- `internal/recovery/http.go:110`: 복구 토큰 GET의 HTML/JSON 분기
- `internal/loginpolicy/lockdown_handler.go`: GET/POST/DELETE 잠금 API
