# Compos ↔ GoAuthy 인증 연결 — 2026-09-27

## 검증된 연결

현재 GoAuthy 작업 트리와 `/absolute/path/to/compos`의 기존 인증 변경을 사용해 실제 HTTPS 연동을 실행했다. Compos HEAD `b18726d`와 fetched `origin/main d5b9f1c`의 tracked tree 차이는 없다. OAuth2와 live-test 파일 등 기존 미커밋 변경은 포함되며 보존했다. 운영 설정·배포·계정 이전은 수행하지 않았다.

| 경로 | 실제 결과 | 의미 |
|---|---|---|
| GoAuthy → Compos 자체 세션 | `TestGoAuthyLiveE2E` PASS 1.61s | 토큰 교환, 반복 로그인 동일 principal/person, 중복 membership 방지, 세션 조회, 타 workspace 거부, 개별 세션 로그아웃과 401 |
| GoAuthy → Compos API Bearer | `TestOAuth2LiveE2E` PASS 0.78s | identity 등록, 명시적 membership 전 403/후 200, 타 workspace·membership 삭제 후 403, 자체 세션 미발급 |
| 잘못된 audience/scope·철회 토큰 | 두 경로 모두 401 확인 | 실제 GoAuthy 발급 및 철회 fixture |
| 실제 만료 토큰 | 두 경로 모두 SKIP | 만료 fixture 미공급. 전체 negative matrix 통과로 간주하지 않음 |

두 runner 모두 종료 코드 0. GoAuthy authorization-code/S256 PKCE로 테스트 토큰을 발급하고 실제 Compos HTTP handler와 독립 Rhiza DB에서 검사했다. 브라우저 자동 로그인 및 Compos CLI 전체 실행을 검사한 것은 아니다.

## 서비스에서 사용할 계약

### Compos 세션이 필요한 기존 CLI/앱

`COMPOS_AUTH_MODE=rauthy`는 호환 모드 이름이며 issuer에는 GoAuthy를 설정한다.

- `COMPOS_RAUTHY_ISSUER`: 정확한 GoAuthy issuer.
- `COMPOS_RAUTHY_INTROSPECTION_CLIENT_ID`, `COMPOS_RAUTHY_INTROSPECTION_CLIENT_SECRET`: 등록한 confidential client의 서버측 자격 증명.
- `COMPOS_RAUTHY_RESOURCE`: 허용 audience. 이번 검사에서는 `https://compos.local.test`.
- `COMPOS_RAUTHY_REQUIRED_SCOPE=openid`.
- `COMPOS_AUTH_ALLOWED_EMAIL_DOMAINS`: 허용할 실제 이메일 도메인.
- `COMPOS_AUTH_SESSION_TTL_SECONDS`: 로컬 세션 수명. 이번 pilot은 300초 상한과 provider token expiry 중 짧은 값.
- 자동 참여가 의도된 경우에만 `COMPOS_RAUTHY_AUTO_WORKSPACE_ID`에 사전에 준비한 workspace를 지정한다.

사용자 흐름: GoAuthy authorization code + S256 PKCE로 `openid email profile` 및 해당 resource의 access token 획득 → `POST /api/v1/auth/rauthy`의 `access_token`으로 교환 → Compos가 발급한 session token 사용 → `/api/v1/auth/logout`으로 해당 세션 폐기.

이 체크아웃의 CLI는 `login --provider rauthy`에서 이미 발급된 access token을 요구한다. 서버 중개 Device 로그인/브라우저 자동 로그인 구현은 확인되지 않았다. GoAuthy 로그아웃·토큰 철회가 기존 Compos 세션을 즉시 폐기하는 back-channel 기능도 없다.

### API에서 GoAuthy 토큰을 직접 검증

- `COMPOS_AUTH_MODE=oauth2`.
- `COMPOS_OAUTH2_ISSUER`: 정확한 GoAuthy issuer.
- `COMPOS_OAUTH2_RESOURCE`: Compos 전용 audience.
- `COMPOS_OAUTH2_REQUIRED_SCOPE=compos.api`.
- `COMPOS_OAUTH2_INTROSPECTION_CLIENT_ID`, `COMPOS_OAUTH2_INTROSPECTION_CLIENT_SECRET`: confidential introspection client.

GoAuthy에 application scope `compos.api`와 RP의 resource 접근을 등록한다. RP는 `openid email profile compos.api`와 해당 resource로 로그인하고, API에 access token을 Bearer로 전달한다. ID token이나 SaaS credential을 전달하지 않는다.

`POST /api/v1/auth/identity`는 identity만 등록한다. 인증 성공이 workspace 참여 권한을 만들지 않으므로 membership은 별도로 부여한다. 매 요청 introspection으로 철회 토큰을 거부한다. 이 모드에서 Compos는 자체 세션을 발급하지 않고 logout API는 405이다. RP가 자신의 세션 및 GoAuthy 토큰 수명을 관리한다.

## 재실행

GoAuthy 저장소에서 기존 runner를 사용한다. 각 프로필은 별도로 실행한다.

```sh
GOAUTHY_E2E_TLS=1 \
GOAUTHY_E2E_COMPOS=1 \
GOAUTHY_E2E_COMPOS_PROJECT_DIR=/absolute/path/to/compos \
GOAUTHY_STANDALONE_OPEN_REG_PORT=18250 \
E2E_PORT_LOCK_DIR=/tmp/goauthy-compos-readiness-18250.lock \
sh scripts/e2e-open-registration-standalone.sh

GOAUTHY_E2E_TLS=1 \
GOAUTHY_E2E_COMPOS_OAUTH2=1 \
GOAUTHY_E2E_COMPOS_PROJECT_DIR=/absolute/path/to/compos \
GOAUTHY_STANDALONE_OPEN_REG_PORT=18260 \
E2E_PORT_LOCK_DIR=/tmp/goauthy-compos-oauth-readiness-18260.lock \
sh scripts/e2e-open-registration-standalone.sh
```

포트 범위는 각각 18250–18252와 18260–18262이다. 다른 runner와 포트가 겹치면 전용 lock을 함께 사용하면 안 된다. 이번 기존 UI preview 18120은 유지했다. 테스트 서버·DB·credential fixture는 종료 시 제거되므로 상시 서비스 연결을 생성한 것은 아니다.

로그: `/tmp/goauthy-compos-session-readiness.log`, `/tmp/goauthy-compos-oauth-readiness.log`.

남은 작업: 실제 만료 토큰 E2E, 사용자용 브라우저/Device 로그인 진입, 배포용 issuer/client/resource와 기존 principal의 명시적 계정 연결 검증. 이메일만으로 기존 계정을 자동 병합하지 않는다.
