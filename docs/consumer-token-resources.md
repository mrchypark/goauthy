# 목적별 사용자 토큰 계약

2026-09-07 현재 source 기준. 이 문서는 배포 설정이나 소비자 구현 완료 선언이
아니다. Backoffice가 한 access token을 모든 API에 전달하면 안 된다.

## 목적과 소유자

| 목적 | audience/resource | 필요한 토큰/권한 |
| --- | --- | --- |
| 사용자 연결 관리·handoff 생성 | 배포의 `GOAUTHY_CONNECTIONS_RESOURCE` 값과 정확히 일치 | Backoffice RP의 human token, `goauthy.connections.read`/`goauthy.connections.write` |
| 승인된 자격증명 사용 | 같은 connections resource | grant에 지정된 실행 consumer 자신의 confidential client로 발급한 human token, `goauthy.connections.use` |
| Beesuh API 호출 | Beesuh가 검증하도록 설정된 exact resource | Beesuh가 허용한 RP/client의 human token과 요구 scope; connections 토큰으로 대체 불가 |
| Compos API 호출 | Compos가 검증하도록 설정된 exact resource | 현재 소비 계약은 `openid`+`compos.api`, 사용자/workspace 권한은 Compos가 검사 |
| 제공자 등록 관리 | 배포의 `GOAUTHY_PROVIDERS_RESOURCE` 값 | 별도 provider 관리 scope와 현재 관리자 권한; 사용자 연결 권한으로 대체 불가 |

resource 문자열은 위 환경변수/소비자 설정에서 합의해야 한다. 테스트용 URL을
운영 주소로 간주하지 않는다. server allowlist는
`GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES`이며, 연결/provider resource는 이 목록에
포함되어야 한다. 해당 RP/consumer에도 필요한 exact audience와 허용 scope를
등록한다. 익명 DCR로 임의 resource 권한을 획득할 수는 없다.

## 한 RP 세션에서 서로 다른 목적의 토큰 받기

지원 방식은 목적별 별도 authorization code + S256 PKCE 요청이다. 기존
GoAuthy 로그인 세션은 재사용할 수 있지만 재로그인·동의·MFA 요구가 없다고
가정하지 않는다. 매번 독립 state/nonce/verifier를 BFF 세션에 저장한다.

- `/oidc/authorize`에 정확히 하나의 `resource`와 그 목적의 scope를 보낸다.
- `/oidc/token`의 code 교환에서는 `resource`를 다시 보내지 않는다.
- refresh에서도 `resource`를 보내지 않는다. 기존 audience를 보존하며 다른
  resource로 전환/좁히는 요청은 현재 `invalid_target`으로 거절된다.
- 다른 목적의 토큰은 새 authorization 요청으로 받는다. 다중 audience 토큰이나
  cross-client token exchange가 지원된다고 가정하지 않는다.
- BFF는 토큰을 issuer/client/resource/scope/subject/expiry별로 분리 저장한다.
  연결 조회용 토큰을 Beesuh API로 보내거나, Backoffice 토큰을 Conductor/Beesuh
  실행 consumer 자신의 credential-use 토큰인 것처럼 사용하면 안 된다.

근거: `internal/oauth/server.go`의 `applyTokenResourceIndicator`,
`applyAuthorizationResourceIndicator`, `applyResourceAudience` 및
`internal/oauth/resource_indicator_test.go`의 authorization/refresh 검사.
Introspection은 등록 client Basic 인증을 요구하지만 **audience별 caller ACL은
아직 없다** (`internal/oauth/introspection.go`). 소비자는 반환된 aud/scope/sub를
직접 검사해야 한다. 이 제한을 API 미존재나 로그인 전체 불가로 확대하지 않는다.

## 승인 이동과 OAuth의 현재 경계

현재 API-key handoff는 [handoff 계약](connection-use-handoffs.md)을 따른다.
로그인 callback과 별도로 선택한 handoff return URI도 RP의 exact HTTPS redirect
목록에 등록해야 하며 query/fragment를 넣지 않는다. BFF는 one-use state와 기대
owner/connection/consumer/generation/mode를 서버에 보관하고, 돌아온 URL 값만
믿지 않고 읽기 권한 토큰으로 grant 상태를 재조회한다. 연결 관리 진입점은
GoAuthy의 `/account`이며 사용자의 실제 인증 세션이 필요하다.

OAuth access-token delivery 및 owner-session refresh는
[credential-use 계약](connection-use-grants.md)을 따른다. delivery는 자동 refresh가
아니며 만료/철회/알 수 없는 expiry는 실행 중단 대상이다. 실행 서비스가 owner
cookie나 refresh/client secret을 대신 가져가면 안 된다. owner가 갱신 또는
재연결하고 consumer가 현재 권한/connection generation을 재확인한 후 재개해야 한다.

OAuth용 provider/account/scopes 검토 handoff는 schema81에서 구현했고 GoAuthy
HTTPS 브라우저 검사를 통과했다. 남은 구현은 실제 외부 BFF callback 통합과
장시간 실행을 위한 승인된 갱신 orchestration, 각 앱의 실제 로그인→승인→실행
통합. 기존 API-key handoff를 OAuth 승인으로 해석하지 않는다. 일반 OAuth 토큰과
account_id만으로 Codex app-server 호환을 보장하지 않는다.
