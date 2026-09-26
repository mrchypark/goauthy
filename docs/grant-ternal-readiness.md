# Grant / Ternal 연동 준비도 — 2026-09-27

## 점검 대상

- GoAuthy: `ea830e24` (현재 origin/main과 동일) + 로컬 인증 UI/브랜딩 변경. 이 작업 트리는 아직 커밋·릴리즈된 동일 산출물이 아니다.
- Ternal: `05d04c1`, 현재 origin/main과 동일, 작업 트리 변경 없음.
- Grant: 로컬 `c2cdb2a`는 최신 origin/main `16020fe`보다 59커밋 뒤처져 있다. 최신 계약은 원격 추적 참조의 소스로 확인하며, 로컬 테스트가 최신 Grant 실행 증거를 대신하지 않는다.
- 운영 배포와 실제 운영 설정은 이번 점검에서 변경하거나 검증하지 않았다.

## 현재 판정

| 범위 | 판정 | 증거·제한 |
|---|---|---|
| Ternal 웹 Authorization Code | 로컬 소비자 연동 통과 | 현재 GoAuthy 소스로 독립 프로세스를 시작해 실제 Ternal 소비자 검사 실행 |
| Ternal CLI Device | 로컬 소비자 연동 통과 | Linux 격리 환경에서 실제 CLI 로그인·whoami·로그아웃을 GoAuthy 재시작 전후 검증 |
| Grant 기존 설정 그대로 | 사용 불가 | 기존 `/auth/v1/oidc/introspect`, `/auth/v1/oidc/userinfo`가 GoAuthy에서 404 |
| Grant 설정·계약 조정 후 | 추가 통합 검증 필요 | 토큰 검증 경로 변경과 관리 API 응답 계약 수정 후 실제 소비자 흐름 검증 필요 |
| 신규 로그인 브랜딩 운영 적용 | 아직 미배포 | 현재 변경은 로컬 작업 트리이며 동일 릴리즈 산출물로 운영 검증하지 않음 |

## 실제 실행 결과

Ternal 저장소에서 실행:

```sh
GOAUTHY_ROOT=/absolute/path/to/goauthy sh deploy/e2e/goauthy-standalone.sh
```

`TestGoAuthyAuthorizationCodeConsumer` 통과. Discovery/JWKS, confidential `client_secret_post`, S256 PKCE, ID token issuer/sub/groups, issuer와 subject에 결합된 principal, 코드 재사용 및 잘못된 PKCE 거부를 검사한다. 근거: Ternal `internal/auth/goauthy_integration_test.go`와 `/tmp/goauthy-ternal-readiness-live.log`.

Ternal 설정 계약: 정확한 callback(`/auth/callback`), client ID/secret, `openid groups`, ID token의 `groups`, 관리자 그룹 `ternal-admins`. Ternal 로그아웃은 Ternal 세션을 폐기하며 provider 전체 로그아웃을 뜻하지 않는다. `(issuer, sub)`가 바뀌면 기존 사용자와 다른 principal이 된다.

CLI는 기존 `deploy/e2e-ternal-device/Dockerfile`과 로컬 Dory BuildKit으로 빌드하고 네트워크가 격리된 Linux 컨테이너에서 실행했다. 저장 공간 정리 후 이미지 export까지 성공했다. 첫 실행은 실제 기기 로그인을 완료했으나, 검증 코드가 옛 `session.json`을 찾아 실패했다. 현재 Ternal의 API origin 해시 기반 파일명과 `api_url`을 포함한 4필드 계약으로 테스트를 수정했다.

최종 `TestTernalDeviceCLILive`는 GoAuthy 재시작 전후 모두 통과하고 runner가 종료 코드 0으로 완료됐다. 실제 `ternalctl login`, 사용자·그룹 조회, 세션 파일 권한 0600과 API origin 결합, 로그아웃 후 파일 삭제·whoami 실패·서버 세션 무효화를 검사했다. 기존 로그인 세션의 재시작 생존 여부를 검사한 것은 아니며, 재시작 뒤 새 로그인 흐름을 반복했다.

- 빌드 로그: `/tmp/goauthy-ternal-device-build-final.log`
- 실행 로그: `/tmp/goauthy-ternal-device-readiness-final.log`
- 테스트 이미지: `goauthy-ternal-device-e2e:readiness-20260927`
- 이미지 manifest list: `sha256:f929bc823a2e26f4253f0882178e7ded27aa8cd7a218df64e3813c4d99edbcc8`

Ternal `docs/goauthy.md`의 Device 미검증 문구보다 이번 실제 실행 결과가 최신이다. 운영 배포 검증을 대신하지 않는다.

## Grant 경로 확인

현재 로컬 GoAuthy에서 자격 증명 없이 경로 존재 여부만 검사했다:

| 요청 | 상태 |
|---|---|
| POST `/auth/v1/oidc/introspect` | 404 |
| POST `/oidc/introspect` | 401 |
| GET `/auth/v1/oidc/userinfo` | 404 |
| GET `/oidc/userinfo` | 401 |

401은 인증 경계가 존재한다는 증거이며, 유효한 Grant 토큰의 계약 통과를 뜻하지 않는다. Discovery도 `/oidc/*` 경로를 제공한다. `/auth/v1/clients/{id}` 관리 API는 그대로 존재하므로 `/auth/v1` 전체를 일괄 치환하면 안 된다.

## 독립 검토

[Pro 검토](https://chatgpt.com/g/g-p-69ecdc42175c819186cf485b225c0e46/c/6ab8160b-dfa8-83ee-b16a-c53c8b96185f)는 Ternal의 검증된 흐름, Grant의 미검증 계약, 운영 전환을 분리하도록 권고했다. 운영 사용 판정에는 동일한 불변 산출물, 의도한 소비자 버전·배포 설정, 기존 identity 연결 및 롤백 경로 검증이 필요하다.

## 최신 Grant에서 확인한 추가 차단 요인

최신 `origin/main`은 Rust crates를 제거하고 Go 구현으로 전환했다. 로컬 옛 Rust 프록시는 최신 버전의 동작으로 간주하면 안 된다.

- [identity_binding_rauthy.go](https://github.com/Conalog/grant/blob/16020fe7/internal/grant/identity_binding_rauthy.go)에서 `GET /auth/v1/clients/{id}`의 응답을 `flows_enabled`, `challenges`로 읽는다. 코드 29–37행의 JSON 계약과 69–75행의 정확한 값 비교를 확인했다.
- GoAuthy `internal/clients/store.go`의 `Client`는 `enabled_flows`를 반환하며 `challenges` 필드는 없다. `internal/rbac/clients_http.go`가 이 Client를 응답한다. 따라서 단순 경로 설정 수정만으로 Grant identity binding 검증을 통과할 수 없다. Public client는 `challenges=["S256"]` 비교도 충족하지 못한다. 이는 소스 계약에서 확인한 불일치이며, 최신 Grant 런타임의 409 응답을 직접 관찰한 것은 아니다.
- 최신 Grant `internal/grant/auth_external.go`는 introspection에 Basic 인증과 form token을 보내고 active/sub/client_id를 검사한다. UserInfo에는 Bearer 인증을 사용하고 동일 sub를 요구한다. 이 경로들은 형식상 연결 가능하지만, 최신 Grant 소비자 실행으로 검증하지 않았다.
- 관리 조회 키는 별도 GoAuthy `Clients:read` API key (`API-Key name$secret`)가 필요하다. OAuth client secret과 혼동하면 안 된다.
- Luna의 기존 로컬 Grant Rust 테스트 빌드도 저장 공간 부족으로 테스트 실행 전에 실패했다. 최신 Go Grant에 대한 실행 통과 증거는 없다.

## 권장 다음 작업

1. 최신 Grant 소스를 기준으로 introspection/userinfo 설정과 client metadata 어댑터를 수정한다. 인증·PKCE 검증을 생략해서 우회하지 않는다.
2. 실제 Grant에서 client identity binding → 사용자 토큰 검증 → 권한 판정 및 비활성/잘못된 토큰 거부를 검증한다.
3. 인증 UI 변경을 포함한 동일 릴리즈 산출물로 각 서비스의 설정·계정 연결·운영 동작을 검증한 뒤 전환한다.

## Conductor / SaaS 후속 검증

사용자 요청으로 [Conductor / SaaS 전달 검증](conductor-saas-readiness.md)을 추가했다. GoAuthy OAuth handoff·동일 세션 재시작 유지·소비자 갱신·철회와 실제 Conductor API-key bridge는 통과했다. Conductor production execution 연결 및 실제 외부 SaaS 로그인 검증은 남아 있다.
