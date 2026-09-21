# OAuth Device Flow pilot

### 2026-09-07 DPoP 후속 검증

Device token endpoint가 기존 nonce/proof 검증으로 access/refresh를 DPoP
키에 연결한다. 기존 Bearer 동작도 유지한다. confidential bootstrap client의
실제 HTTPS Device 승인·발급·갱신·UserInfo는 standalone 재시작 전후 통과했다.
후속 공개 클라이언트(auth_method=none)의 등록·Device 발급·키에 묶인 갱신·
UserInfo·등록 삭제도 재시작 전후 통과했다. 새 HA 검증은 별도이며 기존
Ternal amd64 후보에는 미포함이다.
실행 선택은 `GOAUTHY_E2E_DEVICE_DPOP=1`; 기존 standalone runner를 사용하고
Ternal CLI/native authcode 선택 플래그와 동시에 켜지 않는다. 정확한 로컬
source-overlay/테스트 범위는 [STATUS.md](STATUS.md)를 따른다.

2026-09-06. 사용자가 확인한 범위는 **기기에서 코드 받기 → 다른 브라우저에서
로그인·승인 → 기기에서 토큰으로 API 사용**이다. 기기 자산 목록이나 passkey
등록 기능을 뜻하지 않는다. 당시 기록은 Rhiza v0.12.0, schema v63 후보 기준이다.
현재 schema는 v79이며 아래 후속 지원 사항은 기존 제한 기록을 갱신한다.

## 구현 및 확인 범위

- [x] `POST /oidc/device`: 코드, verification URI, 만료와 polling interval 반환.
- [x] 로그인하지 않은 verification 브라우저를 `/oidc/device/login`으로 연결.
  사용자 코드는 서버 저장 일회용 interaction에 넣고 로그인 후 돌려준다.
- [x] 기존 비밀번호 검증·로그인 제한·peer-bound 세션·CSRF를 재사용하고
  성공 시 세션을 교체한다. 로그인만으로 승인하지 않는다.
- [x] 사용자가 코드 확인 후 명시적으로 승인하거나 거절한다.
- [x] 승인 후 access/refresh 발급, introspection으로 보호된 HTTP API 사용,
  refresh 회전, 잘못된 토큰·사용된 코드·이전 refresh 재사용 거절.
- [x] standalone 실제 HTTP E2E 및 동일 DB 프로세스 재시작 후 새 흐름 통과.
- [x] confidential 생성 시 Fosite Basic/post 인증, public `none` 정책,
  혼합/중복 인증 입력 거절 및 비밀번호 검증 전 분산 요청 제한.
- [x] public DCR device+refresh 등록 → cold login/승인 → API 사용/갱신/거절:
  standalone 및 재시작 후 재실행 통과. 기기에 bootstrap secret을 넣지 않는다.
- [x] exact-three HA 교차 Pod 요청 및 goauthy-0 UID 교체·3 Pod Ready 후 재실행.
- [x] public/confidential HA 흐름과 승인 대기 중 **동일 grant**의 Pod 교체 후
  생존 Pod 로그인·승인·교환 및 코드 재사용 거절.
- [ ] 쿼럼 상실 및 외부 provider 장애 검증. 단일 Pod 교체 통과와 구분한다.

`test/e2e/browser/device_login_flow_test.go`는 실제 서버에 cookie jar와
HTTP 폼 요청을 보내는 E2E다. 이번 결과는 Chromium 렌더링/클릭 검증이 아니다.
보호된 리소스는 테스트용 HTTP RP이며 실제 배포된 introspection endpoint에
인증하여 `active`, `sub`, `goauthy.read`를 검사한다. GoAuthy 자체가 사용자
비즈니스 API를 제공한다는 의미는 아니다.

## 결정 순서와 펜싱

승인·거절의 유효 범위는 기기 흐름을 시작한 브라우저 세션이 아니라 grant
상태로 정한다. 이 순서는 확정된 계약이며 고정 테스트로 검증한다.

- 결정은 `state='pending'`과 grant 만료로만 펜싱하고, 흐름을 시작한
  세션·개시자에게는 묶지 않는다. 다른 기기에서의 승인이 이 흐름의 목적이므로
  사용자 코드를 가진 인증된 subject는 누구나 결정할 수 있다.
- 요청 제한은 인증 후에 인증된 승인자 subject(`verify/<subject>`)에 부과한다.
  인증되지 않은 호출자가 다른 subject의 예산을 소모할 수 없다.
- 거절은 subject를 기록하지 않고, 승인은 승인자 subject를 grant subject로
  기록한다.

순서와 제한 키는 `internal/device/http.go`의 `verifyDevice`·`allow`가,
상태·만료 펜싱과 subject 기록은 `internal/device/store.go`의 `decide`가
강제한다. 고정 테스트는 `internal/device/http_decision_contract_test.go`다.

## 재실행

### 실제 Ternal CLI 소비자 (opt-in)

**Linux 격리 환경 전용이다.** macOS의
`os.UserConfigDir`는 `XDG_CONFIG_HOME`을 무시하므로 native macOS 실행을
스크립트와 Go 테스트 모두 프로세스 시작 전에 거절한다.
GoAuthy 저장소에서 다음 프로필은 지정한 Ternal 소스의 API와 CLI를 임시
디렉터리에 빌드한다. 기존 Ternal 서비스·설정·데이터는 사용하거나 변경하지 않는다.
테스트는 실제 CLI가 출력한 Device 코드를 기존 HTTP 브라우저 승인 흐름에 연결한다.
Ternal CLI 내부의 프로토콜 polling 간격은 유지하고 테스트가 추가 sleep을 넣지 않는다.
이 프로필은 GoAuthy 재시작 전후 **새 Ternal workflow**를 검사하며 같은 Ternal
세션의 재시작 지속성, SSH/relay 및 공개 바이너리 배포 검증은 별도다.

```sh
GOAUTHY_E2E_TERNAL_DEVICE=1 \
GOAUTHY_E2E_TERNAL_PROJECT_DIR=/absolute/path/to/ternal \
GOAUTHY_STANDALONE_OPEN_REG_PORT=26490 \
sh scripts/e2e-open-registration-standalone.sh
```

macOS에서는 위 native 명령을 실행하지 말고 Dory의 Linux 컨테이너를 사용한다.
빌드 context는 Ternal 소스 경로이며 Dockerfile은 go.mod/go.sum/cmd/internal만
복사한다. 실행에는 호스트 마운트나 공개 port를 추가하지 않는다.

```sh
docker buildx build --builder dory --load \
  --build-context ternal=/absolute/path/to/ternal \
  -f deploy/e2e-ternal-device/Dockerfile \
  -t goauthy-ternal-device-e2e:local .
docker run --name goauthy-ternal-device-e2e-local \
  --network none --cap-drop ALL --cap-add NET_ADMIN \
  goauthy-ternal-device-e2e:local
```

실행 후 종료 상태/exit code를 확인하고 본인이 생성한 컨테이너만 제거한다.
현재 테스트는 실제 소스 빌드이며 공개 배포된 Ternal CLI 바이너리 검증과 구분한다.

### GoAuthy Device HTTP 프로필

```sh
GOAUTHY_E2E_DEVICE_LOGIN_FLOW=1 \
GOAUTHY_STANDALONE_OPEN_REG_PORT=26290 \
sh scripts/e2e-open-registration-standalone.sh

GOAUTHY_E2E_DEVICE_LOGIN_FLOW=1 \
make e2e-kind E2E_PROFILE=open-registration \
  KIND_CLUSTER=goauthy-device-pilot E2E_PORT=26390
```

`GOAUTHY_E2E_MANAGED_CLIENTS=1`을 추가하면 관리 클라이언트 HTTP CRUD 검증도
같은 배포에서 실행한다. runner는 기존 동명 cluster를 거절하고 생성한 테스트
cluster만 정리한다. 포트와 cluster 이름은 비어 있는 것으로 선택한다.

성공 시나리오는 승인 응답 뒤 첫 token 요청을 하므로 polling sleep이 없다.
pending/slow_down/만료 경계는 기존 고정 시계 단위 테스트에서 검증한다.
네트워크와 Kubernetes readiness deadline은 종료 상한이며 정확한 초 경과를
기능 성공 조건으로 사용하지 않는다. 재시작 검사는 **새 흐름 재실행**이고,
추가 chaos gate는 교체 전에 생성한 **같은 grant**를 사용한다.
이 runner의 exact-three는 GoAuthy/Rhiza 3개 Pod/peer이며 단일 Kind
control-plane에 배치된다. 서로 다른 물리 호스트의 장애 검증은 아니다.

## 실제 도입 전 남은 제한

- public-client cold-login + offline_access는 standalone에서 검증했다.
  DCR 등록용 관리자 bearer는 서버 운영자만 보관한다. 기기는 생성된 public
  client ID만 사용하고, introspection 인증은 RP 서버에서 처리한다.
  DCR 허용 scope는 현재 서버 전역 정책이다. 테스트 runner만
  `goauthy.read offline_access`를 추가하며 production 기본값은 넓히지 않았다.
  public HA도 검증했다. 이제 [관리 클라이언트 화면](managed-clients-implementation.md)에서
  별도 DCR 등록 bearer 없이 public Device/refresh 정책을 생성할 수 있다.
  관리 화면으로 만든 클라이언트의 standalone/재시작 흐름은 통과했고 해당 후보의
  HA/동일 managed pending grant 교체 검증은 진행 중이다.
- 현재 `/oidc/device`는 명시적인 `scope`를 요구한다. RFC의 생략 가능 scope
  기본 정책 및 전체 프로토콜 동등성을 완료했다고 주장하지 않는다.
- `openid groups offline_access`와 ID token/현재 그룹 refresh는 2026-09-07
  후속 구현 및 standalone HTTP E2E에서 지원·검증했다. 당시 OAuth-only pilot과
  구분한다. Custom user claims와 Device DPoP의 전체 지원을 뜻하지 않는다.
- 승인 화면에 서버 기반 요청 client ID·scope·선택 resource를 표시한다.
  검토한 정규화 코드에 CSRF MAC을 결합하며 수동 입력은 GET 조회 후 승인한다.
  만료/이미 결정된 요청은 정보를 노출하지 않는다. 수동 입력의 실제 Chromium
  경로도 후속 검증했으며 모바일 실기기 검증은 별도 미완료다.
- 초기 관리자 MFA는 기본 optional이다. 강제 MFA가 켜져 있으면 이 새
  비밀번호 전용 화면은 MFA를 우회하지 않고 거절한다. 새 화면 내 MFA
  step-up UI는 없으며 이미 인증된 MFA 세션은 verifier에서 사용할 수 있다.
- 기기별 이름/목록/개별 연결 해제 UI, QR 이미지, 외부 provider 로그인 및
  모바일/브라우저별 사용성 검증은 이번 흐름 완료로 주장하지 않는다.

## 증거

- 2026-09-07 실제 Ternal API/CLI: Linux 격리 이미지
  `goauthy-ternal-device-e2e:20260907`에서 HTTPS GoAuthy 재시작 전 5.54초/후
  5.56초 PASS. CLI Device login, subject/groups, private0600 session schema,
  logout/local session 삭제 및 서버 authenticated=false 확인. 로그
  `/tmp/goauthy-ternal-device-isolated-public-20260907.log`, runner 종료 0.
  Host mounts/ports 없음, network none. Host session 메타데이터 실행 전후 동일.
  앞선 macOS 격리 실패 및 덮어쓰기 사건은 STATUS.md에 별도로 보존한다.

- 2026-09-07 수동 코드 입력 후속 검사: 기존 `device-review-20260907` 이미지에
  변경된 `device_oidc_test.go`, `device_oidc_ui_test.go`만 복사한 test-only overlay.
  서버 소스 변경 없음. `complete_uri`/`manual_code` 각각 cold login → 검토 → 승인
  → OIDC/refresh/revoke 검사. 재시작 전 2.57/2.22초, 후 2.26/2.26초 PASS.
  `/tmp/goauthy-device-manual-public-20260907.log`, runner 종료 0.

- 2026-09-07 승인 context 후속 후보 `goauthy-saas-oauth-e2e:device-review-20260907`:
  실제 Chromium의 정확한 client/scopes 표시·코드 확인·명시적 승인 및 OIDC
  재시작 전후 2.45/2.30초 PASS, runner 종료 0. 로그
  `/tmp/goauthy-device-review-public-20260907.log`, 화면
  `/tmp/goauthy-device-review-20260907.png`. 기존 계정 CSS를 재사용했다.
  Device 전체 단위 검사 37.598초 PASS. 아래 미표시 기록은 이전 후보의 상태다.

- 2026-09-07 최신 Chromium OIDC gate: `GOAUTHY_E2E_DEVICE_OIDC=1`과
  `GOAUTHY_E2E_DEVICE_OIDC_UI=1`을 함께 사용한다. 기존 격리 Dory test image의
  기본 SaaS workflow는 `GOAUTHY_E2E_REGISTERED_OAUTH2=0`으로 끈다.
  `GOAUTHY_E2E_DEVICE_OIDC_SCREENSHOT`은 컨테이너 내부 캡처 경로다.
  최종 소스 이미지 `goauthy-saas-oauth-e2e:device-native-final-20260907`의
  재시작 전후 3.97/3.35초 PASS. 로그
  `/tmp/goauthy-device-native-final-public-20260907.log`.
  네이티브 폼의 null Origin에 기존 login과 동일한 제한적 stdlib 검사를 적용했고
  subject/CSRF를 유지했다. 전체 device race 191.477초 PASS.
  승인 화면의 요청 앱/권한 표시는 미완료다. 기존 HTTP-only 결과와 구분한다.

- `/tmp/goauthy-device-public-ha-retry-20260906.log`: 새 Dory에서 종료 0.
  공통 E2E 15.500초; confidential 7.49/7.56초, public 1.90/2.41초,
  managed 1.99/2.23초. 동일 pending grant Pod 교체 chaos 5.54초 통과.
  종료 뒤 소유 Kind cluster/container 제거 확인. 첫 실행은 VM inotify 한도,
  두 번째는 Kind CNI stdin 대기에서 중단했고 이 실패들은 통과로 세지 않는다.
- `/tmp/goauthy-device-public-standalone-pass-20260906.log`: 종료 0.
  confidential 5.26/3.97초, public 1.13/1.39초, managed 1.67/0.92초.
  이전 실패들은 등록 fixture/정책 및 삭제된 등록의 idempotency replay 문제를
  드러냈으며 성공으로 세지 않는다. 새 실행은 새 등록 키를 사용한다.
- `/tmp/goauthy-device-public-standalone-replay-20260906.log`: 최종 public refresh
  replay `invalid_grant` 검사 추가 후 종료 0. confidential 4.24/3.70초,
  public 1.10/1.04초. 이 실행의 managed gate는 꺼져 있어 해당 skip을
  managed 검증으로 세지 않는다.
- `/tmp/goauthy-device-auth-final-20260906.log`: OAuth 인증/기존 grant 집중 검사 통과.
  `/tmp/goauthy-device-ambiguity-20260906.log`: 혼합·중복·malformed 인증 입력 통과.
  `/tmp/goauthy-device-http-final-20260906.log`: device 패키지 전체 통과.
  `/tmp/goauthy-device-dcr-verified-20260906.log`: HTTP 등록 회귀 검사 통과.
- `/tmp/goauthy-device-auth-race-20260906.log`: device 9.604초,
  OAuth 62.603초 집중 race 통과. 최종 vet 및 runner 구문/session-policy 통과.
- `/tmp/goauthy-device-pilot-standalone-20260906.log`: 종료 0.
  Device HTTP E2E 3.20초, 재시작 후 3.24초; managed-client도 두 번 통과.
- `/tmp/goauthy-device-pilot-ha-final-20260906.log`: Device 7.27초,
  Pod 교체 후 6.59초 통과. 관리 client 2.57/1.98초, 공통 E2E 15.040초.
  runner 종료 0 및 테스트 cluster 정리 확인.
  첫 HA 실행의 공통 smoke/전용 관리자 gate 분리 오류는 수정했으며
  이전 실패 로그는 통과로 세지 않는다.
- `internal/login/device_test.go`: 코드 보존, blank-code 수동 입력 경로,
  query/CSRF/일회용 interaction 및 강제 MFA 비밀번호 경계.
- `cmd/goauthy/main_test.go`: forced-MFA verifier의 password session 거절과
  MFA session 허용. 전체 관련 패키지 실행 결과는 status 문서에 기록한다.

모든 Rauthy 기능 및 RFC 8628 전체 완료 체크는 그대로 미완료다.
