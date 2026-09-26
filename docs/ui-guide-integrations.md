# 관리자 통합 설정 안내

이 문서는 OAuth 클라이언트, 사용자 속성·스코프, 인증 컬렉션, SaaS 제공자를 설정하는 운영 흐름과 현재 HTTP 테스트의 검증 범위를 정리합니다. 화면을 저장해도 API 계약이나 외부 제공자 설정이 자동으로 완료되는 것은 아니므로, 각 단계의 서버 응답과 실제 연동 조건을 함께 확인하세요.

## OAuth 클라이언트 등록

1. `Clients`에서 **New client**를 누르고 서비스 안에서 고유한 `Client ID`와 알아보기 쉬운 이름을 입력합니다. ID는 2–256자의 영문자, 숫자, 점, 밑줄, 하이픈으로 구성합니다.
2. 브라우저 기반 웹 앱이면 `Web` 프리셋을, 사용자 코드 승인을 사용하는 기기 앱이면 `Device` 프리셋을 선택합니다. 프리셋은 입력값을 채우는 편의 기능이므로 저장 전 리디렉션 URI, 스코프, 기본 스코프, 허용 플로를 검토하세요.
3. 공개 클라이언트에는 비밀이 없습니다. 공개 클라이언트에 `client_credentials` 플로를 지정할 수 없습니다. Authorization Code 플로에는 리디렉션 URI가 필요합니다.
4. 필요한 HTTPS 리소스 대상을 `Resource audiences`에 한 줄씩 입력하고 허용·기본 스코프를 별도로 설정합니다. `Force MFA`는 이 클라이언트의 로그인 정책에 적용됩니다.
5. **Create client**를 누릅니다. 편집 시 서버 revision을 조건으로 저장하므로 다른 운영자가 먼저 변경한 경우 충돌 오류를 확인하고 최신 값을 불러온 다음 다시 편집하세요.

편집 화면에서 비밀 값은 요청할 때만 읽거나 교체할 수 있습니다. **Rotate secret**은 기존 비밀을 즉시 무효화합니다. 교체된 새 값은 화면을 떠나기 전에 소비자 서비스의 비밀 저장소에 반영하고 동작을 검증하세요. 저장 응답에 revision이 없으면 추가 변경 전에 페이지를 다시 불러오도록 UI가 안내합니다. 클라이언트 삭제는 확인 후 진행되며 해당 ID는 재사용할 수 없습니다.

### 클라이언트별 로그인 화면 꾸미기

관리자 **클라이언트 → 꾸미기** 또는 클라이언트 편집 화면의 **로그인 화면** 링크에서 `/auth/v1/admin/clients/{id}/theme`으로 이동합니다.

1. 수정할 OAuth 클라이언트에서 **로그인 화면**을 엽니다. 이 설정은 선택한 클라이언트의 OIDC 로그인 화면에 적용됩니다. 계정 화면, 관리자 화면, 다른 클라이언트의 로그인 화면 전체를 꾸미는 설정은 아닙니다.
2. Light와 dark 각각의 7개 색 토큰을 조정합니다: `text`(글자), `text_high`(강조 글자), `bg`(배경), `bg_high`(강조 배경), `action`(주요 동작), `accent`(강조), `error`(오류). 각 모드의 버튼 글자색(`btn_text`)과 공통 모서리 반경(`border_radius`)도 조정할 수 있습니다.
3. 값 변경은 비인증 미리보기에 반영됩니다. 미리보기는 디자인을 확인하는 화면이며 로그인, 클라이언트 권한 변경, 자격 증명 작업을 수행하지 않습니다.
4. **테마 저장**을 눌러야 해당 클라이언트의 명시적 테마 override로 저장됩니다. 미리보기만 바꾸고 저장하지 않으면 적용되지 않습니다.
5. 저장된 값으로 돌아가려면 편집기를 다시 불러옵니다. 다시 불러오면 저장하지 않은 로컬 변경은 버려집니다.
6. **공통 테마 상속으로 복원 → 복원 확인**은 이 클라이언트의 override를 삭제합니다. 이후 클라이언트 로그인 화면은 전역 `rauthy` 테마를 사용하고, 전역 테마가 없으면 기본 테마로 fallback합니다.

로고는 PNG·JPEG·SVG 파일을 선택해 별도로 업로드합니다. 업로드·삭제는 즉시 저장되며, 테마 저장/복원과 별개입니다. 서버에서 이미지 검증과 SVG 정제를 수행합니다. 로고 삭제 시 공통 로고가 있으면 상속하고, 없으면 GoAuthy 기본 표시로 돌아갑니다.

한국어·영어별 로그인 제목·안내문·버튼 문구를 입력할 수 있습니다(각 120·500·60자 제한). 빈 한국어 항목은 영어 항목을 사용하고, 영어도 비어 있으면 기본 문구를 사용합니다. 일반 텍스트이므로 HTML은 실행하지 않습니다. 문구는 OAuth 로그인 화면에 적용하며 MFA·패스키 단계의 보안 안내, 계정 로그인, 가입·복구 화면은 기존 문구를 유지합니다.

로고 정렬과 카드 너비(320–640px, 기본값 선택 가능), light/dark 색상, 버튼 글자색, 모서리를 함께 조정할 수 있습니다. 문구와 레이아웃은 **테마 저장** 시 적용되며, 저장 전 변경은 이 브라우저 편집기의 미리보기에만 반영됩니다. 영구 초안·게시 이력·이전 버전 복원 기능과 자유 HTML·스크립트 편집은 이번 단계에 포함하지 않습니다. 이 기능은 기존 클라이언트별 테마 모듈과 theme API를 사용하며 OAuth 클라이언트의 권한, 플로, 리디렉션 URI, 비밀 값은 변경하지 않습니다. 실제 로컬 브라우저에서 저장·새로고침·라이트/다크 값 유지와 실제 OAuth 로그인 CSS 반영을 확인했습니다. 회귀 검사는 공통 테마 상속, 저장 실패, 중복 제출, 복원을 포함합니다.

## 사용자 속성과 스코프

`User attributes`는 사용자별 클레임 값을 정의하고, `Scopes`는 어떤 속성을 ID 토큰 또는 access token 클레임에 포함할지 정의합니다. 둘은 별도 항목이므로 속성만 만들었다고 토큰에 자동 포함되지는 않습니다.

1. `User attributes`에서 새 속성을 만들고 안정적인 이름을 지정합니다. 선택 항목은 설명(최대 128자), 기본값(JSON), 유형, `User editable`입니다. 기본값을 입력한다면 JSON 값 전체가 유효해야 합니다. 사용자 편집 허용은 해당 값의 변경 경로를 여는 정책이므로 꼭 필요한 속성에만 켜세요.
2. `Scopes`에서 새 스코프 이름을 만들고 access-token 및 ID-token에 포함할 속성 이름을 각각 쉼표로 구분해 지정합니다. `Put claims at root`는 포함된 클레임의 JSON 위치를 바꾸므로 소비자 토큰 파서를 확인한 뒤 선택하세요.
3. 클라이언트의 허용 스코프와 기본 스코프에 필요한 스코프를 추가합니다. 토큰에서 실제 값을 확인해 속성 이름, 스코프 허용 여부, 토큰 종류를 함께 진단하세요.

이 화면은 속성·스코프 카탈로그를 관리합니다. 사용자 개별 값의 입력은 사용자/계정 속성 편집 흐름에서 하며, 해당 화면의 규칙에 따라 값이 생성되거나 사용자가 편집할 수 있습니다. 속성 이름과 스코프 이름은 소비자 계약이므로 변경 전에 기존 토큰 사용처를 조사하세요.

## 인증 컬렉션 정의

인증 컬렉션은 계정 연결에 필요한 메타데이터 필드와 인증 방식을 정의합니다. 관리 화면의 설명에 있는 것처럼 컬렉션 정의와 draft 연결은 제공자 인증을 시작하거나 자격 증명을 저장하는 동작과 다릅니다.

1. `Collections`에서 **New collection**을 누르고 고유한 ID와 이름을 입력합니다. ID는 2–128자의 영문 소문자, 숫자, 점, 밑줄, 하이픈으로 구성합니다.
2. `Authentication method`를 `OAuth 2`, `API key`, `Device flow` 중에서 고릅니다. 이 값은 서버에 전송되는 기술 enum이므로 번역된 화면에서도 그대로 유지됩니다.
3. 필요하면 제공자 ID를 한 줄에 하나씩 추가합니다. ID는 고유한 소문자 형식(최대 32개)이어야 합니다. OAuth에서 목록이 비어 있으면 제공자를 허용하지 않고, 연결된 API key 설정에서 비어 있으면 legacy 암호화 저장 경로가 적용됩니다. API key 컬렉션은 제공자 ID를 최대 하나만 허용하고, device flow 컬렉션은 제공자 ID를 허용하지 않습니다.
4. metadata field를 추가해 필드 이름, 유형(`string`, `boolean`, `integer`, `enum`), 필수 여부를 정합니다. 문자열에만 최대 길이를 지정하고, enum에는 문자열 배열인 JSON `Options`를 지정합니다. 최대 32개 필드를 정의할 수 있습니다. 필드 제거·수정은 기존 연결 데이터와의 호환성을 검토한 뒤 하세요.
5. **Create collection** 또는 **Save changes** 후 목록으로 돌아가 revision을 확인합니다. 편집과 삭제는 revision으로 보호됩니다. 기존 컬렉션의 제공자 ID를 제거하면 연결이 영구 취소될 수 있어 확인창이 표시됩니다. 서버가 기존 연결 때문에 정의 변경을 거부하면 최신 연결 상태를 확인하세요.

저장된 컬렉션을 사용자 연결로 만드는 작업, 실제 OAuth 인증, API key 등록, 소비자 서비스에 대한 grant는 별도 사용자 계정 흐름입니다. 컬렉션 생성 성공만으로 이 후속 동작을 검증한 것으로 보지 마세요.

## SaaS 제공자 등록

`Providers`는 컬렉션에서 참조하는 upstream 연결 설정을 관리합니다. 실제 계정 인증·토큰 교환은 사용자가 해당 연결 절차를 완료할 때 일어납니다.

### OAuth 2 제공자

1. **New provider**에서 ID와 이름을 정하고 `Kind`를 `OAuth 2`로 둡니다.
2. 제공자 측에 등록한 callback URI, client ID/secret, authorization/token endpoint, scope를 입력합니다. `Auth style`은 제공자의 token endpoint 계약에 맞춰 HTTP Basic 헤더 또는 form POST 파라미터를 선택합니다.
3. 선택적으로 identity/userinfo endpoint와 JSON subject claim 경로를 입력합니다. 이 값은 GoAuthy 내부 연결 주체를 식별하는 제공자 응답 필드에 맞아야 합니다.
4. 생성하거나 저장한 뒤 테스트 계정으로 연결·콜백·상태 확인을 검증합니다. 편집에서 secret을 비워 두면 기존 값이 유지됩니다. secret을 새 값으로 보내면 제공자 자격 증명이 교체됩니다.

### API key 제공자

`Kind`를 `API key`로 선택하고 connector JSON을 작성합니다. 설정의 `id`는 provider ID와 같아야 하며, header와 prefix, 허용 operation, 각 operation의 HTTPS URL 및 response field schema를 정의합니다. 올바른 JSON이어도 operation 주소나 반환 schema가 실제 API와 맞지 않으면 실행은 실패할 수 있습니다. 키 값 자체는 connector 설정이 아니라 사용자의 연결 키 등록 흐름에서 저장합니다.

제공자를 삭제할 때는 연결된 컬렉션·사용자 연결 및 grant에 대한 서버 제한을 먼저 확인하세요. 변경 요청에는 revision 검사가 적용되어 충돌하면 새 값을 불러와야 합니다. 화면에서 저장 성공을 보았다는 사실만으로 외부 OAuth 서버 또는 API의 가용성을 증명하지는 않습니다.

## HTTP 통합 테스트와 실행 조건

아래 E2E 테스트는 `net/http` 요청으로 프로토콜/API를 확인하며 Chrome, chromedp, Playwright를 실행하지 않습니다. 단, 일부는 `test/e2e/browser` 디렉터리에 있으므로 반드시 표시된 `-run` 정규식으로 대상 함수만 지정하세요. 이 테스트들은 생성한 클라이언트·제공자·컬렉션·연결·사용자·그룹·grant를 원격 배포에 기록합니다. 정리 코드를 갖춘 경우에도 중간 종료나 프로세스 강제 종료 시 찌꺼기가 남을 수 있으므로 격리된 폐기 가능 배포에서만 실행하세요.

| 범위 | 실행 명령 | 필수 fixture / 부작용 | 확인하는 것과 한계 |
|---|---|---|---|
| Managed OAuth client | `go test -count=1 -v ./test/e2e -run '^TestManagedClientsHTTPWorkflow$'` | `GOAUTHY_E2E_MANAGED_CLIENTS=1`, `GOAUTHY_E2E_URL`, `GOAUTHY_E2E_SECONDARY_URL`, `GOAUTHY_E2E_BROWSER_USERNAME`, `GOAUTHY_E2E_BROWSER_PASSWORD`. 생성한 임의 ID client를 삭제하는 정리 절차가 있음. | revision, secret read/rotate, enable/disable, token 사용, 삭제 및 두 URL에서의 상태를 확인. 동일 URL 두 번 지정하면 단일 인스턴스에서만 동작 확인이며 HA 증거가 아님. |
| OAuth/API-key provider CRUD | `go test -count=1 -v ./test/e2e/browser -run '^TestProviderRegistrationLive$'` | `GOAUTHY_E2E_PROVIDER_REGISTRATION=1` 및 `browserE2EConfig`의 두 URL과 관리자 계정. 임의 ID 제공자를 생성하고 revision으로 삭제. 등록 단계는 테스트 주석상 upstream에 요청하지 않음. | secret 미노출, identity metadata 유지, CAS, OAuth/API-key 입력 검증과 삭제를 확인. 실제 upstream 로그인/토큰 교환은 확인하지 않음. |
| Collections across nodes | `go test -count=1 -v ./test/e2e/browser -run '^TestAuthCollectionsAcrossPods$'` | `GOAUTHY_E2E_AUTH_COLLECTIONS=1`, primary/secondary/tertiary 세 URL, 관리자 계정, client secret, `GOAUTHY_E2E_SMTP_SINK_URL`. 새 컬렉션·일반 사용자·연결을 만들고 메일 sink를 조회한 후 정리. chaos 하위 흐름은 `GOAUTHY_E2E_AUTH_COLLECTIONS_CHAOS=1`일 때만 추가 Kubernetes context/namespace/pod fixture가 필요. | 여러 노드에서 컬렉션/연결 흐름 및 revision 경계를 확인. SMTP sink 없이는 시작 불가. 기기코드 UI나 실제 upstream OAuth 연결을 대신 검증하지 않음. |
| Connection-use grants | `go test -count=1 -v ./test/e2e/browser -run '^TestConnectionUseGrantLive$'` | `GOAUTHY_E2E_USE_GRANTS=1`와 `browserE2EConfig`의 primary/secondary URL, 관리자 계정, client secret. 테스트가 임시 API-key provider, collection, 계정 연결, 소비자 client와 grant/key를 만들고 삭제. baseline에서는 `GOAUTHY_E2E_GRANT_UI`, `GOAUTHY_E2E_REGISTERED_KEY_UI`, `GOAUTHY_E2E_CREDENTIAL_DELIVERY`, `GOAUTHY_E2E_HANDOFF`를 설정하지 마세요. | 권한 경계, 키 결합/회전, grant 생성/취소 및 선택적으로 HTTP invoke/status(`GOAUTHY_E2E_GRANT_INVOKE=1`, `GOAUTHY_E2E_GRANT_STATUS=1`)를 확인. 외부 API 호출을 별도 활성화하지 않는 baseline도 실제 원격 서비스 동작은 증명하지 않음. |
| Device authorization protocol | `go test -count=1 -v ./test/e2e/browser -run '^TestDeviceAuthorizationAcrossPods$'` | `browserE2EConfig`의 두 URL, tertiary URL, 사용자 계정, client secret. device grant를 발급·승인·거부하고 토큰 만료를 확인. 사용자 승인은 HTTP 요청으로 처리. | pending/slow-down/승인/거부/만료 및 노드 간 토큰 사용을 확인. 관리자 멤버십을 바꾸지는 않지만 실제 device flow가 있는 격리 배포에서만 실행. |
| Device OIDC lifecycle | `go test -count=1 -v ./test/e2e/browser -run '^TestDeviceOIDCLive$'` | `GOAUTHY_E2E_DEVICE_OIDC=1`, primary/secondary/tertiary URL, 관리자 계정, client secret. 테스트가 임시 그룹을 만들고 bootstrap-admin 그룹 멤버십을 변경했다가 원복. `GOAUTHY_E2E_DEVICE_OIDC_UI`는 반드시 미설정/0으로 두어 HTTP 경로 사용. | 기기 승인·ID/access/refresh token, 그룹 갱신, revoke를 확인. 관리자 멤버십을 변경하므로 공유 프리뷰에서는 금지. UI 자동화는 별도 UI 플래그가 필요하므로 여기서는 실행하지 않음. |

`test/e2e/browser`라는 경로명은 그 패키지의 일부 테스트가 브라우저 자동화를 한다는 뜻입니다. 위 표의 선택한 테스트 함수는 코드 경로를 확인했을 때 `net/http` 클라이언트만 사용합니다. 특히 디바이스 테스트에서 `GOAUTHY_E2E_DEVICE_OIDC_UI=1`을 설정하면 승인에 UI 자동화가 선택되므로 본 HTTP 테스트 명령에서는 지정하지 않습니다. 테스트 프로세스가 실패해 cleanup이 실행되지 않은 경우 임의 접두사 `managed-e2e-`, `provider-`, `auth-collections-`, `device-oidc-`, `use-grant-`를 가진 fixture가 남을 수 있습니다.

### `localhost:18120` 프리뷰에서의 제한

이 작업에서는 프리뷰에 쓰기 요청을 보내지 않았습니다. `18120`이 공유 단일 인스턴스라면 위 테스트를 직접 실행하지 마세요. 대부분 fixture를 생성·변경·삭제하고, collections/device OIDC 테스트는 사용자·멤버십까지 바꿉니다. 둘 또는 세 URL 환경변수에 `18120` 하나를 반복 지정해도 서로 다른 노드 상태를 검증하지 못합니다. 프리뷰의 비변경 readiness 확인은 `curl -fsS http://localhost:18120/readyz`이며 이는 로그인·권한·영속성·다중 노드 동작을 검증하지 않습니다.

Managed client 테스트는 `scripts/e2e-standalone.sh`가 `GOAUTHY_E2E_MANAGED_CLIENTS=1`일 때 격리 임시 DB에 대해 실행하는 지원 경로가 있습니다. 기본 포트는 `18081`이고, 이 스크립트는 빌드·서버 시작/종료를 직접 수행하므로 공유 `18120`을 재시작하는 용도로 사용하면 안 됩니다. provider/collection/grant/device 전체 E2E를 단일 standalone으로 바꾸어 실행하는 공식 fixture recipe는 이 조사에서 확인하지 못했습니다.

## 확인한 테스트 증거와 미검증 항목

이 작업에서 통과한 focused Node checks는 `catalog_ui_test.js`, `clients_ui_test.js`, `collections_ui_test.js`, `providers_ui_test.js`입니다. 로컬 HTTP handler/store 검증 `go test ./internal/rbac ./internal/authcollection ./internal/saas ./internal/ipblacklist ./internal/claims ./internal/device ./internal/eventlog`도 통과했습니다.

이 작업 중 위 원격 E2E 명령은 실행하지 않았습니다. 따라서 문서에 적힌 fixture의 실제 현재 배포 준비 여부, preview 18120의 권한·영속성 설정, 외부 제공자/API 연동, SMTP 수신, 둘 이상의 실제 pod 간 복제, 장애 후 정리 동작은 확인되지 않았습니다. Node UI fixture는 요청 payload와 화면 상태를 검증하지만 실제 로그인·CSRF·서버 권한이나 DB persistence를 단독으로 증명하지 않습니다. 이를 확인하려면 별도 폐기 가능 배포에서 표에 적힌 fixture를 준비하고 지정 E2E만 실행해야 합니다.

추가로 요청된 `TestAdminUserCreateLifecycle`은 HTTP 전용 테스트지만 공유 preview에서 실행하지 않았습니다. 실행 gate는 `GOAUTHY_E2E_ADMIN_USER_CREATE=1`이며 관리자 로그인 설정과 `GOAUTHY_E2E_SMTP_SINK_URL`이 필요합니다. 테스트는 고정 멤버 이메일 `admin-created@goauthy.e2e`를 생성하고 남겨 두며, activation password 문자열은 [`admin_user_create_test.go`](../test/e2e/browser/admin_user_create_test.go#L109)에 있습니다(비밀 값은 문서화하지 않음). 이 고정 계정이 이미 있으면 create 단계에서 충돌할 수 있고, 이 테스트는 그 계정을 삭제하지 않습니다. 현재 셸에는 테스트 URL·계정·SMTP 설정이 없었고 readiness만 `curl -fsS http://localhost:18120/readyz`로 확인됐으므로 HTTP E2E 요청은 보내지 않았습니다. 이 테스트도 독립 폐기 fixture에서만 실행하세요.

별도 `TestAdminUserUpdateAcrossPods` 흐름은 새 사용자 생성 시 역할 목록을 빈 배열로 만들고, 최종 이메일을 `admin-updated@goauthy.e2e`로 바꾸며 역할도 빈 배열로 유지합니다([`admin_user_update_test.go`](../test/e2e/browser/admin_user_update_test.go#L21), [`admin_user_update_test.go`](../test/e2e/browser/admin_user_update_test.go#L46)). 테스트가 실제 실행된 배포에서 남아 있는 비관리자 fixture일 가능성은 있지만, 이 작업에는 해당 테스트를 실행할 접속 설정이 없어 현재 preview에서 존재 여부나 상태를 조회하지 않았습니다. 비밀번호 상수의 정의 위치는 같은 파일 22행입니다.
