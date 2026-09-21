# GoAuthy 보안 아키텍처

이 문서는 GoAuthy의 보안 아키텍처와 구현된 보안 제어에 대해 설명합니다.

## 목차

1. [보안 원칙](#보안-원칙)
2. [패스워드 보안](#패스워드-보안)
3. [세션 관리](#세션-관리)
4. [CSRF 보호](#csrf-보호)
5. [Rate Limiting](#rate-limiting)
6. [보안 헤더](#보안-헤더)
7. [IP 블랙리스트](#ip-블랙리스트)
8. [Geo-blocking](#geo-blocking)
9. [DPoP (Demonstrating Proof-of-Possession)](#dpop)
10. [Audience contract](#audience-contract)
11. [감사 로깅](#감사-로깅)
12. [설정 가이드](#설정-가이드)

---

## 보안 원칙

GoAuthy는 다음 보안 원칙을 따릅니다:

1. **Defense in Depth**: 다층 보안 제어
2. **Least Privilege**: 최소 권한 원칙
3. **Fail Secure**: 실패 시 안전한 기본값
4. **Zero Trust**: 모든 요청 검증

### 준수 표준

- **NIST SP 800-63B**: 디지털 인증 가이드라인
- **OWASP Top 10**: 웹 애플리케이션 보안 위협
- **RFC 6749/6750**: OAuth 2.0
- **RFC 9449**: DPoP
- **RFC 8628**: Device Authorization Grant

---

## 패스워드 보안

### 해싱 알고리즘

GoAuthy는 **Argon2id v=19**를 사용합니다:

```
파라미터 (기본값):
- m (메모리): 19456 KiB (19 MiB)
- t (반복): 2
- p (병렬화): 1
- 최대 동시성: 2
```

### 패스워드 정책

기본 패스워드 정책:

| 파라미터 | 기본값 | 설명 |
|---------|--------|------|
| LengthMin | 14 | 최소 길이 |
| LengthMax | 128 | 최대 길이 |
| LowerCase | 1 | 최소 소문자 수 |
| UpperCase | 1 | 최소 대문자 수 |
| Digits | 1 | 최소 숫자 수 |
| History | 3 | 패스워드 이력 |
| ValidDays | 0 | production에서는 패스워드 자동 만료 비활성화 |
| BlockCommonPasswords | true | 일반 패스워드 차단 |
| MinEntropyBits | 60 | 최소 엔트로피 비트 |

`credential.DefaultRules()` 자체에는 과거 호환을 위한 `ValidDays=180` 기본값이
남아 있지만, 현재 production startup은 이를 `0`으로 고정하며
`GOAUTHY_PASSWORD_VALID_DAYS`의 0이 아닌 값을 거절한다. 따라서 실제 서버의
기본 동작은 기간 기반 패스워드 만료를 사용하지 않는다. 만료 정책을 다시 노출하려면
reset/self-service lifecycle과 함께 별도 제품 기능으로 검증해야 한다.

### 일반 패스워드 차단

NIST SP 800-63B 섹션 5.1.1.2에 따라 다음 패스워드가 차단됩니다:

- 알려진 일반 패스워드 (상위 1000개)
- 사전 단어
- 반복 패턴
- 키보드 패턴

### 엔트로피 검사

패스워드 엔트로피는 문자셋 크기와 길이를 기반으로 계산됩니다:

```
엔트로피 = length × log2(charsetSize)
```

- 소문자: 26
- 대문자: 26
- 숫자: 10
- 특수문자: 33

최소 60 비트 엔트로피가 필요합니다.

### 패스워드 재해싱

성공적인 로그인 후, 저장된 패스워드가 현재 정책보다 약하면 자동으로 재해싱됩니다:

```go
// 자동 재해싱 조건
if target.memory > stored.memory || 
   target.time > stored.time || 
   target.parallelism > stored.parallelism {
    // 재해싱 수행
}
```

---

## 세션 관리

### 쿠키 보안

세션 쿠키는 다음 보안 속성을 가집니다:

| 속성 | 값 | 설명 |
|------|-----|------|
| HttpOnly | true | JavaScript 접근 차단 |
| Secure | true (HTTPS) | HTTPS에서만 전송 |
| SameSite | Lax | CSRF 보호 |
| Path | / | 전체 경로 |
| __Host- 프리픽스 | true (HTTPS) | 쿠키 보안 강화 |

### 세션 수명

- **기본 유휴 타임아웃**: 90분
- **세션 IP 바인딩**: 세션 생성 시 IP 기록
- **피어 IP 검증**: 요청 시 IP 일치 확인

### 세션 무효화

세션은 다음 경우에 무효화됩니다:

1. 유휴 타임아웃 초과
2. 절대 만료 시간 초과
3. 명시적 로그아웃
4. 패스워드 변경
5. 관리자 강제 로그아웃

### FedCM 세션

FedCM은 별도의 세션 쿠키를 사용합니다:

```
쿠키 이름: __Host-goauthy_fedcm_session
SameSite: None (cross-site 필요)
Secure: true
```

---

## CSRF 보호

### Double Submit Cookie 패턴

GoAuthy는 세션 토큰에서 파생된 CSRF 토큰을 사용합니다:

```go
// CSRF 토큰 생성
func DeriveCSRFToken(sessionToken string) (string, error) {
    mac := hmac.New(sha256.New, raw)
    mac.Write([]byte(csrfDomain))
    return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
```

### 검증 프로세스

1. **X-CSRF-Token 헤더** 검증
2. **Sec-Fetch-Site** 검증 (cross-site 차단)
3. **Origin/Referer** 검증

### Fetch Metadata 보호

```go
// Sec-Fetch-Site 검증
if fetchSite == "cross-site" {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}
```

---

## Rate Limiting

### 로그인 보호

로그인 시도에 대한 rate limiting:

| 실패 횟수 | 차단 시간 |
|----------|----------|
| 7회 | 1분 |
| 10회 | 10분 |
| 15회 | 15분 |
| 20회 | 1시간 |
| 25회+ | 24시간 |

### 패스워드 재설정 제한

- **윈도우**: 1분
- **제한**: 5회/분

### 오픈 등록 제한

- **윈도우**: 1분
- **제한**: 5회/분

### 디바이스 흐름 제한

- 직접 TCP 피어 기반
- 포워딩 헤더 무시 (명시적 신뢰 프록시 없이)

---

## 보안 헤더

### 기본 보안 헤더

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-Permitted-Cross-Domain-Policies: none
Cache-Control: no-store, no-cache, must-revalidate
```

### API 전용 헤더

```http
Referrer-Policy: no-referrer
Cache-Control: no-store
```

### 정적 리소스 헤더

```http
X-Frame-Options: SAMEORIGIN
Cache-Control: public, max-age=31536000, immutable
```

---

## IP 블랙리스트

### 자동 블랙리스트

로그인 실패 시 자동으로 IP가 블랙리스트에 추가됩니다:

| 실패 횟수 | 블랙리스트 기간 |
|----------|----------------|
| 7회 | 1분 |
| 10회 | 10분 |
| 15회 | 15분 |
| 20회 | 1시간 |
| 25회+ | 24시간 |

### 수동 블랙리스트

관리자가 수동으로 IP를 블랙리스트에 추가할 수 있습니다:

```bash
# 영구 차단
curl -X POST /auth/v1/blacklist \
  -H "Authorization: Bearer <token>" \
  -d '{"prefix": "192.168.1.0/24", "note": "악의적인 활동"}'

# 만료 시간 있는 차단
curl -X POST /auth/v1/blacklist \
  -d '{"prefix": "10.0.0.0/8", "expires_at": "2024-12-31T23:59:59Z"}'
```

---

## Geo-blocking

### 설정

```bash
GOAUTHY_GEOBLOCK_ENABLED=true
GOAUTHY_GEOBLOCK_MODE=allow  # 또는 deny
GOAUTHY_GEOBLOCK_COUNTRIES=KR,JP,US
```

### 모드

- **allow**: 지정된 국가만 허용
- **deny**: 지정된 국가 차단

### 신뢰 프록시

```bash
GOAUTHY_GEOBLOCK_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12
GOAUTHY_GEOBLOCK_COUNTRY_HEADER=X-Country
```

---

## DPoP

### 지원 알고리즘

- EdDSA (Ed25519)
- ES256 (ECDSA P-256)
- RS256 (RSA-SHA256)

### nonce 보호

- 서버 발행 nonce 사용
- replay 방지
- 다중 Pod 환경에서 안전

---

## Audience contract

`internal/oauth/forward_auth.go`의 `forward_auth` 핸들러는 리버스 프록시를 위한 인증 게이트이며,
보호 리소스별 audience 격리를 구현하지 않습니다. 이 동작은 누락이 아니라 결정된 계약입니다.

1. **게이트 조건**: `openid` 스코프를 가진 살아 있는 사용자 액세스 토큰, 살아 있는 클라이언트,
   비어 있지 않은 subject, 통과하는 클라이언트 그룹 정책을 모두 만족할 때만 요청을 허용합니다.
2. **리소스별 audience 격리 없음**: 한 리소스를 위해 발급된 사용자 토큰은 프록시가 보호하는
   다른 리소스에도 그대로 허용됩니다. 보호 리소스 사이의 격리는 프록시의 책임이며, 프록시가 어떤
   클라이언트와 그룹 정책을 요구하는지로 표현합니다. 따라서 액세스 토큰의 `aud`와 보호 리소스를
   비교하는 검사는 의도적으로 없습니다.
3. **거부 대상**: DPoP 바인딩 토큰, 사용자 토큰이 아닌 토큰(예: client credentials), 알 수 없는
   클라이언트는 거부합니다.

이 계약은 `internal/oauth/forward_auth_audience_contract_test.go`가 고정하고, 엔드투엔드 경로는
`scripts/e2e-forward-auth-standalone.sh`가 검증합니다.

---

## 감사 로깅

### 이벤트 유형

| 이벤트 | 설명 |
|--------|------|
| login_success | 성공적인 로그인 |
| login_failure | 실패한 로그인 |
| password_change | 패스워드 변경 |
| session_create | 세션 생성 |
| session_revoke | 세션 무효화 |
| ip_blacklisted | IP 블랙리스트 추가 |
| mfa_enabled | MFA 활성화 |

---

## 설정 가이드

### 프로덕션 권장 설정

```bash
# 패스워드 해싱
GOAUTHY_ARGON2_MEMORY_KIB=32768
GOAUTHY_ARGON2_ITERATIONS=3
GOAUTHY_ARGON2_PARALLELISM=2
GOAUTHY_ARGON2_MAX_CONCURRENCY=2

# 세션
GOAUTHY_SESSION_IDLE_TIMEOUT=30m

# Rate Limiting
GOAUTHY_RATE_LIMIT_ENABLED=true

# 보안 헤더
GOAUTHY_HSTS_ENABLED=true

# Geo-blocking (선택)
GOAUTHY_GEOBLOCK_ENABLED=true
GOAUTHY_GEOBLOCK_MODE=allow
GOAUTHY_GEOBLOCK_COUNTRIES=KR
```

### 개발 환경 설정

```bash
# 패스워드 해싱 (빠른 테스트)
GOAUTHY_ARGON2_MEMORY_KIB=19456
GOAUTHY_ARGON2_ITERATIONS=2
GOAUTHY_ARGON2_PARALLELISM=1

# HTTPS 비활성화
GOAUTHY_TLS_ENABLED=false
```

---

## 보안 체크리스트

### 배포 전 확인사항

- [ ] HTTPS 활성화
- [ ] HSTS 설정
- [ ] CSP 정책 검토
- [ ] Rate limiting 활성화
- [ ] IP 블랙리스트 활성화
- [ ] 감사 로깅 활성화
- [ ] 패스워드 정책 검토
- [ ] 세션 타임아웃 검토

### 정기 검토

- [ ] 보안 헤더 검증
- [ ] 패스워드 정책 준수 확인
- [ ] 감사 로그 검토
- [ ] 블랙리스트 상태 확인
- [ ] 세션 관리 정책 검토

---

## 관련 문서

- [features.md](features.md) - 전체 기능 목록
- [status.md](status.md) - 현재 상태
- [passkey-bootstrap.md](passkey-bootstrap.md) - 패스키 설정
- [backup-operator.md](backup-operator.md) - 백업 운영
