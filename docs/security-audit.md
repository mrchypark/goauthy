# GoAuthy 보안 감사 보고서

## 감사 일시
2026-09-12

## 감사 범위
- internal/credential (패스워드 해싱)
- internal/browser (세션 관리, CSRF)
- internal/security (보안 헤더)
- internal/loginpolicy (로그인 정책)
- internal/ipblacklist (IP 차단)

---

## 1. 패스워드 보안 (internal/credential)

### 현재 상태
- **해싱 알고리즘**: Argon2id (OWASP 권장)
- **기본 정책**: m=19456 KiB, t=2, p=1
- **동시성 제한**: MaxConcurrency=2

### 발견된 취약점

#### [중요] V1: 패스워드 강도 검증 부족
현재 `validPassword()` 함수는 길이만 검증:
```go
func validPassword(password []byte) bool {
    return len(password) > 0 && len(password) <= maxPasswordBytes
}
```

**영향**: 약한 패스워드("123456", "password") 허용

**권장 조치**: 패스워드 정책 검증 함수 추가

#### [중요] V2: 일반 패스워드 차단 없음
Have I Been Pwned 등 알려진 유출 패스워드 차단 미구현

---

## 2. 세션 보안 (internal/browser)

### 현재 상태
- **세션 ID**: 32바이트 crypto/rand 기반
- **토큰 저장**: SHA-256 다이제스트만 저장
- **유휴 타임아웃**: 90분 (기본)
- **쿠키 속성**: HttpOnly, Secure, SameSite=Lax

### 발견된 취약점

#### [중간] V3: IP 바인딩 우회 가능성
`CheckPeerIP()`은 세션의 peer_ip가 비어있으면 항상 통과:
```go
func CheckPeerIP(session Session, currentPeerIP string) error {
    if session.PeerIP == "" {
        return nil  // 레거시 세션 허용
    }
    ...
}
```

**영향**: 레거시 세션에서 IP 변경 감지 불가

---

## 3. CSRF 보호 (internal/browser)

### 현재 상태
- **토큰 생성**: HMAC-SHA256 기반 결정적 토큰
- **검증**: 상수 시간 비교 (hmac.Equal)
- **바인딩**: 세션 토큰에 도메인 분리 바인딩

### 보안 평가: **양호**
- 토큰이 세션에 바인딩됨
- 상수 시간 비교로 타이밍 공격 방어
- Base64 인코딩 검증 엄격함

---

## 4. 보안 헤더 (internal/security)

### 현재 상태
- **HSTS**: max-age=63072000; includeSubDomains; preload
- **CSP**: default-src 'self'; style-src 'self' 'unsafe-inline'
- **X-Frame-Options**: DENY
- **X-Content-Type-Options**: nosniff

### 발견된 취약점

#### [중간] V4: CSP에서 'unsafe-inline' 허용
```go
ContentSecurityPolicy: "... style-src 'self' 'unsafe-inline'; ..."
```

**영향**: 인라인 스타일 기반 XSS 가능성

---

## 5. Rate Limiting (internal/loginpolicy)

### 현재 상태
- **로그인 시도**: 분당 20회 제한
- **실패 차단**: 7/10/15/20/25회 실패 시 점진적 차단
- **IP 블랙리스트**: 자동/수동 차단

### 보안 평가: **우수**
- 점진적 차단 (1분 → 24시간)
- 자동 IP 블랙리스트 연동
- 크로스-팟 보호

---

## 6. 종합 권장사항

### 즉시 조치 필요
1. 패스워드 정책 강화 함수 구현
2. 일반 패스워드 차단 목록 추가

### 단기 조치 (1-2주)
3. CSP에서 nonce 기반 인라인 스타일 허용
4. 레거시 세션 마이그레이션 계획

### 중기 조치 (1개월)
5. 패스워드 만료 정책 구현
6. 감사 로그 강화

---

## 7. 검증 결과 요약

| 영역 | 등급 | 비고 |
|------|------|------|
| 패스워드 해싱 | A | Argon2id, OWASP 권장 |
| 패스워드 정책 | C | 강도 검증 부족 |
| 세션 관리 | A- | IP 바인딩 우화 가능 |
| CSRF 보호 | A | HMAC 기반, 상수 시간 |
| 보안 헤더 | B+ | CSP 'unsafe-inline' |
| Rate Limiting | A | 점진적 차단, 자동 블랙리스트 |
