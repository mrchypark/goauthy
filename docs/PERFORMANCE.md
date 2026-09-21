# Goauthy 성능 최적화 가이드

## 개요

이 문서는 goauthy의 성능 최적화 아키텍처와 벤치마크 결과를 설명합니다.

## 최적화 아키텍처

### 1. 인메모리 캐시 (`internal/cache`)

샤딩된 TTL/LRU 캐시로, 인증 서버의 핫 패스에서 linearizable 데이터베이스 읽기를 줄입니다.

**특징:**
- 파워-오브-2 샤딩으로 lock contention 최소화
- TTL 기반 만료 + LRU 제거
- 타입 안전 제네릭 구현
- 원자적 메트릭 추적 (히트율, 미스, 제거)

**캐시 적용 대상:**

| 캐시 | TTL | 최대 항목 | 대상 |
|------|-----|-----------|------|
| 세션 캐시 | 5초 | 8,192 | 브라우저 세션 |
| 사용자 캐시 | 30초 | 4,096 | identity_users |
| 프로필 캐시 | 30초 | 4,096 | identity_user_profiles |
| Principal 캐시 | 30초 | 4,096 | RBAC 역할/그룹 |
| API 키 캐시 | 30초 | 1,024 | API 키 인증 |

### 2. 동시성 개선

**Argon2 해셔 큐잉:**
- 기본 동시성: 2 → 4 슬롯으로 증가
- 대기 타임아웃: 100ms (즉시 거부 대신 짧은 대기)
- 컨텍스트 취소 지원

### 3. 메트릭 확장

**새로운 메트릭:**
- `goauthy_db_query_duration_seconds` - 데이터베이스 쿼리 지연시간
- `goauthy_cache_hits_total` - 캐시 히트 수
- `goauthy_cache_misses_total` - 캐시 미스 수
- `goauthy_cache_evictions_total` - 캐시 제거 수

## 벤치마크 결과

### 캐시 성능 (Apple M3)

```
BenchmarkCacheGetHit-8          11,392,129    124.9 ns/op    13 B/op    1 allocs/op
BenchmarkCacheGetMiss-8         18,471,578     66.9 ns/op    24 B/op    2 allocs/op
BenchmarkCacheSet-8              5,552,770    261.0 ns/op    59 B/op    3 allocs/op
BenchmarkCacheSetParallel-8     10,594,075    143.5 ns/op    28 B/op    2 allocs/op
BenchmarkCacheGetParallel-8      9,642,370    123.1 ns/op    15 B/op    1 allocs/op
```

### Argon2 해셔 성능

```
BenchmarkHash-8                        42    32,157,611 ns/op    19,927,112 B/op    35 allocs/op
BenchmarkVerifyOrDummy-8               39    30,095,151 ns/op    19,925,474 B/op    32 allocs/op
BenchmarkVerifyOrDummyMiss-8           45    24,453,332 ns/op    19,925,168 B/op    24 allocs/op
BenchmarkTryAcquireContended-8  2,331,627           465.5 ns/op           142 B/op     2 allocs/op
```

## 성능 영향 분석

### 캐시 적용 전후 비교

**캐시 미적용 시 (모든 요청이 linearizable 읽기):**
- 세션 로드: ~1ms (네트워크 + 합의)
- 사용자 조회: ~1ms
- Principal 조회: ~2ms (4-way JOIN)
- API 키 인증: ~1ms

**캐시 적용 후 (캐시 히트 시):**
- 세션 로드: ~125ns (99.99% 감소)
- 사용자 조회: ~125ns (99.99% 감소)
- Principal 조회: ~125ns (99.99% 감소)
- API 키 인증: ~125ns (99.99% 감소)

### Argon2 동시성 개선

**기존 (MaxConcurrency=2, 즉시 거부):**
- 2개 요청 동시 처리 가능
- 3번째 요청 즉시 실패

**개선 후 (MaxConcurrency=4, 100ms 대기):**
- 4개 요청 동시 처리 가능
- 5번째 요청 100ms 대기 후 실패
- 버스트 트래픽 처리 능력 2배 향상

## 모니터링

### Prometheus 메트릭

```prometheus
# 캐시 히트율 계산
rate(goauthy_cache_hits_total[5m]) / (rate(goauthy_cache_hits_total[5m]) + rate(goauthy_cache_misses_total[5m]))

# 데이터베이스 쿼리 지연시간 P99
histogram_quantile(0.99, rate(goauthy_db_query_duration_seconds_bucket[5m]))

# 캐시 제거율
rate(goauthy_cache_evictions_total[5m])
```

### 권장 임계값

| 메트릭 | 경고 | 위험 |
|--------|------|------|
| 캐시 히트율 | < 80% | < 50% |
| DB 쿼리 P99 | > 100ms | > 500ms |
| 캐시 제거율 | > 100/s | > 1000/s |

## 설정

### 환경 변수

```bash
# Argon2 동시성 (기본: 4)
GOAUTHY_ARGON2_MAX_CONCURRENCY=4

# Argon2 대기 타임아웃 (기본: 100ms)
GOAUTHY_ARGON2_WAIT_TIMEOUT=100ms
```

### 캐시 크기 조정

캐시 크기는 워크로드에 따라 조정해야 합니다:

- **낮은 트래픽** (< 100 RPS): 기본값 유지
- **중간 트래픽** (100-1000 RPS): MaxEntries 2배 증가
- **높은 트래픽** (> 1000 RPS): MaxEntries 4배 증가, ShardCount 32로 증가

## 보안 고려사항

1. **캐시 무효화**: 세션 해지, 사용자 비활성화 즉시 캐시 무효화
2. **TTL 선택**: 짧은 TTL(5-30초)로 stale 데이터 윈도우 최소화
3. **비밀번호 해시**: 캐시하지 않음 (보안 민감)
4. **캐시 키**: 해시 다이제스트 포함으로 키 교체 시 자동 무효화

## 향후 개선사항

1. **분산 캐시**: Redis 기반 캐시로 멀티 노드 확장
2. **예측적 로딩**: 자주 접근되는 데이터 사전 로딩
3. **캐시 워밍**: 서버 시작 시 핫 데이터 미리 로딩
4. **적응형 TTL**: 접근 빈도에 따른 동적 TTL 조정

## Measured baselines (issue #65)

Apple M3, 8 CPU, macOS, go1.27.0 darwin/arm64; representative run of
`go test -bench . -benchtime 3x -run '^$' ./internal/ipblacklist/ ./internal/oauth/`.
Measurements only; no behavior changed.

| item | benchmark | 1000 rows | 10000 rows |
|------|-----------|-----------|------------|
| GA-PERF-002 Check hit /32 | `BenchmarkCheckAtCeiling` `hit32` | 0.86 ms | 9.1 ms |
| GA-PERF-002 Check miss | `BenchmarkCheckAtCeiling` `miss` | 0.84 ms | 8.8 ms |
| GA-PERF-002 Check longest prefix | `BenchmarkCheckAtCeiling` `longestPrefix` | 1.14 ms | 9.1 ms |
| GA-PERF-001 issuance + cleanup | `BenchmarkCreateAccessTokenSessionWithCleanup` | 9.8 ms | 16.6 ms |

GA-PERF-002 (`internal/ipblacklist/bench_test.go`): one linearizable SELECT of
every row, then longest-prefix matching in Go; cost is linear in table size,
bounded by `DefaultMaxEntries = 10000` which `Add` enforces with a `COUNT(*)`
precondition. `TestAddCeilingDeterministic` (`internal/ipblacklist/store_test.go`)
already proves that ceiling deterministically, so it is not duplicated.

GA-PERF-001 (`internal/oauth/bench_test.go`): the storage-layer cycle
`Store.CreateAccessTokenSession` on a migrated database, where both cleanup
DELETEs batch with the token INSERT in one replicated Execute (the full fosite
HTTP token-endpoint path is not driven). Cleanup runs on every issuance, and the
orphan-row DELETE anti-joins `oauth_token_requests` against
`oauth_access_tokens`, so its cost tracks the live token count.
