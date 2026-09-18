// Package security provides HTTP 보안 헤더 미들웨어를 제공합니다.
// OWASP 보안 헤더 모범 사례 및 NIST 가이드라인을 따릅니다.
package security

import (
	"net/http"
	"strings"
)

// Config는 보안 헤더 설정을 정의합니다.
type Config struct {
	// HSTS는 Strict-Transport-Security 헤더 값입니다.
	// 빈 문자열이면 HSTS 헤더를 설정하지 않습니다.
	// 예: "max-age=63072000; includeSubDomains; preload"
	HSTS string

	// ContentSecurityPolicy는 Content-Security-Policy 헤더 값입니다.
	ContentSecurityPolicy string

	// XFrameOptions는 X-Frame-Options 헤더 값입니다.
	// 기본값: "DENY"
	XFrameOptions string

	// XContentTypeOptions는 X-Content-Type-Options 헤더 값입니다.
	// 기본값: "nosniff"
	XContentTypeOptions string

	// ReferrerPolicy는 Referrer-Policy 헤더 값입니다.
	// 기본값: "strict-origin-when-cross-origin"
	ReferrerPolicy string

	// PermissionsPolicy는 Permissions-Policy 헤더 값입니다.
	// 예: "camera=(), microphone=(), geolocation=()"
	PermissionsPolicy string

	// CrossOriginOpenerPolicy는 Cross-Origin-Opener-Policy 헤더 값입니다.
	// 기본값: "same-origin"
	CrossOriginOpenerPolicy string

	// CrossOriginResourcePolicy는 Cross-Origin-Resource-Policy 헤더 값입니다.
	// 기본값: "same-origin"
	CrossOriginResourcePolicy string

	// CrossOriginEmbedderPolicy는 Cross-Origin-Embedder-Policy 헤더 값입니다.
	// 빈 문자열이면 설정하지 않습니다.
	CrossOriginEmbedderPolicy string

	// XPermittedCrossDomainPolicies는 X-Permitted-Cross-Domain-Policies 값입니다.
	// 기본값: "none"
	XPermittedCrossDomainPolicies string

	// CacheControl는 API 응답에 대한 Cache-Control 값입니다.
	// 기본값: "no-store, no-cache, must-revalidate"
	CacheControl string

	// DisableCSPReportOnly은 CSP 리포트 모드를 비활성화합니다.
	DisableCSPReportOnly bool
}

// DefaultConfig는 OWASP 권장사항에 따른 기본 보안 설정을 반환합니다.
func DefaultConfig() Config {
	return Config{
		HSTS:                          "max-age=63072000; includeSubDomains; preload",
		ContentSecurityPolicy:         "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'",
		XFrameOptions:                 "DENY",
		XContentTypeOptions:           "nosniff",
		ReferrerPolicy:                "strict-origin-when-cross-origin",
		PermissionsPolicy:             "camera=(), microphone=(), geolocation=(), interest-cohort=()",
		CrossOriginOpenerPolicy:       "same-origin",
		CrossOriginResourcePolicy:     "same-origin",
		XPermittedCrossDomainPolicies: "none",
		CacheControl:                  "no-store, no-cache, must-revalidate",
	}
}

// APIConfig는 API 엔드포인트에 적합한 보안 설정을 반환합니다.
func APIConfig() Config {
	return Config{
		HSTS:                          "max-age=63072000; includeSubDomains; preload",
		XFrameOptions:                 "DENY",
		XContentTypeOptions:           "nosniff",
		ReferrerPolicy:                "no-referrer",
		XPermittedCrossDomainPolicies: "none",
		CacheControl:                  "no-store",
	}
}

// StaticConfig는 정적 리소스에 적합한 보안 설정을 반환합니다.
func StaticConfig() Config {
	return Config{
		HSTS:                          "max-age=63072000; includeSubDomains; preload",
		XFrameOptions:                 "SAMEORIGIN",
		XContentTypeOptions:           "nosniff",
		ReferrerPolicy:                "strict-origin-when-cross-origin",
		XPermittedCrossDomainPolicies: "none",
		CacheControl:                  "public, max-age=31536000, immutable",
	}
}

// Middleware는 HTTP 응답에 보안 헤더를 추가하는 미들웨어를 반환합니다.
func Middleware(config Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// HSTS는 HTTPS에서만 설정
			if config.HSTS != "" && (r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https") {
				w.Header().Set("Strict-Transport-Security", config.HSTS)
			}

			if config.ContentSecurityPolicy != "" {
				w.Header().Set("Content-Security-Policy", config.ContentSecurityPolicy)
			}

			if config.XFrameOptions != "" {
				w.Header().Set("X-Frame-Options", config.XFrameOptions)
			}

			if config.XContentTypeOptions != "" {
				w.Header().Set("X-Content-Type-Options", config.XContentTypeOptions)
			}

			if config.ReferrerPolicy != "" {
				w.Header().Set("Referrer-Policy", config.ReferrerPolicy)
			}

			if config.PermissionsPolicy != "" {
				w.Header().Set("Permissions-Policy", config.PermissionsPolicy)
			}

			if config.CrossOriginOpenerPolicy != "" {
				w.Header().Set("Cross-Origin-Opener-Policy", config.CrossOriginOpenerPolicy)
			}

			if config.CrossOriginResourcePolicy != "" {
				w.Header().Set("Cross-Origin-Resource-Policy", config.CrossOriginResourcePolicy)
			}

			if config.CrossOriginEmbedderPolicy != "" {
				w.Header().Set("Cross-Origin-Embedder-Policy", config.CrossOriginEmbedderPolicy)
			}

			if config.XPermittedCrossDomainPolicies != "" {
				w.Header().Set("X-Permitted-Cross-Domain-Policies", config.XPermittedCrossDomainPolicies)
			}

			if config.CacheControl != "" {
				w.Header().Set("Cache-Control", config.CacheControl)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// APIMiddleware는 API 엔드포인트에 적합한 보안 헤더를 추가합니다.
func APIMiddleware() func(http.Handler) http.Handler {
	return Middleware(APIConfig())
}

// CORSMiddleware는 CORS 헤더를 설정하는 미들웨어를 반환합니다.
// allowedOrigins는 허용된 origin 목록입니다.
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	originSet := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[o] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if origin != "" && originSet[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token, X-Requested-With")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Max-Age", "86400")

				// Preflight 요청 처리
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			} else if origin != "" && len(allowedOrigins) == 0 {
				// allowedOrigins가 비어있으면 모든 origin 허용 (개발 환경)
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CSRFProtectionMiddleware는 CSRF 보호를 위한 헤더를 검증합니다.
// Fetch Metadata 표준( Sec-Fetch-Site)을 활용한 보호를 제공합니다.
func CSRFProtectionMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// GET, HEAD, OPTIONS는 안전한 메서드
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			// Fetch Metadata 검증
			fetchSite := r.Header.Get("Sec-Fetch-Site")
			if fetchSite != "" {
				// same-origin만 허용 (cross-site 차단)
				if fetchSite == "cross-site" {
					http.Error(w, "Forbidden: cross-site request", http.StatusForbidden)
					return
				}
			}

			// Origin/Referer 검증
			origin := r.Header.Get("Origin")
			referer := r.Header.Get("Referer")

			// 둘 다 없으면 same-origin으로 간주 (일부 브라우저)
			if origin == "" && referer == "" {
				// API 클라이언트일 수 있으므로 허용
				next.ServeHTTP(w, r)
				return
			}

			// Origin이 있으면 호스트와 비교
			if origin != "" {
				if !isSameOrigin(r, origin) {
					http.Error(w, "Forbidden: origin mismatch", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isSameOrigin은 요청의 origin이 서버와 같은 origin인지 확인합니다.
func isSameOrigin(r *http.Request, origin string) bool {
	// 간단한 호스트 비교
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	// origin에서 host 추출
	// origin 형식: "https://example.com" 또는 "https://example.com:8080"
	if strings.HasPrefix(origin, "https://") {
		originHost := strings.TrimPrefix(origin, "https://")
		originHost = strings.Split(originHost, "/")[0]
		return originHost == host
	}
	if strings.HasPrefix(origin, "http://") {
		originHost := strings.TrimPrefix(origin, "http://")
		originHost = strings.Split(originHost, "/")[0]
		return originHost == host
	}

	return false
}
