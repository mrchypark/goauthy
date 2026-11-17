# captcha

## Overview
`internal/captcha` provides a pluggable CAPTCHA verification abstraction supporting Cloudflare Turnstile, hCaptcha, and a no-op fallback configured via environment variables.

## Interface
- `[captcha.go:Verifier]`: Interface with `Verify(ctx context.Context, response, remoteIP string) (bool, error)` and `SiteKey() string`.
- `[captcha.go:NewVerifier]`, `[captcha.go:EnvFromOS]`: Reads `GOAUTHY_CAPTCHA_PROVIDER`, `GOAUTHY_CAPTCHA_SITE_KEY`, and `GOAUTHY_CAPTCHA_SECRET_KEY` via `getenv` (or OS env via `EnvFromOS`) and returns `CloudflareTurnstileVerifier`, `HCaptchaVerifier`, or a no-op verifier.
- `[captcha.go:CloudflareTurnstileVerifier]`: Verifies tokens against `https://challenges.cloudflare.com/turnstile/v0/siteverify`.
- `[captcha.go:HCaptchaVerifier]`: Verifies tokens against `https://api.hcaptcha.com/siteverify`.

## Invariants
- Empty token short-circuit: Both `[captcha.go:CloudflareTurnstileVerifier.Verify]` and `[captcha.go:HCaptchaVerifier.Verify]` return `(false, nil)` immediately if `response == ""` without making an HTTP request.
- Graceful unconfigured fallback: `[captcha.go:NewVerifier]` returns a no-op verifier (always returning `true, nil` and `SiteKey() == ""`) when provider/keys are unset or unrecognized.

## Side Effects
- Makes outbound HTTPS POST requests (`application/x-www-form-urlencoded`) to Cloudflare Turnstile or hCaptcha `siteverify` endpoints when enabled.

## Verification
- Run: `go test ./internal/captcha`
