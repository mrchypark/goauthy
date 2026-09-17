package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Verifier interface {
	Verify(ctx context.Context, response, remoteIP string) (bool, error)
	SiteKey() string
}

func NewVerifier(getenv func(string) string) Verifier {
	provider := getenv("GOAUTHY_CAPTCHA_PROVIDER")
	siteKey := getenv("GOAUTHY_CAPTCHA_SITE_KEY")
	secretKey := getenv("GOAUTHY_CAPTCHA_SECRET_KEY")
	if provider == "" || siteKey == "" || secretKey == "" {
		return &noopVerifier{}
	}
	switch strings.ToLower(provider) {
	case "turnstile":
		return &CloudflareTurnstileVerifier{siteKey: siteKey, secretKey: secretKey}
	case "hcaptcha":
		return &HCaptchaVerifier{siteKey: siteKey, secretKey: secretKey}
	default:
		return &noopVerifier{}
	}
}

type noopVerifier struct{}

func (n *noopVerifier) Verify(_ context.Context, _, _ string) (bool, error) {
	return true, nil
}
func (n *noopVerifier) SiteKey() string { return "" }

type CloudflareTurnstileVerifier struct {
	siteKey  string
	secretKey string
}

func (v *CloudflareTurnstileVerifier) SiteKey() string { return v.siteKey }

func (v *CloudflareTurnstileVerifier) Verify(ctx context.Context, response, remoteIP string) (bool, error) {
	if response == "" {
		return false, nil
	}
	data := url.Values{
		"secret":   {v.secretKey},
		"response": {response},
	}
	if remoteIP != "" {
		data.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://challenges.cloudflare.com/turnstile/v0/siteverify", strings.NewReader(data.Encode()))
	if err != nil {
		return false, fmt.Errorf("create turnstile request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return doVerify(req)
}

type HCaptchaVerifier struct {
	siteKey  string
	secretKey string
}

func (v *HCaptchaVerifier) SiteKey() string { return v.siteKey }

func (v *HCaptchaVerifier) Verify(ctx context.Context, response, remoteIP string) (bool, error) {
	if response == "" {
		return false, nil
	}
	data := url.Values{
		"secret":   {v.secretKey},
		"response": {response},
	}
	if remoteIP != "" {
		data.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.hcaptcha.com/siteverify", strings.NewReader(data.Encode()))
	if err != nil {
		return false, fmt.Errorf("create hcaptcha request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return doVerify(req)
}

type siteVerifyResponse struct {
	Success bool `json:"success"`
}

func doVerify(req *http.Request) (bool, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("captcha verification request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, fmt.Errorf("read captcha verification response: %w", err)
	}
	var result siteVerifyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("decode captcha verification response: %w", err)
	}
	return result.Success, nil
}

func EnvFromOS(name string) string {
	return os.Getenv(name)
}
