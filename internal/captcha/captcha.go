package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Verifier validates human-verification tokens submitted by callers.
type Verifier interface {
	Verify(ctx context.Context, response, remoteIP string) (bool, error)
	SiteKey() string
}

// NewVerifier constructs a Turnstile, hCaptcha, or no-op Verifier from getenv.
func NewVerifier(getenv func(string) string) Verifier {
	provider := getenv("GOAUTHY_CAPTCHA_PROVIDER")
	siteKey := getenv("GOAUTHY_CAPTCHA_SITE_KEY")
	secretKey := getenv("GOAUTHY_CAPTCHA_SECRET_KEY")
	if provider == "" || siteKey == "" || secretKey == "" {
		return &noopVerifier{}
	}
	switch strings.ToLower(provider) {
	case "turnstile":
		return &httpVerifier{
			provider:  "turnstile",
			verifyURL: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
			siteKey:   siteKey,
			secretKey: secretKey,
		}
	case "hcaptcha":
		return &httpVerifier{
			provider:  "hcaptcha",
			verifyURL: "https://api.hcaptcha.com/siteverify",
			siteKey:   siteKey,
			secretKey: secretKey,
		}
	default:
		return &noopVerifier{}
	}
}

type noopVerifier struct{}

func (n *noopVerifier) Verify(_ context.Context, _, _ string) (bool, error) {
	return true, nil
}
func (n *noopVerifier) SiteKey() string { return "" }

type httpVerifier struct {
	provider  string
	verifyURL string
	siteKey   string
	secretKey string
}

func (v *httpVerifier) SiteKey() string { return v.siteKey }

func (v *httpVerifier) Verify(ctx context.Context, response, remoteIP string) (bool, error) {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, strings.NewReader(data.Encode()))
	if err != nil {
		return false, fmt.Errorf("create %s request: %w", v.provider, err)
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("captcha verification returned HTTP %d", resp.StatusCode)
	}
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
