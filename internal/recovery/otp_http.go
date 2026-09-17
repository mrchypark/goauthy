package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const otpStartLimit = 4 << 10
const otpVerifyLimit = 1 << 10

type OTPHandler struct {
	otp       *OTPService
	sender    *SMTPSender
	enabled   bool
	interacts *OTPInteractionStore
	now       func() time.Time
}

func NewOTPHandler(otp *OTPService, sender *SMTPSender, enabled bool, interacts *OTPInteractionStore) *OTPHandler {
	return &OTPHandler{otp: otp, sender: sender, enabled: enabled, interacts: interacts, now: time.Now}
}

func (h *OTPHandler) Enabled() bool { return h.enabled }

func (h *OTPHandler) SendOTP(ctx context.Context, subject, lang string, expiresAt time.Time) error {
	if !h.enabled || h.otp == nil || h.sender == nil {
		return errors.New("OTP unavailable")
	}
	code, err := h.otp.GenerateOTP(ctx, subject)
	if err != nil {
		return err
	}
	return h.sender.SendOTP(ctx, subject, code, lang, expiresAt)
}

func (h *OTPHandler) StoreInteraction(sessionDigest, subject, interactionToken string, expiresAt time.Time) error {
	if h.interacts == nil {
		return errors.New("OTP interaction store unavailable")
	}
	return h.interacts.Store(sessionDigest, subject, interactionToken, expiresAt)
}

func (h *OTPHandler) ConsumeInteraction(sessionDigest string) (string, string, error) {
	if h.interacts == nil {
		return "", "", errors.New("OTP interaction store unavailable")
	}
	return h.interacts.Consume(sessionDigest)
}

func (h *OTPHandler) VerifyOTPCode(ctx context.Context, subject, code string) (bool, error) {
	if h.otp == nil {
		return false, errors.New("OTP service unavailable")
	}
	return h.otp.VerifyOTP(ctx, subject, code)
}

type otpStartRequest struct {
	Subject string `json:"subject"`
}

type otpVerifyRequest struct {
	Subject string `json:"subject"`
	Code    string `json:"code"`
}

type otpStartResponse struct {
	ExpiresAt time.Time `json:"expires_at"`
}

type otpVerifyResponse struct {
	OK bool `json:"ok"`
}

func (h *OTPHandler) Start(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if crossSite(r) {
		forbidden(w)
		return
	}
	if !h.enabled || h.otp == nil || h.sender == nil {
		unavailable(w)
		return
	}
	req, err := decodeJSON[otpStartRequest](w, r, otpStartLimit)
	if err != nil || req.Subject == "" {
		badRequest(w)
		return
	}
	lang := ""
	langHeader := r.Header.Get("Accept-Language")
	if langHeader != "" {
		lang = parseLang(langHeader)
	}
	if lang == "" {
		lang = "en"
	}
	code, err := h.otp.GenerateOTP(r.Context(), req.Subject)
	if errors.Is(err, ErrOTPRateLimited) {
		w.Header().Set("Retry-After", "300")
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}
	if err != nil {
		unavailable(w)
		return
	}
	expiresAt := h.now().UTC().Add(otpExpiry)
	if err := h.sender.SendOTP(r.Context(), req.Subject, code, lang, expiresAt); err != nil {
		unavailable(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(otpStartResponse{ExpiresAt: expiresAt})
}

func (h *OTPHandler) Verify(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if crossSite(r) {
		forbidden(w)
		return
	}
	if !h.enabled || h.otp == nil {
		unavailable(w)
		return
	}
	req, err := decodeJSON[otpVerifyRequest](w, r, otpVerifyLimit)
	if err != nil || req.Subject == "" || req.Code == "" {
		badRequest(w)
		return
	}
	ok, err := h.otp.VerifyOTP(r.Context(), req.Subject, req.Code)
	if errors.Is(err, ErrOTPInvalid) {
		http.Error(w, "Invalid OTP", http.StatusUnauthorized)
		return
	}
	if errors.Is(err, ErrOTPExpired) {
		http.Error(w, "OTP expired", http.StatusGone)
		return
	}
	if err != nil {
		unavailable(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(otpVerifyResponse{OK: ok})
}

func parseLang(header string) string {
	for _, part := range splitLangHeader(header) {
		lang := normalizeLang(part)
		if lang != "" {
			return lang
		}
	}
	return ""
}

func splitLangHeader(header string) []string {
	var result []string
	current := ""
	for _, c := range header {
		if c == ',' {
			if current != "" {
				result = append(result, current)
			}
			current = ""
		} else if c != ' ' && c != '\t' {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func normalizeLang(raw string) string {
	lang := ""
	quality := 1.0
	for i, part := range splitOn(raw, ';') {
		part = trimSpace(part)
		if i == 0 {
			lang = part
		} else if len(part) > 2 && part[:2] == "q=" {
			if q, err := parseFloat(part[2:]); err == nil {
				quality = q
			}
		}
	}
	if quality <= 0 {
		return ""
	}
	langCode := lang
	if idx := indexByte(lang, '-'); idx >= 0 {
		langCode = lang[:idx]
	}
	if idx := indexByte(lang, '_'); idx >= 0 {
		langCode = lang[:idx]
	}
	switch langCode {
	case "de", "en", "fr", "ko", "nb", "nl", "ru", "uk", "zh":
		if langCode == "zh" {
			return "zh_hans"
		}
		return langCode
	}
	return ""
}

func splitOn(s string, sep byte) []string {
	var result []string
	current := ""
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			result = append(result, current)
			current = ""
		} else {
			current += string(s[i])
		}
	}
	result = append(result, current)
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func parseFloat(s string) (float64, error) {
	var result float64
	seenDot := false
	divisor := 1.0
	for _, c := range s {
		if c == '.' {
			seenDot = true
			continue
		}
		if c < '0' || c > '9' {
			return 0, errors.New("invalid float")
		}
		digit := float64(c - '0')
		if seenDot {
			divisor *= 10
			result += digit / divisor
		} else {
			result = result*10 + digit
		}
	}
	return result, nil
}
