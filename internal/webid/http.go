// Package webid serves the bounded public WebID profile document.
package webid

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
)

const (
	maxDocumentBytes = 8 << 10
	maxAcceptBytes   = 8 << 10
	maxAcceptRanges  = 32
)

const (
	foafType    = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
	foafPerson  = "http://xmlns.com/foaf/0.1/Person"
	foafProfile = "http://xmlns.com/foaf/0.1/PersonalProfileDocument"
	foafTopic   = "http://xmlns.com/foaf/0.1/primaryTopic"
	foafGiven   = "http://xmlns.com/foaf/0.1/givenname"
	foafFamily  = "http://xmlns.com/foaf/0.1/family_name"
	solidIssuer = "http://www.w3.org/ns/solid/terms#oidcIssuer"
)

// Handler serves only active account profile data. Credentials, email,
// roles, groups, and custom attributes are deliberately not represented.
type Handler struct {
	issuer   string
	identity *identity.Store
}

func NewHandler(issuer string, identities *identity.Store) (*Handler, error) {
	if identities == nil {
		return nil, errors.New("webid handler requires identity store")
	}
	normalized, err := oidc.NormalizeIssuer(issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid WebID issuer: %w", err)
	}
	if len(normalized) > maxDocumentBytes {
		return nil, errors.New("WebID issuer is too long")
	}
	return &Handler{issuer: normalized, identity: identities}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	securityHeaders(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" {
		http.NotFound(w, r)
		return
	}
	if !acceptsTurtle(r.Header.Values("Accept")) {
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}
	subject := r.PathValue("subject")
	if !validPathSubject(subject) {
		http.NotFound(w, r)
		return
	}
	profile, err := h.identity.AccountProfileBySubject(r.Context(), subject)
	if err != nil {
		if errors.Is(err, identity.ErrInactiveSubject) || errors.Is(err, identity.ErrInvalidSubject) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	body, err := renderTurtle(h.issuer, subject, profile)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/turtle; charset=utf-8")
	_, _ = w.Write(body)
}

func acceptsTurtle(values []string) bool {
	if len(values) == 0 {
		return true
	}
	ranges, ok := splitAcceptRanges(values)
	if !ok {
		return false
	}
	selectedSpecificity := -1
	selectedQuality := 0
	for _, value := range ranges {
		if strings.HasSuffix(strings.TrimRight(value, " \t"), ";") {
			return false
		}
		mediaType, params, err := mime.ParseMediaType(value)
		if err != nil {
			return false
		}
		specificity, matches := turtleSpecificity(mediaType)
		if !matches {
			continue
		}
		quality := 1000
		if raw, exists := params["q"]; exists {
			quality, ok = parseQValue(raw)
			if !ok {
				return false
			}
		}
		if specificity > selectedSpecificity {
			selectedSpecificity = specificity
			selectedQuality = quality
		} else if specificity == selectedSpecificity && quality < selectedQuality {
			// Equal-specificity duplicates are contradictory. Fail closed so a
			// q=0 cannot be bypassed by another value for the same range.
			selectedQuality = quality
		}
	}
	return selectedSpecificity >= 0 && selectedQuality > 0
}

func splitAcceptRanges(values []string) ([]string, bool) {
	totalBytes := 0
	ranges := make([]string, 0, len(values))
	for _, value := range values {
		totalBytes += len(value)
		if len(ranges) > 0 {
			totalBytes++ // The field values are equivalent to one comma-joined field.
		}
		if totalBytes > maxAcceptBytes {
			return nil, false
		}
		start := 0
		quoted := false
		escaped := false
		for index, char := range value {
			if quoted {
				switch {
				case escaped:
					escaped = false
				case char == '\\':
					escaped = true
				case char == '"':
					quoted = false
				}
				continue
			}
			switch char {
			case '"':
				quoted = true
			case ',':
				rangeValue := strings.Trim(value[start:index], " \t")
				if rangeValue == "" || len(ranges) >= maxAcceptRanges {
					return nil, false
				}
				ranges = append(ranges, rangeValue)
				start = index + 1
			}
		}
		if quoted || escaped {
			return nil, false
		}
		rangeValue := strings.Trim(value[start:], " \t")
		if rangeValue == "" || len(ranges) >= maxAcceptRanges {
			return nil, false
		}
		ranges = append(ranges, rangeValue)
	}
	return ranges, true
}

func turtleSpecificity(mediaType string) (int, bool) {
	switch mediaType {
	case "text/turtle":
		return 2, true
	case "text/*":
		return 1, true
	case "*/*":
		return 0, true
	default:
		return 0, false
	}
}

func parseQValue(value string) (int, bool) {
	if value == "0" {
		return 0, true
	}
	if value == "1" {
		return 1000, true
	}
	if len(value) < 3 || (value[0] != '0' && value[0] != '1') || value[1] != '.' || len(value) > 5 {
		return 0, false
	}
	fraction := value[2:]
	if len(fraction) == 0 || len(fraction) > 3 {
		return 0, false
	}
	for _, char := range fraction {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	if value[0] == '1' && strings.Trim(fraction, "0") != "" {
		return 0, false
	}
	if value[0] == '1' {
		return 1000, true
	}
	parsed, err := strconv.Atoi(fraction)
	if err != nil {
		return 0, false
	}
	for multiplier := len(fraction); multiplier < 3; multiplier++ {
		parsed *= 10
	}
	return parsed, true
}

func validPathSubject(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 512 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~') {
			return false
		}
	}
	return true
}

func renderTurtle(issuer, subject string, profile identity.AccountProfile) ([]byte, error) {
	if profile.Subject != subject || !utf8.ValidString(profile.GivenName) || !utf8.ValidString(profile.FamilyName) {
		return nil, errors.New("invalid WebID profile")
	}
	card, ok := CanonicalProfilePath(issuer, subject)
	if !ok {
		return nil, errors.New("invalid WebID path")
	}
	webID := card + "#me"
	var b strings.Builder
	write := func(value string) bool {
		if b.Len()+len(value) > maxDocumentBytes {
			return false
		}
		b.WriteString(value)
		return true
	}
	if !write("<" + card + "> <" + foafType + "> <" + foafProfile + ">;\n\t<" + foafTopic + "> <" + webID + "> .\n<" + webID + "> <" + solidIssuer + "> <" + issuer + ">;\n\t<" + foafType + "> <" + foafPerson + ">") {
		return nil, errors.New("WebID document exceeds size limit")
	}
	if profile.GivenName != "" {
		if !write(";\n\t<" + foafGiven + "> " + turtleLiteral(profile.GivenName)) {
			return nil, errors.New("WebID document exceeds size limit")
		}
	}
	if profile.FamilyName != "" {
		if !write(";\n\t<" + foafFamily + "> " + turtleLiteral(profile.FamilyName)) {
			return nil, errors.New("WebID document exceeds size limit")
		}
	}
	if !write(" .\n") {
		return nil, errors.New("WebID document exceeds size limit")
	}
	return []byte(b.String()), nil
}

func turtleLiteral(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range value {
		switch c {
		case '\\':
			b.WriteString("\\\\")
		case '"':
			b.WriteString("\\\"")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if c < 0x20 || c == 0x7f {
				fmt.Fprintf(&b, "\\u%04X", c)
			} else {
				b.WriteRune(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
}

// CanonicalProfilePath returns the public path used in a WebID document.
// It is intentionally limited to one escaped-safe subject segment.
func CanonicalProfilePath(issuer, subject string) (string, bool) {
	if !validPathSubject(subject) {
		return "", false
	}
	if escaped := url.PathEscape(subject); escaped != subject {
		return "", false
	}
	return strings.TrimRight(issuer, "/") + "/auth/" + subject + "/profile", true
}
