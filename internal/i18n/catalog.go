// Package i18n provides the small, embedded catalog used by browser pages.
package i18n

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
)

const (
	maxAcceptLanguageLength = 1024
	maxLanguageRanges       = 16
)

//go:embed catalog/en.json
var englishCatalog []byte

//go:embed catalog/ko.json
var koreanCatalog []byte

// Messages is the deliberately small common browser-page vocabulary. Values
// are catalog data, not template source, so html/template continues to escape
// all dynamic page values normally.
type Messages struct {
	Language       string
	SignIn         string `json:"sign_in"`
	ContinueTo     string `json:"continue_to"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	SignOut        string `json:"sign_out"`
	ConfirmSignOut string `json:"confirm_sign_out"`
	SignedIn       string `json:"signed_in"`
	PasskeyButton  string `json:"passkey_button"`
}

var catalogs = map[string]Messages{
	"en": mustCatalog(englishCatalog, "en"),
	"ko": mustCatalog(koreanCatalog, "ko"),
}

func mustCatalog(data []byte, language string) Messages {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		panic("invalid embedded i18n catalog")
	}
	values := make(map[string]string, 7)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !catalogKey(key) || values[key] != "" {
			panic("invalid embedded i18n catalog")
		}
		var value string
		if decoder.Decode(&value) != nil || value == "" {
			panic("invalid embedded i18n catalog")
		}
		values[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		panic("invalid embedded i18n catalog")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || len(values) != 8 {
		panic("invalid embedded i18n catalog")
	}
	messages := Messages{SignIn: values["sign_in"], ContinueTo: values["continue_to"], Username: values["username"], Password: values["password"], SignOut: values["sign_out"], ConfirmSignOut: values["confirm_sign_out"], SignedIn: values["signed_in"], PasskeyButton: values["passkey_button"]}
	messages.Language = language
	return messages
}

func catalogKey(key string) bool {
	switch key {
	case "sign_in", "continue_to", "username", "password", "sign_out", "confirm_sign_out", "signed_in", "passkey_button":
		return true
	default:
		return false
	}
}

// Resolve selects a supported language from one Accept-Language field. An
// empty, malformed, or unsupported value deliberately falls back to English.
// Higher q wins; header order breaks ties deterministically.
func Resolve(header string) string {
	return resolve(header, []string{"en", "ko"})
}

// UserLanguageFromRequest uses the non-sensitive locale preference cookie
// before Accept-Language. It selects account/mail language, not UI catalog support.
func UserLanguageFromRequest(r *http.Request) string {
	if cookie, err := r.Cookie("locale"); err == nil {
		switch cookie.Value {
		case "en", "en-US":
			return "en"
		case "de", "de-DE":
			return "de"
		case "fr", "fr-FR":
			return "fr"
		case "ko", "ko-KR":
			return "ko"
		case "nb", "nb-NO", "no-NO":
			return "nb"
		case "nl", "nl-NL":
			return "nl"
		case "ru", "ru-RU":
			return "ru"
		case "uk", "uk-UA":
			return "uk"
		case "zh", "zhhans", "zh-hans", "zh-Hans":
			return "zhhans"
		default:
			return "en"
		}
	}
	values := r.Header.Values("Accept-Language")
	size := 0
	for _, value := range values {
		size += len(value) + 1
		if size > maxAcceptLanguageLength+1 {
			return "en"
		}
	}
	return resolve(strings.Join(values, ","), []string{"en", "de", "fr", "ko", "nb", "nl", "ru", "uk", "zhhans"})
}

func ValidUserLanguage(value string) bool {
	switch value {
	case "de", "en", "fr", "ko", "nb", "nl", "ru", "uk", "zhhans":
		return true
	}
	return false
}

func resolve(header string, supported []string) string {
	if header == "" || len(header) > maxAcceptLanguageLength {
		return "en"
	}
	ranges := strings.Split(header, ",")
	if len(ranges) > maxLanguageRanges {
		return "en"
	}
	type preference struct {
		language string
		q        int
		order    int
	}
	preferences := make([]preference, 0, len(ranges))
	excluded := make(map[string]bool)
	for order, raw := range ranges {
		language, q, ok := parseRange(raw)
		if !ok {
			return "en"
		}
		if language == "no" {
			language = "nb"
		} else if language == "zh" {
			language = "zhhans"
		}
		preferences = append(preferences, preference{language: language, q: q, order: order})
		if language != "*" && q == 0 {
			excluded[language] = true
		}
	}
	bestLanguage, bestQ, bestOrder := "en", -1, len(ranges)+1
	for _, preference := range preferences {
		language := preference.language
		if language == "*" {
			language = wildcardLanguage(excluded, supported)
		}
		if language == "" || excluded[language] || preference.q == 0 {
			continue
		}
		if !slices.Contains(supported, language) {
			continue
		}
		if preference.q > bestQ || preference.q == bestQ && preference.order < bestOrder {
			bestLanguage, bestQ, bestOrder = language, preference.q, preference.order
		}
	}
	return bestLanguage
}

func wildcardLanguage(excluded map[string]bool, supported []string) string {
	for _, language := range supported {
		if !excluded[language] {
			return language
		}
	}
	return ""
}

func parseRange(raw string) (string, int, bool) {
	parts := strings.Split(raw, ";")
	if len(parts) > 2 {
		return "", 0, false
	}
	language := strings.ToLower(strings.TrimSpace(parts[0]))
	if !validLanguage(language) {
		return "", 0, false
	}
	if i := strings.IndexByte(language, '-'); i >= 0 {
		language = language[:i]
	}
	if len(parts) == 1 {
		return language, 1000, true
	}
	quality := strings.TrimSpace(parts[1])
	if len(quality) < 3 || !strings.EqualFold(quality[:2], "q=") {
		return "", 0, false
	}
	q, ok := parseQValue(quality[2:])
	if !ok {
		return "", 0, false
	}
	return language, q, true
}

// parseQValue accepts the RFC 9110 qvalue grammar as used here: 0 or 1,
// optionally followed by one to three decimal digits; 1 may only have zero
// fractional digits. Empty fractions are rejected fail-safe.
func parseQValue(value string) (int, bool) {
	if value == "0" {
		return 0, true
	}
	if value == "1" {
		return 1000, true
	}
	if len(value) < 3 || len(value) > 5 || value[1] != '.' || value[0] != '0' && value[0] != '1' {
		return 0, false
	}
	frac := value[2:]
	if len(frac) > 3 {
		return 0, false
	}
	thousandths := 0
	for index, digit := range frac {
		if digit < '0' || digit > '9' || value[0] == '1' && digit != '0' {
			return 0, false
		}
		multiplier := 100
		if index == 1 {
			multiplier = 10
		} else if index == 2 {
			multiplier = 1
		}
		thousandths += int(digit-'0') * multiplier
	}
	if value[0] == '1' {
		return 1000, true
	}
	return thousandths, true
}

func validLanguage(value string) bool {
	if value == "*" {
		return true
	}
	if value == "" || len(value) > 35 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for index, part := range strings.Split(value, "-") {
		if part == "" || len(part) > 8 {
			return false
		}
		for _, c := range part {
			if index == 0 && !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') || index != 0 && !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
				return false
			}
		}
	}
	return true
}

// MessagesFor returns the selected immutable catalog values.
func MessagesFor(header string) Messages { return catalogs[Resolve(header)] }
