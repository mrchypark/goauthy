package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/rhiza"
)

func JWKSHandler(db *rhiza.DB, keyring *Keyring, issuer string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := LoadActiveSigningKey(r.Context(), db, keyring, issuer); err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		keys, err := LoadJWKSKeys(r.Context(), db, time.Now().UTC())
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		body, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		digest := sha256.Sum256(body)
		etag := `"` + base64.RawURLEncoding.EncodeToString(digest[:]) + `"`
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, must-revalidate", int(JWKSCacheMaxAge.Seconds())))
		w.Header().Set("ETag", etag)
		if matchesETag(r.Header.Get("If-None-Match"), etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(body)
	})
}

func matchesETag(header, etag string) bool {
	for len(header) > 0 {
		for len(header) > 0 && (header[0] == ' ' || header[0] == '\t' || header[0] == ',') {
			header = header[1:]
		}
		if header == "*" || len(header) > 1 && header[0] == '*' && header[1] == ',' {
			return true
		}
		weak := len(header) >= 2 && header[0] == 'W' && header[1] == '/'
		if weak {
			header = header[2:]
		}
		if len(header) == 0 || header[0] != '"' {
			if comma := nextComma(header); comma >= 0 {
				header = header[comma+1:]
				continue
			}
			return false
		}
		end := 1
		for end < len(header) && header[end] != '"' {
			end++
		}
		if end == len(header) {
			return false
		}
		if header[:end+1] == etag {
			return true
		}
		header = header[end+1:]
	}
	return false
}

func nextComma(s string) int {
	for i := range len(s) {
		if s[i] == ',' {
			return i
		}
	}
	return -1
}
