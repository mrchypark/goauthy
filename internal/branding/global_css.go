package branding

import (
	_ "embed"
	"net/http"
	"strconv"
)

// Source: Rauthy v0.36.2 frontend/src/css/global.css,
// https://github.com/sebadob/rauthy/blob/v0.36.2/frontend/src/css/global.css.
// Licensed under Apache-2.0; see licenses/RAUTHY-APACHE-2.0.txt.
//
//go:embed global.css
var globalCSS []byte

const globalCSSCacheControl = "public, max-age=300, must-revalidate"

// GlobalCSSHandler serves the embedded global stylesheet at its mounted route.
func GlobalCSSHandler() http.Handler {
	body := globalCSS
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/css")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Cache-Control", globalCSSCacheControl)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body)
	})
}
