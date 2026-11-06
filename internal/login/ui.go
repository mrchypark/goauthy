package login

import (
	"html/template"
	"net/http"

	ui "github.com/mrchypark/elysdui/ui/gohtmx"
)

func newLoginUITemplates() *template.Template {
	t, err := ui.NewTemplates()
	if err != nil {
		panic(err)
	}
	return t
}

// UIStylesheet serves the same public, embedded stylesheet used by elysdui.
func UIStylesheet() http.Handler {
	data, err := ui.Files.ReadFile("assets/app.css")
	if err != nil {
		panic(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(data)
	})
}
