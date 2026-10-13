package account

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/branding"
	"golang.org/x/net/html"
)

func TestElyDashboardPreservesControlContracts(t *testing.T) {
	var page bytes.Buffer
	if err := dashboardTemplate.Execute(&page, struct {
		BasePath, Language string
		IsAdmin            bool
		Brand              branding.Brand
	}{"/realm", "ko", true, branding.Brand{Name: "Example", ThemeURL: "/theme/custom"}}); err != nil {
		t.Fatal(err)
	}
	doc, err := html.Parse(strings.NewReader(page.String()))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]map[string]string{}
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		attrs := map[string]string{}
		for _, a := range n.Attr {
			attrs[a.Key] = a.Val
		}
		if id := attrs["id"]; id != "" {
			if _, exists := ids[id]; exists {
				t.Errorf("duplicate id %q", id)
			}
			ids[id] = attrs
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(doc)
	for _, tc := range []struct {
		id, slot, key, value string
	}{
		{"preferred-username", "input", "name", "preferred_username"},
		{"password-current", "input", "autocomplete", "current-password"},
		{"password-new", "input", "name", "password_new"},
		{"password-confirm", "input", "name", "password_confirm"},
		{"passkey-current-password", "", "hidden", ""},
		{"passkey-name", "input", "maxlength", "128"},
		{"password-restore-new", "input", "required", ""},
		{"password-restore-confirm", "input", "required", ""},
		{"passkey-add", "button", "type", "submit"},
		{"passwordless-convert", "button", "type", "button"},
		{"password-restore-submit", "button", "type", "submit"},
		{"connections-refresh", "button", "type", "button"},
		{"connections-save", "button", "type", "submit"},
		{"connections-cancel", "", "hidden", ""},
		{"connections-collection", "select", "disabled", ""},
		{"devices-refresh", "button", "type", "button"},
		{"self-delete-confirm", "input", "autocomplete", "off"},
		{"self-delete-button", "button", "disabled", ""},
	} {
		attrs := ids[tc.id]
		if value, exists := attrs[tc.key]; !exists || value != tc.value || attrs["data-slot"] != tc.slot {
			t.Errorf("%s lost Ely/native contract: %v", tc.id, attrs)
		}
	}
	for _, id := range []string{"username-form", "password-form", "attributes-form", "passkey-form", "password-restore-form", "connections-form"} {
		if ids[id]["method"] != "post" {
			t.Errorf("%s lost POST form contract", id)
		}
	}
	for _, want := range []string{`lang="ko"`, `/realm/auth/v1/ui/app.css`, `/realm/auth/v1/branding/brand.css`, `/realm/theme/custom`, `/realm/account/app.js`, `data-i18n="Save username"`} {
		if !strings.Contains(page.String(), want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(page.String(), "hx-post") || strings.Contains(page.String(), "/assets/") {
		t.Fatal("dashboard introduced an alternate mutation or unprefixed asset path")
	}
}
