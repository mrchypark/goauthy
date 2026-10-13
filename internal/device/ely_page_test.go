package device

import (
	"bytes"
	"strings"
	"testing"
)

func TestElyDevicePagePreservesNativeDecision(t *testing.T) {
	for _, review := range []*Review{nil, {ClientID: "client<script>"}} {
		var out bytes.Buffer
		if err := verificationPage.Execute(&out, verificationPageData{BasePath: "/tenant", UserCode: "CODE", CSRFToken: "csrf", Review: review}); err != nil {
			t.Fatal(err)
		}
		body := out.String()
		for _, want := range []string{`/tenant/auth/v1/ui/`, `data-slot="input"`, `data-slot="button"`, `name="user_code"`, `action="verify"`} {
			if !strings.Contains(body, want) {
				t.Errorf("missing %s", want)
			}
		}
		if strings.Contains(body, "<script") || strings.Contains(body, "hx-") {
			t.Fatal("script or enhanced submission added")
		}
		if review != nil {
			for _, want := range []string{`method="post"`, `name="csrf_token" value="csrf"`, `name="action" value="approve"`, `name="action" value="deny"`, `value="CODE" required readonly`, `client&lt;script&gt;`} {
				if !strings.Contains(body, want) {
					t.Errorf("missing %s", want)
				}
			}
		}
	}
}
