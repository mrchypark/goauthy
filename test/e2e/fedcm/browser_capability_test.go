package fedcm

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestChromeFedCMCapability is a capability gate, not a protocol success
// oracle. A browser without IdentityCredential support is reported as a
// skip; the HTTP contract test remains authoritative in that environment.
func TestChromeFedCMCapability(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_FEDCM_BROWSER") != "1" {
		t.Skip("set GOAUTHY_E2E_FEDCM_BROWSER=1 to probe Chrome FedCM capability")
	}
	chrome := ""
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if path, err := exec.LookPath(name); err == nil {
			chrome = path
			break
		}
	}
	if chrome == "" {
		t.Skip("Chrome/Chromium unavailable: browser FedCM is not claimed; run protocol E2E only")
	}
	// Headless Chrome exposes the secure-context API surface without needing a
	// test page or a timing-based sleep. This deliberately does not claim that
	// the browser completed an identity mediation flow.
	page := `data:text/html,<script>document.title=('IdentityCredential' in window)?'fedcm-capable':'fedcm-unsupported'</script>`
	out, err := exec.Command(chrome, "--headless=new", "--no-sandbox", "--disable-gpu", "--dump-dom", page).CombinedOutput()
	if err != nil {
		t.Skipf("Chrome capability probe failed: %v", err)
	}
	if !strings.Contains(string(out), "fedcm-capable") {
		t.Skip("Chrome lacks IdentityCredential: browser FedCM is not claimed; run protocol E2E only")
	}
}
