package recovery

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/rhiza"
)

// TestRegisterPasskeyStartFailsClosedWithoutReservingIdentity covers GA-BR-02:
// passkey-first enrollment has no usable session binding, so a start that
// cannot complete must reject without reserving a passkey-only identity.
func TestRegisterPasskeyStartFailsClosedWithoutReservingIdentity(t *testing.T) {
	t.Parallel()
	service, _ := testService(t, "subject-1", "alice")
	config := RegistrationConfig{Enabled: true, PasskeyEnabled: true, AllowedDomains: []string{"example.test"}, RedirectValidator: ExactRedirectURIs(nil)}
	if err := WithOpenRegistration(config, time.Hour, func(context.Context, string) (bool, error) { return true, nil })(service); err != nil {
		t.Fatal(err)
	}
	service.SetPasskeyService(testPasskeyService(t, service.db))
	challenge, err := service.pow.Issue(context.Background(), service.powDifficulty, service.powTTL)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"email":"passkey@example.test","given_name":"Alice","passkey_name":"laptop","pow":"` + solveProof(t, challenge) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/auth/v1/register/passkey/start", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.60:1234"
	response := httptest.NewRecorder()
	service.RegisterPasskeyStart(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("start status=%d body=%q", response.Code, response.Body.String())
	}
	for _, query := range []string{
		`SELECT COUNT(*) FROM identity_users WHERE username='passkey@example.test'`,
		`SELECT COUNT(*) FROM identity_recovery_emails WHERE email='passkey@example.test'`,
	} {
		rows, err := service.db.Query(context.Background(), rhiza.QueryRequest{SQL: query, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
			t.Fatalf("query %q rows=%v err=%v", query, rows.Rows, err)
		}
	}
}

func testPasskeyService(t *testing.T, db *rhiza.DB) *passkey.Service {
	t.Helper()
	directory := t.TempDir()
	key := bytes.Repeat([]byte{0x11}, 32)
	if err := os.WriteFile(filepath.Join(directory, "master-a"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(directory, "master-a")
	if err != nil {
		t.Fatal(err)
	}
	service, err := passkey.New(db, passkey.Config{RPID: "example.test", RPDisplayName: "Example", Origins: []string{"https://example.test"}, CookieKey: bytes.Repeat([]byte{0x22}, 32), Keyring: keyring})
	if err != nil {
		t.Fatal(err)
	}
	return service
}
