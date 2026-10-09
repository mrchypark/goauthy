package login

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/recovery"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// startOTPSMTPFixture accepts one plaintext SMTP transaction per connection, so
// a forced-MFA password step can hand the OTP to the real mail boundary without
// leaving the test process, and reports what was delivered.
func startOTPSMTPFixture(t *testing.T) (string, int, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	delivered := make(chan string, 4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveOTPSMTP(conn, delivered)
		}
	}()
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return host, number, delivered
}

func serveOTPSMTP(conn net.Conn, delivered chan<- string) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	_, _ = writer.WriteString("220 fixture ESMTP\r\n")
	_ = writer.Flush()
	var body strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		switch {
		case strings.HasPrefix(line, "EHLO "), strings.HasPrefix(line, "HELO "):
			_, _ = writer.WriteString("250 fixture\r\n")
		case strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"):
			_, _ = writer.WriteString("250 OK\r\n")
		case line == "DATA\r\n":
			_, _ = writer.WriteString("354 send data\r\n")
			_ = writer.Flush()
			for {
				line, err = reader.ReadString('\n')
				if err != nil || line == ".\r\n" {
					break
				}
				body.WriteString(line)
			}
			delivered <- body.String()
			_, _ = writer.WriteString("250 queued\r\n")
		case line == "QUIT\r\n":
			_, _ = writer.WriteString("221 bye\r\n")
			_ = writer.Flush()
			return
		default:
			_, _ = writer.WriteString("250 OK\r\n")
		}
		_ = writer.Flush()
	}
}

// testOTPStepUp wires the email OTP boundary to the local SMTP fixture and the
// replicated interaction store, and models the forced-MFA deployment that has no
// passkeys configured.
func testOTPStepUp(t *testing.T, h *Handler, db *rhiza.DB) (*recovery.OTPService, <-chan string) {
	t.Helper()
	ctx := context.Background()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "login-otp-step-up-schema", Statements: recovery.SchemaStatements()}); err != nil {
		t.Fatal(err)
	}
	host, port, delivered := startOTPSMTPFixture(t)
	sender, err := recovery.NewSMTPSender(recovery.SMTPConfig{Host: host, Port: port, From: "support@example.test", Timeout: 5 * time.Second, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	service, err := recovery.NewOTPService(db)
	if err != nil {
		t.Fatal(err)
	}
	h.SetOTPHandler(recovery.NewOTPHandler(service, sender, true, recovery.NewOTPInteractionStore(db)))
	h.passkeys = nil
	return service, delivered
}

func postOTPForm(cookie *http.Cookie, code string) *http.Request {
	form := url.Values{"code": {code}}
	request := httptest.NewRequest(http.MethodPost, "/auth/v1/users/otp/verify", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(cookie)
	return request
}

func postOTPJSON(cookie *http.Cookie, code string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/auth/v1/users/otp/verify", strings.NewReader("{\"code\":\""+code+"\"}"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(cookie)
	return request
}

// TestForcedMFAOTPStepUpCompletesAsMFA covers the passkeys-unconfigured
// forced-MFA fallback end to end: the password step answers with a step-up form
// instead of a JSON body, the code submitted through that form (and through the
// JSON API) is verified exactly once through the shared completion path, and the
// stored session carries the "mfa" method the client policy and amr claim need.
func TestForcedMFAOTPStepUpCompletesAsMFA(t *testing.T) {
	t.Parallel()
	h, db := testHandlerWithDB(t, true)
	service, delivered := testOTPStepUp(t, h, db)
	ctx := context.Background()
	second, err := testHash(ctx, []byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.identity.BootstrapUser(ctx, "user-2", "bob", second); err != nil {
		t.Fatal(err)
	}
	// BootstrapUser creates no profile row, and a subject is an opaque
	// identifier: the OTP step needs the mailbox bound to the subject.
	for _, profile := range []struct{ requestID, subject, email string }{
		{"otp-step-up-profile-1", "user-1", "alice@example.test"},
		{"otp-step-up-profile-2", "user-2", "bob@example.test"},
	} {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
			RequestID: profile.requestID,
			SQL:       "INSERT OR IGNORE INTO identity_user_profiles (subject,email,email_verified,preferred_username) VALUES (?,?,1,?)",
			Args:      []any{profile.subject, profile.email, profile.subject},
		}); err != nil {
			t.Fatal(err)
		}
	}

	for _, test := range []struct {
		name     string
		username string
		subject  string
		email    string
		submit   func(*http.Cookie, string) *http.Request
	}{
		{name: "step-up form", username: "alice", subject: "user-1", email: "alice@example.test", submit: postOTPForm},
		{name: "json api", username: "bob", subject: "user-2", email: "bob@example.test", submit: postOTPJSON},
	} {
		t.Run(test.name, func(t *testing.T) {
			page := httptest.NewRecorder()
			h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
			if page.Code != http.StatusOK {
				t.Fatalf("authorize status=%d", page.Code)
			}
			init := page.Result().Cookies()[0]
			interaction := interactionToken(t, page.Body.String())

			stepUp := httptest.NewRecorder()
			h.Login(stepUp, postLogin(init, interaction, test.username, "correct password"))
			if stepUp.Code != http.StatusOK || !strings.HasPrefix(stepUp.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("step-up status=%d content-type=%q body=%q", stepUp.Code, stepUp.Header().Get("Content-Type"), stepUp.Body.String())
			}
			body := stepUp.Body.String()
			if !strings.Contains(body, "/auth/v1/users/otp/verify") || !strings.Contains(body, "name=\"code\"") || strings.Contains(body, "expires_at") {
				t.Fatalf("step-up body=%q", body)
			}
			if !strings.Contains(stepUp.Header().Get("Content-Security-Policy"), "form-action 'self' http://localhost") {
				t.Fatalf("step-up policy=%q", stepUp.Header().Get("Content-Security-Policy"))
			}
			select {
			case message := <-delivered:
				if !strings.Contains(message, test.email) {
					t.Fatalf("OTP delivered to the wrong mailbox: %q", message)
				}
			default:
				t.Fatal("step-up issued no OTP delivery")
			}

			code, err := service.GenerateOTP(ctx, test.subject)
			if err != nil {
				t.Fatal(err)
			}
			completed := httptest.NewRecorder()
			h.OTPVerify(completed, test.submit(init, code))
			location, err := url.Parse(completed.Header().Get("Location"))
			if err != nil || completed.Code != http.StatusSeeOther || location.Query().Get("code") == "" || location.Query().Get("state") != strings.Repeat("s", 32) {
				t.Fatalf("completion status=%d location=%q err=%v body=%q", completed.Code, completed.Header().Get("Location"), err, completed.Body.String())
			}
			session, err := h.browser.LoadSession(ctx, completed.Result().Cookies()[0].Value)
			if err != nil || session.Subject != test.subject || session.AuthenticationMethod != "mfa" {
				t.Fatalf("rotated session=%#v err=%v", session, err)
			}
			// The consumed code and the consumed interaction are single use.
			replay := httptest.NewRecorder()
			h.OTPVerify(replay, test.submit(init, code))
			if replay.Code != http.StatusForbidden || replay.Header().Get("Location") != "" {
				t.Fatalf("replay status=%d location=%q body=%q", replay.Code, replay.Header().Get("Location"), replay.Body.String())
			}
		})
	}
}

func TestOTPCompletionRejectsFirstFactorChangeAfterVerification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		advance string
	}{
		{name: "password reset", advance: "password-reset"},
		{name: "password mode changed", advance: "password-mode-change"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, db := testHandlerWithDB(t, true)
			service, delivered := testOTPStepUp(t, h, db)
			ctx := context.Background()
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "otp-final-guard-profile", SQL: `INSERT INTO identity_user_profiles(subject,email,email_verified) VALUES('user-1','alice@example.test',1)`}); err != nil {
				t.Fatal(err)
			}
			page := httptest.NewRecorder()
			h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
			if page.Code != http.StatusOK {
				t.Fatalf("authorize status=%d", page.Code)
			}
			init := page.Result().Cookies()[0]
			interaction := interactionToken(t, page.Body.String())
			stepUp := httptest.NewRecorder()
			h.Login(stepUp, postLogin(init, interaction, "alice", "correct password"))
			if stepUp.Code != http.StatusOK {
				t.Fatalf("step-up status=%d", stepUp.Code)
			}
			select {
			case <-delivered:
			case <-time.After(5 * time.Second):
				t.Fatal("OTP was not delivered")
			}
			code, err := service.GenerateOTP(ctx, "user-1")
			if err != nil {
				t.Fatal(err)
			}

			var resetter *identity.Store
			var resetToken string
			var challenge identity.PasswordResetChallenge
			if tc.advance == "password-reset" {
				resetter = testPasswordResetStore(t, db)
				resetToken, _, err = resetter.IssuePasswordReset(ctx, "user-1", time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				challenge, err = resetter.BeginPasswordReset(ctx, "user-1", resetToken)
				if err != nil {
					t.Fatal(err)
				}
			}
			h.SetLoginLocationObserver(func(r *http.Request, subject, _, _, _ string) error {
				if tc.advance == "password-reset" {
					_, err := resetter.ResetPassword(r.Context(), subject, resetToken, challenge.CookieToken, challenge.CSRFToken, []byte("ChangedPassword2"), "")
					return err
				}
				_, err := storage.Execute(r.Context(), db, rhiza.ExecuteRequest{RequestID: "otp-final-guard-mode-change", SQL: `UPDATE identity_authentication_modes SET mode='passkey',generation=generation+1 WHERE subject=?`, Args: []any{subject}})
				return err
			})
			completed := httptest.NewRecorder()
			request := postOTPForm(init, code)
			request.Header.Set("User-Agent", "Browser")
			h.OTPVerify(completed, request)
			if completed.Code != http.StatusServiceUnavailable || completed.Header().Get("Location") != "" || len(completed.Result().Cookies()) != 0 {
				t.Fatalf("stale OTP completion status=%d location-set=%t cookies=%d body=%q", completed.Code, completed.Header().Get("Location") != "", len(completed.Result().Cookies()), completed.Body.String())
			}
			if got := otpLoginRowCount(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE subject='user-1' AND revoked_at_unix_ms IS NULL`); got != 0 {
				t.Fatalf("stale OTP completion left authenticated sessions=%d", got)
			}
			if got := otpLoginRowCount(t, db, `SELECT COUNT(*) FROM oauth_authorize_codes WHERE json_extract(request_json,'$.subject')='user-1'`); got != 0 {
				t.Fatalf("stale OTP completion issued authorization codes=%d", got)
			}
		})
	}
}

func otpLoginRowCount(t *testing.T, db *rhiza.DB, query string) int64 {
	t.Helper()
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: query, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 {
		t.Fatalf("query rows=%v err=%v", rows.Rows, err)
	}
	return rows.Rows[0][0].(int64)
}

func TestPasswordOTPRotationReauthenticatesWithOriginalProof(t *testing.T) {
	t.Parallel()
	h, _ := testHandlerWithDB(t, false)
	ctx := context.Background()
	auth, err := h.identity.Authenticate(ctx, "alice", []byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	parent, err := h.browser.CreateSession(ctx, auth.Subject, "pwd", time.Now().Add(time.Hour), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	init, err := h.browser.CreateInitSession(ctx, time.Now().Add(time.Hour), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	issued, err := h.rotateBrowserSessionWithParent(response, httptest.NewRequest(http.MethodPost, "/", nil), init.Token, auth.Subject, "mfa", "192.0.2.1", auth.PasswordGeneration, auth.AuthenticationGeneration, parent.ID, nil)
	if err != nil || issued.AuthenticationMethod != "mfa" {
		t.Fatalf("current OTP proof reauthentication session=%#v err=%v", issued, err)
	}
	if _, err := h.browser.LoadSessionReadOnly(ctx, parent.Token); !errors.Is(err, browser.ErrRevoked) {
		t.Fatalf("successful reauthentication did not retire parent: %v", err)
	}
}

func TestPasswordOTPRotationReauthenticationRejectsStaleProof(t *testing.T) {
	t.Parallel()
	h, db := testHandlerWithDB(t, false)
	ctx := context.Background()
	auth, err := h.identity.Authenticate(ctx, "alice", []byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	parent, err := h.browser.CreateSession(ctx, auth.Subject, "pwd", time.Now().Add(time.Hour), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	init, err := h.browser.CreateInitSession(ctx, time.Now().Add(time.Hour), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	h.SetLoginLocationObserver(func(r *http.Request, subject, _, _, _ string) error {
		_, err := storage.Execute(r.Context(), db, rhiza.ExecuteRequest{
			RequestID: "otp-reauth-final-guard-mode-change",
			SQL:       `UPDATE identity_authentication_modes SET mode='passkey',generation=generation+1 WHERE subject=?`,
			Args:      []any{subject},
		})
		return err
	})
	response := httptest.NewRecorder()
	_, err = h.rotateBrowserSessionWithParent(response, httptest.NewRequest(http.MethodPost, "/", nil), init.Token, auth.Subject, "mfa", "192.0.2.1", auth.PasswordGeneration, auth.AuthenticationGeneration, parent.ID, nil)
	if err == nil {
		t.Fatal("reauthentication accepted stale password-plus-OTP proof")
	}
	if _, err := h.browser.LoadSessionReadOnly(ctx, parent.Token); err != nil {
		t.Fatalf("failed reauthentication revoked its parent: %v", err)
	}
	if _, err := h.browser.LoadSessionReadOnly(ctx, init.Token); err != nil {
		t.Fatalf("failed reauthentication consumed its init session: %v", err)
	}
	if got := otpLoginRowCount(t, db, `SELECT COUNT(*) FROM browser_sessions WHERE subject='user-1' AND revoked_at_unix_ms IS NULL`); got != 1 {
		t.Fatalf("stale reauthentication left authenticated sessions=%d, want parent only", got)
	}
}

// TestForcedMFAOTPStepUpPersistsOnlyTheInteractionDigest proves GA66-OTP-003:
// the pending password-plus-OTP binding keeps the canonical interaction digest
// in replicated state instead of the raw continuation token, and completion
// still works through the digest path.
func TestForcedMFAOTPStepUpPersistsOnlyTheInteractionDigest(t *testing.T) {
	t.Parallel()
	h, db := testHandlerWithDB(t, true)
	service, _ := testOTPStepUp(t, h, db)
	ctx := context.Background()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "otp-digest-profile",
		SQL:       "INSERT OR IGNORE INTO identity_user_profiles (subject,email,email_verified,preferred_username) VALUES (?,?,1,?)",
		Args:      []any{"user-1", "alice@example.test", "user-1"},
	}); err != nil {
		t.Fatal(err)
	}

	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	if page.Code != http.StatusOK {
		t.Fatalf("authorize status=%d", page.Code)
	}
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())
	interactionDigest, err := browser.CanonicalTokenDigest(interaction)
	if err != nil {
		t.Fatal(err)
	}
	sessionDigest, err := browser.CanonicalTokenDigest(init.Value)
	if err != nil {
		t.Fatal(err)
	}

	stepUp := httptest.NewRecorder()
	h.Login(stepUp, postLogin(init, interaction, "alice", "correct password"))
	if stepUp.Code != http.StatusOK {
		t.Fatalf("step-up status=%d body=%q", stepUp.Code, stepUp.Body.String())
	}

	rows, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT interaction_digest FROM identity_email_otp_interactions WHERE session_digest=?",
		Args:        []any{sessionDigest},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 1 {
		t.Fatalf("binding rows=%#v err=%v", rows.Rows, err)
	}
	stored, ok := rows.Rows[0][0].(string)
	if !ok || stored != interactionDigest {
		t.Fatalf("stored interaction=%#v, want the canonical digest", rows.Rows[0][0])
	}
	if stored == interaction {
		t.Fatal("the raw continuation token was persisted")
	}
	raw, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT COUNT(*) FROM identity_email_otp_interactions WHERE session_digest=? OR subject=? OR interaction_digest=?",
		Args:        []any{interaction, interaction, interaction},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(raw.Rows) != 1 || raw.Rows[0][0] != int64(0) {
		t.Fatalf("raw token sentinel found in persisted rows: rows=%#v err=%v", raw.Rows, err)
	}

	code, err := service.GenerateOTP(ctx, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	completed := httptest.NewRecorder()
	h.OTPVerify(completed, postOTPForm(init, code))
	if completed.Code != http.StatusSeeOther || completed.Header().Get("Location") == "" {
		t.Fatalf("completion status=%d location=%q body=%q", completed.Code, completed.Header().Get("Location"), completed.Body.String())
	}
	session, err := h.browser.LoadSession(ctx, completed.Result().Cookies()[0].Value)
	if err != nil || session.Subject != "user-1" || session.AuthenticationMethod != "mfa" {
		t.Fatalf("rotated session=%#v err=%v", session, err)
	}
}

// TestAuthorizeRendersForcedMFAContinuationScript proves the shipped password
// page continues a forced-MFA challenge in the browser instead of navigating to
// the raw JSON, and that the nonce policy that permits the script is present.
func TestAuthorizeRendersForcedMFAContinuationScript(t *testing.T) {
	t.Parallel()
	h := testHandlerWithForceMFA(t)
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	if page.Code != http.StatusOK {
		t.Fatalf("authorize status=%d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{
		// The continuation must re-encode the form: the login boundary accepts
		// only urlencoded bodies, so a multipart FormData post would be rejected.
		"new URLSearchParams(new FormData(loginForm))",
		"challenge.rcr",
		"/auth/v1/users/webauthn_finish",
		"navigator.credentials.get",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("forced-MFA page missing %q in body=%q", want, body)
		}
	}
	if !strings.Contains(page.Header().Get("Content-Security-Policy"), "script-src 'nonce-") || !strings.Contains(body, "nonce=") {
		t.Fatalf("forced-MFA page script policy=%q body=%q", page.Header().Get("Content-Security-Policy"), body)
	}
}

// TestAuthorizeOmitsMFAContinuationForUnforcedClient keeps the native password
// submission for clients that do not force MFA, so the ordinary login redirect
// is never replaced by a fetched continuation.
func TestAuthorizeOmitsMFAContinuationForUnforcedClient(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	if page.Code != http.StatusOK {
		t.Fatalf("authorize status=%d", page.Code)
	}
	body := page.Body.String()
	if strings.Contains(body, "URLSearchParams(new FormData(loginForm))") || strings.Contains(body, "challenge.rcr") {
		t.Fatalf("unforced client rendered the MFA continuation body=%q", body)
	}
	if !strings.Contains(body, "/auth/v1/users/webauthn_start") {
		t.Fatalf("unforced client lost the passkey button script body=%q", body)
	}
}
