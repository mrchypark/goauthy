package login

import (
	"errors"
	"fmt"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/rhiza"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginLocationObserverKeepsBrowserID(t *testing.T) {
	h := &Handler{issuer: "https://issuer.example.test"}
	var ids []string
	h.SetLoginLocationObserver(func(observed *http.Request, subject, id, ip, ua string) error {
		if observed.Header.Get("User-Agent") != "Browser" || subject != "alice" || ip != "192.0.2.1" || ua != "Browser" {
			t.Fatal("incorrect login observation")
		}
		ids = append(ids, id)
		return nil
	})
	req := httptest.NewRequest("GET", h.issuer, nil)
	req.Header.Set("User-Agent", "Browser")
	response := httptest.NewRecorder()
	if err := h.setBrowserIDCookie(response, req); err != nil {
		t.Fatal(err)
	}
	h.recordLoginLocation(response, req, "alice", "192.0.2.1")
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || len(ids) != 1 || ids[0] != "" {
		t.Fatal("missing browser correlation cookie")
	}
	req.AddCookie(cookies[0])
	second := httptest.NewRecorder()
	h.recordLoginLocation(second, req, "alice", "192.0.2.1")
	if len(ids) != 2 || cookies[0].Value != ids[1] || len(second.Result().Cookies()) != 0 {
		t.Fatal("known browser identity was replaced")
	}
}

func TestPasswordLocationNotifiesBeforeMFACompletion(t *testing.T) {
	for _, forceMFA := range []bool{false, true} {
		t.Run(fmt.Sprint("forceMFA=", forceMFA), func(t *testing.T) {
			h := testHandlerWithForce(t, forceMFA)
			finalStatus := http.StatusSeeOther
			if forceMFA {
				finalStatus = http.StatusNotAcceptable
			}
			calls := 0
			h.SetLoginLocationObserver(func(_ *http.Request, subject, id, ip, ua string) error {
				calls++
				if subject == "" || ip == "" || ua != "Browser" {
					t.Fatal("missing authenticated location metadata")
				}
				return nil
			})
			page := httptest.NewRecorder()
			h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
			cookies := page.Result().Cookies()
			if len(cookies) != 2 || cookies[1].Name != "rbid" || len(cookies[1].Value) != 32 {
				t.Fatal("login page did not issue browser identity cookie")
			}
			init := cookies[0]
			interaction := interactionToken(t, page.Body.String())
			for _, tc := range []struct {
				password, ua  string
				status, count int
			}{
				{"wrong password", "Browser", http.StatusUnauthorized, 0},
				{"correct password", "", http.StatusBadRequest, 0},
				{"correct password", "Browser", finalStatus, 1},
			} {
				r := postLogin(init, interaction, "alice", tc.password)
				r.Header.Set("User-Agent", tc.ua)
				response := httptest.NewRecorder()
				h.Login(response, r)
				if response.Code != tc.status || calls != tc.count {
					t.Fatalf("status=%d calls=%d want %d/%d", response.Code, calls, tc.status, tc.count)
				}
			}

		})
	}
}

func TestPasskeyLocationRequiresUserAgentBeforeSession(t *testing.T) {
	h, db := testHandlerWithDB(t, false)
	h.SetLoginLocationObserver(func(*http.Request, string, string, string, string) error { t.Fatal("invalid UA notified"); return nil })
	for _, method := range []string{"webauthn", "mfa"} {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		response := httptest.NewRecorder()
		_, err := h.rotateBrowserSession(response, r, "unused", "user-1", method, "192.0.2.1")
		if !errors.Is(err, identity.ErrInvalidUserAgent) {
			t.Fatalf("method=%s error=%v", method, err)
		}
		if len(response.Result().Cookies()) != 0 {
			t.Fatal("invalid UA published session cookie")
		}
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM browser_sessions WHERE subject='user-1'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
		t.Fatalf("invalid UA session state=%v error=%v", rows.Rows, err)
	}
}

func TestLoginLocationFailureStopsPasswordResponse(t *testing.T) {
	h := testHandler(t)
	const private = "private-location-error"
	h.SetLoginLocationObserver(func(*http.Request, string, string, string, string) error { return errors.New(private) })
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	req := postLogin(page.Result().Cookies()[0], interactionToken(t, page.Body.String()), "alice", "correct password")
	req.Header.Set("User-Agent", "Browser")
	response := httptest.NewRecorder()
	h.Login(response, req)
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), private) || response.Header().Get("Location") != "" || len(response.Result().Cookies()) != 0 {
		t.Fatalf("failed location status=%d", response.Code)
	}
}

func TestLoginLocationUsesConfiguredBrowserCookie(t *testing.T) {
	h := &Handler{issuer: "https://issuer.test"}
	policy, err := browser.NewBrowserIDPolicy(browser.BrowserIDSecure, true)
	if err != nil {
		t.Fatal(err)
	}
	h.SetBrowserIDPolicy(policy)
	var observed string
	h.SetLoginLocationObserver(func(_ *http.Request, subject, id, ip, ua string) error { observed = id; return nil })
	r := httptest.NewRequest(http.MethodGet, h.issuer+"/auth", nil)
	w := httptest.NewRecorder()
	if err := h.setBrowserIDCookie(w, r); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Secure-rbid" || cookies[0].Path != "/auth" {
		t.Fatal("configured cookie not emitted")
	}
	r.AddCookie(cookies[0])
	if err := h.recordLoginLocation(w, r, "alice", "192.0.2.1"); err != nil || observed != cookies[0].Value {
		t.Fatal("configured cookie not read")
	}
}
