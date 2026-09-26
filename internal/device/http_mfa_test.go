package device

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDeviceVerificationUsesServerMFAEvidence(t *testing.T) {
	for _, mfa := range []bool{false, true} {
		t.Run(map[bool]string{false: "password", true: "mfa"}[mfa], func(t *testing.T) {
			t.Parallel()
			ctx, store, db := testStore(t)
			_, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "mfa-client", SQL: `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,deleted,metadata_json,force_mfa) VALUES('mfa-client','g1',1,1,0,'{}',1)`})
			if err != nil {
				t.Fatal(err)
			}
			grant, err := store.CreateWithBinding(ctx, "mfa-client", []string{"openid"}, ClientBinding{ID: "mfa-client", Generation: "g1", Revision: 1}, deviceHTTPTestNow)
			if err != nil {
				t.Fatal(err)
			}
			h := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return nil }, func(*http.Request) (string, bool, bool) { return "user-1", mfa, true })
			cookie, csrf := verificationCSRF(t, h, grant.UserCode)
			r := formRequest(http.MethodPost, verificationPath, url.Values{"user_code": {grant.UserCode}, "csrf_token": {csrf}, "action": {"approve"}})
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if mfa && w.Code != http.StatusOK || !mfa && w.Code != http.StatusBadRequest {
				t.Fatalf("approval=%d %s", w.Code, w.Body.String())
			}
			row, found, err := store.load(ctx, digest(grant.DeviceCode), "mfa-client")
			if err != nil || !found || row.mfa != mfa || (mfa && row.state != "approved") || (!mfa && row.state != "pending") {
				t.Fatalf("approval=%+v found=%t err=%v", row, found, err)
			}
		})
	}
}

func TestDeviceMFAReauthenticationDoesNotApprove(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "review", true: "policy tightened after review"}[late], func(t *testing.T) {
			ctx, store, db := testStore(t)
			seedManagedBinding(t, ctx, store, "stepup-client", "g1", 1, 1)
			grant, err := store.CreateWithBinding(ctx, "stepup-client", nil, ClientBinding{ID: "stepup-client", Generation: "g1", Revision: 1}, deviceHTTPTestNow)
			if err != nil {
				t.Fatal(err)
			}
			h := testDeviceHandler(t, store, func(*http.Request, string, []string) error { return nil }, func(*http.Request) (string, bool, bool) { return "user-1", false, true })
			called := 0
			h.SetReauthentication(func(w http.ResponseWriter, r *http.Request, code string) {
				called++
				if NormalizeUserCode(code) != NormalizeUserCode(grant.UserCode) {
					t.Fatal("step-up lost code")
				}
				w.WriteHeader(http.StatusAccepted)
			})
			cookie, csrf := verificationCSRF(t, h, grant.UserCode)
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "stepup-tighten", SQL: "UPDATE managed_oauth_clients SET force_mfa=1,revision=2 WHERE id='stepup-client'"}); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, verificationPath+"?user_code="+url.QueryEscape(grant.UserCode), nil)
			if late {
				r = formRequest(http.MethodPost, verificationPath, url.Values{"user_code": {grant.UserCode}, "csrf_token": {csrf}, "action": {"approve"}})
				r.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if called != 1 || w.Code != http.StatusAccepted {
				t.Fatalf("calls=%d status=%d body=%s", called, w.Code, w.Body.String())
			}
			row, found, err := store.load(ctx, digest(grant.DeviceCode), "stepup-client")
			if err != nil || !found || row.state != "pending" || row.subject != "" {
				t.Fatalf("reauthentication changed grant=%+v err=%v", row, err)
			}
		})
	}
}
