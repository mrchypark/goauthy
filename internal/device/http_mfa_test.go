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
			grant, err := store.Create(ctx, "mfa-client", []string{"openid"}, deviceHTTPTestNow)
			if err != nil {
				t.Fatal(err)
			}
			_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "mfa-client", SQL: `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,deleted,metadata_json,force_mfa) VALUES('mfa-client','g1',1,1,0,'{}',1)`})
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
