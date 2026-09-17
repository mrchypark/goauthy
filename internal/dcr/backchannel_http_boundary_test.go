package dcr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBackchannelLogoutURIHTTPBoundary(t *testing.T) {
	base := `{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","client_name":"Logout RP"}`

	t.Run("null accepted", func(t *testing.T) {
		h := testHandler(t, testGlobalToken)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, requestWithKey(http.MethodPost, registrationPath, base[:len(base)-1]+`,"backchannel_logout_uri":null}`, testGlobalToken, "backchannel-null"))
		if response.Code != http.StatusCreated {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		var registration registrationResponse
		if err := json.Unmarshal(response.Body.Bytes(), &registration); err != nil {
			t.Fatal(err)
		}
		if registration.BackchannelLogoutURI != "" {
			t.Fatalf("backchannel logout URI=%q, want empty", registration.BackchannelLogoutURI)
		}
	})

	for _, tc := range []struct {
		name, key, uri string
		status         int
	}{
		{name: "HTTP query accepted", key: "backchannel-http-query", uri: "http://localhost:8080/logout?tenant=a&next=b#fragment", status: http.StatusCreated},
		{name: "explicit empty rejected", key: "backchannel-empty", uri: "", status: http.StatusBadRequest},
		{name: "malformed rejected", key: "backchannel-malformed", uri: "https://rp.example.test/bad path", status: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := testHandler(t, testGlobalToken)
			body := base[:len(base)-1] + `,"backchannel_logout_uri":"` + tc.uri + `"}`
			response := httptest.NewRecorder()
			h.ServeHTTP(response, requestWithKey(http.MethodPost, registrationPath, body, testGlobalToken, tc.key))
			if response.Code != tc.status {
				t.Fatalf("status=%d want %d body=%s", response.Code, tc.status, response.Body.String())
			}
			if response.Code != http.StatusCreated {
				return
			}
			var registration registrationResponse
			if err := json.Unmarshal(response.Body.Bytes(), &registration); err != nil {
				t.Fatal(err)
			}
			if registration.BackchannelLogoutURI != tc.uri {
				t.Fatalf("backchannel logout URI=%q want %q", registration.BackchannelLogoutURI, tc.uri)
			}
		})
	}

	t.Run("wrong registration token cannot mutate URI", func(t *testing.T) {
		h := testHandler(t, testGlobalToken)
		created := registerClientWithKey(t, h, base[:len(base)-1]+`,"backchannel_logout_uri":"https://rp.example.test/logout"}`, "backchannel-create")
		updateBody := `{"client_id":"` + created.ClientID + `",` + base[1:len(base)-1] + `,"backchannel_logout_uri":"https://attacker.example.test/logout"}`
		updated := httptest.NewRecorder()
		h.ServeHTTP(updated, request(http.MethodPut, registrationPath+"/"+created.ClientID, updateBody, "wrong-registration-token"))
		if updated.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d want %d body=%s", updated.Code, http.StatusUnauthorized, updated.Body.String())
		}

		read := httptest.NewRecorder()
		h.ServeHTTP(read, request(http.MethodGet, registrationPath+"/"+created.ClientID, "", created.RegistrationAccessToken))
		if read.Code != http.StatusOK {
			t.Fatalf("GET status=%d body=%s", read.Code, read.Body.String())
		}
		var registration registrationResponse
		if err := json.Unmarshal(read.Body.Bytes(), &registration); err != nil {
			t.Fatal(err)
		}
		if registration.BackchannelLogoutURI != "https://rp.example.test/logout" {
			t.Fatalf("backchannel logout URI=%q was mutated", registration.BackchannelLogoutURI)
		}
	})
}
