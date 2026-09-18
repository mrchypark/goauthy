package dcr

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func FuzzDecodeRegistrationRequest(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"redirect_uris":["https://rp.example.test/callback"],"grant_types":["authorization_code"],"response_types":["code"],"client_name":"RP"}`),
		[]byte(`{"client_name":"one","client_name":"two"}`),
		[]byte(`{"scope":"openid"}`),
		[]byte(`{`),
		make([]byte, registrationBodyLimit+1),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > registrationBodyLimit+1 {
			return
		}
		response := httptest.NewRecorder()
		request := httptest.NewRequest("POST", registrationPath, bytes.NewReader(body))
		_, _ = decodeRegistrationRequest(response, request)
		if response.Body.Len() > registrationBodyLimit {
			t.Fatalf("parser response exceeded body limit: %d", response.Body.Len())
		}
	})
}
