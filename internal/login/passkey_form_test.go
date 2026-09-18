package login

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDecodePasskeyFinish(t *testing.T) {
	tests := []struct {
		name     string
		ct       string
		body     string
		wantErr  bool
		wantCode string
		wantData string
	}{
		{
			name:     "JSON valid",
			ct:       "application/json",
			body:     `{"code":"c1","data":"d1"}`,
			wantCode: "c1",
			wantData: "d1",
		},
		{
			name:     "form valid",
			ct:       "application/x-www-form-urlencoded",
			body:     url.Values{"code": {"c2"}, "data": {"d2"}}.Encode(),
			wantCode: "c2",
			wantData: "d2",
		},
		{
			name:    "form missing code",
			ct:      "application/x-www-form-urlencoded",
			body:    url.Values{"data": {"d3"}}.Encode(),
			wantErr: true,
		},
		{
			name:    "form missing data",
			ct:      "application/x-www-form-urlencoded",
			body:    url.Values{"code": {"c4"}}.Encode(),
			wantErr: true,
		},
		{
			name:    "form duplicate code",
			ct:      "application/x-www-form-urlencoded",
			body:    "code=c5&code=c5b&data=d5",
			wantErr: true,
		},
		{
			name:    "form duplicate data",
			ct:      "application/x-www-form-urlencoded",
			body:    "code=c6&data=d6&data=d6b",
			wantErr: true,
		},
		{
			name:    "form unknown field",
			ct:      "application/x-www-form-urlencoded",
			body:    url.Values{"code": {"c7"}, "data": {"d7"}, "evil": {"e7"}}.Encode(),
			wantErr: true,
		},
		{
			name:    "form oversized",
			ct:      "application/x-www-form-urlencoded",
			body:    "code=" + strings.Repeat("x", 65537) + "&data=d8",
			wantErr: true,
		},
		{
			name:    "form query-only no post",
			ct:      "application/x-www-form-urlencoded",
			body:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = bytes.NewBufferString(tt.body)
			} else {
				body = strings.NewReader("")
			}
			r := httptest.NewRequest(http.MethodPost, "/passkey/finish", body)
			r.Header.Set("Content-Type", tt.ct)
			w := httptest.NewRecorder()

			got, err := decodePasskeyFinish(w, r)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got code=%q data=%q", got.Code, got.Data)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", got.Code, tt.wantCode)
			}
			if got.Data != tt.wantData {
				t.Errorf("Data = %q, want %q", got.Data, tt.wantData)
			}
		})
	}
}

func TestDecodePasskeyFinish_JSON_actualdecoder(t *testing.T) {
	payload := passkeyFinishRequest{Code: "c", Data: "d"}
	raw, _ := json.Marshal(payload)
	r := httptest.NewRequest(http.MethodPost, "/passkey/finish", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	got, err := decodePasskeyFinish(w, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Code != "c" || got.Data != "d" {
		t.Errorf("got code=%q data=%q, want c/d", got.Code, got.Data)
	}
}

func TestDecodePasskeyFinish_CT_values(t *testing.T) {
	mediaType, _, _ := mime.ParseMediaType("application/x-www-form-urlencoded; charset=utf-8")
	if mediaType != "application/x-www-form-urlencoded" {
		t.Fatalf("mime parse failed: %q", mediaType)
	}
}
