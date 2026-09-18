package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMountMasterKeyRetirementRoutes(t *testing.T) {
	mux := http.NewServeMux()
	mountMasterKeyRetirementRoutes(mux, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/auth/v1/master_key_retirement", nil),
		httptest.NewRequest(http.MethodPost, "/auth/v1/master_key_retirement/prepare", nil),
	} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s %s status=%d", request.Method, request.URL.Path, response.Code)
		}
	}
}
