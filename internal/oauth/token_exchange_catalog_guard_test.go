package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestTokenExchangeCustomCatalogGuardWithoutPrincipalResolver(t *testing.T) {
	accessValue := json.RawMessage(`"catalog-v1"`)
	server := customClaimsServer(t, false, &accessValue)
	server.oidc.ResolvePrincipal = nil
	source := exchangeCatalogSource(t, server, "n")
	beforeAccess, beforeRequests := exchangeCatalogArtifacts(t, server)
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "exchange-catalog-without-principal", SQL: `UPDATE claims_catalog SET revision=revision+1 WHERE id=1`}); err != nil {
			t.Fatal(err)
		}
	}
	response := postToken(server, exchangeCatalogForm(source))
	if response.Code != http.StatusBadRequest || oauthErrorCode(t, response) != "invalid_grant" {
		t.Fatalf("catalog race status=%d error=%q", response.Code, oauthErrorCode(t, response))
	}
	assertExchangeCatalogArtifacts(t, server, beforeAccess, beforeRequests)
}

func TestTokenExchangeCustomClaimsWithoutPrincipalResolverStillIssues(t *testing.T) {
	accessValue := json.RawMessage(`"catalog-v1"`)
	server := customClaimsServer(t, false, &accessValue)
	server.oidc.ResolvePrincipal = nil
	source := exchangeCatalogSource(t, server, "p")
	issued := decodeToken(t, postToken(server, exchangeCatalogForm(source)))
	if claims := jwtPayload(t, issued.AccessToken); claims["custom"].(map[string]any)["access_value"] != "catalog-v1" {
		t.Fatalf("custom exchange claims=%#v", claims)
	}
}

func TestTokenExchangePrincipalRevisionGuardWithResolver(t *testing.T) {
	accessValue := json.RawMessage(`"catalog-v1"`)
	server := customClaimsServer(t, false, &accessValue)
	source := exchangeCatalogSource(t, server, "r")
	beforeAccess, beforeRequests := exchangeCatalogArtifacts(t, server)
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "exchange-principal-revision", SQL: `UPDATE rbac_principal_versions SET revision=revision+1 WHERE subject='user-1'`}); err != nil {
			t.Fatal(err)
		}
	}
	response := postToken(server, exchangeCatalogForm(source))
	if response.Code != http.StatusBadRequest || oauthErrorCode(t, response) != "invalid_grant" {
		t.Fatalf("principal race status=%d error=%q", response.Code, oauthErrorCode(t, response))
	}
	assertExchangeCatalogArtifacts(t, server, beforeAccess, beforeRequests)
}

func TestTokenExchangePrincipalRevisionGuardWithoutPrincipalResolver(t *testing.T) {
	accessValue := json.RawMessage(`"catalog-v1"`)
	server := customClaimsServer(t, false, &accessValue)
	source := exchangeCatalogSource(t, server, "q")
	// Source issuance uses the normal resolver. Exchange then exercises the
	// valid configuration that resolves scoped custom claims without a separate
	// principal resolver.
	server.oidc.ResolvePrincipal = nil
	beforeAccess, beforeRequests := exchangeCatalogArtifacts(t, server)
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		if _, err := storage.Execute(context.Background(), server.store.db, rhiza.ExecuteRequest{RequestID: "exchange-principal-without-resolver", SQL: `UPDATE rbac_principal_versions SET revision=revision+1 WHERE subject='user-1'`}); err != nil {
			t.Fatal(err)
		}
	}
	response := postToken(server, exchangeCatalogForm(source))
	if response.Code != http.StatusBadRequest || oauthErrorCode(t, response) != "invalid_grant" {
		t.Fatalf("principal race without resolver status=%d error=%q", response.Code, oauthErrorCode(t, response))
	}
	assertExchangeCatalogArtifacts(t, server, beforeAccess, beforeRequests)
}

func exchangeCatalogSource(t *testing.T, server *Server, seed string) string {
	t.Helper()
	return decodeToken(t, postToken(server, codeTokenForm(t, server, seed, "employee goauthy.read"))).AccessToken
}

func exchangeCatalogForm(source string) url.Values {
	return url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {source}, "subject_token_type": {accessTokenType}, "scope": {"employee goauthy.read"}}
}

func exchangeCatalogArtifacts(t *testing.T, server *Server) (int64, int64) {
	t.Helper()
	rows, err := server.store.db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens), (SELECT COUNT(*) FROM oauth_token_requests)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 2 {
		t.Fatalf("exchange artifact query rows=%v err=%v", rows.Rows, err)
	}
	access, accessOK := rows.Rows[0][0].(int64)
	requests, requestsOK := rows.Rows[0][1].(int64)
	if !accessOK || !requestsOK {
		t.Fatalf("exchange artifact types rows=%v", rows.Rows)
	}
	return access, requests
}

func assertExchangeCatalogArtifacts(t *testing.T, server *Server, wantAccess, wantRequests int64) {
	t.Helper()
	access, requests := exchangeCatalogArtifacts(t, server)
	if access != wantAccess || requests != wantRequests {
		t.Fatalf("exchange artifacts access=%d/%d requests=%d/%d", access, wantAccess, requests, wantRequests)
	}
}
