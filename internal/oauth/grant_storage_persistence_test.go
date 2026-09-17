package oauth

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

func TestEncodeRequestDropsTransientFormFieldsWithoutMutatingRequest(t *testing.T) {
	server := oauthTestServer(t, oauthTestDB(t), randomSecret(t))
	form := url.Values{
		"grant_type":            {"authorization_code"},
		"response_type":         {"code"},
		"scope":                 {"goauthy.read"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirectURI},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
		"resource":              {"https://resource.example.test/api"},
	}
	for field := range transientRequestFormFields {
		form.Set(field, "transient-"+field)
	}
	// Keep credential fixtures independent of the production exclusion list:
	// removing an exclusion must not also remove the input that tests it.
	form["password"] = []string{"raw-password", "duplicate-password"}
	form["client_secret"] = []string{"raw-client-secret"}
	request := fosite.NewRequest()
	request.ID, request.Client, request.RequestedAt, request.Form = "request-1", server.store.client, unixMillis(1700000000000), form
	request.Session = &fosite.DefaultSession{Subject: "subject-1"}

	encoded, err := encodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	var record requestRecord
	if err := json.Unmarshal([]byte(encoded), &record); err != nil {
		t.Fatal(err)
	}
	want := url.Values{
		"grant_type":            {"authorization_code"},
		"response_type":         {"code"},
		"scope":                 {"goauthy.read"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirectURI},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
		"resource":              {"https://resource.example.test/api"},
	}
	if !reflect.DeepEqual(record.Form, want) {
		t.Fatalf("persisted form=%#v, want=%#v", record.Form, want)
	}
	if !reflect.DeepEqual(request.GetRequestForm(), form) {
		t.Fatalf("encodeRequest mutated request form=%#v, want=%#v", request.GetRequestForm(), form)
	}
}

func TestPersistedRequestRowsDropTransientFormsAcrossGrantPaths(t *testing.T) {
	server := exchangeTestServer(t)
	db := server.store.db
	verifier := strings.Repeat("v", 43)

	code := issueCode(t, server, verifier)
	codeSignature := server.authorizeCodes.AuthorizeCodeSignature(context.Background(), code)
	assertSafeRequestRow(t, db, "oauth_authorize_codes", codeSignature)
	assertSafeRequestRow(t, db, "oauth_pkce_requests", codeSignature)

	clientCredentials := decodeToken(t, postToken(server, mapForm("grant_type", "client_credentials")))
	clientCredentialsSignature := server.accessTokens.AccessTokenSignature(context.Background(), clientCredentials.AccessToken)
	assertSafeRequestRow(t, db, "oauth_token_requests", clientCredentialsSignature)

	exchangeCode := issueExchangeCode(t, server)
	issued := decodeToken(t, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {exchangeCode}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)},
	}))
	accessSignature := server.accessTokens.AccessTokenSignature(context.Background(), issued.AccessToken)
	assertSafeRequestRow(t, db, "oauth_token_requests", accessSignature)
	refreshStrategy, ok := server.accessTokens.(oauth2.RefreshTokenStrategy)
	if !ok {
		t.Fatal("OAuth strategy does not support refresh tokens")
	}
	refreshSignature := refreshStrategy.RefreshTokenSignature(context.Background(), issued.RefreshToken)
	assertSafeRequestRow(t, db, "oauth_refresh_tokens", refreshSignature)

	deviceStore := device.NewStore(db)
	seedDeviceUser(t, db, "device-user", nil)
	deviceNow := time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)
	grant, err := deviceStore.Create(context.Background(), testClientID, []string{"goauthy.read", "offline_access"}, deviceNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := deviceStore.Approve(context.Background(), grant.UserCode, "device-user", deviceNow); err != nil {
		t.Fatal(err)
	}
	deviceIssued := decodeToken(t, postToken(server, url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}}))
	deviceAccessSignature := server.accessTokens.AccessTokenSignature(context.Background(), deviceIssued.AccessToken)
	assertSafeRequestRow(t, db, "oauth_token_requests", deviceAccessSignature)
	deviceRefreshSignature := refreshStrategy.RefreshTokenSignature(context.Background(), deviceIssued.RefreshToken)
	assertSafeRequestRow(t, db, "oauth_refresh_tokens", deviceRefreshSignature)

	exchanged := decodeToken(t, postToken(server, url.Values{
		"grant_type": {TokenExchangeGrantType}, "subject_token": {issued.AccessToken}, "subject_token_type": {accessTokenType},
	}))
	exchangeSignature := server.accessTokens.AccessTokenSignature(context.Background(), exchanged.AccessToken)
	assertSafeRequestRow(t, db, "oauth_token_requests", exchangeSignature)
}

func assertSafeRequestRow(t *testing.T, db *rhiza.DB, table, signature string) {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL: `SELECT request_json FROM ` + table + ` WHERE signature = ?`, Args: []any{signature}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("%s request row=%#v err=%v", table, result.Rows, err)
	}
	encoded, ok := result.Rows[0][0].(string)
	if !ok {
		t.Fatalf("%s request row=%#v", table, result.Rows)
	}
	var record requestRecord
	if err := json.Unmarshal([]byte(encoded), &record); err != nil {
		t.Fatalf("%s request JSON: %v", table, err)
	}
	for field := range transientRequestFormFields {
		if _, found := record.Form[field]; found {
			t.Fatalf("%s persisted transient form field %q", table, field)
		}
	}
}

// unixMillis adapts a fixed millisecond value to the request timestamp type.
func unixMillis(ms int64) time.Time { return time.UnixMilli(ms).UTC() }
