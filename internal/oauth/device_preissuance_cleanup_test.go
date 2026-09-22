package oauth

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

type emptyDeviceRequestID struct{ *fosite.AccessRequest }

func (r emptyDeviceRequestID) GetID() string { return "" }

func TestDevicePreissuanceCleanupBeginTXFailureReleasesClaim(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	request := claimedDeviceRequest(t, server, db)

	outerCtx, err := server.store.BeginTX(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	handler := deviceGrantTokenHandler(t, server)
	if err := handler.PopulateTokenEndpointResponse(outerCtx, request, fosite.NewAccessResponse()); err == nil {
		t.Fatal("nested BeginDeviceTX unexpectedly succeeded")
	}
	if txFrom(outerCtx).done {
		t.Fatal("outer transaction was rolled back")
	}
	assertDeviceClaimReleased(t, db)
	assertNoDeviceTokenArtifacts(t, db)
}

func TestDevicePreissuanceCleanupSetRequestIDFailureReleasesClaim(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	request := claimedDeviceRequest(t, server, db)
	requestWithEmptyID := emptyDeviceRequestID{AccessRequest: request}

	handler := deviceGrantTokenHandler(t, server)
	if err := handler.PopulateTokenEndpointResponse(context.Background(), requestWithEmptyID, fosite.NewAccessResponse()); err == nil {
		t.Fatal("empty device request ID unexpectedly succeeded")
	}
	assertDeviceClaimReleased(t, db)
	assertNoDeviceTokenArtifacts(t, db)
}

func deviceGrantTokenHandler(t *testing.T, server *Server) *deviceGrantHandler {
	t.Helper()
	provider, ok := server.provider.(*fosite.Fosite)
	if !ok {
		t.Fatal("provider is not Fosite")
	}
	for _, candidate := range provider.Config.GetTokenEndpointHandlers(context.Background()) {
		if handler, ok := candidate.(*deviceGrantHandler); ok {
			return handler
		}
	}
	t.Fatal("device grant handler not configured")
	return nil
}

func claimedDeviceRequest(t *testing.T, server *Server, db *rhiza.DB) *fosite.AccessRequest {
	t.Helper()
	seedDeviceUser(t, db, "preissuance-cleanup-user", nil)
	store := device.NewStore(db)
	now := time.Now().UTC()
	grant, err := store.Create(context.Background(), testClientID, []string{"goauthy.read", "offline_access"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(context.Background(), grant.UserCode, "preissuance-cleanup-user", now); err != nil {
		t.Fatal(err)
	}
	request := fosite.NewAccessRequest(&fosite.DefaultSession{})
	request.ID = "preissuance-cleanup-request"
	request.Client = server.store.client
	request.GrantTypes = fosite.Arguments{DeviceGrantType}
	request.Form = url.Values{"device_code": {grant.DeviceCode}}
	handler := deviceGrantTokenHandler(t, server)
	if err := handler.HandleTokenEndpointRequest(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if claim, ok := request.GetSession().(*fosite.DefaultSession).Extra[deviceClaimExtra].(string); !ok || claim == "" {
		t.Fatal("device handler did not attach a claim")
	}
	return request
}

func assertDeviceClaimReleased(t *testing.T, db *rhiza.DB) {
	t.Helper()
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_device_grants WHERE state='approved' AND claim_token_digest IS NULL`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) {
		t.Fatalf("released claim state rows=%#v err=%v", rows.Rows, err)
	}
}

func assertNoDeviceTokenArtifacts(t *testing.T, db *rhiza.DB) {
	t.Helper()
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT (SELECT COUNT(*) FROM oauth_access_tokens), (SELECT COUNT(*) FROM oauth_refresh_tokens), (SELECT COUNT(*) FROM oauth_token_requests)`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 3 || rows.Rows[0][0] != int64(0) || rows.Rows[0][1] != int64(0) || rows.Rows[0][2] != int64(0) {
		t.Fatalf("failed pre-issuance left token artifacts rows=%#v err=%v", rows.Rows, err)
	}
}
