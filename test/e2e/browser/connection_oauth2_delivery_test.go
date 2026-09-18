package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// oauth2DeliveryProbe provisions consent for the already-ready OAuth2
// connection. The returned callbacks let the caller check both token versions
// and revoke consent before deleting the connection.
func oauth2DeliveryProbe(t *testing.T, owner *http.Client, primary string, cookie *http.Cookie, headers map[string]string, collectionID, connectionID, providerID, fixtureBase string) (func(int64), func(int64), func(), func()) {
	t.Helper()
	fixtureURL, err := url.Parse(fixtureBase)
	if err != nil || fixtureURL.Scheme != "https" || fixtureURL.Hostname() == "" {
		t.Fatal("invalid OAuth2 fixture URL")
	}
	fixture := oauth2FixtureClient(t, fixtureURL)
	const redirect = "https://rp.example.test/use-grant"
	newConsumer := func(label string) (string, string) {
		id := label + "-" + randomManagedUIID(t)
		body := `{"id":"` + id + `","name":"OAuth2 delivery E2E","confidential":true,"redirect_uris":["` + redirect + `"],"audience":["` + useGrantResource + `"],"scopes":["goauthy.connections.use"],"default_scopes":["goauthy.connections.use"],"enabled_flows":["authorization_code"]}`
		r := do(t, owner, http.MethodPost, primary+"/auth/v1/clients", strings.NewReader(body), headers)
		var created struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
		}
		err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&created)
		r.Body.Close()
		if r.StatusCode != http.StatusCreated || err != nil || created.ID != id || created.Revision < 1 {
			t.Fatalf("delivery consumer create status=%d", r.StatusCode)
		}
		secretResponse := do(t, owner, http.MethodPost, primary+"/auth/v1/clients/"+url.PathEscape(id)+"/secret", nil, headers)
		var secret struct {
			Secret string `json:"secret"`
		}
		err = json.NewDecoder(io.LimitReader(secretResponse.Body, 4096)).Decode(&secret)
		secretResponse.Body.Close()
		if secretResponse.StatusCode != http.StatusOK || err != nil || secret.Secret == "" {
			t.Fatalf("delivery consumer secret status=%d", secretResponse.StatusCode)
		}
		t.Cleanup(func() {
			get := do(t, owner, http.MethodGet, primary+"/auth/v1/clients/"+url.PathEscape(id), nil, headers)
			var current struct {
				Revision int64 `json:"revision"`
			}
			err := json.NewDecoder(io.LimitReader(get.Body, 4096)).Decode(&current)
			get.Body.Close()
			if get.StatusCode != http.StatusOK || err != nil || current.Revision < 1 {
				t.Errorf("delivery consumer cleanup lookup status=%d", get.StatusCode)
				return
			}
			remove := do(t, owner, http.MethodDelete, primary+"/auth/v1/clients/"+url.PathEscape(id), nil, sessionHeader(headers, "If-Match", `"`+strconv.FormatInt(current.Revision, 10)+`"`))
			remove.Body.Close()
			if remove.StatusCode != http.StatusNoContent {
				t.Errorf("delivery consumer cleanup status=%d", remove.StatusCode)
			}
		})
		return id, secret.Secret
	}
	consumerID, consumerSecret := newConsumer("oauth2-delivery")
	otherID, otherSecret := newConsumer("oauth2-delivery-other")
	consumerToken := issueGrantResourceTokenWithSecret(t, owner, primary, consumerID, useGrantResource, "goauthy.connections.use", consumerSecret)
	otherToken := issueGrantResourceTokenWithSecret(t, owner, primary, otherID, useGrantResource, "goauthy.connections.use", otherSecret)

	connectionURL := primary + "/auth/v1/account/connections/" + url.PathEscape(collectionID) + "/" + url.PathEscape(connectionID)
	consentExpiry := time.Now().Add(time.Hour).UnixMilli()
	allowRefresh := os.Getenv("GOAUTHY_E2E_CONSUMER_REFRESH") == "1"
	var grantJSON []byte
	if os.Getenv("GOAUTHY_E2E_OAUTH2_HANDOFF_UI") == "1" {
		grantJSON, consentExpiry = createOAuth2GrantHandoffUI(t, owner, primary, cookie, headers, collectionID, connectionID, consumerID, allowRefresh)
	} else if os.Getenv("GOAUTHY_E2E_OAUTH2_GRANT_UI") == "1" {
		grantJSON, consentExpiry = createOAuth2GrantUI(t, owner, primary, cookie, headers, collectionID, connectionID, consumerID)
	} else {
		grantBody := `{"consumer_client_id":"` + consumerID + `","mode":"credential_delivery","purpose":"OAuth2 credential delivery","expires_at_unix_ms":` + strconv.FormatInt(consentExpiry, 10)
		if allowRefresh {
			grantBody += `,"allow_refresh":true`
		}
		grantBody += `}`
		grant := do(t, owner, http.MethodPost, connectionURL+"/grants", strings.NewReader(grantBody), headers)
		grantJSON, err = io.ReadAll(io.LimitReader(grant.Body, 8192))
		grant.Body.Close()
		if err != nil || grant.StatusCode != http.StatusCreated {
			t.Fatalf("OAuth2 delivery grant status=%d", grant.StatusCode)
		}
	}
	var grantDoc struct {
		ID           string `json:"id"`
		Revision     int64  `json:"revision"`
		Provider     string `json:"provider_id"`
		Generation   string `json:"generation"`
		Expires      int64  `json:"expires_at_unix_ms"`
		Consumer     string `json:"consumer_client_id"`
		Mode         string `json:"mode"`
		AllowRefresh bool   `json:"allow_refresh"`
	}
	err = json.Unmarshal(grantJSON, &grantDoc)
	if err != nil || grantDoc.ID == "" || grantDoc.Revision != 1 || grantDoc.Provider != providerID || grantDoc.Generation == "" || grantDoc.Expires != consentExpiry || grantDoc.Consumer != consumerID || grantDoc.Mode != "credential_delivery" || grantDoc.AllowRefresh != allowRefresh {
		t.Fatal("OAuth2 delivery grant metadata mismatch")
	}

	bearer := map[string]string{"Authorization": "Bearer " + consumerToken}
	refreshBearer := map[string]string{"Authorization": "Bearer " + consumerToken, "Content-Type": "application/json"}
	credentialStatus := func(token, id string, want int, version int64) {
		before := readOAuth2FixtureStats(t, fixture, fixtureBase)
		headers := map[string]string{}
		if token != "" {
			headers["Authorization"] = "Bearer " + token
		}
		r := do(t, newBrowserClient(t), http.MethodGet, primary+"/auth/v1/connection-grants/"+url.PathEscape(id)+"/credential-status", nil, headers)
		if want != http.StatusOK {
			assertMetadataOnlyOAuth2Response(t, r, want)
		} else {
			data, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
			r.Body.Close()
			var status struct {
				Connected  bool     `json:"connected"`
				State      string   `json:"state"`
				Version    int64    `json:"version"`
				ProviderID string   `json:"provider_id"`
				AccountID  string   `json:"account_id"`
				Scopes     []string `json:"scopes"`
			}
			var fields map[string]json.RawMessage
			fieldErr := json.Unmarshal(data, &fields)
			if r.StatusCode != http.StatusOK || r.Header.Get("Cache-Control") != "no-store" || err != nil || json.Unmarshal(data, &status) != nil || fieldErr != nil || len(fields) != 6 || !status.Connected || status.State != "ready" || status.Version != version || status.ProviderID != providerID || status.AccountID != "fixture-subject" || len(status.Scopes) != 1 || status.Scopes[0] != "account" || fields["access_token"] != nil || fields["refresh_token"] != nil || fields["client_secret"] != nil {
				t.Fatalf("consumer credential status contract failed: status=%d", r.StatusCode)
			}
		}
		if after := readOAuth2FixtureStats(t, fixture, fixtureBase); after != before {
			t.Fatal("credential status caused an external provider request")
		}
	}
	refreshDenied := func(token string, id, version string, want int) {
		before := readOAuth2FixtureStats(t, fixture, fixtureBase)
		headers := map[string]string{}
		if token != "" {
			headers["Authorization"] = "Bearer " + token
		}
		headers["Content-Type"] = "application/json"
		r := do(t, newBrowserClient(t), http.MethodPost, primary+"/auth/v1/connection-grants/"+url.PathEscape(id)+"/refresh", strings.NewReader(`{"credential_version":`+version+`}`), headers)
		assertMetadataOnlyOAuth2Response(t, r, want)
		if after := readOAuth2FixtureStats(t, fixture, fixtureBase); after != before {
			t.Fatal("denied consumer refresh caused an external provider request")
		}
	}
	if !allowRefresh {
		refreshDenied(consumerToken, grantDoc.ID, "1", http.StatusNotFound)
	} else {
		refreshDenied("", grantDoc.ID, "1", http.StatusUnauthorized)
		refreshDenied(otherToken, grantDoc.ID, "1", http.StatusNotFound)
		refreshDenied(consumerToken, grantDoc.ID, "99", http.StatusNotFound)
	}
	credentialStatus(consumerToken, grantDoc.ID, http.StatusOK, 1)
	credentialStatus(otherToken, grantDoc.ID, http.StatusNotFound, 0)
	credentialStatus("", grantDoc.ID, http.StatusUnauthorized, 0)
	missing := do(t, newBrowserClient(t), http.MethodPost, primary+"/auth/v1/connection-grants/"+url.PathEscape(grantDoc.ID)+"/credential", nil, nil)
	assertMetadataOnlyOAuth2Response(t, missing, http.StatusUnauthorized)
	other := do(t, newBrowserClient(t), http.MethodPost, primary+"/auth/v1/connection-grants/"+url.PathEscape(grantDoc.ID)+"/credential", nil, map[string]string{"Authorization": "Bearer " + otherToken})
	assertMetadataOnlyOAuth2Response(t, other, http.StatusNotFound)

	var deliveredToken string
	var deliveredVersion int64
	check := func(version int64) {
		before := readOAuth2FixtureStats(t, fixture, fixtureBase)
		deliver := do(t, newBrowserClient(t), http.MethodPost, primary+"/auth/v1/connection-grants/"+url.PathEscape(grantDoc.ID)+"/credential", nil, bearer)
		data, readErr := io.ReadAll(io.LimitReader(deliver.Body, 16<<10))
		deliver.Body.Close()
		var got struct {
			Kind           string   `json:"kind"`
			AccessToken    string   `json:"access_token"`
			TokenType      string   `json:"token_type"`
			GrantID        string   `json:"grant_id"`
			ProviderID     string   `json:"provider_id"`
			Generation     string   `json:"connection_generation"`
			Version        int64    `json:"credential_version"`
			AccountID      string   `json:"account_id"`
			Scopes         []string `json:"scopes"`
			TokenExpires   int64    `json:"token_expires_at_unix_ms"`
			ConsentExpires int64    `json:"consent_expires_at_unix_ms"`
		}
		var fields map[string]json.RawMessage
		err := json.Unmarshal(data, &got)
		fieldErr := json.Unmarshal(data, &fields)
		if deliver.StatusCode != http.StatusOK || deliver.Header.Get("Cache-Control") != "no-store" || readErr != nil || err != nil || fieldErr != nil || len(fields) != 11 || got.Kind != "oauth2" || got.AccessToken == "" || got.TokenType != "Bearer" || got.GrantID != grantDoc.ID || got.ProviderID != providerID || got.Generation != grantDoc.Generation || got.Version != version || got.AccountID != "fixture-subject" || len(got.Scopes) != 1 || got.Scopes[0] != "account" || got.TokenExpires <= time.Now().UnixMilli() || got.ConsentExpires != grantDoc.Expires || fields["api_key"] != nil || fields["client_secret"] != nil || fields["refresh_token"] != nil {
			t.Fatalf("OAuth2 delivery response contract failed: status=%d", deliver.StatusCode)
		}
		if after := readOAuth2FixtureStats(t, fixture, fixtureBase); after != before {
			t.Fatal("credential delivery caused an external provider request")
		}
		credentialStatus(consumerToken, grantDoc.ID, http.StatusOK, version)
		if deliveredVersion != 0 && version != deliveredVersion && got.AccessToken == deliveredToken {
			t.Fatal("OAuth2 delivery returned the pre-refresh access token")
		}
		if deliveredVersion == version && got.AccessToken != deliveredToken {
			t.Fatal("OAuth2 delivery changed the access token without a version change")
		}
		deliveredToken = got.AccessToken
		deliveredVersion = version
		userinfo := do(t, fixture, http.MethodGet, strings.TrimRight(fixtureBase, "/")+"/userinfo", nil, map[string]string{"Authorization": "Bearer " + got.AccessToken})
		var subject struct {
			Subject string `json:"sub"`
		}
		err = json.NewDecoder(io.LimitReader(userinfo.Body, 4096)).Decode(&subject)
		userinfo.Body.Close()
		if userinfo.StatusCode != http.StatusOK || err != nil || subject.Subject != "fixture-subject" {
			t.Fatalf("delivered token userinfo status=%d subject=%q", userinfo.StatusCode, subject.Subject)
		}
	}

	denied := func() {
		before := readOAuth2FixtureStats(t, fixture, fixtureBase)
		r := do(t, newBrowserClient(t), http.MethodPost, primary+"/auth/v1/connection-grants/"+url.PathEscape(grantDoc.ID)+"/credential", nil, bearer)
		assertMetadataOnlyOAuth2Response(t, r, http.StatusNotFound)
		if after := readOAuth2FixtureStats(t, fixture, fixtureBase); after != before {
			t.Fatal("denied credential delivery caused an external provider request")
		}
	}
	revoked := false
	revoke := func() {
		if revoked {
			return
		}
		r := do(t, owner, http.MethodDelete, connectionURL+"/grants/"+url.PathEscape(grantDoc.ID), nil, sessionHeader(headers, "If-Match", `"1"`))
		r.Body.Close()
		if r.StatusCode != http.StatusNoContent {
			t.Fatalf("OAuth2 delivery grant revoke status=%d", r.StatusCode)
		}
		revoked = true
		denied()
		if allowRefresh {
			refreshDenied(consumerToken, grantDoc.ID, "2", http.StatusNotFound)
		}
		credentialStatus(consumerToken, grantDoc.ID, http.StatusNotFound, 0)
	}
	t.Cleanup(revoke)
	refresh := func(version int64) {}
	if allowRefresh {
		refresh = func(version int64) {
			before := readOAuth2FixtureStats(t, fixture, fixtureBase)
			r := do(t, newBrowserClient(t), http.MethodPost, primary+"/auth/v1/connection-grants/"+url.PathEscape(grantDoc.ID)+"/refresh", strings.NewReader(`{"credential_version":`+strconv.FormatInt(version, 10)+`}`), refreshBearer)
			data, readErr := io.ReadAll(io.LimitReader(r.Body, 16<<10))
			r.Body.Close()
			var status struct {
				Connected  bool     `json:"connected"`
				State      string   `json:"state"`
				Version    int64    `json:"version"`
				ProviderID string   `json:"provider_id"`
				AccountID  string   `json:"account_id"`
				Scopes     []string `json:"scopes"`
			}
			var fields map[string]json.RawMessage
			err := json.Unmarshal(data, &status)
			fieldErr := json.Unmarshal(data, &fields)
			if r.StatusCode != http.StatusOK || readErr != nil || err != nil || fieldErr != nil || len(fields) != 6 || !status.Connected || status.State != "ready" || status.Version != version+1 || status.ProviderID != providerID || status.AccountID != "fixture-subject" || len(status.Scopes) != 1 || status.Scopes[0] != "account" || fields["access_token"] != nil || fields["refresh_token"] != nil || fields["client_secret"] != nil {
				t.Fatalf("consumer refresh response contract failed: status=%d", r.StatusCode)
			}
			after := readOAuth2FixtureStats(t, fixture, fixtureBase)
			if after.Authorize != before.Authorize || after.Token != before.Token+1 || after.UserInfo != before.UserInfo+1 {
				t.Fatalf("consumer refresh provider stats delta=%+v", oauth2FixtureStatsSnapshot{after.Authorize - before.Authorize, after.Token - before.Token, after.UserInfo - before.UserInfo})
			}
		}
	}
	return check, refresh, revoke, denied
}
