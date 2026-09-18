package webid_ha

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const defaultSubject = "webid-subject"

func TestWebIDHA(t *testing.T) {
	urls := strings.Split(strings.TrimSpace(os.Getenv("GOAUTHY_E2E_WEBID_URLS")), ",")
	if len(urls) == 1 && urls[0] == "" {
		t.Skip("set GOAUTHY_E2E_WEBID_URLS to three comma-separated pod URLs")
	}
	if len(urls) != 3 {
		t.Fatalf("GOAUTHY_E2E_WEBID_URLS has %d URLs, want exactly 3", len(urls))
	}
	for i := range urls {
		urls[i] = strings.TrimRight(strings.TrimSpace(urls[i]), "/")
		if urls[i] == "" {
			t.Fatalf("GOAUTHY_E2E_WEBID_URLS contains an empty URL")
		}
	}
	issuer := strings.TrimRight(os.Getenv("GOAUTHY_E2E_WEBID_ISSUER"), "/")
	if issuer == "" {
		t.Fatal("GOAUTHY_E2E_WEBID_ISSUER is required")
	}
	subject := os.Getenv("GOAUTHY_E2E_WEBID_SUBJECT")
	if subject == "" {
		subject = defaultSubject
	}
	client := &http.Client{Timeout: 10 * time.Second}
	path := "/auth/" + subject + "/profile"
	expected := []byte(fmt.Sprintf("<%s/auth/%s/profile> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://xmlns.com/foaf/0.1/PersonalProfileDocument>;\n\t<http://xmlns.com/foaf/0.1/primaryTopic> <%s/auth/%s/profile#me> .\n<%s/auth/%s/profile#me> <http://www.w3.org/ns/solid/terms#oidcIssuer> <%s>;\n\t<http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <http://xmlns.com/foaf/0.1/Person> .\n", issuer, subject, issuer, subject, issuer, subject, issuer))

	for _, base := range urls {
		assertReady(t, client, base)
	}
	for _, accept := range []string{"", "text/turtle", "text/turtle; charset=utf-8", "text/turtle;q=0.9", "*/*"} {
		var first []byte
		for i, base := range urls {
			body := assertProfile(t, client, base+path, accept, expected)
			if i == 0 {
				first = body
			} else if !bytes.Equal(first, body) {
				t.Fatalf("cross-pod WebID body mismatch for Accept %q: pod %d differs", accept, i)
			}
		}
	}

	for _, base := range urls {
		assertStatus(t, client, http.MethodGet, base+path, "text/turtle;q=0", http.StatusNotAcceptable)
		assertStatus(t, client, http.MethodGet, base+path, "application/ld+json", http.StatusNotAcceptable)
		assertStatus(t, client, http.MethodGet, base+path+"?probe=1", "text/turtle", http.StatusNotFound)
		assertStatus(t, client, http.MethodGet, base+"/auth/"+subject+"%2Fother/profile", "text/turtle", http.StatusNotFound)
		assertStatus(t, client, http.MethodGet, base+"/auth/"+subject+"/other/profile", "text/turtle", http.StatusNotFound)
		assertStatus(t, client, http.MethodGet, base+"/auth/unknown-subject/profile", "text/turtle", http.StatusNotFound)
		assertStatus(t, client, http.MethodHead, base+path, "text/turtle", http.StatusMethodNotAllowed)
		assertStatus(t, client, http.MethodPost, base+path, "text/turtle", http.StatusMethodNotAllowed)
	}
	t.Logf("WebID enabled output and privacy/Accept/path negatives passed across %d pods (phase=%s)", len(urls), os.Getenv("GOAUTHY_E2E_WEBID_PHASE"))
}

func assertReady(t *testing.T, client *http.Client, base string) {
	t.Helper()
	response, err := client.Get(base + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("%s/readyz status=%d", base, response.StatusCode)
	}
}

func assertProfile(t *testing.T, client *http.Client, endpoint, accept string, expected []byte) []byte {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/turtle; charset=utf-8" {
		t.Fatalf("WebID GET %s Accept=%q status=%d content-type=%q", endpoint, accept, response.StatusCode, response.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, expected) {
		firstDifference := -1
		for i := 0; i < len(body) && i < len(expected); i++ {
			if body[i] != expected[i] {
				firstDifference = i
				break
			}
		}
		t.Fatalf("unexpected WebID body for %s: got %q (len=%d) want %q (len=%d), first difference=%d", endpoint, body, len(body), expected, len(expected), firstDifference)
	}
	for _, private := range []string{"webid@example.test", "email", "roles", "groups"} {
		if bytes.Contains(body, []byte(private)) {
			t.Fatalf("WebID body leaked private marker %q", private)
		}
	}
	return body
}

func assertStatus(t *testing.T, client *http.Client, method, endpoint, accept string, want int) {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Accept", accept)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != want {
		t.Fatalf("WebID %s %s Accept=%q status=%d want=%d", method, endpoint, accept, response.StatusCode, want)
	}
}
