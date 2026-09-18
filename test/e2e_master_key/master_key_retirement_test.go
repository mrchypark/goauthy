package e2e_master_key

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const retirementPath = "/auth/v1/master_key_retirement"

type barrier struct {
	Epoch            int64         `json:"epoch"`
	OldKeyID         string        `json:"old_key_id"`
	ReplacementKeyID string        `json:"replacement_key_id"`
	Membership       []string      `json:"membership"`
	State            string        `json:"state"`
	Attestations     []attestation `json:"attestations"`
}

type attestation struct {
	NodeID              string `json:"node_id"`
	BootID              string `json:"boot_id"`
	ActiveKeyID         string `json:"active_key_id"`
	AttestationSequence int64  `json:"attestation_sequence"`
	Status              status `json:"status"`
}

type status struct {
	OldReferences       int64 `json:"old_references"`
	NonActiveReferences int64 `json:"non_active_references"`
	LegacyReferences    int64 `json:"legacy_references"`
	TamperReferences    int64 `json:"tamper_references"`
	OIDCReferences      int64 `json:"oidc_references"`
	DCRReferences       int64 `json:"dcr_references"`
	UpstreamReferences  int64 `json:"upstream_references"`
	PasskeyEnabled      bool  `json:"passkey_enabled"`
	PasskeyReferences   int64 `json:"passkey_references"`
}

func TestMasterKeyRetirementKind(t *testing.T) {
	phase := os.Getenv("GOAUTHY_E2E_RETIREMENT_PHASE")
	if phase == "" {
		t.Skip("set GOAUTHY_E2E_RETIREMENT_PHASE to run the deployed Kind gate")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_RETIREMENT_URL"), "/")
	apiKey := os.Getenv("GOAUTHY_E2E_RETIREMENT_API_KEY")
	if primary == "" || apiKey == "" {
		t.Fatal("GOAUTHY_E2E_RETIREMENT_URL and GOAUTHY_E2E_RETIREMENT_API_KEY are required")
	}

	switch phase {
	case "prepare":
		prepared := mutate(t, client, primary+retirementPath+"/prepare", apiKey, map[string]any{"epoch": 1, "old_key_id": "key-a", "replacement_key_id": "key-b"})
		assertBarrier(t, prepared, "prepared", "key-a", "key-b")
		createDCR(t, client, primary, os.Getenv("GOAUTHY_E2E_RETIREMENT_DCR_TOKEN"), "master-key-retirement-before-fence")
	case "fence":
		before := getBarrier(t, client, primary, apiKey)
		assertBarrier(t, before, "prepared", "key-a", "key-b")
		fenced := mutate(t, client, primary+retirementPath+"/fence", apiKey, map[string]any{"epoch": 1})
		assertBarrier(t, fenced, "fenced", "key-a", "key-b")
		response := dcr(t, client, primary, os.Getenv("GOAUTHY_E2E_RETIREMENT_DCR_TOKEN"), "master-key-retirement-after-fence")
		response.Body.Close()
		if response.StatusCode == http.StatusCreated {
			t.Fatal("old-key DCR writer committed after fence")
		}
	case "attest":
		value := waitBarrier(t, client, primary, apiKey, func(v barrier) bool {
			return v.State == "fenced" && validFreshAttestations(v, "key-b")
		})
		t.Logf("exact-three fenced attestations: %+v", value.Attestations)
		writeNodeZeroEvidence(t, value)
	case "after-restart":
		oldBoot, oldSequence := readNodeZeroEvidence(t)
		value := waitBarrier(t, client, primary, apiKey, func(v barrier) bool {
			for _, a := range v.Attestations {
				if a.NodeID == "goauthy-0" {
					return v.State == "fenced" && a.ActiveKeyID == "key-b" && a.BootID != oldBoot && a.AttestationSequence > oldSequence && a.Status == (status{})
				}
			}
			return false
		})
		if !validFreshAttestations(value, "key-b") {
			t.Fatalf("restart left invalid exact-three evidence: %#v", value)
		}
		t.Logf("exact-three post-restart attestations: %+v", value.Attestations)
	case "ready":
		before := getBarrier(t, client, primary, apiKey)
		assertBarrier(t, before, "fenced", "key-a", "key-b")
		ready := mutate(t, client, primary+retirementPath+"/ready", apiKey, map[string]any{"epoch": 1})
		assertBarrier(t, ready, "ready", "key-a", "key-b")
	default:
		t.Fatalf("unknown retirement phase %q", phase)
	}
}

func getBarrier(t *testing.T, client *http.Client, base, apiKey string) barrier {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, base+retirementPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "API-Key "+apiKey)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		t.Fatalf("retirement GET status=%d body=%s", response.StatusCode, body)
	}
	var value barrier
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func mutate(t *testing.T, client *http.Client, endpoint, apiKey string, payload map[string]any) barrier {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "API-Key "+apiKey)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		t.Fatalf("retirement mutation %s status=%d body=%s", endpoint, response.StatusCode, body)
	}
	var value barrier
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func waitBarrier(t *testing.T, client *http.Client, base, apiKey string, ready func(barrier) bool) barrier {
	t.Helper()
	deadline := time.NewTimer(4 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last barrier
	for {
		last = getBarrier(t, client, base, apiKey)
		if ready(last) {
			return last
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-deadline.C:
			t.Fatalf("timed out waiting for retirement barrier: %#v", last)
		case <-ticker.C:
		}
	}
}

func validFreshAttestations(value barrier, activeKey string) bool {
	if value.State != "fenced" || len(value.Membership) != 3 || len(value.Attestations) != 3 {
		return false
	}
	if !sameThreeNodes(value.Membership) {
		return false
	}
	seenNodes, seenBoots := map[string]bool{}, map[string]bool{}
	for _, a := range value.Attestations {
		if a.ActiveKeyID != activeKey || a.BootID == "" || a.AttestationSequence <= 0 || seenNodes[a.NodeID] || seenBoots[a.BootID] || a.Status != (status{}) {
			return false
		}
		seenNodes[a.NodeID], seenBoots[a.BootID] = true, true
	}
	return len(seenNodes) == 3 && seenNodes["goauthy-0"] && seenNodes["goauthy-1"] && seenNodes["goauthy-2"]
}

func sameThreeNodes(nodes []string) bool {
	if len(nodes) != 3 {
		return false
	}
	seen := map[string]bool{}
	for _, node := range nodes {
		seen[node] = true
	}
	return len(seen) == 3 && seen["goauthy-0"] && seen["goauthy-1"] && seen["goauthy-2"]
}

func writeNodeZeroEvidence(t *testing.T, value barrier) {
	t.Helper()
	path := os.Getenv("GOAUTHY_E2E_RETIREMENT_STATE_FILE")
	if path == "" {
		t.Fatal("GOAUTHY_E2E_RETIREMENT_STATE_FILE is required")
	}
	for _, a := range value.Attestations {
		if a.NodeID == "goauthy-0" {
			data := "node0_boot=" + a.BootID + "\nnode0_sequence=" + strconv.FormatInt(a.AttestationSequence, 10) + "\n"
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("exact-three evidence omitted goauthy-0")
}

func readNodeZeroEvidence(t *testing.T) (string, int64) {
	t.Helper()
	path := os.Getenv("GOAUTHY_E2E_RETIREMENT_STATE_FILE")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	sequence, err := strconv.ParseInt(values["node0_sequence"], 10, 64)
	if err != nil || values["node0_boot"] == "" || sequence <= 0 {
		t.Fatalf("invalid node-zero evidence %q: %v", data, err)
	}
	return values["node0_boot"], sequence
}

func assertBarrier(t *testing.T, value barrier, state, oldKey, replacementKey string) {
	t.Helper()
	if value.Epoch != 1 || value.State != state || value.OldKeyID != oldKey || value.ReplacementKeyID != replacementKey || !sameThreeNodes(value.Membership) {
		t.Fatalf("barrier=%#v want state=%s", value, state)
	}
}

func createDCR(t *testing.T, client *http.Client, base, token, label string) {
	t.Helper()
	response := dcr(t, client, base, token, label)
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		t.Fatalf("pre-fence DCR status=%d body=%s", response.StatusCode, body)
	}
}

func dcr(t *testing.T, client *http.Client, base, token, label string) *http.Response {
	t.Helper()
	body := []byte(fmt.Sprintf(`{"redirect_uris":["https://rp.example.test/%s"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"client_secret_basic","client_name":"%s"}`, label, label))
	request, err := http.NewRequest(http.MethodPost, base+"/oidc/register", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "master-key-retirement-"+label)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
