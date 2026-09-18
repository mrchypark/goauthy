package masterkeyretirement

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mrchypark/goauthy/internal/apidocs"
	"github.com/mrchypark/goauthy/internal/storage"
)

func TestBarrierResponseMatchesPublishedOpenAPI(t *testing.T) {
	docBytes, err := apidocs.Document("https://issuer.example", apidocs.Features{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(docBytes)
	if err != nil {
		t.Fatal(err)
	}
	schema := doc.Paths.Value("/auth/v1/master_key_retirement").Get.Responses.Status(200).Value.Content.Get("application/json").Schema.Value
	base := time.UnixMilli(1700000000000).UTC()
	fixtures := []storage.MasterKeyRetirement{
		{Epoch: 1, OldKeyID: "old", ReplacementKeyID: "new", Membership: []string{"a"}, MembershipDigest: "digest", State: "prepared", PreparedAt: base, Attestations: []storage.MasterKeyRetirementAttestation{}},
		{Epoch: 2, OldKeyID: "old", ReplacementKeyID: "new", Membership: []string{"a", "b", "c"}, MembershipDigest: "digest", State: "ready", PreparedAt: base, ReadyAt: base.Add(time.Second), Attestations: []storage.MasterKeyRetirementAttestation{{NodeID: "a", BootID: "boot", ActiveKeyID: "new", AttestationSequence: 3, AttestedAt: base.Add(2 * time.Second), Status: storage.MasterKeyRetirementStatus{PasskeyEnabled: true, OldReferences: 0}}}},
	}
	for _, fixture := range fixtures {
		payload, err := json.Marshal(barrierResponse(fixture))
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(payload, &value); err != nil {
			t.Fatal(err)
		}
		if err := schema.VisitJSON(value); err != nil {
			t.Fatalf("fixture state %q rejected: %v", fixture.State, err)
		}
	}
}
