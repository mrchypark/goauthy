package saas

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestAuthorizationProofUsesPKCEAndRedacts(t *testing.T) {
	proof := newAuthorizationProof()
	if !validState(proof.state) || !validVerifier(proof.verifier) || len(proof.state) != 43 {
		t.Fatal("invalid generated authorization proof")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		printed := fmt.Sprintf(format, proof)
		if strings.Contains(printed, proof.state) || strings.Contains(printed, proof.verifier) {
			t.Fatal("debug output exposes raw proof")
		}
	}
	encoded, err := json.Marshal(proof)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("proof JSON exposed: err=%v", err)
	}
	// RFC 7636 Appendix B's SHA-256 vector; the same encoding is used for
	// persisted digests, without storing the raw verifier.
	if got := authorizationDigest("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("digest encoding=%q", got)
	}
}
