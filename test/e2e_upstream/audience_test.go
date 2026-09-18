package e2e_upstream

import (
	"encoding/json"
	"testing"
)

func TestAudienceUnmarshalString(t *testing.T) {
	raw := `{"aud":"goauthy-dev"}`
	var claims idTokenClaims
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		t.Fatalf("unmarshal string aud: %v", err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "goauthy-dev" {
		t.Fatalf("expected [goauthy-dev], got %v", claims.Audience)
	}
}

func TestAudienceUnmarshalArray(t *testing.T) {
	raw := `{"aud":["goauthy-dev","other"]}`
	var claims idTokenClaims
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		t.Fatalf("unmarshal array aud: %v", err)
	}
	if len(claims.Audience) != 2 || claims.Audience[0] != "goauthy-dev" || claims.Audience[1] != "other" {
		t.Fatalf("expected [goauthy-dev other], got %v", claims.Audience)
	}
}

func TestAudienceRejectsInvalid(t *testing.T) {
	raw := `{"aud":42}`
	var claims idTokenClaims
	if err := json.Unmarshal([]byte(raw), &claims); err == nil {
		t.Fatalf("expected error for numeric aud, got claims=%+v", claims)
	}
}

func TestAudienceRejectsWrongAudience(t *testing.T) {
	raw := `{"aud":"wrong-client"}`
	var claims idTokenClaims
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if contains([]string(claims.Audience), bootstrapClientID) {
		t.Fatalf("wrong audience should not match bootstrapClientID")
	}
}

func TestAudienceRejectsNull(t *testing.T) {
	raw := `{"aud":null}`
	var claims idTokenClaims
	if err := json.Unmarshal([]byte(raw), &claims); err == nil {
		t.Fatalf("expected error for null aud, got claims=%+v", claims)
	}
}

func TestAudienceRejectsArrayWithNull(t *testing.T) {
	raw := `{"aud":["goauthy-dev",null]}`
	var claims idTokenClaims
	if err := json.Unmarshal([]byte(raw), &claims); err == nil {
		t.Fatalf("expected error for array with null element, got claims=%+v", claims)
	}
}

func TestAudienceRejectsObject(t *testing.T) {
	raw := `{"aud":{}}`
	var claims idTokenClaims
	if err := json.Unmarshal([]byte(raw), &claims); err == nil {
		t.Fatalf("expected error for object aud, got claims=%+v", claims)
	}
}

func TestAudienceRejectsBool(t *testing.T) {
	raw := `{"aud":true}`
	var claims idTokenClaims
	if err := json.Unmarshal([]byte(raw), &claims); err == nil {
		t.Fatalf("expected error for bool aud, got claims=%+v", claims)
	}
}
