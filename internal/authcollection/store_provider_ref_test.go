package authcollection

import (
	"errors"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestUpdateDefinitionBlocksRemovingReferencedProviderUnlessRevoked(t *testing.T) {
	t.Parallel()
	s, ctx := collectionFixture(t)
	def, err := s.CreateDefinition(ctx, DefinitionInput{
		ID: "coll-ref", Name: "Ref", AuthMethod: "oauth2", Enabled: true,
		ProviderIDs: []string{"prov-1", "prov-2"},
	}, func() (string, []any) { return "1", nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"ready", "refreshing", "uncertain"} {
		claim := any(nil)
		if state == "refreshing" {
			claim = "claim-" + state
		}
		if _, err := s.db.Execute(ctx, rhiza.ExecuteRequest{
			RequestID: "seed-cred-ref-" + state,
			SQL:       `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential,refresh_claim) VALUES(?,'alice','coll-ref','prov-1','g1',1,?,x'01',?)`,
			Args:      []any{"c-" + state, state, claim},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.UpdateDefinition(ctx, def.ID, def.Revision, DefinitionInput{
			Name: "Ref", AuthMethod: "oauth2", Enabled: true, ProviderIDs: []string{"prov-2"},
		}, func() (string, []any) { return "1", nil }); !errors.Is(err, ErrConflict) {
			t.Fatalf("remove %s provider reference err=%v; want ErrConflict", state, err)
		}
		if _, err := s.db.Execute(ctx, rhiza.ExecuteRequest{
			RequestID: "revoke-cred-ref-" + state,
			SQL:       `UPDATE saas_connection_credentials SET state='revoked',refresh_claim=NULL WHERE collection_id='coll-ref' AND connection_id=?`,
			Args:      []any{"c-" + state},
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Removing prov-1 after all staged states are revoked must now succeed.
	updated, err := s.UpdateDefinition(ctx, def.ID, def.Revision, DefinitionInput{
		Name: "Ref", AuthMethod: "oauth2", Enabled: true, ProviderIDs: []string{"prov-2"},
	}, func() (string, []any) { return "1", nil })
	if err != nil || len(updated.ProviderIDs) != 1 || updated.ProviderIDs[0] != "prov-2" {
		t.Fatalf("remove revoked provider updated=%+v err=%v", updated, err)
	}

	// Legacy api_key collection with providers_json=[] and active provider_id='api-key' must still allow updates.
	legacy, err := s.CreateDefinition(ctx, DefinitionInput{
		ID: "coll-legacy-apikey", Name: "Legacy", AuthMethod: "api_key", Enabled: true, ProviderIDs: []string{},
	}, func() (string, []any) { return "1", nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Execute(ctx, rhiza.ExecuteRequest{
		RequestID: "seed-legacy-apikey-cred",
		SQL:       `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential) VALUES('c-legacy','alice','coll-legacy-apikey','api-key','g1',1,'ready',x'01')`,
	}); err != nil {
		t.Fatal(err)
	}
	if updatedLegacy, err := s.UpdateDefinition(ctx, legacy.ID, legacy.Revision, DefinitionInput{
		Name: "Legacy Renamed", AuthMethod: "api_key", Enabled: false, ProviderIDs: []string{},
	}, func() (string, []any) { return "1", nil }); err != nil || updatedLegacy.Name != "Legacy Renamed" || updatedLegacy.Enabled {
		t.Fatalf("legacy api_key update err=%v updated=%+v", err, updatedLegacy)
	}
}
