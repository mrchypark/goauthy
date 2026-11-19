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
	if _, err := s.db.Execute(ctx, rhiza.ExecuteRequest{
		RequestID: "seed-cred-ref",
		SQL:       `INSERT INTO saas_connection_credentials(connection_id,owner_subject,collection_id,provider_id,generation,token_version,state,credential) VALUES('c1','alice','coll-ref','prov-1','g1',1,'ready',x'01')`,
	}); err != nil {
		t.Fatal(err)
	}
	// Removing prov-1 while state='ready' must fail with ErrConflict.
	if _, err := s.UpdateDefinition(ctx, def.ID, def.Revision, DefinitionInput{
		Name: "Ref", AuthMethod: "oauth2", Enabled: true, ProviderIDs: []string{"prov-2"},
	}, func() (string, []any) { return "1", nil }); !errors.Is(err, ErrConflict) {
		t.Fatalf("remove active provider err=%v; want ErrConflict", err)
	}
	// Transition credential to revoked; removing prov-1 must now succeed.
	if _, err := s.db.Execute(ctx, rhiza.ExecuteRequest{
		RequestID: "revoke-cred-ref",
		SQL:       `UPDATE saas_connection_credentials SET state='revoked' WHERE connection_id='c1'`,
	}); err != nil {
		t.Fatal(err)
	}
	updated, err := s.UpdateDefinition(ctx, def.ID, def.Revision, DefinitionInput{
		Name: "Ref", AuthMethod: "oauth2", Enabled: true, ProviderIDs: []string{"prov-2"},
	}, func() (string, []any) { return "1", nil })
	if err != nil || len(updated.ProviderIDs) != 1 || updated.ProviderIDs[0] != "prov-2" {
		t.Fatalf("remove revoked provider updated=%+v err=%v", updated, err)
	}
}
