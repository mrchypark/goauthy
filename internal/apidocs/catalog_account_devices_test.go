package apidocs

import (
	"context"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestAccountDeviceCatalogContract(t *testing.T) {
	doc := &openapi3.T{OpenAPI: "3.0.3", Info: &openapi3.Info{Title: "test", Version: "test"}, Paths: openapi3.NewPaths(), Components: &openapi3.Components{Schemas: openapi3.Schemas{}}}
	if err := addAccountDeviceOperations(doc); err != nil {
		t.Fatal(err)
	}
	get := doc.Paths.Value("/auth/v1/account/devices").Get
	if get == nil || get.Security == nil || (*get.Security)[0]["browserSession"] == nil {
		t.Fatal("device list missing browser security")
	}
	del := doc.Paths.Value("/auth/v1/account/devices/{id}").Delete
	if del == nil || del.Security == nil || (*del.Security)[0]["csrfToken"] == nil {
		t.Fatal("device delete missing csrf security")
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
}
