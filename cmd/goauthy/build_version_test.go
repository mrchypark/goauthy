package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainerReleaseInjectsOpenAPIVersion(t *testing.T) {
	root := filepath.Join("..", "..")
	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ARG GOAUTHY_VERSION",
		"-X github.com/mrchypark/goauthy/internal/apidocs.buildVersion=${GOAUTHY_VERSION}",
	} {
		if !strings.Contains(string(dockerfile), want) {
			t.Fatalf("Dockerfile missing %q", want)
		}
	}
	publish, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "publish.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`goauthy_version="sha-${sha:0:12}"`,
		`echo "goauthy_version=$goauthy_version" >> "$GITHUB_OUTPUT"`,
		`GOAUTHY_VERSION=${{ steps.source.outputs.goauthy_version }}`,
	} {
		if !strings.Contains(string(publish), want) {
			t.Fatalf("publish workflow missing %q", want)
		}
	}
}
