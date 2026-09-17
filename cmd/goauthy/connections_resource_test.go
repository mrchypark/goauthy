package main

import "testing"

func TestConnectionsResourceFromEnv(t *testing.T) {
	const resource = "https://identity.example/connections"
	for _, tc := range []struct {
		name    string
		value   string
		allowed []string
		wantErr bool
	}{
		{"disabled", "", nil, false},
		{"registered", resource, []string{resource}, false},
		{"unregistered", resource, nil, true},
		{"different resource", resource, []string{"https://other.example"}, true},
		{"no normalization", resource + "/", []string{resource}, true},
		{"no trimming", " " + resource, []string{resource}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resourceFromEnv(func(key string) string {
				if key != "GOAUTHY_CONNECTIONS_RESOURCE" {
					t.Fatalf("unexpected key %s", key)
				}
				return tc.value
			}, "GOAUTHY_CONNECTIONS_RESOURCE", tc.allowed)
			if (err != nil) != tc.wantErr || (err == nil && got != tc.value) {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}
