package cimd

import "testing"

func FuzzStrictMetadataParsers(f *testing.F) {
	for _, seed := range []struct {
		target string
		body   []byte
	}{
		{"https://metadata.example/client.json", []byte(`{"client_id":"https://metadata.example/client.json","redirect_uris":["https://metadata.example/callback"]}`)},
		{"https://metadata.example/client.json", []byte(`{"client_id":"one","client_id":"two"}`)},
		{"https://metadata.example/%2e%2e/client.json", []byte(`{`)},
		{"https://metadata.example/client.json", make([]byte, maxDocumentBytes+1)},
	} {
		f.Add(seed.target, seed.body)
	}
	f.Fuzz(func(t *testing.T, rawTarget string, body []byte) {
		if len(rawTarget) > maxValueLength+1 || len(body) > maxDocumentBytes+1 {
			return
		}
		_, _ = parseTarget(rawTarget)
		client, err := parseTarget("https://metadata.example/client.json")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = decodeMetadata(body, client)
	})
}
