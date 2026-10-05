package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixtures contain only the two permitted sources. Real module files are never
// copied or changed by these controls; the separate diagnostic app build checks
// the transformed pinned sources against their actual dependencies.
func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, source string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(nodeRelative, "package node\nimport (\"context\";\"log\";\"time\")\nfunc install(){\n"+nodeOld+"\n}\n")
	write(serverRelative, "package network\nimport (\n\t\"io\"\n\t\"context\"\n\t\"time\"\n)\n"+serverOld+"\n")
	return root
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCopiesAndOriginalMapping(t *testing.T) {
	root := fixture(t)
	before := map[string]string{}
	for _, rel := range []string{nodeRelative, serverRelative} {
		before[rel] = read(t, filepath.Join(root, rel))
	}
	out := filepath.Join(t.TempDir(), "overlay")
	if err := run([]string{root, out}); err != nil {
		t.Fatal(err)
	}
	var mapping struct{ Replace map[string]string }
	if err := json.Unmarshal([]byte(read(t, filepath.Join(out, "overlay.json"))), &mapping); err != nil {
		t.Fatal(err)
	}
	if len(mapping.Replace) != 2 {
		t.Fatal("overlay must map exactly two original files")
	}
	for rel, old := range before {
		original := filepath.Join(root, rel)
		copy := filepath.Join(out, filepath.Base(rel))
		if mapping.Replace[original] != copy {
			t.Fatalf("wrong replacement for %s", rel)
		}
		if read(t, original) != old {
			t.Fatalf("original modified: %s", rel)
		}
		if _, err := os.Stat(copy); err != nil {
			t.Fatal(err)
		}
	}
	// Explicit regression controls for the rejected constant-zero/missing-var
	// proposal; actual package build additionally checks type correctness.
	node := read(t, filepath.Join(out, "node.go"))
	if !strings.Contains(node, "var walNS int64") || strings.Count(node, "walNS = time.Since(walStart).Nanoseconds()") != 2 {
		t.Fatal("WAL must be measured on success and error")
	}
	if strings.Count(node, "return err") != 2 {
		t.Fatal("both ACK error guards must survive")
	}
	server := read(t, filepath.Join(out, "server.go"))
	for _, call := range []string{"s.proposeOnce(ctx, value)", "s.applyDecisions(ctx, call.slot)", "s.waitDurable(ctx, call.slot)", "context.WithTimeout(s.proposalCtx, 30*time.Second)", "close(call.done)"} {
		if strings.Count(server, call) != 1 {
			t.Fatalf("original call/guard changed: %s", call)
		}
	}
}

func TestDriftRefusedBeforeOutput(t *testing.T) {
	for _, which := range []string{"missing", "duplicate", "mutation", "import", "aliased_log"} {
		t.Run(which, func(t *testing.T) {
			root := fixture(t)
			p := filepath.Join(root, serverRelative)
			source := read(t, p)
			switch which {
			case "missing":
				source = strings.Replace(source, serverOld, "// missing", 1)
			case "duplicate":
				source += "\n" + serverOld
			case "mutation":
				source = strings.Replace(source, "cancel()\n", "cancel() \n", 1)
			case "import":
				source = strings.Replace(source, serverImportAnchor, "", 1)
			case "aliased_log":
				source = strings.Replace(source, serverImportAnchor, serverImportAnchor+"\talias \"log\"\n", 1)
			}
			if err := os.WriteFile(p, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "overlay")
			if err := run([]string{root, out}); err == nil {
				t.Fatal("drift accepted")
			}
			if _, err := os.Lstat(out); !os.IsNotExist(err) {
				t.Fatal("output created on refused drift")
			}
			if read(t, p) != source {
				t.Fatal("refused original modified")
			}
		})
	}
}

func TestExistingPathsRefused(t *testing.T) {
	root := fixture(t)
	base := t.TempDir()
	target := filepath.Join(base, "keep")
	if err := os.WriteFile(target, []byte("KEEP"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{base, target, link, "relative"} {
		if err := run([]string{root, out}); err == nil {
			t.Fatalf("accepted existing/relative path %s", out)
		}
	}
	if read(t, target) != "KEEP" {
		t.Fatal("existing target modified")
	}
}
