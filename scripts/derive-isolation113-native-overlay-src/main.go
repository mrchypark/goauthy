// Command derive-isolation113-native-overlay is a DIAGNOSTIC ONLY helper.
//
// It reads exactly two allowlisted pinned Rhiza source files, replaces one
// exact full block in each with a timing-instrumented equivalent, formats the
// result with go/format, and writes an overlay that maps the ORIGINAL absolute
// module file paths to the final OUTPUT copies. Those output files persist
// after this process exits, so the overlay never references a temporary path.
//
// The instrumentation only measures existing calls. It preserves every call,
// context, guard, return, error, ID, lock and ACK behaviour, and adds no
// goroutine, sleep, limit or retry.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const nodeRelative = "pkg/node/node.go"
const serverRelative = "pkg/network/server.go"

const nodeOld = `		server.SetDurabilityBarrier(func(ctx context.Context, slot quepaxa.Slot) error {
			if err := core.EnsureDurable(slot); err != nil {
				return err
			}
			if err := n.archive.SyncThrough(ctx, core, slot); err != nil {
				return err
			}
			return nil
		})`

const nodeNew = `		server.SetDurabilityBarrier(func(ctx context.Context, slot quepaxa.Slot) error {
			// DIAGNOSTIC113: timing only. Local durations and call bits.
			walCalled := 1
			walStart := time.Now()
			var walNS int64
			archiveCalled := 0
			var archiveNS int64
			defer func() {
				log.Printf("DIAGNOSTIC113_ACK wal_called=%d wal_ns=%d archive_called=%d archive_ns=%d", walCalled, walNS, archiveCalled, archiveNS)
			}()
			if err := core.EnsureDurable(slot); err != nil {
				walNS = time.Since(walStart).Nanoseconds()
				return err
			}
			walNS = time.Since(walStart).Nanoseconds()
			archiveCalled = 1
			archiveStart := time.Now()
			if err := n.archive.SyncThrough(ctx, core, slot); err != nil {
				archiveNS = time.Since(archiveStart).Nanoseconds()
				return err
			}
			archiveNS = time.Since(archiveStart).Nanoseconds()
			return nil
		})`

const serverOld = `func (s *Server) runProposal(hash [32]byte, call *proposalCall, value []byte) {
	defer s.proposalWG.Done()
	ctx, cancel := context.WithTimeout(s.proposalCtx, 30*time.Second)
	call.slot, call.err = s.proposeOnce(ctx, value)
	if call.err == nil {
		call.err = s.applyDecisions(ctx, call.slot)
	}
	if call.err == nil {
		call.err = s.waitDurable(ctx, call.slot)
	}
	cancel()
	s.proposeMu.Lock()
	if s.inflight[hash] == call {
		delete(s.inflight, hash)
	}
	s.operationB -= len(value)
	s.localB -= len(value)
	<-s.operationCap
	<-s.localCap
	close(call.done)
	s.proposeMu.Unlock()
}`

const serverNew = `func (s *Server) runProposal(hash [32]byte, call *proposalCall, value []byte) {
	defer s.proposalWG.Done()
	ctx, cancel := context.WithTimeout(s.proposalCtx, 30*time.Second)
	// DIAGNOSTIC113: timing only. Local durations and call bits.
	proposeCalled := 1
	proposeStart := time.Now()
	var proposeNS int64
	applyCalled := 0
	var applyNS int64
	durabilityCalled := 0
	var durabilityNS int64
	defer func() {
		log.Printf("DIAGNOSTIC113_PROPOSAL propose_called=%d propose_ns=%d apply_called=%d apply_ns=%d durability_called=%d durability_ns=%d", proposeCalled, proposeNS, applyCalled, applyNS, durabilityCalled, durabilityNS)
	}()
	call.slot, call.err = s.proposeOnce(ctx, value)
	proposeNS = time.Since(proposeStart).Nanoseconds()
	if call.err == nil {
		applyCalled = 1
		applyStart := time.Now()
		call.err = s.applyDecisions(ctx, call.slot)
		applyNS = time.Since(applyStart).Nanoseconds()
	}
	if call.err == nil {
		durabilityCalled = 1
		durabilityStart := time.Now()
		call.err = s.waitDurable(ctx, call.slot)
		durabilityNS = time.Since(durabilityStart).Nanoseconds()
	}
	cancel()
	s.proposeMu.Lock()
	if s.inflight[hash] == call {
		delete(s.inflight, hash)
	}
	s.operationB -= len(value)
	s.localB -= len(value)
	<-s.operationCap
	<-s.localCap
	close(call.done)
	s.proposeMu.Unlock()
}`

const serverImportAnchor = "\t\"io\"\n"
const serverImportNew = "\t\"io\"\n\t\"log\"\n"

// transform replaces exactly one full-block occurrence and formats the result.
func transform(source, old, replacement, label string) ([]byte, error) {
	if strings.Count(source, old) != 1 {
		return nil, fmt.Errorf("%s: expected exactly one anchor block, found %d", label, strings.Count(source, old))
	}
	return format.Source([]byte(strings.Replace(source, old, replacement, 1)))
}

func run(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: derive-isolation113-native-overlay MODULE_ROOT OUT_DIR")
	}
	root, out := args[0], args[1]
	if !filepath.IsAbs(root) || !filepath.IsAbs(out) {
		return fmt.Errorf("module root and output directory must be absolute paths")
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return fmt.Errorf("module root is not a directory: %s", root)
	}
	if _, err := os.Lstat(out); err == nil {
		return fmt.Errorf("output directory already exists; refusing to overwrite: %s", out)
	} else if !os.IsNotExist(err) {
		return err
	}

	nodePath := filepath.Join(root, nodeRelative)
	serverPath := filepath.Join(root, serverRelative)
	nodeSource, err := os.ReadFile(nodePath)
	if err != nil {
		return err
	}
	serverSource, err := os.ReadFile(serverPath)
	if err != nil {
		return err
	}

	// Validate and format both before any output directory is created.
	nodeOut, err := transform(string(nodeSource), nodeOld, nodeNew, "node.go")
	if err != nil {
		return err
	}
	serverText := string(serverSource)
	imports, err := parser.ParseFile(token.NewFileSet(), "server.go", serverSource, parser.ImportsOnly)
	if err != nil {
		return err
	}
	for _, imp := range imports.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return err
		}
		if path == "log" {
			return fmt.Errorf("server.go: log import already present")
		}
	}
	if strings.Count(serverText, serverImportAnchor) != 1 {
		return fmt.Errorf("server.go: expected exactly one io import anchor, found %d", strings.Count(serverText, serverImportAnchor))
	}
	if strings.Count(serverText, "\n\t\"log\"\n") != 0 {
		return fmt.Errorf("server.go: log import already present; refusing a second insertion")
	}
	// Do not format before matching the original function: formatting would
	// normalize whitespace drift and silently weaken the full-block guard.
	serverText = strings.Replace(serverText, serverImportAnchor, serverImportNew, 1)
	serverOut, err := transform(serverText, serverOld, serverNew, "server.go")
	if err != nil {
		return err
	}

	nodeOutPath := filepath.Join(out, "node.go")
	serverOutPath := filepath.Join(out, "server.go")
	overlayPath := filepath.Join(out, "overlay.json")

	// The overlay maps the ORIGINAL absolute module paths to these final,
	// surviving output files.
	overlay := map[string]any{"Replace": map[string]string{
		nodePath:   nodeOutPath,
		serverPath: serverOutPath,
	}}
	encoded, err := json.MarshalIndent(overlay, "", "  ")
	if err != nil {
		return err
	}
	if !bytes.Contains(encoded, []byte(nodePath)) || !bytes.Contains(encoded, []byte(serverPath)) {
		return fmt.Errorf("overlay mapping is missing an original module path")
	}

	if err := os.Mkdir(out, 0o700); err != nil {
		return err
	}
	for path, data := range map[string][]byte{
		nodeOutPath:   nodeOut,
		serverOutPath: serverOut,
		overlayPath:   append(encoded, '\n'),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("diagnostic native overlay written to %s\n", out)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "derive-isolation113-native-overlay:", err)
		os.Exit(1)
	}
}
