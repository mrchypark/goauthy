package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestMarshalReadManifestValidatesStagedObjects(t *testing.T) {
	objects := map[string][]byte{
		"archive/head.bin":         []byte("head"),
		"archive/blocks/block-one": []byte("block"),
		"checkpoint/roots/root":    []byte("root"),
		"checkpoint/blocks/block":  []byte("checkpoint"),
	}
	manifest := testManifest(objects)
	stage, inventory := writeManifestStage(t, manifest, objects)
	got, err := ReadManifest(stage, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if got.CheckpointRootHash != manifest.CheckpointRootHash || len(got.Objects) != len(manifest.Objects) {
		t.Fatalf("manifest = %#v", got)
	}
}

func TestReadManifestRejectsInvalidMetadata(t *testing.T) {
	objects := completeObjects(map[string][]byte{"archive/head.bin": []byte("head")})
	manifest := testManifest(objects)
	valid, err := MarshalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(string) string{
		"unknown": func(raw string) string { return raw[:len(raw)-1] + `,"extra":true}` },
		"duplicate": func(raw string) string {
			return strings.Replace(raw, `"format_version":1`, `"format_version":1,"format_version":1`, 1)
		},
		"unsupported":      func(raw string) string { return strings.Replace(raw, `"format_version":1`, `"format_version":2`, 1) },
		"trailing":         func(raw string) string { return raw + ` {}` },
		"case alias":       func(raw string) string { return strings.Replace(raw, `"format_version"`, `"FORMAT_VERSION"`, 1) },
		"nested alias":     func(raw string) string { return strings.Replace(raw, `"sha256"`, `"SHA256"`, 1) },
		"nested duplicate": func(raw string) string { return strings.Replace(raw, `"size":4`, `"size":4,"size":4`, 1) },
		"null size":        func(raw string) string { return strings.Replace(raw, `"size":4`, `"size":null`, 1) },
		"invalid utf8":     func(raw string) string { return strings.Replace(raw, "head.bin", "head\xff.bin", 1) },
	} {
		t.Run(name, func(t *testing.T) {
			stage, inventory := writeManifestStage(t, manifest, objects)
			if _, err := ReadManifest(stage, inventory); err != nil {
				t.Fatalf("valid control: %v", err)
			}
			raw := []byte(mutate(string(valid)))
			if err := os.WriteFile(filepath.Join(stage, ManifestEntry), raw, 0600); err != nil {
				t.Fatal(err)
			}
			inventory[0].Size = int64(len(raw))
			if _, err := ReadManifest(stage, inventory); err == nil {
				t.Fatal("ReadManifest succeeded")
			}
		})
	}
}

func TestReadManifestRejectsMissingExtraAndAlteredObjects(t *testing.T) {
	objects := completeObjects(map[string][]byte{"archive/head.bin": []byte("head"), "archive/blocks/block": []byte("block")})
	manifest := testManifest(objects)
	for name, mutate := range map[string]func([]Inventory) []Inventory{
		"missing": func(inventory []Inventory) []Inventory { return inventory[:len(inventory)-1] },
		"extra": func(inventory []Inventory) []Inventory {
			return append(inventory, Inventory{Name: "objects/archive/blocks/other", Size: 1})
		},
		"wrong size": func(inventory []Inventory) []Inventory {
			out := append([]Inventory(nil), inventory...)
			out[len(out)-1].Size++
			return out
		},
	} {
		t.Run(name, func(t *testing.T) {
			stage, inventory := writeManifestStage(t, manifest, objects)
			if _, err := ReadManifest(stage, mutate(inventory)); err == nil {
				t.Fatal("ReadManifest succeeded")
			}
		})
	}
	t.Run("digest", func(t *testing.T) {
		stage, inventory := writeManifestStage(t, manifest, objects)
		if err := os.WriteFile(filepath.Join(stage, ObjectEntryPrefix, "archive/blocks/block"), []byte("other"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadManifest(stage, inventory); err == nil {
			t.Fatal("ReadManifest succeeded")
		}
	})
	t.Run("missing physical object", func(t *testing.T) {
		stage, inventory := writeManifestStage(t, manifest, objects)
		if err := os.Remove(filepath.Join(stage, ObjectEntryPrefix, "archive/blocks/block")); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadManifest(stage, inventory); err == nil {
			t.Fatal("ReadManifest succeeded")
		}
	})
	t.Run("manifest inventory size", func(t *testing.T) {
		stage, inventory := writeManifestStage(t, manifest, objects)
		inventory[0].Size++
		if _, err := ReadManifest(stage, inventory); err == nil {
			t.Fatal("ReadManifest succeeded")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		stage, inventory := writeManifestStage(t, manifest, objects)
		target := filepath.Join(stage, "replacement")
		if err := os.WriteFile(target, []byte("block"), 0600); err != nil {
			t.Fatal(err)
		}
		object := filepath.Join(stage, ObjectEntryPrefix, "archive/blocks/block")
		if err := os.Remove(object); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, object); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadManifest(stage, inventory); err == nil {
			t.Fatal("ReadManifest accepted symlink")
		}
	})
}

func TestMarshalManifestRejectsInvalidShape(t *testing.T) {
	objects := completeObjects(map[string][]byte{"archive/head.bin": []byte("head")})
	manifest := testManifest(objects)
	for name, mutate := range map[string]func(*SnapshotManifest){
		"source cluster binding": func(m *SnapshotManifest) { m.SourcePrefix = "exports/other" },
		"unsupported object":     func(m *SnapshotManifest) { m.Objects[0].Name = "journal/entry" },
		"duplicate object": func(m *SnapshotManifest) {
			m.Objects = append(m.Objects, m.Objects[0])
		},
		"hash":                 func(m *SnapshotManifest) { m.CheckpointRootHash = "not-a-hash" },
		"zero hash":            func(m *SnapshotManifest) { m.CheckpointRootHash = stringsOf('0') },
		"config":               func(m *SnapshotManifest) { m.ConfigID = 2 },
		"zero index":           func(m *SnapshotManifest) { m.CheckpointIndex = 0 },
		"zero object size":     func(m *SnapshotManifest) { m.Objects[0].Size = 0 },
		"overflow object size": func(m *SnapshotManifest) { m.Objects[0].Size = math.MaxInt64 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := manifest
			candidate.Objects = append([]ManifestObject(nil), manifest.Objects...)
			mutate(&candidate)
			if _, err := MarshalManifest(candidate); err == nil {
				t.Fatal("MarshalManifest succeeded")
			}
		})
	}
}

func TestArchiveOnlyManifestV2(t *testing.T) {
	objects := map[string][]byte{"archive/head.bin": []byte("head"), "archive/blocks/block": []byte("block")}
	m := testManifest(objects)
	m.FormatVersion = 2
	m.RecoveryMode = "archive-only"
	m.ArchiveTip = 3
	m.CheckpointIndex = 0
	m.CheckpointRootHash = ""
	m.CheckpointStateHash = ""
	stage, inventory := writeManifestStage(t, m, objects)
	if _, err := ReadManifest(stage, inventory); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SnapshotManifest){"mode": func(x *SnapshotManifest) { x.RecoveryMode = "other" }, "tip": func(x *SnapshotManifest) { x.ArchiveTip = 0 }, "max": func(x *SnapshotManifest) { x.ArchiveTip = ^uint64(0) }, "checkpoint": func(x *SnapshotManifest) {
		x.Objects = append(x.Objects, ManifestObject{Name: "checkpoint/roots/x", Size: 1, SHA256: stringsOf('c')})
	}} {
		t.Run(name, func(t *testing.T) {
			x := m
			x.Objects = append([]ManifestObject(nil), m.Objects...)
			mutate(&x)
			if _, err := MarshalManifest(x); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestManifestVersionFields(t *testing.T) {
	v1, err := MarshalManifest(testManifest(completeObjects(map[string][]byte{"archive/head.bin": []byte("head")})))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(v1, []byte("recovery_mode")) || bytes.Contains(v1, []byte("archive_tip")) {
		t.Fatal("v1 encoding changed")
	}
	v2 := bytes.Replace(v1, []byte(`"format_version":1`), []byte(`"format_version":2`), 1)
	// All malformed schemas are rejected before object inventory validation.
	for name, raw := range map[string][]byte{
		"v1_null_mode":      append(append([]byte(nil), v1[:len(v1)-1]...), []byte(`,"recovery_mode":null}`)...),
		"v1_zero_tip":       append(append([]byte(nil), v1[:len(v1)-1]...), []byte(`,"archive_tip":0}`)...),
		"v2_missing_fields": v2,
		"unknown_version":   bytes.Replace(v1, []byte(`"format_version":1`), []byte(`"format_version":3`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeManifest(raw); err == nil {
				t.Fatal("accepted invalid version fields")
			}
		})
	}
}

func testManifest(objects map[string][]byte) SnapshotManifest {
	manifest := SnapshotManifest{
		FormatVersion:       1,
		RhizaVersion:        "v0.12.3",
		SourcePrefix:        "exports/cluster-a",
		ClusterID:           "cluster-a",
		ConfigID:            1,
		CheckpointIndex:     2,
		CheckpointRootHash:  stringsOf('a'),
		CheckpointStateHash: stringsOf('b'),
	}
	for name, data := range objects {
		sum := sha256.Sum256(data)
		manifest.Objects = append(manifest.Objects, ManifestObject{Name: name, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])})
	}
	sort.Slice(manifest.Objects, func(i, j int) bool { return manifest.Objects[i].Name < manifest.Objects[j].Name })
	return manifest
}

func writeManifestStage(t *testing.T, manifest SnapshotManifest, objects map[string][]byte) (string, []Inventory) {
	t.Helper()
	stage := t.TempDir()
	raw, err := MarshalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, ManifestEntry), raw, 0600); err != nil {
		t.Fatal(err)
	}
	inventory := []Inventory{{Name: ManifestEntry, Size: int64(len(raw))}}
	for _, object := range manifest.Objects {
		name := filepath.Join(stage, filepath.FromSlash(ObjectEntryPrefix+object.Name))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, objects[object.Name], 0600); err != nil {
			t.Fatal(err)
		}
		inventory = append(inventory, Inventory{Name: ObjectEntryPrefix + object.Name, Size: object.Size})
	}
	return stage, inventory
}

func stringsOf(b byte) string { return string(bytes.Repeat([]byte{b}, sha256.Size*2)) }

func completeObjects(extra map[string][]byte) map[string][]byte {
	objects := map[string][]byte{
		"checkpoint/roots/root":   []byte("root"),
		"checkpoint/blocks/block": []byte("checkpoint"),
	}
	for name, data := range extra {
		objects[name] = data
	}
	return objects
}
