package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"path"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/mrchypark/rhiza"
	"github.com/mrchypark/rhiza/pkg/quepaxa"
	"github.com/mrchypark/rhiza/pkg/recovery"
	"github.com/thanos-io/objstore"
	"github.com/thanos-io/objstore/providers/filesystem"
)

func TestExportManifestRecordsRhizaBuildInfoForBothFormats(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	want := rhizaVersionFromBuildInfo(info, ok)
	for _, format := range []int{1, 2} {
		t.Run(map[int]string{1: "checkpoint", 2: "archive-only"}[format], func(t *testing.T) {
			var source objstore.Bucket
			var prefix string
			if format == 1 {
				source, prefix = createRetrySource(t, t.Context())
			} else {
				source, prefix = createArchiveOnlySource(t, t.Context())
			}
			defer source.Close()
			identity, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			var bundle bytes.Buffer
			manifest, err := Export(t.Context(), source, prefix, "cluster", &bundle, []age.Recipient{identity.Recipient()}, t.TempDir(), createRetryLimits)
			if err != nil {
				t.Fatal(err)
			}
			if manifest.FormatVersion != format || manifest.RhizaVersion != want {
				t.Fatalf("manifest format/version = %d/%q, want %d/%q", manifest.FormatVersion, manifest.RhizaVersion, format, want)
			}
		})
	}
}

func TestRhizaVersionFromBuildInfo(t *testing.T) {
	for name, test := range map[string]struct {
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		"dependency": {
			info: &debug.BuildInfo{Deps: []*debug.Module{{Path: rhizaModulePath, Version: "v1.2.3"}}},
			ok:   true,
			want: "v1.2.3",
		},
		"pseudo-version": {
			info: &debug.BuildInfo{Deps: []*debug.Module{{Path: rhizaModulePath, Version: "v0.19.1-0.20261008214459-3895b723e194"}}},
			ok:   true,
			want: "v0.19.1-0.20261008214459-3895b723e194",
		},
		"abbreviated version": {
			info: &debug.BuildInfo{Deps: []*debug.Module{{Path: rhizaModulePath, Version: "v1.2"}}},
			ok:   true,
			want: "unknown",
		},
		"versioned replacement": {
			info: &debug.BuildInfo{Deps: []*debug.Module{{Path: rhizaModulePath, Replace: &debug.Module{Path: "/private/build/rhiza", Version: "v2.3.4"}}}},
			ok:   true,
			want: "v2.3.4",
		},
		"local replacement": {
			info: &debug.BuildInfo{Deps: []*debug.Module{{Path: rhizaModulePath, Replace: &debug.Module{Path: "/private/build/rhiza"}}}},
			ok:   true,
			want: "unknown",
		},
		"absent dependency": {info: &debug.BuildInfo{}, ok: true, want: "unknown"},
		"unavailable info":  {info: &debug.BuildInfo{}, ok: false, want: "unknown"},
		"nil info":          {ok: true, want: "unknown"},
		"invalid version": {
			info: &debug.BuildInfo{Deps: []*debug.Module{{Path: rhizaModulePath, Version: "/private/build/rhiza"}}},
			ok:   true,
			want: "unknown",
		},
		"invalid replacement version": {
			info: &debug.BuildInfo{Deps: []*debug.Module{{Path: rhizaModulePath, Version: "v1.2.3", Replace: &debug.Module{Path: "/private/build/rhiza", Version: "/private/build/rhiza"}}}},
			ok:   true,
			want: "unknown",
		},
		"other dependency": {
			info: &debug.BuildInfo{Deps: []*debug.Module{{Path: "example.com/other", Version: "v1.2.3"}}},
			ok:   true,
			want: "unknown",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := rhizaVersionFromBuildInfo(test.info, test.ok); got != test.want {
				t.Fatalf("rhizaVersionFromBuildInfo() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestManifestRhizaProvenanceCompatibility(t *testing.T) {
	objects := completeObjects(map[string][]byte{"archive/head.bin": []byte("head")})
	for _, version := range []string{"v0.12.3", "unknown", "v99.0.0", "v1.2.3+" + strings.Repeat("a", maxRhizaVersionBytes-len("v1.2.3+"))} {
		t.Run(version, func(t *testing.T) {
			manifest := testManifest(objects)
			manifest.RhizaVersion = version
			stage, inventory := writeManifestStage(t, manifest, objects)
			got, err := ReadManifest(stage, inventory)
			if err != nil {
				t.Fatalf("ReadManifest(%q): %v", version, err)
			}
			if got.RhizaVersion != version {
				t.Fatalf("legacy/provenance version = %q, want %q", got.RhizaVersion, version)
			}
		})
	}
	for _, version := range []string{"", "v1.2", "/private/build/rhiza", "v1.2.3+private/path", "v1.2.3+" + strings.Repeat("a", maxRhizaVersionBytes-len("v1.2.3+")+1)} {
		t.Run("reject_"+version, func(t *testing.T) {
			manifest := testManifest(objects)
			manifest.RhizaVersion = version
			if _, err := MarshalManifest(manifest); err == nil {
				t.Fatalf("MarshalManifest accepted invalid provenance %q", version)
			}
		})
	}
}

func createArchiveOnlySource(t *testing.T, ctx context.Context) (objstore.Bucket, string) {
	t.Helper()
	root := t.TempDir()
	prefix := "live/cluster"
	config := rhiza.Config{ClusterID: "cluster", NodeID: "node", DataDir: path.Join(root, "data"), ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: path.Join(root, "objects"), ObjStorePrefix: "live", ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck, CheckpointInterval: time.Hour}
	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	base, err := filesystem.NewBucket(config.ObjStoreDir)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	copy := objstore.NewInMemBucket()
	if err := base.Iter(ctx, "", func(name string) error {
		r, err := base.Get(ctx, name)
		if err != nil {
			return err
		}
		defer r.Close()
		return copy.Upload(ctx, name, r)
	}, objstore.WithRecursiveIter()); err != nil {
		t.Fatal(err)
	}
	archive := recovery.NewManager(copy, prefix, 1)
	decisionValue := []byte("synthetic archive-only decision")
	decision := quepaxa.DecidedValue{Slot: 1, Hash: sha256.Sum256(decisionValue), Value: decisionValue, Certificate: []byte("synthetic certificate")}
	source := syntheticArchiveSource{decision: decision, tip: 1}
	if err := archive.SyncThrough(ctx, source, 1); err != nil {
		archive.Close()
		t.Fatal(err)
	}
	archive.Close()
	check := recovery.NewManager(copy, prefix, 1)
	defer check.Close()
	if err := check.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := check.RecoveryBase(); ok || check.Tip() == 0 {
		t.Fatalf("synthetic archive has checkpoint=%t tip=%d, want no checkpoint and nonzero tip", ok, check.Tip())
	}
	return copy, prefix
}

type syntheticArchiveSource struct {
	decision quepaxa.DecidedValue
	tip      quepaxa.Slot
}

func (s syntheticArchiveSource) DecisionsFromBounded(from quepaxa.Slot, limit, _ int) ([]quepaxa.DecidedValue, quepaxa.Slot, error) {
	if from != 1 || limit < 1 {
		return nil, s.tip, nil
	}
	return []quepaxa.DecidedValue{s.decision}, s.tip, nil
}

func (s syntheticArchiveSource) PrefixHash(slot quepaxa.Slot) ([32]byte, bool) {
	if slot == 0 {
		return [32]byte{}, true
	}
	if slot == s.decision.Slot {
		return quepaxa.AdvancePrefixHash([32]byte{}, s.decision.Slot, s.decision.Hash), true
	}
	return [32]byte{}, false
}

func (s syntheticArchiveSource) Tip() quepaxa.Slot { return s.tip }
