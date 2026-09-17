package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path"
	"strings"
	"unicode/utf8"
)

const (
	// ManifestEntry is reserved for the JSON inventory of a snapshot bundle.
	ManifestEntry = "manifest.json"
	// ObjectEntryPrefix contains objects named relative to SourcePrefix.
	ObjectEntryPrefix = "objects/"
	maxManifestBytes  = 1 << 20
)

// SnapshotManifest describes one complete Rhiza v0.12.3 recovery snapshot.
type SnapshotManifest struct {
	FormatVersion       int              `json:"format_version"`
	RhizaVersion        string           `json:"rhiza_version"`
	SourcePrefix        string           `json:"source_prefix"`
	ClusterID           string           `json:"cluster_id"`
	ConfigID            uint64           `json:"config_id"`
	CheckpointIndex     uint64           `json:"checkpoint_index"`
	CheckpointRootHash  string           `json:"checkpoint_root_hash"`
	CheckpointStateHash string           `json:"checkpoint_state_hash"`
	RecoveryMode        string           `json:"recovery_mode,omitempty"`
	ArchiveTip          uint64           `json:"archive_tip,omitempty"`
	Objects             []ManifestObject `json:"objects"`
}

// ManifestObject is one object relative to SnapshotManifest.SourcePrefix.
type ManifestObject struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// MarshalManifest validates and deterministically encodes a supported manifest.
func MarshalManifest(manifest SnapshotManifest) ([]byte, error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxManifestBytes {
		return nil, errors.New("backup manifest exceeds size limit")
	}
	return encoded, nil
}

// ReadManifest strictly reads and validates ManifestEntry in stageDir. Inventory
// must be the complete bundle inventory returned by Extract. Each listed object
// is rooted below stageDir and hashed before this function returns.
func ReadManifest(stageDir string, inventory []Inventory) (SnapshotManifest, error) {
	root, err := os.OpenRoot(stageDir)
	if err != nil {
		return SnapshotManifest{}, err
	}
	defer root.Close()
	manifestInfo, err := root.Lstat(ManifestEntry)
	if err != nil || !manifestInfo.Mode().IsRegular() {
		return SnapshotManifest{}, errors.New("invalid backup manifest")
	}
	manifestFile, err := root.Open(ManifestEntry)
	if err != nil {
		return SnapshotManifest{}, err
	}
	openedInfo, err := manifestFile.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || openedInfo.Size() > maxManifestBytes {
		_ = manifestFile.Close()
		return SnapshotManifest{}, errors.New("invalid backup manifest")
	}
	raw, readErr := io.ReadAll(io.LimitReader(manifestFile, maxManifestBytes+1))
	closeErr := manifestFile.Close()
	if readErr != nil {
		return SnapshotManifest{}, readErr
	}
	if closeErr != nil {
		return SnapshotManifest{}, closeErr
	}
	if len(raw) == 0 || len(raw) > maxManifestBytes {
		return SnapshotManifest{}, errors.New("invalid backup manifest")
	}
	manifest, err := decodeManifest(raw)
	if err != nil {
		return SnapshotManifest{}, err
	}
	if err := validateInventory(manifest, inventory, int64(len(raw))); err != nil {
		return SnapshotManifest{}, err
	}
	for _, object := range manifest.Objects {
		entryName := objectPath(object.Name)
		info, err := root.Lstat(entryName)
		if err != nil || !info.Mode().IsRegular() {
			return SnapshotManifest{}, errors.New("invalid backup object")
		}
		file, err := root.Open(entryName)
		if err != nil {
			return SnapshotManifest{}, err
		}
		openedInfo, err := file.Stat()
		if err != nil || !openedInfo.Mode().IsRegular() || openedInfo.Size() != object.Size {
			_ = file.Close()
			return SnapshotManifest{}, errors.New("invalid backup object")
		}
		hash := sha256.New()
		n, copyErr := io.Copy(hash, io.LimitReader(file, object.Size+1))
		closeErr := file.Close()
		if copyErr != nil {
			return SnapshotManifest{}, copyErr
		}
		if closeErr != nil {
			return SnapshotManifest{}, closeErr
		}
		if n != object.Size || hex.EncodeToString(hash.Sum(nil)) != object.SHA256 {
			return SnapshotManifest{}, errors.New("backup object does not match manifest")
		}
	}
	return manifest, nil
}

func decodeManifest(raw []byte) (SnapshotManifest, error) {
	if !utf8.Valid(raw) || duplicateJSONKeys(raw) {
		return SnapshotManifest{}, errors.New("invalid backup manifest")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return SnapshotManifest{}, errors.New("invalid backup manifest")
	}
	versionRaw, ok := probe["format_version"]
	if !ok {
		return SnapshotManifest{}, errors.New("invalid backup manifest")
	}
	var version int
	if err := json.Unmarshal(versionRaw, &version); err != nil {
		return SnapshotManifest{}, errors.New("invalid backup manifest")
	}
	allowed := []string{"format_version", "rhiza_version", "source_prefix", "cluster_id", "config_id", "checkpoint_index", "checkpoint_root_hash", "checkpoint_state_hash", "objects"}
	if version == 2 {
		allowed = append(allowed, "recovery_mode", "archive_tip")
	}
	fields, err := jsonFields(raw, allowed)
	if err != nil {
		return SnapshotManifest{}, errors.New("invalid backup manifest")
	}
	var rawObjects []json.RawMessage
	if err := json.Unmarshal(fields["objects"], &rawObjects); err != nil {
		return SnapshotManifest{}, errors.New("invalid backup manifest")
	}
	for _, rawObject := range rawObjects {
		if _, err := jsonFields(rawObject, []string{"name", "size", "sha256"}); err != nil {
			return SnapshotManifest{}, errors.New("invalid backup manifest")
		}
	}
	var manifest SnapshotManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return SnapshotManifest{}, errors.New("invalid backup manifest")
	}
	if err := validateManifest(manifest); err != nil {
		return SnapshotManifest{}, err
	}
	return manifest, nil
}

func validateManifest(manifest SnapshotManifest) error {
	if (manifest.FormatVersion != 1 && manifest.FormatVersion != 2) || manifest.RhizaVersion != "v0.12.3" || !validName(manifest.SourcePrefix) || !validName(manifest.ClusterID) || strings.Contains(manifest.ClusterID, "/") || (manifest.SourcePrefix != manifest.ClusterID && !strings.HasSuffix(manifest.SourcePrefix, "/"+manifest.ClusterID)) || manifest.ConfigID != 1 {
		return errors.New("invalid backup manifest")
	}
	if manifest.FormatVersion == 1 && (manifest.CheckpointIndex == 0 || !validHash(manifest.CheckpointRootHash) || !validHash(manifest.CheckpointStateHash) || manifest.RecoveryMode != "" || manifest.ArchiveTip != 0) {
		return errors.New("invalid backup manifest")
	}
	if manifest.FormatVersion == 2 && (manifest.RecoveryMode != "archive-only" || manifest.ArchiveTip == 0 || manifest.ArchiveTip == ^uint64(0) || manifest.CheckpointIndex != 0 || manifest.CheckpointRootHash != "" || manifest.CheckpointStateHash != "") {
		return errors.New("invalid backup manifest")
	}
	seen := make(map[string]struct{}, len(manifest.Objects))
	for _, object := range manifest.Objects {
		if !validObjectName(object.Name) || object.Size <= 0 || object.Size >= math.MaxInt64 || !validHash(object.SHA256) {
			return errors.New("invalid backup manifest object")
		}
		if _, ok := seen[object.Name]; ok {
			return errors.New("duplicate backup manifest object")
		}
		seen[object.Name] = struct{}{}
	}
	if manifest.FormatVersion == 2 {
		if !seenObject(seen, "archive/head.bin") || !seenPrefix(seen, "archive/blocks/") {
			return errors.New("invalid archive-only manifest")
		}
		for name := range seen {
			if name != "archive/head.bin" && !strings.HasPrefix(name, "archive/blocks/") {
				return errors.New("invalid archive-only manifest")
			}
		}
		return nil
	}
	if len(manifest.Objects) == 0 || !seenObject(seen, "archive/head.bin") || !seenPrefix(seen, "checkpoint/roots/") || !seenPrefix(seen, "checkpoint/blocks/") {
		return errors.New("invalid backup manifest")
	}
	return nil
}

func validObjectName(name string) bool {
	if !validName(name) {
		return false
	}
	return name == "archive/head.bin" || strings.HasPrefix(name, "archive/blocks/") || strings.HasPrefix(name, "checkpoint/roots/") || strings.HasPrefix(name, "checkpoint/blocks/")
}

func validHash(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.Trim(value, "0") != ""
}

func seenObject(seen map[string]struct{}, name string) bool {
	_, ok := seen[name]
	return ok
}

func seenPrefix(seen map[string]struct{}, prefix string) bool {
	for name := range seen {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func jsonFields(raw []byte, allowed []string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&fields); err != nil || decoder.Decode(new(any)) != io.EOF || len(fields) != len(allowed) {
		return nil, errors.New("invalid JSON object")
	}
	for _, name := range allowed {
		if _, ok := fields[name]; !ok {
			return nil, errors.New("missing JSON field")
		}
	}
	return fields, nil
}

func validateInventory(manifest SnapshotManifest, inventory []Inventory, manifestSize int64) error {
	expected := make(map[string]int64, len(manifest.Objects)+1)
	expected[ManifestEntry] = manifestSize
	for _, object := range manifest.Objects {
		expected[ObjectEntryPrefix+object.Name] = object.Size
	}
	if len(inventory) != len(expected) {
		return errors.New("backup inventory does not match manifest")
	}
	seen := make(map[string]struct{}, len(inventory))
	for _, item := range inventory {
		expectedSize, ok := expected[item.Name]
		if !ok || item.Size != expectedSize {
			return errors.New("backup inventory does not match manifest")
		}
		if _, duplicate := seen[item.Name]; duplicate {
			return errors.New("backup inventory does not match manifest")
		}
		seen[item.Name] = struct{}{}
	}
	return nil
}

// duplicateJSONKeys rejects duplicate object member names at every depth.
func duplicateJSONKeys(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if duplicateJSONValue(decoder) != nil {
		return true
	}
	return decoder.Decode(new(any)) != io.EOF
}

func duplicateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if _, duplicate := seen[name]; duplicate {
				return errors.New("duplicate JSON key")
			}
			seen[name] = struct{}{}
			if err := duplicateJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := duplicateJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("invalid JSON delimiter")
	}
}

// objectPath is kept near manifest validation so the reserved layout is not
// duplicated by callers within this package.
func objectPath(name string) string { return path.Join(ObjectEntryPrefix, name) }
