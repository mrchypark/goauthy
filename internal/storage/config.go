package storage

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mrchypark/rhiza"
)

const (
	// RhizaProfileStandalone is the production single-node profile.
	RhizaProfileStandalone = "standalone"
	// RhizaProfileDev is one local embedded node. It never accepts cluster
	// peers or object-store credentials.
	RhizaProfileDev = "dev"
	// RhizaProfileCluster is exactly three fixed embedded peers.
	RhizaProfileCluster = "cluster"
)

var rhizaClusterEnv = []string{
	"GOAUTHY_RHIZA_PEER_ADDR",
	"GOAUTHY_RHIZA_ADMIN_TOKEN",
	"GOAUTHY_RHIZA_PEER_TOKEN",
	"GOAUTHY_RHIZA_MEMBERS",
	"GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER",
	"GOAUTHY_RHIZA_OBJECT_STORE_DIR",
	"GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT",
	"GOAUTHY_RHIZA_OBJECT_STORE_BUCKET",
	"GOAUTHY_RHIZA_OBJECT_STORE_PREFIX",
	"GOAUTHY_RHIZA_OBJECT_STORE_REGION",
	"GOAUTHY_RHIZA_OBJECT_STORE_INSECURE",
	"GOAUTHY_RHIZA_OBJECT_STORE_RETRIES",
	"GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY",
	"GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY",
	"GOAUTHY_RHIZA_OBJECT_STORE_SESSION_TOKEN",
	"GOAUTHY_RHIZA_OBJECT_STORE_SERVICE_ACCOUNT",
	"GOAUTHY_RHIZA_OBJECT_STORE_AZURE_TENANT_ID",
	"GOAUTHY_RHIZA_OBJECT_STORE_AZURE_CLIENT_ID",
	"GOAUTHY_RHIZA_OBJECT_STORE_AZURE_CLIENT_SECRET",
	"GOAUTHY_RHIZA_OBJECT_STORE_AZURE_STORAGE_ACCOUNT",
	"GOAUTHY_RHIZA_OBJECT_STORE_AZURE_STORAGE_ACCOUNT_KEY",
	"GOAUTHY_RHIZA_OBJECT_STORE_AZURE_CONNECTION_STRING",
	"GOAUTHY_RHIZA_OBJECT_STORE_AZURE_USER_ASSIGNED_ID",
	"GOAUTHY_RHIZA_OBJECT_STORE_DURABILITY",
	"GOAUTHY_RHIZA_OBJECT_STORE_SYNC_INTERVAL",
	"GOAUTHY_RHIZA_OBJECT_STORE_BATCH_DELAY",
	"GOAUTHY_RHIZA_OBJECT_STORE_GC_INTERVAL",
	"GOAUTHY_RHIZA_OBJECT_STORE_GC_GRACE_PERIOD",
	"GOAUTHY_RHIZA_CHECKPOINT_INTERVAL",
}

const (
	rhizaCheckpointIntervalEnv = "GOAUTHY_RHIZA_CHECKPOINT_INTERVAL"
	// One second matches the deterministic HA backup E2E polling cadence;
	// 24 hours prevents an accidental interval from disabling useful checkpoints.
	rhizaCheckpointIntervalMin = time.Second
	rhizaCheckpointIntervalMax = 24 * time.Hour
)

var unsupportedClusterObjectStoreEnv = []string{
	"GOAUTHY_RHIZA_OBJECT_STORE_DIR",
	"GOAUTHY_RHIZA_OBJECT_STORE_RETRIES",
	"GOAUTHY_RHIZA_OBJECT_STORE_SERVICE_ACCOUNT",
	"GOAUTHY_RHIZA_OBJECT_STORE_AZURE_TENANT_ID",
	"GOAUTHY_RHIZA_OBJECT_STORE_AZURE_CLIENT_ID",
	"GOAUTHY_RHIZA_OBJECT_STORE_AZURE_CLIENT_SECRET",
	"GOAUTHY_RHIZA_OBJECT_STORE_AZURE_STORAGE_ACCOUNT",
	"GOAUTHY_RHIZA_OBJECT_STORE_AZURE_STORAGE_ACCOUNT_KEY",
	"GOAUTHY_RHIZA_OBJECT_STORE_AZURE_CONNECTION_STRING",
	"GOAUTHY_RHIZA_OBJECT_STORE_AZURE_USER_ASSIGNED_ID",
	"GOAUTHY_RHIZA_OBJECT_STORE_DURABILITY",
	"GOAUTHY_RHIZA_OBJECT_STORE_SYNC_INTERVAL",
	"GOAUTHY_RHIZA_OBJECT_STORE_BATCH_DELAY",
	"GOAUTHY_RHIZA_OBJECT_STORE_GC_INTERVAL",
	"GOAUTHY_RHIZA_OBJECT_STORE_GC_GRACE_PERIOD",
}

// s3OnlyObjectStoreEnv cannot be set for GCS. Rhiza uses Application Default
// Credentials for GCS; accepting any S3 setting here would make a deployment
// look configured while silently ignoring its credential or transport intent.
var s3OnlyObjectStoreEnv = []string{
	"GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT",
	"GOAUTHY_RHIZA_OBJECT_STORE_REGION",
	"GOAUTHY_RHIZA_OBJECT_STORE_INSECURE",
	"GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY",
	"GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY",
	"GOAUTHY_RHIZA_OBJECT_STORE_SESSION_TOKEN",
}

// RhizaConfigFromEnv builds only the supported embedded Rhiza profiles.
// It intentionally does not configure Rhiza's optional HTTP handler: GoAuthy
// calls the public in-process API and owns the only public HTTP listener.
//
// Required in all profiles: GOAUTHY_RHIZA_PROFILE, GOAUTHY_CLUSTER_ID,
// GOAUTHY_NODE_ID, and GOAUTHY_DATA_DIR. Standalone may opt into durable
// object storage with a bucket and prefix; partial settings fail closed.
// Dev remains local-only. The cluster profile additionally
// requires GOAUTHY_RHIZA_PEER_ADDR, GOAUTHY_RHIZA_MEMBERS (a three-element
// JSON array of rhiza.Member with distinct voter tokens), and
// GOAUTHY_RHIZA_ADMIN_TOKEN (GOAUTHY_RHIZA_PEER_TOKEN is the legacy alias),
// GOAUTHY_RHIZA_OBJECT_STORE_BUCKET, and GOAUTHY_RHIZA_OBJECT_STORE_PREFIX.
// S3 is the default object-store provider. GCS uses Application Default
// Credentials only; service-account JSON and S3 settings are rejected.
func RhizaConfigFromEnv(getenv func(string) string) (rhiza.Config, error) {
	profile := getenv("GOAUTHY_RHIZA_PROFILE")
	clusterID := getenv("GOAUTHY_CLUSTER_ID")
	nodeID := getenv("GOAUTHY_NODE_ID")
	dataDir := getenv("GOAUTHY_DATA_DIR")
	if profile != RhizaProfileDev && profile != RhizaProfileStandalone && profile != RhizaProfileCluster {
		return rhiza.Config{}, fmt.Errorf("GOAUTHY_RHIZA_PROFILE must be %q, %q, or %q", RhizaProfileStandalone, RhizaProfileDev, RhizaProfileCluster)
	}
	if clusterID == "" || nodeID == "" || dataDir == "" {
		return rhiza.Config{}, fmt.Errorf("GOAUTHY_CLUSTER_ID, GOAUTHY_NODE_ID, and GOAUTHY_DATA_DIR are required")
	}
	if cleaned := filepath.Clean(dataDir); cleaned == "." || cleaned == ".." || cleaned == string(filepath.Separator) {
		return rhiza.Config{}, fmt.Errorf("GOAUTHY_DATA_DIR must name a dedicated directory")
	}

	config := rhiza.Config{ClusterID: clusterID, NodeID: nodeID, DataDir: dataDir}
	requireObjectStore, err := optionalBool(getenv("GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE"))
	if err != nil {
		return rhiza.Config{}, fmt.Errorf("GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE: %w", err)
	}
	if requireObjectStore && profile == RhizaProfileDev {
		return rhiza.Config{}, fmt.Errorf("dev Rhiza profile does not support required object storage")
	}
	if profile == RhizaProfileDev || profile == RhizaProfileStandalone {
		objectStore := requireObjectStore
		for _, name := range rhizaClusterEnv {
			if getenv(name) != "" {
				if profile == RhizaProfileStandalone && (strings.HasPrefix(name, "GOAUTHY_RHIZA_OBJECT_STORE_") || name == rhizaCheckpointIntervalEnv) {
					objectStore = true
					continue
				}
				return rhiza.Config{}, fmt.Errorf("%s Rhiza profile does not accept %s", profile, name)
			}
		}
		if objectStore {
			return withObjectStore(config, getenv)
		}
		return config, nil
	}

	peerAddr := getenv("GOAUTHY_RHIZA_PEER_ADDR")
	if err := validateAddress(peerAddr); err != nil {
		return rhiza.Config{}, fmt.Errorf("GOAUTHY_RHIZA_PEER_ADDR: %w", err)
	}
	members, err := parseMembers(getenv("GOAUTHY_RHIZA_MEMBERS"), nodeID)
	if err != nil {
		return rhiza.Config{}, err
	}
	adminToken, legacyToken := getenv("GOAUTHY_RHIZA_ADMIN_TOKEN"), getenv("GOAUTHY_RHIZA_PEER_TOKEN")
	if adminToken != "" && legacyToken != "" {
		return rhiza.Config{}, fmt.Errorf("GOAUTHY_RHIZA_ADMIN_TOKEN and legacy GOAUTHY_RHIZA_PEER_TOKEN must not both be set")
	}
	if adminToken == "" {
		adminToken = legacyToken
	}
	if adminToken == "" {
		return rhiza.Config{}, fmt.Errorf("GOAUTHY_RHIZA_ADMIN_TOKEN is required for the cluster profile")
	}
	for _, member := range members {
		if member.Token == adminToken {
			return rhiza.Config{}, fmt.Errorf("GOAUTHY_RHIZA_ADMIN_TOKEN must differ from voter token for %s", member.ID)
		}
	}
	config.PeerAddr = peerAddr
	config.AdminToken = adminToken
	config.Members = members
	return withObjectStore(config, getenv)
}

// withObjectStore keeps durable standalone and HA on the same before-ack path.
// DataDir is a disposable cache; encryption keys must be supplied separately.
func withObjectStore(config rhiza.Config, getenv func(string) string) (rhiza.Config, error) {
	for _, name := range unsupportedClusterObjectStoreEnv {
		if getenv(name) != "" {
			return rhiza.Config{}, fmt.Errorf("Rhiza profile does not support %s; before-ack durability is fixed", name)
		}
	}
	bucket, prefix := getenv("GOAUTHY_RHIZA_OBJECT_STORE_BUCKET"), getenv("GOAUTHY_RHIZA_OBJECT_STORE_PREFIX")
	if bucket == "" || prefix == "" {
		return rhiza.Config{}, fmt.Errorf("GOAUTHY_RHIZA_OBJECT_STORE_BUCKET and GOAUTHY_RHIZA_OBJECT_STORE_PREFIX are required for durable storage")
	}
	checkpointInterval, err := parseCheckpointInterval(getenv(rhizaCheckpointIntervalEnv))
	if err != nil {
		return rhiza.Config{}, err
	}
	provider := getenv("GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER")
	if provider == "" {
		provider = "s3"
	}
	if provider != "s3" && provider != "gcs" {
		return rhiza.Config{}, fmt.Errorf("GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER must be %q or %q", "s3", "gcs")
	}
	if provider == "gcs" {
		for _, name := range s3OnlyObjectStoreEnv {
			if getenv(name) != "" {
				return rhiza.Config{}, fmt.Errorf("GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER=gcs does not support %s; use workload identity ADC", name)
			}
		}
		config.ObjStoreProvider = provider
		config.ObjStoreBucket = bucket
		config.ObjStorePrefix = prefix
		config.ObjStoreDurability = rhiza.ObjectStoreDurabilityBeforeAck
		config.CheckpointInterval = checkpointInterval
		return config, nil
	}
	endpoint := getenv("GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT")
	if endpoint != "" {
		if err := validateS3Endpoint(endpoint); err != nil {
			return rhiza.Config{}, fmt.Errorf("GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT: %w", err)
		}
	}
	accessKey, secretKey := getenv("GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY"), getenv("GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY")
	if (accessKey == "") != (secretKey == "") {
		return rhiza.Config{}, fmt.Errorf("GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY and GOAUTHY_RHIZA_OBJECT_STORE_SECRET_KEY must be set together")
	}
	insecure, err := optionalBool(getenv("GOAUTHY_RHIZA_OBJECT_STORE_INSECURE"))
	if err != nil {
		return rhiza.Config{}, fmt.Errorf("GOAUTHY_RHIZA_OBJECT_STORE_INSECURE: %w", err)
	}
	if getenv("GOAUTHY_RHIZA_OBJECT_STORE_SESSION_TOKEN") != "" && accessKey == "" {
		return rhiza.Config{}, fmt.Errorf("GOAUTHY_RHIZA_OBJECT_STORE_SESSION_TOKEN requires static access credentials")
	}

	config.ObjStoreProvider = provider
	config.ObjStoreEndpoint = endpoint
	config.ObjStoreBucket = bucket
	config.ObjStorePrefix = prefix
	config.ObjStoreRegion = getenv("GOAUTHY_RHIZA_OBJECT_STORE_REGION")
	config.ObjStoreInsecure = insecure
	config.ObjStoreAccessKey = accessKey
	config.ObjStoreSecretKey = secretKey
	config.ObjStoreSessionToken = getenv("GOAUTHY_RHIZA_OBJECT_STORE_SESSION_TOKEN")
	config.ObjStoreDurability = rhiza.ObjectStoreDurabilityBeforeAck
	config.CheckpointInterval = checkpointInterval
	return config, nil
}

func parseCheckpointInterval(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	interval, err := time.ParseDuration(raw)
	if err != nil || interval < rhizaCheckpointIntervalMin || interval > rhizaCheckpointIntervalMax {
		return 0, fmt.Errorf("%s must be a duration between %s and %s", rhizaCheckpointIntervalEnv, rhizaCheckpointIntervalMin, rhizaCheckpointIntervalMax)
	}
	return interval, nil
}

func parseMembers(raw, nodeID string) ([]rhiza.Member, error) {
	var members []rhiza.Member
	if err := json.Unmarshal([]byte(raw), &members); err != nil || len(members) != 3 {
		return nil, fmt.Errorf("GOAUTHY_RHIZA_MEMBERS must be a JSON array with exactly three members")
	}
	seen := make(map[string]struct{}, len(members))
	seenURLs := make(map[string]struct{}, len(members))
	seenTokens := make(map[string]struct{}, len(members))
	local := false
	for i, member := range members {
		id := string(member.ID)
		if id == "" {
			return nil, fmt.Errorf("GOAUTHY_RHIZA_MEMBERS[%d] has an empty node_id", i)
		}
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("GOAUTHY_RHIZA_MEMBERS has duplicate node_id %q", id)
		}
		seen[id] = struct{}{}
		local = local || id == nodeID
		if member.Token == "" {
			return nil, fmt.Errorf("GOAUTHY_RHIZA_MEMBERS[%d] has an empty voter token", i)
		}
		if _, ok := seenTokens[member.Token]; ok {
			return nil, fmt.Errorf("GOAUTHY_RHIZA_MEMBERS has duplicate voter token")
		}
		seenTokens[member.Token] = struct{}{}
		if err := validatePeerURL(member.PeerURL); err != nil {
			return nil, fmt.Errorf("GOAUTHY_RHIZA_MEMBERS[%d].peer_url: %w", i, err)
		}
		for _, endpoint := range []struct {
			name  string
			value string
		}{{"peer_url", member.PeerURL}, {"url", member.URL}, {"log_url", member.LogURL}} {
			if endpoint.value == "" {
				continue
			}
			if _, ok := seenURLs[endpoint.value]; ok {
				return nil, fmt.Errorf("GOAUTHY_RHIZA_MEMBERS has duplicate %s %q", endpoint.name, endpoint.value)
			}
			seenURLs[endpoint.value] = struct{}{}
		}
	}
	if !local {
		return nil, fmt.Errorf("GOAUTHY_NODE_ID %q is not a cluster member", nodeID)
	}
	return members, nil
}

func validateAddress(address string) error {
	if address == "" {
		return fmt.Errorf("is required")
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return fmt.Errorf("must be host:port")
	}
	return nil
}

func validatePeerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "quic" || u.Host == "" || u.Path != "" {
		return fmt.Errorf("must be a quic://host:port URL")
	}
	return validateAddress(u.Host)
}

func validateS3Endpoint(raw string) error {
	u, err := url.Parse("//" + raw)
	if err != nil || u.Host != raw || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("must be a host or host:port without a URL scheme or path")
	}
	return nil
}

func optionalBool(raw string) (bool, error) {
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("must be a boolean")
	}
	return value, nil
}
