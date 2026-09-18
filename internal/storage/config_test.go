package storage

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
)

func TestRhizaConfigFromEnvStandaloneProfiles(t *testing.T) {
	base := map[string]string{
		"GOAUTHY_CLUSTER_ID": "prod", "GOAUTHY_NODE_ID": "node-0", "GOAUTHY_DATA_DIR": "./data/node-0",
	}
	var configs []rhiza.Config
	for _, profile := range []string{RhizaProfileDev, RhizaProfileStandalone} {
		env := copyEnv(base)
		env["GOAUTHY_RHIZA_PROFILE"] = profile
		config, err := RhizaConfigFromEnv(envMap(env))
		if err != nil {
			t.Fatalf("profile %q: %v", profile, err)
		}
		if config.Members != nil || config.ObjStoreProvider != "" || config.PeerAddr != "" || config.AdminToken != "" {
			t.Fatalf("profile %q unexpectedly enables cluster features: %#v", profile, config)
		}
		configs = append(configs, config)
	}
	if !reflect.DeepEqual(configs[0], configs[1]) {
		t.Fatalf("dev and standalone configs differ: %#v != %#v", configs[0], configs[1])
	}
}

func TestRhizaConfigFromEnvStandaloneRejectsClusterSettings(t *testing.T) {
	base := map[string]string{
		"GOAUTHY_RHIZA_PROFILE": RhizaProfileStandalone, "GOAUTHY_CLUSTER_ID": "prod", "GOAUTHY_NODE_ID": "node-0", "GOAUTHY_DATA_DIR": "./data/node-0",
	}
	for _, profile := range []string{RhizaProfileDev, RhizaProfileStandalone} {
		for _, field := range rhizaClusterEnv {
			t.Run(profile+"/"+field, func(t *testing.T) {
				env := copyEnv(base)
				env["GOAUTHY_RHIZA_PROFILE"] = profile
				env[field] = "configured"
				if _, err := RhizaConfigFromEnv(envMap(env)); err == nil {
					t.Fatalf("profile %q accepted %s", profile, field)
				}
			})
		}
	}
}

func TestRhizaConfigFromEnvCluster(t *testing.T) {
	env := clusterEnv()
	env["GOAUTHY_RHIZA_CHECKPOINT_INTERVAL"] = "1s"
	config, err := RhizaConfigFromEnv(envMap(env))
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Members) != 3 || config.Members[0].ID != "goauthy-0" || config.Members[0].Token != "voter-0" || config.AdminToken != "admin-token" || config.ObjStoreDurability != rhiza.ObjectStoreDurabilityBeforeAck || config.ObjStoreProvider != "s3" || config.CheckpointInterval != time.Second {
		t.Fatalf("unexpected cluster config: %#v", config)
	}
}

func TestRhizaConfigFromEnvDurableStandalone(t *testing.T) {
	env := clusterEnv()
	env["GOAUTHY_RHIZA_PROFILE"] = RhizaProfileStandalone
	env["GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE"] = "true"
	for _, name := range []string{"GOAUTHY_RHIZA_MEMBERS", "GOAUTHY_RHIZA_PEER_ADDR", "GOAUTHY_RHIZA_ADMIN_TOKEN"} {
		delete(env, name)
	}
	config, err := RhizaConfigFromEnv(envMap(env))
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Members) != 0 || config.PeerAddr != "" || config.AdminToken != "" || config.ObjStoreProvider != "s3" || config.ObjStoreDurability != rhiza.ObjectStoreDurabilityBeforeAck || config.ObjStorePrefix != "production" {
		t.Fatal("durable standalone did not preserve the isolated before-ack contract")
	}
	for _, name := range []string{"GOAUTHY_RHIZA_OBJECT_STORE_BUCKET", "GOAUTHY_RHIZA_OBJECT_STORE_PREFIX"} {
		invalid := copyEnv(env)
		delete(invalid, name)
		if _, err := RhizaConfigFromEnv(envMap(invalid)); err == nil {
			t.Fatalf("partial object storage accepted without %s", name)
		}
	}
	for _, name := range []string{"GOAUTHY_RHIZA_PEER_ADDR", "GOAUTHY_RHIZA_MEMBERS", "GOAUTHY_RHIZA_ADMIN_TOKEN", "GOAUTHY_RHIZA_OBJECT_STORE_DURABILITY", "GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY"} {
		invalid := copyEnv(env)
		invalid[name] = "unexpected"
		if _, err := RhizaConfigFromEnv(envMap(invalid)); err == nil {
			t.Fatalf("unsafe standalone override accepted: %s", name)
		}
	}
}

func TestRhizaConfigFromEnvGCSBeforeAck(t *testing.T) {
	for _, profile := range []string{RhizaProfileStandalone, RhizaProfileCluster} {
		t.Run(profile, func(t *testing.T) {
			env := clusterEnv()
			env["GOAUTHY_RHIZA_PROFILE"] = profile
			env["GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER"] = "gcs"
			if profile == RhizaProfileStandalone {
				env["GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE"] = "true"
				for _, name := range []string{"GOAUTHY_RHIZA_MEMBERS", "GOAUTHY_RHIZA_PEER_ADDR", "GOAUTHY_RHIZA_ADMIN_TOKEN"} {
					delete(env, name)
				}
			}
			config, err := RhizaConfigFromEnv(envMap(env))
			if err != nil {
				t.Fatal(err)
			}
			if config.ObjStoreProvider != "gcs" || config.ObjStoreBucket != "goauthy" || config.ObjStorePrefix != "production" || config.ObjStoreDurability != rhiza.ObjectStoreDurabilityBeforeAck || config.ObjStoreEndpoint != "" || config.ObjStoreAccessKey != "" || config.ObjStoreSecretKey != "" {
				t.Fatalf("unexpected GCS config: %#v", config)
			}
		})
	}
}

func TestRhizaConfigFromEnvGCSRejectsS3Settings(t *testing.T) {
	for _, name := range s3OnlyObjectStoreEnv {
		t.Run(name, func(t *testing.T) {
			env := clusterEnv()
			env["GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER"] = "gcs"
			env[name] = "configured"
			if _, err := RhizaConfigFromEnv(envMap(env)); err == nil {
				t.Fatalf("GCS accepted S3-only %s", name)
			}
		})
	}
}

func TestRhizaConfigFromEnvRejectsUnknownObjectStoreProvider(t *testing.T) {
	env := clusterEnv()
	env["GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER"] = "azure"
	if _, err := RhizaConfigFromEnv(envMap(env)); err == nil {
		t.Fatal("unknown object-store provider accepted")
	}
}

func TestRhizaConfigRequiredObjectStoreFailsClosed(t *testing.T) {
	base := map[string]string{
		"GOAUTHY_CLUSTER_ID": "test", "GOAUTHY_NODE_ID": "node-0", "GOAUTHY_DATA_DIR": "./data",
		"GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE": "true",
	}
	for _, profile := range []string{RhizaProfileStandalone, RhizaProfileDev} {
		env := copyEnv(base)
		env["GOAUTHY_RHIZA_PROFILE"] = profile
		if _, err := RhizaConfigFromEnv(envMap(env)); err == nil {
			t.Fatalf("%s silently fell back to local storage", profile)
		}
	}
	env := clusterEnv()
	env["GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE"] = "invalid"
	if _, err := RhizaConfigFromEnv(envMap(env)); err == nil {
		t.Fatal("invalid durability requirement accepted")
	}
}

func TestRhizaConfigFromEnvRejectsUnsafeCheckpointIntervals(t *testing.T) {
	for _, interval := range []string{"not-a-duration", "0s", "-1s", "999ms", "24h1m", "2562048h"} {
		t.Run(interval, func(t *testing.T) {
			env := clusterEnv()
			env["GOAUTHY_RHIZA_CHECKPOINT_INTERVAL"] = interval
			if _, err := RhizaConfigFromEnv(envMap(env)); err == nil {
				t.Fatalf("unsafe checkpoint interval %q was accepted", interval)
			}
		})
	}
}

func TestRhizaConfigFromEnvAcceptsLegacyAdminTokenAlias(t *testing.T) {
	env := clusterEnv()
	env["GOAUTHY_RHIZA_PEER_TOKEN"] = env["GOAUTHY_RHIZA_ADMIN_TOKEN"]
	delete(env, "GOAUTHY_RHIZA_ADMIN_TOKEN")
	config, err := RhizaConfigFromEnv(envMap(env))
	if err != nil {
		t.Fatal(err)
	}
	if config.AdminToken != "admin-token" {
		t.Fatalf("legacy admin token was not mapped: %q", config.AdminToken)
	}
}

func TestRhizaConfigFromEnvRejectsUnsafeClusterConfig(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]string)
	}{
		{"missing admin token", func(env map[string]string) { delete(env, "GOAUTHY_RHIZA_ADMIN_TOKEN") }},
		{"both admin token names", func(env map[string]string) { env["GOAUTHY_RHIZA_PEER_TOKEN"] = "legacy-admin-token" }},
		{"wrong member count", func(env map[string]string) { env["GOAUTHY_RHIZA_MEMBERS"] = `[]` }},
		{"local node absent", func(env map[string]string) { env["GOAUTHY_NODE_ID"] = "goauthy-9" }},
		{"missing voter token", func(env map[string]string) {
			env["GOAUTHY_RHIZA_MEMBERS"] = `[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.headless:9090","token":""},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.headless:9090","token":"voter-1"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.headless:9090","token":"voter-2"}]`
		}},
		{"duplicate voter token", func(env map[string]string) {
			env["GOAUTHY_RHIZA_MEMBERS"] = `[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.headless:9090","token":"voter-0"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.headless:9090","token":"voter-0"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.headless:9090","token":"voter-2"}]`
		}},
		{"voter token equals admin", func(env map[string]string) {
			env["GOAUTHY_RHIZA_MEMBERS"] = `[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.headless:9090","token":"admin-token"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.headless:9090","token":"voter-1"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.headless:9090","token":"voter-2"}]`
		}},
		{"duplicate member ID", func(env map[string]string) {
			env["GOAUTHY_RHIZA_MEMBERS"] = `[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.headless:9090","token":"voter-0"},{"node_id":"goauthy-0","peer_url":"quic://goauthy-1.headless:9090","token":"voter-1"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.headless:9090","token":"voter-2"}]`
		}},
		{"duplicate peer URL", func(env map[string]string) {
			env["GOAUTHY_RHIZA_MEMBERS"] = `[{"node_id":"goauthy-0","peer_url":"quic://same.headless:9090","token":"voter-0"},{"node_id":"goauthy-1","peer_url":"quic://same.headless:9090","token":"voter-1"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.headless:9090","token":"voter-2"}]`
		}},
		{"partial credentials", func(env map[string]string) { env["GOAUTHY_RHIZA_OBJECT_STORE_ACCESS_KEY"] = "key" }},
		{"session token without static credentials", func(env map[string]string) { env["GOAUTHY_RHIZA_OBJECT_STORE_SESSION_TOKEN"] = "session" }},
		{"endpoint URL scheme", func(env map[string]string) { env["GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT"] = "http://minio:9000" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			env := clusterEnv()
			test.mutate(env)
			if _, err := RhizaConfigFromEnv(envMap(env)); err == nil {
				t.Fatal("unsafe cluster configuration was accepted")
			}
		})
	}
}

func TestRhizaConfigFromEnvRejectsUnsupportedClusterObjectStoreSettings(t *testing.T) {
	for _, field := range unsupportedClusterObjectStoreEnv {
		t.Run(field, func(t *testing.T) {
			env := clusterEnv()
			env[field] = "configured"
			if _, err := RhizaConfigFromEnv(envMap(env)); err == nil {
				t.Fatalf("cluster profile accepted unsupported %s", field)
			}
		})
	}
}

func TestRhizaOpenRejectsMissingVoterTokenAfterParse(t *testing.T) {
	config, err := RhizaConfigFromEnv(envMap(clusterEnv()))
	if err != nil {
		t.Fatal(err)
	}
	config.Members[1].Token = ""
	config.DataDir = t.TempDir()
	if _, err := rhiza.Open(context.Background(), config); err == nil {
		t.Fatal("rhiza.Open accepted a missing voter token")
	}
}

func TestRhizaConfigFromEnvRejectsUnknownProfile(t *testing.T) {
	if _, err := RhizaConfigFromEnv(envMap(map[string]string{"GOAUTHY_RHIZA_PROFILE": "four-peer"})); err == nil {
		t.Fatal("unknown profile was accepted")
	}
}

func TestRhizaConfigFromEnvRejectsBroadDataDirectory(t *testing.T) {
	for _, directory := range []string{".", "..", "/"} {
		if _, err := RhizaConfigFromEnv(envMap(map[string]string{
			"GOAUTHY_RHIZA_PROFILE": RhizaProfileStandalone, "GOAUTHY_CLUSTER_ID": "dev", "GOAUTHY_NODE_ID": "dev-0", "GOAUTHY_DATA_DIR": directory,
		})); err == nil {
			t.Fatalf("broad data directory %q accepted", directory)
		}
	}
}

func clusterEnv() map[string]string {
	return map[string]string{
		"GOAUTHY_RHIZA_PROFILE": "cluster", "GOAUTHY_CLUSTER_ID": "prod", "GOAUTHY_NODE_ID": "goauthy-1", "GOAUTHY_DATA_DIR": "/data",
		"GOAUTHY_RHIZA_PEER_ADDR": ":9090", "GOAUTHY_RHIZA_ADMIN_TOKEN": "admin-token",
		"GOAUTHY_RHIZA_MEMBERS":             `[{"node_id":"goauthy-0","peer_url":"quic://goauthy-0.headless:9090","token":"voter-0"},{"node_id":"goauthy-1","peer_url":"quic://goauthy-1.headless:9090","token":"voter-1"},{"node_id":"goauthy-2","peer_url":"quic://goauthy-2.headless:9090","token":"voter-2"}]`,
		"GOAUTHY_RHIZA_OBJECT_STORE_BUCKET": "goauthy", "GOAUTHY_RHIZA_OBJECT_STORE_PREFIX": "production",
	}
}

func copyEnv(values map[string]string) map[string]string {
	copy := make(map[string]string, len(values))
	for key, value := range values {
		copy[key] = value
	}
	return copy
}

func envMap(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}
