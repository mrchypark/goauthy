//go:build integration

package storage_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	cloudstorage "cloud.google.com/go/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	kitlog "github.com/go-kit/log"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/mrchypark/rhiza/pkg/recovery"
	"github.com/thanos-io/objstore"
	thanazure "github.com/thanos-io/objstore/providers/azure"
	"google.golang.org/api/iterator"
)

func TestObjectStoreDependencyContract(t *testing.T) {
	if os.Getenv("GOAUTHY_OBJECT_CONTRACT") != "1" {
		t.Skip("requires the isolated object-store emulator launcher")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	provider := os.Getenv("GOAUTHY_OBJECT_PROVIDER")
	endpoint := os.Getenv("GOAUTHY_OBJECT_ENDPOINT")
	endpointURL, err := loopbackObjectEndpoint(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := waitForObjectStoreEndpoint(ctx, endpointURL); err != nil {
		t.Fatalf("wait for object-store emulator readiness: %v", err)
	}
	runID := fmt.Sprintf("%d", time.Now().UnixNano())
	bucketName := "goauthy-contract-" + runID
	prefix := "contract-" + runID
	dataDir := filepath.Join(t.TempDir(), "data")
	config := rhiza.Config{
		Local: true, ClusterID: "object-contract-" + runID, NodeID: "local", DataDir: dataDir,
		ObjStoreBucket: bucketName, ObjStorePrefix: prefix, ObjStoreProvider: provider,
		ObjStoreAccessKey: "test", ObjStoreSecretKey: "test", ObjStoreRegion: "us-east-1",
		ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck,
	}

	var bucket objstore.Bucket
	var azureClient *azblob.Client
	switch provider {
	case "s3":
		config.ObjStoreEndpoint = os.Getenv("GOAUTHY_RECOVERY_S3_ENDPOINT")
		if config.ObjStoreEndpoint == "" {
			config.ObjStoreEndpoint = endpointURL.Host
		}
		s3Endpoint, err := loopbackObjectEndpoint("http://" + config.ObjStoreEndpoint)
		if err != nil || !sameObjectStoreAuthority(endpointURL, s3Endpoint) {
			t.Fatal("S3 endpoint must match the explicit loopback emulator endpoint")
		}
		if value := os.Getenv("GOAUTHY_RECOVERY_S3_ACCESS_KEY"); value != "" {
			config.ObjStoreAccessKey = value
		}
		if value := os.Getenv("GOAUTHY_RECOVERY_S3_SECRET_KEY"); value != "" {
			config.ObjStoreSecretKey = value
		}
		config.ObjStoreInsecure = true
		s3Client, err := minio.New(config.ObjStoreEndpoint, &minio.Options{
			Creds:  credentials.NewStaticV4(config.ObjStoreAccessKey, config.ObjStoreSecretKey, config.ObjStoreSessionToken),
			Secure: false, Region: config.ObjStoreRegion, BucketLookup: minio.BucketLookupPath,
		})
		if err != nil {
			t.Fatalf("create loopback S3 SDK client: %v", err)
		}
		if err := s3Client.MakeBucket(ctx, config.ObjStoreBucket, minio.MakeBucketOptions{Region: config.ObjStoreRegion}); err != nil {
			t.Fatalf("create disposable S3 bucket: %v", err)
		}
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			for object := range s3Client.ListObjects(cleanupCtx, config.ObjStoreBucket, minio.ListObjectsOptions{Recursive: true}) {
				if object.Err != nil {
					t.Errorf("list disposable S3 bucket objects for cleanup: %v", object.Err)
					return
				}
				if err := s3Client.RemoveObject(cleanupCtx, config.ObjStoreBucket, object.Key, minio.RemoveObjectOptions{}); err != nil {
					t.Errorf("remove disposable S3 object %q: %v", object.Key, err)
					return
				}
			}
			if err := s3Client.RemoveBucket(cleanupCtx, config.ObjStoreBucket); err != nil {
				t.Errorf("remove disposable S3 bucket: %v", err)
			}
		})
		bucket, err = storage.OpenObjectStore(ctx, config)
		if err != nil {
			t.Fatalf("open GoAuthy S3 adapter: %v", err)
		}
		defer bucket.Close()
	case "gcs":
		t.Setenv("STORAGE_EMULATOR_HOST", endpoint)
		gcsClient, err := cloudstorage.NewClient(ctx)
		if err != nil {
			t.Fatalf("create loopback GCS SDK client: %v", err)
		}
		if err := gcsClient.Bucket(config.ObjStoreBucket).Create(ctx, "goauthy-object-contract", nil); err != nil {
			_ = gcsClient.Close()
			t.Fatalf("create disposable GCS bucket: %v", err)
		}
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			defer func() {
				if err := gcsClient.Close(); err != nil {
					t.Errorf("close GCS SDK client: %v", err)
				}
			}()
			gcsBucket := gcsClient.Bucket(config.ObjStoreBucket)
			objects := gcsBucket.Objects(cleanupCtx, nil)
			for {
				attrs, err := objects.Next()
				if errors.Is(err, iterator.Done) {
					break
				}
				if err != nil {
					t.Errorf("list disposable GCS bucket objects for cleanup: %v", err)
					return
				}
				if err := gcsBucket.Object(attrs.Name).Delete(cleanupCtx); err != nil {
					t.Errorf("remove disposable GCS object %q: %v", attrs.Name, err)
					return
				}
			}
			if err := gcsBucket.Delete(cleanupCtx); err != nil {
				t.Errorf("remove disposable GCS bucket: %v", err)
			}
		})
		tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "POST required", http.StatusMethodNotAllowed)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "emulator-test-token", "token_type": "Bearer", "expires_in": 3600})
		}))
		t.Cleanup(tokenServer.Close)
		if _, err := loopbackObjectEndpoint(tokenServer.URL); err != nil {
			t.Fatalf("GCS test token endpoint: %v", err)
		}
		config.ObjStoreServiceAccount = objectContractGCSServiceAccount(t, tokenServer.URL)
		bucket, err = storage.OpenObjectStore(ctx, config)
		if err != nil {
			t.Fatalf("open GoAuthy GCS adapter: %v", err)
		}
		defer bucket.Close()
	case "azure":
		connectionString := os.Getenv("GOAUTHY_OBJECT_AZURE_CONNECTION_STRING")
		if connectionString == "" {
			t.Fatal("GOAUTHY_OBJECT_AZURE_CONNECTION_STRING is required")
		}
		blobEndpoint, accountName := "", ""
		blobEndpointSet, accountNameSet := false, false
		for _, field := range strings.Split(connectionString, ";") {
			key, value, ok := strings.Cut(field, "=")
			if ok {
				switch {
				case strings.EqualFold(key, "BlobEndpoint"):
					if blobEndpointSet {
						t.Fatal("Azure connection string must contain one BlobEndpoint")
					}
					blobEndpointSet = true
					blobEndpoint = value
				case strings.EqualFold(key, "AccountName"):
					if accountNameSet {
						t.Fatal("Azure connection string must contain one AccountName")
					}
					accountNameSet = true
					accountName = value
				}
			}
		}
		if !blobEndpointSet || !accountNameSet || accountName == "" {
			t.Fatal("Azure connection string must contain one BlobEndpoint and a nonempty AccountName")
		}
		blobURL, err := loopbackObjectEndpoint(blobEndpoint)
		if err != nil || !sameObjectStoreAuthority(endpointURL, blobURL) {
			t.Fatal("Azure connection string must name the explicit loopback emulator endpoint")
		}
		azureClient, err = azblob.NewClientFromConnectionString(connectionString, nil)
		if err != nil {
			t.Fatalf("create Azure SDK client: %v", err)
		}
		azureURL, err := loopbackObjectEndpoint(azureClient.ServiceClient().URL())
		if err != nil || !sameObjectStoreEndpoint(blobURL, azureURL) {
			t.Fatal("Azure SDK endpoint must exactly match its validated loopback connection-string endpoint")
		}
		config.ObjStoreAzureConnectionString = connectionString
		config.ObjStoreAzureStorageAccount = accountName
		config.ObjStoreEndpoint = ""
		if _, err := azureClient.CreateContainer(ctx, bucketName, nil); err != nil {
			t.Fatalf("create Azure SDK container: %v", err)
		}
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			if _, err := azureClient.DeleteContainer(cleanupCtx, bucketName, nil); err != nil {
				t.Errorf("remove disposable Azure container: %v", err)
			}
		})
		key := path.Join(prefix, "sdk-contract")
		if _, err := azureClient.UploadBuffer(ctx, bucketName, key, []byte("sdk round trip"), nil); err != nil {
			t.Fatalf("Azure SDK upload: %v", err)
		}
		got, err := azureClient.DownloadStream(ctx, bucketName, key, nil)
		if err != nil {
			t.Fatalf("Azure SDK download: %v", err)
		}
		body, readErr := io.ReadAll(got.Body)
		if err := errors.Join(readErr, got.Body.Close()); err != nil {
			t.Fatalf("read Azure SDK object: %v", err)
		}
		if !bytes.Equal(body, []byte("sdk round trip")) {
			t.Fatalf("Azure SDK round trip = %q", body)
		}
		if _, err := azureClient.DeleteBlob(ctx, bucketName, key, nil); err != nil {
			t.Fatalf("Azure SDK delete: %v", err)
		}
		bucket, err = thanazure.NewBucketWithConfig(kitlog.NewNopLogger(), thanazure.Config{
			StorageAccountName: accountName, StorageConnectionString: connectionString,
			ContainerName: bucketName, StorageCreateContainer: false,
		}, "goauthy-object-contract", nil)
		if err != nil {
			t.Fatalf("open pinned Thanos Azure adapter for Rhiza archive reads: %v", err)
		}
		defer bucket.Close()
	default:
		t.Fatalf("unsupported integration provider %q", provider)
	}
	if bucket != nil {
		key := path.Join(prefix, "sdk-contract")
		if err := bucket.Upload(ctx, key, strings.NewReader("adapter round trip")); err != nil {
			t.Fatalf("GoAuthy %s adapter upload: %v", provider, err)
		}
		reader, err := bucket.Get(ctx, key)
		if err != nil {
			t.Fatalf("GoAuthy %s adapter download: %v", provider, err)
		}
		body, readErr := io.ReadAll(reader)
		if err := errors.Join(readErr, reader.Close()); err != nil {
			t.Fatalf("read GoAuthy %s adapter object: %v", provider, err)
		}
		if string(body) != "adapter round trip" {
			t.Fatalf("GoAuthy %s adapter round trip = %q", provider, body)
		}
		if err := bucket.Delete(ctx, key); err != nil {
			t.Fatalf("GoAuthy %s adapter delete: %v", provider, err)
		}
	}

	// Rhiza v0.21 has no public manual Local checkpoint method. Its documented
	// first-adoption Open publishes existing Local state before returning ready.
	// Keep the normal 15-minute checkpoint default so migrations cannot overlap
	// the periodic checkpointer's proposal quiescence.
	seedConfig := rhiza.Config{
		Local: true, ClusterID: config.ClusterID, NodeID: config.NodeID, DataDir: dataDir,
	}
	seedDB, err := rhiza.Open(ctx, seedConfig)
	if err != nil {
		t.Fatalf("open Local store before first object-store adoption: %v", err)
	}
	defer func() {
		if seedDB != nil {
			_ = seedDB.Close()
		}
	}()
	if err := waitForLocalReady(ctx, seedDB); err != nil {
		t.Fatalf("wait for initial Local readiness: %v", err)
	}
	if err := storage.Migrate(ctx, seedDB); err != nil {
		t.Fatalf("migrate initial Local storage: %v", err)
	}
	for _, statement := range []struct{ id, sql string }{
		{"contract-schema", `CREATE TABLE contract_rows (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)`},
		{"contract-base", `INSERT INTO contract_rows VALUES (1, '{"mistake_candidates":["typo","omission"]}')`},
	} {
		response, err := seedDB.Execute(ctx, rhiza.ExecuteRequest{RequestID: statement.id, SQL: statement.sql})
		if err != nil {
			t.Fatalf("execute %s before object-store adoption: %v", statement.id, err)
		}
		if response.Status != rhiza.MutationCommitted || response.Slot == 0 {
			t.Fatalf("execute %s receipt=%+v; want a committed nonzero-slot receipt", statement.id, response.MutationReceipt)
		}
	}
	if err := seedDB.Close(); err != nil {
		t.Fatalf("close Local store before object-store adoption: %v", err)
	}
	seedDB = nil

	db, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatalf("adopt existing Local state into %s object storage: %v", provider, err)
	}
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()
	if err := waitForLocalReady(ctx, db); err != nil {
		t.Fatalf("wait for Local Rhiza readiness before migrations: %v", err)
	}
	archivePrefix := path.Join(prefix, string(config.ClusterID), "local/v1")
	archiveBeforeTail, err := recovery.OpenLocalArchive(ctx, bucket, archivePrefix)
	if err != nil {
		t.Fatalf("open adopted Local archive through Rhiza public recovery API: %v", err)
	}
	checkpointBeforeTail := archiveBeforeTail.Snapshot()
	if checkpointBeforeTail == nil {
		t.Fatal("adopted Local archive has no snapshot")
	}
	tailResponse, err := db.Execute(ctx, rhiza.ExecuteRequest{RequestID: "contract-tail", SQL: `INSERT INTO contract_rows VALUES (2, '{"mistake_candidates":["stale","duplicate"]}')`})
	if err != nil {
		t.Fatalf("execute acknowledged archive tail: %v", err)
	}
	if tailResponse.Status != rhiza.MutationCommitted || tailResponse.Slot == 0 || tailResponse.RowsAffected != 1 {
		t.Fatalf("archive tail receipt=%+v; want committed one-row mutation", tailResponse.MutationReceipt)
	}
	archiveAfterTail, err := recovery.OpenLocalArchive(ctx, bucket, archivePrefix)
	if err != nil {
		t.Fatalf("open Local archive after acknowledged tail: %v", err)
	}
	checkpointAfterTail := archiveAfterTail.Snapshot()
	if checkpointAfterTail == nil ||
		checkpointAfterTail.Seal.Index != checkpointBeforeTail.Seal.Index ||
		checkpointAfterTail.Seal.RootHash != checkpointBeforeTail.Seal.RootHash ||
		checkpointAfterTail.Seal.StateHash != checkpointBeforeTail.Seal.StateHash {
		t.Fatalf("snapshot advanced across acknowledged tail: before=%v after=%v", checkpointBeforeTail, checkpointAfterTail)
	}
	if uint64(checkpointAfterTail.Seal.Index) >= tailResponse.Slot || uint64(archiveAfterTail.Tip()) < tailResponse.Slot {
		t.Fatalf("remote archive snapshot/tip do not bracket acknowledged tail: snapshot=%d tip=%d tail=%d", checkpointAfterTail.Seal.Index, archiveAfterTail.Tip(), tailResponse.Slot)
	}
	decisions := archiveAfterTail.DecisionsFrom(checkpointAfterTail.Seal.Index+1, int(tailResponse.Slot-uint64(checkpointAfterTail.Seal.Index)))
	if len(decisions) == 0 || uint64(decisions[len(decisions)-1].Slot) != tailResponse.Slot {
		t.Fatalf("remote archive decisions do not reach acknowledged tail slot %d", tailResponse.Slot)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close source Local store: %v", err)
	}
	db = nil
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatalf("simulate full local data loss: %v", err)
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("local data directory survived loss simulation: %v", err)
	}

	restoredDB, err := rhiza.Open(ctx, config)
	if err != nil {
		t.Fatalf("restore Local store from fresh archive: %v", err)
	}
	defer func() {
		if err := restoredDB.Close(); err != nil {
			t.Errorf("close restored Local store: %v", err)
		}
	}()
	rows, err := restoredDB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id, payload FROM contract_rows ORDER BY id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 2 ||
		rows.Rows[0][0] != int64(1) || rows.Rows[0][1] != `{"mistake_candidates":["typo","omission"]}` ||
		rows.Rows[1][0] != int64(2) || rows.Rows[1][1] != `{"mistake_candidates":["stale","duplicate"]}` {
		t.Fatalf("checkpoint plus archive tail restore rows=%v err=%v", rows.Rows, err)
	}
	replayResponse, err := restoredDB.Execute(ctx, rhiza.ExecuteRequest{RequestID: "contract-tail", SQL: `INSERT INTO contract_rows VALUES (2, '{"mistake_candidates":["stale","duplicate"]}')`})
	if err != nil {
		t.Fatalf("replay acknowledged request: %v", err)
	}
	if replayResponse.MutationReceipt != tailResponse.MutationReceipt {
		t.Fatalf("replay receipt=%+v; want original receipt %+v", replayResponse.MutationReceipt, tailResponse.MutationReceipt)
	}
	rows, err = restoredDB.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id FROM contract_rows ORDER BY id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 2 {
		t.Fatalf("request replay duplicated a row: rows=%v err=%v", rows.Rows, err)
	}
}

func loopbackObjectEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("object-store emulator endpoint must be an explicit loopback HTTP URL")
	}
	host := u.Hostname()
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("object-store emulator endpoint must use a loopback host")
		}
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("object-store emulator endpoint must specify a valid port")
	}
	return u, nil
}

func waitForObjectStoreEndpoint(ctx context.Context, endpoint *url.URL) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	address := net.JoinHostPort(endpoint.Hostname(), endpoint.Port())
	dialer := net.Dialer{Timeout: time.Second}
	var lastErr error
	for {
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			return conn.Close()
		}
		lastErr = err
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("TCP endpoint %s was not ready within 60s: %w (last dial: %v)", address, ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
}

func sameObjectStoreAuthority(a, b *url.URL) bool {
	return b != nil && a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) && a.Port() == b.Port()
}

func sameObjectStoreEndpoint(a, b *url.URL) bool {
	return sameObjectStoreAuthority(a, b) && strings.TrimRight(a.EscapedPath(), "/") == strings.TrimRight(b.EscapedPath(), "/")
}

func waitForLocalReady(ctx context.Context, db *rhiza.DB) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	for !db.Ready() {
		select {
		case <-ctx.Done():
			return fmt.Errorf("Local node did not become ready within 60s: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil
}

func objectContractGCSServiceAccount(t *testing.T, tokenURL string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate emulator-only GCS credentials: %v", err)
	}
	credentials, err := json.Marshal(map[string]string{
		"type": "service_account", "project_id": "goauthy-object-contract",
		"private_key_id": "integration-test", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		"client_email": "test@goauthy-object-contract.iam.gserviceaccount.com", "client_id": "0",
		"auth_uri": tokenURL, "token_uri": tokenURL,
		"auth_provider_x509_cert_url": tokenURL, "client_x509_cert_url": tokenURL,
		"universe_domain": "googleapis.com",
	})
	if err != nil {
		t.Fatalf("marshal emulator-only GCS credentials: %v", err)
	}
	return string(credentials)
}
